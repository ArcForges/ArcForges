#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Capture bounded native performance evidence from one verified installed Node cohort."""

import argparse
import base64
from contextlib import closing
import ctypes
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
from sbom import ROOT, digest, json_input, require

sys.path.insert(0, str(ROOT / "packaging" / "mxc"))
from verify_install import protect_install_root, verify


WIN = os.name == "nt"
RID = "win-x64" if WIN else "linux-x64"
SUFFIX = ".exe" if WIN else ""
PROFILE = "windows-process-executor-v1" if WIN else "linux-bubblewrap-sdk-v1"
REVISION = "win-wrapper-local-v1" if WIN else PROFILE
OUTPUT_BYTES = 262_144


def checked(arguments, cwd, env, timeout=40):
    result = subprocess.run(arguments, cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        diagnostic = result.stderr[-1024:].decode("utf-8", "replace").strip()
        if not diagnostic and len(result.stdout) <= 65_536:
            try:
                error = json.loads(result.stdout).get("error", {})
                diagnostic = f"{error.get('code', 'unknown')} {error.get('details', {}).get('state', {}).get('reason', '')}".strip()
            except (ValueError, AttributeError):
                diagnostic = "no structured diagnostic"
        verbs = [argument for argument in arguments[1:4] if not argument.startswith("--")]
        raise ValueError(f"Fixture {Path(arguments[0]).name} {' '.join(verbs)} exited {result.returncode}: {diagnostic}")
    return result.stdout


def launch_times(bench, host, root, env, runs):
    command = [str(bench), "startup", "--exe", str(host), "--arg", "--version", "--timeout-ms", "15000"]
    first = json.loads(checked(command + ["--runs", "1", "--warmup", "0"], root, env))
    warm = json.loads(checked(command + ["--runs", str(runs), "--warmup", "1"], root, env, timeout=180))
    return {"firstProcess": first, "repeatedProcesses": warm,
            "method": "Process launch to exit; one first observation, then explicit warm-up; no OS cache flush."}


def linux_process(pid):
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
    require(stat[0] not in ("Z", "X"), "The observed process exited")
    status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    rss = next((int(line.split()[1]) * 1024 for line in status.splitlines() if line.startswith("VmRSS:")), None)
    require(rss is not None, "Linux resident memory counter unavailable")
    return {"creationIdentity": int(stat[19]), "cpuSeconds": (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK"),
            "rssBytes": rss, "privateCommitBytes": None}


def windows_process(pid):
    from ctypes import wintypes

    class Memory(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ("peakWorkingSet", "workingSet", "peakPagedQuota", "pagedQuota",
            "peakNonpagedQuota", "nonpagedQuota", "pagefile", "peakPagefile", "privateUsage")]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.GetProcessTimes.argtypes = (wintypes.HANDLE, *([ctypes.POINTER(ctypes.c_uint64)] * 4))
    kernel.K32GetProcessMemoryInfo.argtypes = (wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD)
    process = kernel.OpenProcess(0x1000, False, pid)
    require(process, "Cannot observe the owned Windows process")
    try:
        birth, exit_, cpu_kernel, cpu_user = (ctypes.c_uint64() for _ in range(4))
        require(kernel.GetProcessTimes(process, ctypes.byref(birth), ctypes.byref(exit_), ctypes.byref(cpu_kernel), ctypes.byref(cpu_user))
                and exit_.value == 0, "The owned Windows process exited or has no timing record")
        memory = Memory()
        memory.size = ctypes.sizeof(memory)
        require(kernel.K32GetProcessMemoryInfo(process, ctypes.byref(memory), memory.size), "Windows process memory is unavailable")
        return {"creationIdentity": birth.value, "cpuSeconds": (cpu_kernel.value + cpu_user.value) / 10_000_000,
                "rssBytes": memory.workingSet, "privateCommitBytes": memory.privateUsage}
    finally:
        kernel.CloseHandle(process)


def process_sample(pid):
    return windows_process(pid) if WIN else linux_process(pid)


def host_memory_bytes():
    if not WIN:
        return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    kib = ctypes.c_uint64()
    require(ctypes.WinDLL("kernel32", use_last_error=True).GetPhysicallyInstalledSystemMemory(ctypes.byref(kib)),
            "Windows physical memory inventory is unavailable")
    return kib.value * 1024


def observed_window(pid, seconds, expected_creation=None):
    first = process_sample(pid)
    start = time.monotonic()
    time.sleep(seconds)
    last = process_sample(pid)
    elapsed = time.monotonic() - start
    require(first["creationIdentity"] == last["creationIdentity"] and
            (expected_creation is None or expected_creation == first["creationIdentity"]), "Native process identity changed")
    cpu = last["cpuSeconds"] - first["cpuSeconds"]
    require(cpu >= 0, "Native CPU counter went backwards")
    return {"windowSeconds": elapsed, "cpuSeconds": cpu, "percentOfOneCore": 100 * cpu / elapsed,
            "rssBytes": [first["rssBytes"], last["rssBytes"]],
            "privateCommitBytes": [first["privateCommitBytes"], last["privateCommitBytes"]],
            "measurement": ("Independent Windows process CPU, working set and private commit." if WIN
                            else "Independent Linux process CPU and RSS. Per-process private commit is unavailable.")}


def wait_for_install_check(data, node):
    """Keep the installed version's background digest pass out of the idle measurement."""
    log = data / "logs" / "node" / "node.log"
    until = time.monotonic() + 30
    while node.poll() is None and time.monotonic() < until:
        try:
            with log.open("rb") as stream:
                if b'"event":"node.version_integrity.verified"' in stream.read(256 * 1024):
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.25)
    raise ValueError("The exact installed version digest pass did not settle before the idle window")


def supervisor_identity(data, run_id):
    # Only the freshly initialized private fixture store is inspected. The Run owner PID is not taken from a process name lookup.
    alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
    require(len(run_id) == 26 and run_id[0] in alphabet[:8] and all(character in alphabet for character in run_id),
            "CLI Run ID is not canonical")
    numeric_id = 0
    for character in run_id:
        numeric_id = numeric_id * 32 + alphabet.index(character)
    with closing(sqlite3.connect((data / "store" / "node.db").as_uri() + "?mode=ro", uri=True, timeout=2)) as connection:
        identity = connection.execute("SELECT process_id, creation_identity FROM supervisor_identity WHERE run_id=?",
                                      (f"{numeric_id:032x}",)).fetchone()
    require(identity and identity[0] > 0, "Run supervisor identity is absent after Run entered RUNNING")
    return identity[0], int(identity[1])


def read_output(raw):
    seen, gaps, lost = 0, 0, 0
    for line in raw.splitlines():
        frame = json.loads(line)
        if "chunk" in frame:
            chunk = frame["chunk"]
            size = len(base64.b64decode(chunk["data"], validate=True))
            require(int(chunk["nextOffset"]) - int(chunk["offset"]) == size, "Installed CLI output cursor does not match the data")
            seen += size
        if "gap" in frame:
            gap = frame["gap"]
            gaps += 1
            if gap.get("reason") != "epoch_changed":
                lost += int(gap["earliestOffset"]) - int(gap["requestedOffset"])
    return seen, gaps, lost


def capture_runs(cli, root, data, owned_tool, original_tool, seconds):
    config = root / "sandbox.json"
    policy = {"profileId": PROFILE, "profileVersion": REVISION,
              "network": {"egress": "NETWORK_MODE_DENY", "ingress": "NETWORK_MODE_DENY", "hostLoopback": False},
              "resources": {"pressureAction": "PRESSURE_ACTION_THROTTLE"}}
    config.write_text(json.dumps(policy), encoding="utf-8")
    sandbox = json.loads(cli("sandbox", "create", "Native performance fixture", "--file", str(config)))["sandbox"]
    private = Path(sandbox["dataLocation"]).resolve(strict=True)
    require(data in private.parents, "Sandbox data location escaped the owned fixture")
    work = private / "work"
    work.mkdir(exist_ok=True)
    target = work / owned_tool
    shutil.copyfile(original_tool, target)
    if not WIN:
        target.chmod(0o700)
    require(digest(target) == digest(original_tool), "TestLoad changed during fixture staging")

    def start(mode, *arguments):
        return json.loads(cli("run", "start", sandbox["sandboxId"], "--terminal", mode, "--cwd", "work", "--",
                              str(target), *arguments))["run"]["runId"]

    def inspect(run):
        return json.loads(cli("run", "inspect", run))["run"]

    started = time.monotonic()
    hold = start("off", "hold", "--hold-ms", str((seconds + 30) * 1000))
    for _ in range(80):
        if inspect(hold)["state"].upper().endswith("RUNNING"):
            break
        require(time.monotonic() - started < 12, "The held workload did not reach RUNNING")
        time.sleep(0.1)
    else:
        raise ValueError("The held workload did not reach RUNNING")
    run_ready = time.monotonic() - started
    supervisor, creation = supervisor_identity(data, hold)
    supervisor_idle = observed_window(supervisor, seconds, creation)
    started = time.monotonic()
    cli("run", "stop", hold, "--grace-ms", "0")
    final = inspect(hold)
    require(final.get("exit", {}).get("groupEmptyVerified") is True, "Stop did not verify an empty Run group")
    stop = time.monotonic() - started

    output_start = time.monotonic()
    output_run = start("on", "output", "--bytes", str(OUTPUT_BYTES), "--line-bytes", str(OUTPUT_BYTES))
    output = cli("run", "logs", output_run, "--follow", "--stream", "terminal")
    seen, gaps, lost = read_output(output)
    terminal_seconds = time.monotonic() - output_start
    require(seen and inspect(output_run).get("exit", {}).get("groupEmptyVerified") is True,
            "Terminal throughput fixture did not capture output and a verified exit")
    return {"profile": policy, "startToRunningSeconds": run_ready, "supervisorIdle": supervisor_idle,
            "stopToVerifiedEmptySeconds": stop, "terminal": {"windowSeconds": terminal_seconds,
            "receivedBytes": seen, "bytesPerSecond": seen / terminal_seconds, "gapFrames": gaps, "gapBytes": lost,
            "sourceBytes": OUTPUT_BYTES,
            "method": "Start through CLI output completion. Includes process/transport startup and native terminal rendering bytes."}}


def capture(install, bench, testload, runs, seconds):
    info = json_input(install / "build-info.json")
    install_receipt = verify(install, RID, info["commit"], distribution="signed-mxc-cohort")
    host = install / ("arcforges" + SUFFIX)
    host_hash, bench_hash, testload_hash = (digest(path) for path in (host, bench, testload))
    scratch_parent = Path(os.environ["LOCALAPPDATA"]) / "Temp" if WIN else Path.home()
    scratch = Path(tempfile.mkdtemp(prefix="afv2-native-performance-", dir=scratch_parent)).resolve()
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("ARCFORGES_")}
    config, data = scratch / "config", scratch / "data"
    ipc = None
    node = None
    cleaned = False
    try:
        protect_install_root(scratch)
        config.mkdir(mode=0o700)
        data.mkdir(mode=0o700)
        protect_install_root(data)
        (config / "node.json").write_text(json.dumps({"dataRoot": str(data)}), encoding="utf-8")
        if WIN:
            endpoint = f"af-perf-{uuid.uuid4().hex}"
        else:
            # The Node's protected Unix socket directory must be outside the Sandbox's private root.
            # Match the closed-loop fixture and leave the actual systemd user manager runtime in place.
            ipc = Path(tempfile.mkdtemp(prefix="af-perf-ipc-", dir="/tmp")).resolve()
            endpoint = str(ipc / "node.sock")
            runtime = Path(env.get("XDG_RUNTIME_DIR") or f"/run/user/{os.geteuid()}").resolve(strict=True)
            require(runtime.is_dir() and runtime != scratch and scratch not in runtime.parents and runtime not in scratch.parents,
                    "The systemd user runtime directory overlaps the owned measurement root")
            env["XDG_RUNTIME_DIR"] = str(runtime)
        env.update(ARCFORGES_CONFIG_DIR=str(config), ARCFORGES_ENDPOINT=endpoint)

        def cli(*arguments, timeout=40):
            return checked([str(host), "--test-mode", "--json", *arguments], scratch, env, timeout)

        launch = launch_times(bench, host, scratch, env, runs)
        node_start = time.monotonic()
        with (scratch / "node-stdout.log").open("wb") as log:
            node = subprocess.Popen([str(host), "node", "run", "--test-mode"], cwd=scratch, env=env,
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        checked([str(host), "node", "wait-ready", "--test-mode", "--timeout", "25s"], scratch, env, 30)
        node_ready = time.monotonic() - node_start
        job = [str(testload), "output", "--bytes", str(OUTPUT_BYTES), "--line-bytes", str(OUTPUT_BYTES),
               "--stream", "stdout", "--report", str(scratch / "reference.json")]
        baseline_started = time.monotonic()
        baseline = checked(job, scratch, env)
        baseline_seconds = time.monotonic() - baseline_started
        require(len(baseline) == OUTPUT_BYTES, "TestLoad reference produced unexpected bytes")
        reference = {"windowSeconds": baseline_seconds, "bytes": len(baseline), "toolReport": json_input(scratch / "reference.json")}
        wait_for_install_check(data, node)
        for _ in range(30):
            initial = json.loads(cli("resources", "show", "--scope", "node"))
            if initial.get("sampleEpoch") and int(initial.get("sampleSequence", 0)) > 0 and not initial.get("stale"):
                break
            time.sleep(0.3)
        else:
            raise ValueError("Node did not publish a fresh resource sample")
        idle = observed_window(node.pid, seconds)
        later = json.loads(cli("resources", "show", "--scope", "node"))
        require(initial["sampleEpoch"] == later["sampleEpoch"], "Node sampler epoch changed during the idle window")
        idle["sampleProgress"] = int(later["sampleSequence"]) - int(initial["sampleSequence"])
        require(idle["sampleProgress"] >= 0, "Node sample sequence went backwards")
        workloads = capture_runs(cli, scratch, data, "arcforges-testload" + SUFFIX, testload, seconds)
        cli("node", "stop", "--stop-runs")
        require(node.wait(timeout=30) == 0, "The owned Node did not stop cleanly")
        cleaned = True
        require(digest(host) == host_hash and digest(testload) == testload_hash and digest(bench) == bench_hash,
                "A measured input changed during capture")
        return {"schema": 1, "capturedUtc": datetime.now(UTC).isoformat(), "installation": install_receipt,
                "os": platform.platform(), "cpuCount": os.cpu_count(), "physicalMemoryBytes": host_memory_bytes(),
                "identity": {"hostSha256": host_hash, "benchSha256": bench_hash, "testloadSha256": testload_hash},
                "cliStartup": launch, "nodeToReadySeconds": node_ready, "nodeIdle": idle, "run": workloads,
                "isolatedReference": reference,
                "missing": ["deliberately stalled consumer backpressure observation", "paired physical resource overhead for the same workload",
                            "isolated CPU cost attributable to sampler cadence; window includes ordinary Node idle work"]}
    finally:
        if node is None or cleaned:
            shutil.rmtree(scratch)
            if ipc is not None:
                shutil.rmtree(ipc)
        else:
            # Keep evidence and files when cleanup cannot be proven. No effect is signaled to other installations.
            if node.poll() is None:
                try:
                    checked([str(host), "node", "stop", "--stop-runs", "--test-mode"], scratch, env, 30)
                    node.wait(timeout=30)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    pass
            print(f"Preserved the isolated measurement fixture: {scratch}", file=sys.stderr)
            if ipc is not None:
                print(f"Preserved the isolated measurement socket directory: {ipc}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("install", "bench", "testload", "output"):
        parser.add_argument("--" + field, required=True, type=Path)
    parser.add_argument("--runs", type=int, default=50, choices=range(1, 101), metavar="1..100")
    parser.add_argument("--idle-seconds", type=int, default=15, choices=range(6, 101), metavar="6..100")
    args = parser.parse_args()
    try:
        require(sys.platform == "linux" or WIN, "Use the native Windows or Linux release venue")
        report = capture(args.install.resolve(strict=True), args.bench.resolve(strict=True), args.testload.resolve(strict=True),
                         args.runs, args.idle_seconds)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    except (KeyError, OSError, TypeError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
        parser.exit(1, f"Native measurements refused: {error}\n")


if __name__ == "__main__":
    main()
