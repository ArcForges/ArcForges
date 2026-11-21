# SPDX-License-Identifier: AGPL-3.0-only
"""Additional bounded comparisons for the owned native performance fixture."""

import json
import queue
import re
import subprocess
import threading
import time

from sbom import json_input, require


def stop_client(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_until(predicate, message, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise ValueError(message)


def paired_cpu_workload(root, work, start, inspect, follow, direct):
    """Use the same deterministic executable and CPU workload on both sides."""
    workload = ["cpu", "--threads", "1", "--iterations", "10000000", "--seed", "1"]
    reference_path, sandbox_path = root / "reference-cpu.json", work / "sandbox-cpu.json"
    began = time.monotonic()
    direct(*workload, "--report", str(reference_path))
    reference_seconds = time.monotonic() - began
    began = time.monotonic()
    run_id = start("off", *workload, "--report", str(sandbox_path))
    follow(run_id, "stdout")
    require(inspect(run_id).get("exit", {}).get("groupEmptyVerified") is True, "Paired CPU Run did not verify an empty native group")
    sandbox_seconds = time.monotonic() - began
    reference, sandbox = json_input(reference_path), json_input(sandbox_path)
    require(all(reference[key] == sandbox[key] for key in ("digest", "parameters", "results")),
            "Direct and managed performance payloads were not the same deterministic workload")
    direct_peak = int(reference["measured"]["peakWorkingSetBytes"])
    sandbox_peak = int(sandbox["measured"]["peakWorkingSetBytes"])
    require(direct_peak > 0 and sandbox_peak > 0, "Paired payload peak working set was unavailable")
    return {"parameters": sandbox["parameters"], "payloadDigest": sandbox["digest"],
            "direct": {"wallSeconds": reference_seconds, "payload": reference["measured"]},
            "sandboxed": {"wallSeconds": sandbox_seconds, "payload": sandbox["measured"]},
            "observedPeakWorkingSetDeltaBytes": sandbox_peak - direct_peak,
            "observedWallDeltaSeconds": sandbox_seconds - reference_seconds,
            "wallBoundaries": {"direct": "Direct TestLoad process start through exit.",
                               "sandboxed": "Managed CLI Start through output drain and final Run inspection. Includes setup, transport and verified native cleanup."},
            "scope": "One paired real workload. Working set is the payload's native peak, not aggregate MXC or OS memory."}


def cadence(root, node_pid, seconds, client, observe, idle):
    """Observe the same Node serving two actual resource-stream cadences."""
    samples = []
    for interval in (1, 5):
        log = root / f"resources-watch-{interval}s.jsonl"
        with log.open("xb") as output:
            viewer = client(True, "resources", "watch", "--scope", "node", "--interval", f"{interval}s", stdout=output)
            try:
                wait_until(lambda: viewer.poll() is None and b"\n" in log.read_bytes(),
                           "Resource watcher did not deliver its initial sample")
                first = log.read_bytes().rfind(b"\n") + 1
                reading = observe(node_pid, max(seconds, 6))
                require(viewer.poll() is None, "Native resource watcher ended during its measured window")
                frames = log.read_bytes()[first:].split(b"\n")
                observed = sum(1 for raw in frames[:-1] if _resource_sample(raw))
                require(observed > 0, "The resource watcher delivered no complete samples at its observed cadence")
            finally:
                stop_client(viewer)
        samples.append({"intervalSeconds": interval, "node": reading, "completeSnapshots": observed,
                        "observedCpuDeltaPercentagePoints": reading["percentOfOneCore"] - idle["percentOfOneCore"]})
    return {"baseline": "same fixture Node without a watcher", "observations": samples,
            "scope": "End-to-end Node resource-stream delivery cost at requested cadences. Internal sampler cost is not isolated."}


def _resource_sample(raw):
    sample = json.loads(raw)
    require("error" not in sample, "Resource watcher reported a typed refusal")
    return "sampleSequence" in sample


def slow_output(work, start, inspect, client):
    """Reproduce the existing installed CLI bounded slow stdout consumer fixture."""
    marker, prefix, tail = work / "slow-output.log", work / "slow-prefix.gate", work / "slow-tail.gate"
    run_id = start("off", "terminal", "slow-output", str(marker), str(prefix), str(tail))

    def marked(value):
        try:
            return value in marker.read_bytes().splitlines()
        except FileNotFoundError:
            return False

    wait_until(lambda: marked(b"started"), "Slow output workload did not enter its private fixture")
    diagnostic_path = work / "slow-observer.stderr"
    with diagnostic_path.open("xb") as diagnostic:
        viewer = client(False, "run", "logs", run_id, "--follow", "--stream", "stdout",
                        stdout=subprocess.PIPE, stderr=diagnostic)
    anchor = b"CORE03 slow viewer \n"
    first = queue.Queue(maxsize=1)
    reader = threading.Thread(target=lambda: first.put(viewer.stdout.read(len(anchor))), daemon=True)
    reader_started = False
    try:
        reader.start()
        reader_started = True
        try:
            require(first.get(timeout=10) == anchor, "Slow output observer did not receive the original anchor")
        except queue.Empty as error:
            raise ValueError("Slow output observer timed out before its anchor") from error
        paused = time.monotonic()
        prefix.write_text("prefix", encoding="ascii")
        wait_until(lambda: marked(b"prefix-complete"), "Slow output producer did not complete its prefix", 8)
        time.sleep(0.35)
        tail.write_text("tail", encoding="ascii")
        wait_until(lambda: marked(b"finished"), "Slow output producer did not finish while stdout was paused", 8)
        wait_until(lambda: inspect(run_id).get("exit", {}).get("groupEmptyVerified") is True,
                   "Native Run did not confirm empty while stdout was paused", 8)
        paused = time.monotonic() - paused
        output, _ = viewer.communicate(timeout=20)
        require(viewer.returncode == 0, "Slow output observer did not drain its retained stream")
    finally:
        try:
            stop_client(viewer)
        finally:
            # After the owned writer exits its pipe releases the blocking anchor read.
            if reader_started:
                reader.join(timeout=5)
                require(not reader.is_alive(), "Owned slow-reader anchor did not exit after pipe cancellation")
            viewer.stdout.close()

    with diagnostic_path.open("rb") as diagnostic:
        errors = diagnostic.read(65_537)
    require(len(errors) <= 65_536, "Slow reader diagnostic exceeded the measurement bound")
    gaps = []
    gap_diagnostic = (rb"output GAP \(stdout, (slow_consumer|retention)\)\. Requested offset (\d+)\. "
                      rb"First retained offset (\d+)\.")
    for reason, requested, earliest in re.findall(gap_diagnostic, errors):
        start_offset, end_offset = int(requested), int(earliest)
        require(end_offset > start_offset, "Slow output observer reported a backwards gap")
        gaps.append({"reason": reason.decode("ascii"), "offset": start_offset, "nextOffset": end_offset})
    require(any(gap["reason"] == "slow_consumer" for gap in gaps), "The installed CLI did not report native slow-consumer backpressure")
    previous = len(anchor)
    dropped = 0
    for gap in sorted(gaps, key=lambda item: item["offset"]):
        dropped += max(0, gap["nextOffset"] - max(previous, gap["offset"]))
        previous = max(previous, gap["nextOffset"])
    total = len(anchor) + 512 * 1024 + 3 * 1024 * 1024
    require(len(anchor) + len(output) + dropped == total, "Actual slow-stream bytes and observed gaps did not account for output")
    return {"mode": "stdout pipe", "readerPauseSeconds": paused, "producedBytes": total,
            "receivedBytes": len(anchor) + len(output), "droppedBytes": dropped, "gaps": gaps, "nativeGroupEmptyBeforeDrain": True}
