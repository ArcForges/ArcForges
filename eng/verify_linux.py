#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The linux-x64 gates of the local pre-push verification (eng/verify_steps.py) that hosted CI runs through PowerShell.

WSL Debian has no PowerShell, so each command does for linux-x64 exactly what the named script does (keep them in step):

  python eng/verify_linux.py publish <group>...          eng/publish.ps1 -RuntimeIdentifier linux-x64 -NoRestore
  python eng/verify_linux.py bench                        eng/bench.ps1 -RuntimeIdentifier linux-x64
  python eng/verify_linux.py compare-startup <baseline>   eng/compare-startup.ps1 -RuntimeIdentifier linux-x64 -BaselineExecutable <baseline>
  python eng/verify_linux.py package                      eng/package.ps1 -RuntimeIdentifier linux-x64

Components: host, desktop, testload, bench (the supervisor is Windows only); a group is a comma-separated list of
components published in order, and several groups are published concurrently. Output and results go to the same
artifacts/ paths as the scripts'.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import uuid
from pathlib import Path

RID = "linux-x64"
REPOSITORY = Path(__file__).resolve().parent.parent
PUBLISH = REPOSITORY / "artifacts" / "publish" / RID
RESULTS = REPOSITORY / "artifacts" / "bench" / RID
BENCH = PUBLISH / "bench" / "arcforges-bench"
HOST = PUBLISH / "host" / "arcforges"
PROJECTS = {
    "host": "src/ArcForges.Host",
    "desktop": "src/ArcForges.Desktop",
    "testload": "tools/ArcForges.TestLoad",
    "bench": "tools/ArcForges.Bench",
}
WARNING = re.compile(r":\s+warning\s+[A-Z]+[0-9]+")
WARNING_COUNT = re.compile(r"^\s*0 Warning\(s\)")
NOTICE = re.compile(r"(license|licence|notice|copying)", re.IGNORECASE)


class Failure(Exception):
    pass


def run(argv: list[str]) -> None:
    print("+ " + " ".join(argv), flush=True)
    code = subprocess.run(argv, cwd=REPOSITORY).returncode
    if code != 0:
        raise Failure(f"{Path(argv[0]).name} {argv[1] if len(argv) > 1 else ''} failed with exit code {code}.")


def publish_group(components: list[str], out: list[str]) -> str:
    """eng/publish.ps1 for the components of one group, in order: Native AOT publish per component; any build, trim or
    AOT warning fails it. Output goes to `out`; returns the failure, or an empty string."""
    for name in components:
        output = PUBLISH / name
        shutil.rmtree(output, ignore_errors=True)
        argv = ["dotnet", "publish", str(REPOSITORY / PROJECTS[name]), "-c", "Release", "-r", RID, "-o", str(output),
                "-warnaserror", "-tl:off", "-clp:Summary;ForceNoAlign", "-p:TrimmerSingleWarn=false", "--no-restore"]
        out.append(f"==> publish {name} ({RID})")
        result = subprocess.run(argv, cwd=REPOSITORY, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace")
        lines = result.stdout.splitlines()
        out.extend(lines)
        if result.returncode != 0:
            return f"Publishing {name} for {RID} failed with exit code {result.returncode}."
        warnings = sorted({line for line in lines if WARNING.search(line)})
        if warnings:
            return f"Publishing {name} for {RID} reported {len(warnings)} warning(s)."
        if not any(WARNING_COUNT.match(line) for line in lines):
            return f"Publishing {name} for {RID} did not report its warning count."
        out.append(f"==> {name} ({RID}): Native AOT publish with 0 warnings -> {output}")
    return ""


def publish(groups: list[str]) -> None:
    """Each argument is a comma-separated group of components. Groups are published concurrently (they must not share a
    project: host and bench both build ArcForges.Node.Store), the components of a group one after another; each group's
    output is printed when it ends."""
    components = [name for group in groups for name in group.split(",")]
    unknown = sorted(set(components) - set(PROJECTS))
    if unknown or len(components) != len(set(components)):
        raise Failure(f"unknown or repeated components: {', '.join(unknown) or ', '.join(components)}")
    outputs: list[list[str]] = [[] for _ in groups]
    failures: list[str] = ["" for _ in groups]

    def work(index: int) -> None:
        failures[index] = publish_group(groups[index].split(","), outputs[index])

    threads = [threading.Thread(target=work, args=(index,)) for index in range(len(groups))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for output in outputs:
        print("\n".join(output), flush=True)
    if any(failures):
        raise Failure(" ".join(failure for failure in failures if failure))


def bench() -> None:
    """eng/bench.ps1: size gates (arcforges, arcforges-desktop), the store growth gate and the CLI cold-start record."""
    RESULTS.mkdir(parents=True, exist_ok=True)
    run([str(BENCH), "size", "--target", "arcforges", "--path", str(HOST), "--output", str(RESULTS / "size-arcforges.json")])
    run([str(BENCH), "size", "--target", "arcforges-desktop", "--path", str(PUBLISH / "desktop"),
         "--output", str(RESULTS / "size-arcforges-desktop.json")])
    growth = [str(BENCH), "store-growth", "--attempts", "10000", "--output", str(RESULTS / "store-growth.json")]
    environments = REPOSITORY / "tests" / "ArcForges.Node.Store.Tests" / "Fixtures" / "environments"
    for environment in sorted(environments.glob("*.json"), key=lambda path: path.name.lower()):
        growth += ["--environment", str(environment)]
    run(growth)
    run([str(BENCH), "startup", "--exe", str(HOST), "--arg", "--version", "--runs", "50", "--warmup", "1",
         "--name", "arcforges --version", "--output", str(RESULTS / "startup-arcforges-version.json")])


def compare_startup(baseline: str, source: str | None) -> None:
    """eng/compare-startup.ps1: the baseline CLI and this build's CLI, measured here interleaved (p50 of 50 runs after one
    warm-up; a regression exceeds both 25% and 5 ms)."""
    for required in (BENCH, HOST):
        if not required.exists():
            raise Failure(f"Run the publish step first: {required} is missing.")
    if not Path(baseline).exists():
        raise Failure(f"The baseline executable {baseline} is missing.")
    RESULTS.mkdir(parents=True, exist_ok=True)
    output = RESULTS / "startup-comparison.json"
    run([str(BENCH), "compare-startup", "--baseline-exe", str(Path(baseline).resolve()), "--current-exe", str(HOST),
         "--runs", "50", "--warmup", "1", "--name", "arcforges --version",
         "--baseline-source", source or f"{baseline} (measured on this machine)", "--arg", "--version",
         "--max-regression-percent", "25", "--noise-floor-ms", "5", "--output", str(output)])


def package() -> None:
    """eng/package.ps1: the desktop publish directory with third-party notices, the lock file and build-info.json."""
    publish_dir = PUBLISH / "desktop"
    if not (publish_dir / "arcforges-desktop").exists():
        raise Failure(f"Publish the {RID} desktop before packaging.")
    stage = REPOSITORY / "artifacts" / "staging" / f"{RID}-{uuid.uuid4().hex}"
    packages = REPOSITORY / "artifacts" / "packages"
    stage.mkdir(parents=True)
    packages.mkdir(parents=True, exist_ok=True)
    for item in publish_dir.iterdir():
        if item.suffix in (".pdb", ".dbg", ".dSYM"):
            continue
        if item.is_dir():
            shutil.copytree(item, stage / item.name, symlinks=True)
        else:
            shutil.copy2(item, stage / item.name)
    shutil.copytree(REPOSITORY / "third-party", stage / "third-party")
    shutil.copy2(REPOSITORY / "src" / "ArcForges.Desktop" / "packages.lock.json", stage)

    # Native component notices from the actual restored application closure.
    assets = json.loads((REPOSITORY / "src" / "ArcForges.Desktop" / "obj" / "project.assets.json").read_text(encoding="utf-8"))
    for library in assets["libraries"].values():
        if library.get("type") != "package" or library["path"].startswith("arcforges.build.policy/"):
            continue
        package_path = next((Path(root) / library["path"] for root in assets["packageFolders"]
                             if (Path(root) / library["path"]).exists()), None)
        if package_path is None:
            raise Failure(f"Restored package is missing: {library['path']}")
        for file in package_path.rglob("*"):
            if not file.is_file() or (not NOTICE.search(file.name) and file.suffix != ".nuspec"):
                continue
            destination = stage / "third-party" / "packages" / library["path"] / file.relative_to(package_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, destination)

    def git(*args: str) -> str:
        result = subprocess.run(["git", "-C", str(REPOSITORY), *args], capture_output=True, text=True)
        if result.returncode != 0:
            raise Failure(f"git {' '.join(args)} failed: {result.stderr.strip()}")
        return result.stdout

    info = {
        "source": "https://github.com/ArcForges/ArcForges",
        "commit": git("rev-parse", "HEAD").strip(),
        "dirty": bool(git("status", "--porcelain").strip()),
        "runtimeIdentifier": RID,
        "sdk": json.loads((REPOSITORY / "global.json").read_text(encoding="utf-8"))["sdk"]["version"],
        "distribution": "unsigned-development-preview",
    }
    (stage / "build-info.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")

    archive = packages / f"arcforges-desktop-{RID}.tar.gz"
    run(["tar", "-czf", str(archive), "-C", str(stage), "."])
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    Path(f"{archive}.sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    print(archive, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(prog="eng/verify_linux.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("publish").add_argument("groups", nargs="+", metavar="component[,component...]")
    commands.add_parser("bench")
    compare = commands.add_parser("compare-startup")
    compare.add_argument("baseline")
    compare.add_argument("--baseline-source")
    commands.add_parser("package")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        print("verify_linux.py runs on Linux (WSL Debian); on Windows use the eng/*.ps1 scripts.", file=sys.stderr)
        return 2
    os.environ["AVALONIA_TELEMETRY_OPTOUT"] = "1"
    try:
        if args.command == "publish":
            publish(args.groups)
        elif args.command == "bench":
            bench()
        elif args.command == "compare-startup":
            compare_startup(args.baseline, args.baseline_source)
        else:
            package()
    except Failure as error:
        print(f"verify_linux {args.command}: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
