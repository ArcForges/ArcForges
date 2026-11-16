#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise fail-closed admission using disposable copies of a real published stage."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


def run(stage, output):
    if output.exists():
        raise ValueError("Evidence output already exists; choose a fresh path")
    output.mkdir(parents=True)
    manifest = json.loads((stage / "mxc-manifest.json").read_text(encoding="utf-8"))
    windows = manifest["rid"] == "win-x64"
    executable = "arcforges-mxc-probe" + (".exe" if windows else "")
    results = []
    for case in ("missing-native", "incompatible-manifest", "unexpected-file", "loader-override"):
        private = output / (case + " install 工作区")
        shutil.copytree(stage, private)
        env = os.environ.copy()
        if case == "missing-native":
            (private / ("mxc_ffi.dll" if windows else "libmxc_ffi.so")).unlink()
        elif case == "incompatible-manifest":
            invalid = dict(manifest, version="0.0.0-unapproved")
            (private / "mxc-manifest.json").write_text(json.dumps(invalid), encoding="utf-8")
        elif case == "unexpected-file":
            (private / "unexpected-native-unit.txt").write_text("must reject before native load", encoding="utf-8")
        else:
            env["MXC_FFI_DIR"] = str(output / "not-an-approved-native-directory")
        work = output / (case + " fixture 工作区")
        report = output / (case + ".json")
        command = [str(private / executable), "--manifest", str(private / "mxc-manifest.json"), "--work", str(work), "--report", str(report)]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
        value = json.loads(report.read_text(encoding="utf-8"))
        passed = result.returncode != 0 and not value["ok"] and not value["stageVerified"] and not value["cases"] and not work.exists()
        results.append({"case": case, "passed": passed, "exitCode": result.returncode, "report": str(report), "fixtureAbsent": not work.exists(), "failure": value["failure"]})
        if not passed:
            raise RuntimeError("Fail-closed case did not reject before workload: " + case)
    (output / "summary.json").write_text(json.dumps({"ok": True, "results": results}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "cases": len(results), "evidence": str(output)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.stage.resolve(), args.output.resolve())
