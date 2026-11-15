# SPDX-License-Identifier: AGPL-3.0-only
"""Record and reject mismatched current local/CI Python and managed SDK selection."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def query(arguments):
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=60,
                            env={**os.environ, "DOTNET_CLI_UI_LANGUAGE": "en-US"})
    if result.returncode:
        raise ValueError("Tool query failed: " + " ".join(arguments) + ": " + result.stderr.strip())
    return result.stdout.strip()


def check(tools):
    expected_python = (ROOT / ".python-version").read_text().strip()
    python = shutil.which("python")
    if platform.python_version() != expected_python or not python or query([python, "--version"]) != "Python " + expected_python:
        raise ValueError("Invoking and PATH Python must both match .python-version " + expected_python)
    report = {"python": {"version": platform.python_version(), "executable": sys.executable, "pathExecutable": python}}
    if "dotnet" in tools:
        expected = json.loads((ROOT / "global.json").read_text())["sdk"]["version"]
        dotnet = shutil.which("dotnet")
        if not dotnet or query([dotnet, "--version"]) != expected:
            raise ValueError("The effective dotnet SDK must match global.json " + expected)
        installed = query([dotnet, "--list-sdks"])
        roots = [Path(line.split("[", 1)[1][:-1]) / expected for line in installed.splitlines()
                 if line.startswith(expected + " [") and line.endswith("]")]
        effective = json.loads(query([dotnet, "msbuild", "src/ArcForges.Host/ArcForges.Host.csproj", "-nologo",
                                      "-getProperty:NETCoreSdkVersion,MSBuildToolsPath,MSBuildSDKsPath"]))["Properties"]
        if effective["NETCoreSdkVersion"] != expected or not any(
                Path(effective["MSBuildToolsPath"]).resolve() == root.resolve()
                and Path(effective["MSBuildSDKsPath"]).resolve() == (root / "Sdks").resolve() for root in roots):
            raise ValueError("Effective MSBuild tools and SDK roots do not match the selected installed SDK")
        override = os.environ.get("MSBuildSDKsPath")
        if override and not any(Path(override).resolve() == (root / "Sdks").resolve() for root in roots):
            raise ValueError("MSBuildSDKsPath conflicts with the pinned current SDK")
        report["dotnet"] = {"version": expected, "executable": dotnet, "effective": effective}
    paths = query(["git", "ls-files", "--", "*packages.lock.json"]).splitlines()
    report["lockSha256Lf"] = {name: hashlib.sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
                              for name in sorted(paths)}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", nargs="+", choices=("python", "dotnet"), default=["python", "dotnet"])
    args = parser.parse_args()
    try:
        print(json.dumps(check(set(args.tools)), sort_keys=True))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("toolchain mismatch: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
