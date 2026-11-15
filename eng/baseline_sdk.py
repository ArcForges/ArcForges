# SPDX-License-Identifier: AGPL-3.0-only
"""Run the immutable startup baseline with its own already installed exact SDK.

The candidate's current SDK root need not contain the old SDK. This selector
never installs tools or changes a baseline file, system PATH or SDK settings.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def select(source):
    expected = json.loads((source / "global.json").read_text())["sdk"]["version"]
    candidates = [Path.home() / ".dotnet"]
    for name in ("DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_ROOT_ARM64"):
        if os.environ.get(name):
            candidates.append(Path(os.environ[name]))
    installed = shutil.which("dotnet")
    if installed:
        candidates.append(Path(installed).resolve().parent)
    candidates += [Path("/usr/share/dotnet"), Path("/usr/local/share/dotnet")]
    if os.environ.get("ProgramFiles"):
        candidates.append(Path(os.environ["ProgramFiles"]) / "dotnet")
    observed = []
    for candidate in dict.fromkeys(path.resolve() for path in candidates):
        dotnet = candidate / ("dotnet.exe" if os.name == "nt" else "dotnet")
        if not dotnet.is_file() or not (candidate / "sdk" / expected).is_dir():
            continue
        environment = {**os.environ, "DOTNET_ROOT": str(candidate),
                       "PATH": str(candidate) + os.pathsep + os.environ.get("PATH", "")}
        environment.pop("MSBuildSDKsPath", None)
        result = subprocess.run([str(dotnet), "--version"], cwd=source, env=environment,
                                capture_output=True, text=True, timeout=30)
        observed.append({"root": str(candidate), "version": result.stdout.strip(), "exit": result.returncode})
        if result.returncode == 0 and result.stdout.strip() == expected:
            return dotnet, environment, {"expected": expected, "executable": str(dotnet), "source": str(source)}
    raise ValueError("The startup baseline needs its retained SDK " + expected + "; observed " + json.dumps(observed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        source = args.source.resolve(strict=True)
        dotnet, environment, report = select(source)
        print(json.dumps({"baselineSdk": report}), flush=True)
        if not args.arguments:
            return 0
        return subprocess.run([str(dotnet), *args.arguments], cwd=source, env=environment).returncode
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("baseline SDK selection failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
