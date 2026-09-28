#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit local-only published-package exchange. Restore dependencies separately."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", action="store_true", required=True)
    parser.add_argument("--sdk-dll", type=Path, help="Existing SDK dotnet.dll; no SDK installation")
    args = parser.parse_args()
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        parser.error("This acceptance executes published consumers and is local-only.")
    root = Path(__file__).resolve().parent
    dotnet = [shutil.which("dotnet") or "dotnet"]
    if args.sdk_dll:
        if not args.sdk_dll.is_file():
            parser.error("--sdk-dll must identify an existing SDK")
        dotnet.append(str(args.sdk_dll.resolve()))

    def run(command):
        subprocess.run(command, cwd=root, check=True)

    run([*dotnet, "build", "Foundation.Acceptance.csproj", "-c", "Release", "--no-restore"])
    with tempfile.TemporaryDirectory(prefix="arcforges-fnd07-") as exchange:
        csharp = str(Path(exchange) / "csharp")
        typescript = str(Path(exchange) / "typescript")
        run([*dotnet, "run", "--project", "Foundation.Acceptance.csproj", "-c", "Release", "--no-build", "--no-restore", "--", "emit", csharp])
        run([shutil.which("node") or "node", "roundtrip.ts", csharp, typescript])
        run([*dotnet, "run", "--project", "Foundation.Acceptance.csproj", "-c", "Release", "--no-build", "--no-restore", "--", "verify", typescript])
    print("FND.07 C# -> TypeScript -> C# and TypeScript -> C# acceptance passed.")


if __name__ == "__main__":
    main()
