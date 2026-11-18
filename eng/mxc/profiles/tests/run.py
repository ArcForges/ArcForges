#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run the profile admission regression and native refusal cases without invoking MXC."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
from xml.sax.saxutils import quoteattr


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True, help="original verified native experiment stage")
    args = parser.parse_args()
    if os.name != "nt":
        os.umask(0o077)

    tests = Path(__file__).resolve().parent
    profiles = tests.parent
    repository = profiles.parents[2]
    capabilities = repository / "src" / "ArcForges.Node.Platform" / "Capabilities"
    files = sorted(capabilities.glob("*.cs")) + [tests / "AdmissionCases.cs"]
    items = "\n".join(f"    <Compile Include={quoteattr(str(file))} />" for file in files)

    with tempfile.TemporaryDirectory(prefix="arcforges-admission-") as temporary:
        project = Path(temporary) / "AdmissionCases.csproj"
        project.write_text(
            f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net11.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
  </PropertyGroup>
  <ItemGroup>
{items}
  </ItemGroup>
</Project>
""",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "dotnet", "run", "--project", str(project), "--configuration", "Release", "--",
                str(profiles), str(args.stage.resolve(strict=True)), temporary,
            ],
            check=True, cwd=repository, timeout=180,
        )


if __name__ == "__main__":
    main()
