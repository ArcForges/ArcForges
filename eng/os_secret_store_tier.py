#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The local runner of ArcForges's OS secret-store integration tier (ArcForges-Design docs/architecture/16-testing-strategy.md section 1).

The tier (tests/ArcForges.OsSecretStoreTier: the node data key through NodeDataKeyRing against the real Windows Credential Manager)
is the only suite of this repository that reaches a real OS secret store. Its evidence is the hosted run
(.github/workflows/os-secret-store-tier.yml); a local run is weaker evidence, because the workstation's store is shared with the
user's applications, and it happens only on the user's explicit opt-in, from a checkout:

  $env:ARCFORGES_OS_SECRET_STORE_TESTS = '1'; python eng/os_secret_store_tier.py; Remove-Item Env:ARCFORGES_OS_SECRET_STORE_TESTS

Without the opt-in nothing runs and the tier is reported as not run, with the reason (exit code 3). The runner never sets the opt-in
itself and passes it only to the one `dotnet test` of the tier project, which runs alone (no other test or node process of the run),
sequentially, under the tier fixture's limits (4 entries at once, 32 store calls, 10 s per call, 5 minutes). The run's name list is
written to artifacts/evidence/os-secret-store-tier/ and is kept with the run's evidence. The node binding's Linux Secret Service tier
(in the isolated ArcForgesTest WSL distribution) is not delivered yet; on Linux the runner refuses outside ArcForgesTest.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPT_IN = "ARCFORGES_OS_SECRET_STORE_TESTS"
PROJECT = "tests/ArcForges.OsSecretStoreTier/ArcForges.OsSecretStoreTier.csproj"
LINUX_DISTRIBUTION = "ArcForgesTest"
EVIDENCE = ROOT / "artifacts/evidence/os-secret-store-tier"
NOT_RUN = 3
# The fixture bounds the tier to five minutes; the process bound adds the cleanup allowance after a failed run (8 calls of at
# most 10 s) and the test host's start-up, so a failing run is never killed mid-cleanup.
PROCESS_TIMEOUT = 420


def refusal(environ: dict[str, str], platform: str) -> tuple[int, str] | None:
    """Why the tier must not run here, as (exit code, message); None when it may."""
    if environ.get(OPT_IN) != "1":
        return NOT_RUN, (f"NOT RUN: the OS secret-store tier needs the explicit opt-in {OPT_IN}=1 in this environment; without it "
                         "no test reaches a real OS secret store")
    if platform.startswith("linux") and environ.get("WSL_DISTRO_NAME") != LINUX_DISTRIBUTION:
        return 1, (f"REFUSED: the Linux Secret Service tier runs only in the isolated {LINUX_DISTRIBUTION} WSL distribution "
                   f"(WSL_DISTRO_NAME is {environ.get('WSL_DISTRO_NAME')!r}), never in the development distribution or a user's "
                   "session keyring")
    if not (platform.startswith("linux") or platform == "win32"):
        return 1, "REFUSED: the OS secret-store tier covers Windows and Linux only"
    return None


def build_command() -> list[str]:
    return ["dotnet", "build", PROJECT, "-c", "Release"]


def test_command() -> list[str]:
    return ["dotnet", "test", "--project", PROJECT, "-c", "Release", "--no-build", "--results-directory", str(EVIDENCE),
            "--report-xunit-trx", "--report-xunit-trx-filename", "os-secret-store-tier.trx"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-build", action="store_true", help="run the already built Release tier project")
    args = parser.parse_args()
    refused = refusal(dict(os.environ), sys.platform)
    if refused is not None:
        code, message = refused
        print(message, file=sys.stderr if code != NOT_RUN else sys.stdout, flush=True)
        return code
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if not args.no_build:
        # The build runs no test, so it never needs the opt-in.
        build = {key: value for key, value in os.environ.items() if key != OPT_IN}
        print("+ " + " ".join(build_command()), flush=True)
        if subprocess.run(build_command(), cwd=ROOT, env=build).returncode:
            print("FAIL: the tier project did not build", file=sys.stderr, flush=True)
            return 1
    argv = test_command()
    print("+ " + " ".join(argv), flush=True)
    try:
        return subprocess.run(argv, cwd=ROOT, env=dict(os.environ), timeout=PROCESS_TIMEOUT).returncode
    except subprocess.TimeoutExpired:
        print(f"FAIL: the OS secret-store tier did not finish within {PROCESS_TIMEOUT} s", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
