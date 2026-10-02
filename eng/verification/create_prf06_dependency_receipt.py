# SPDX-License-Identifier: AGPL-3.0-only
"""Create the immutable PRF.06 dependency-admission snapshot from its locked graph.

Usage: python eng/verification/create_prf06_dependency_receipt.py --baseline <40 hex main commit>

The receipt chains from whichever receipt is active on the checked-out main, so rerun it after a rebase that
moved the active receipt or any dependency input. It writes only the PRF.06 receipt and the policy fields the
existing admission gate binds to it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eng"))
import dependency_policy  # noqa: E402


RECEIPT = "eng/policy/dependency-reviews/prf-06-r1.json"
NUGET_FEED = "https://api.nuget.org/v3/index.json"
NUGET_CACHE = Path.home() / ".nuget" / "packages"
CONTRACTS_SOURCE_COMMIT = "4047930ef2207e8a4c6de9e7ef679f0d9359a8e4"
CONTRACTS_VERSION = "1.0.0-ci.270.1"

# Only the coordinates that PRF.06 adds. Anything already admitted keeps its existing row.
NEW_COORDINATES = {
    f"arcforges.contracts.foundation/{CONTRACTS_VERSION}": (
        "Apache-2.0",
        "Exact CON.11 Foundation candidate (Contracts source 4047930, CI run 36809684358), consumed only by the "
        "non-packable PRF.06 realtime AOT probe through a project-conditioned version update.",
        True,
    ),
    f"arcforges.contracts.publicapi/{CONTRACTS_VERSION}": (
        "Apache-2.0",
        "Exact CON.11 PublicApi candidate (Contracts source 4047930), a direct reference of the non-packable PRF.06 "
        "realtime AOT probe for ExecutionOwner and the shared annex 10 records; project-conditioned pin.",
        True,
    ),
    f"arcforges.contracts.events/{CONTRACTS_VERSION}": (
        "Apache-2.0",
        "Exact CON.11 Events candidate (Contracts source 4047930) providing the generated EventService and "
        "ExecutionService clients and the StreamFrame records; used only by the non-packable PRF.06 realtime AOT "
        "probe; project-conditioned pin.",
        True,
    ),
    "grpc.net.client.web/2.84.0": (
        "Apache-2.0",
        "Exact permitted gRPC-Web handler candidate for the binary gRPC-Web transport (annex 10 section 1), the single "
        "shared Grpc.Net.Client.Web pin of PRF.05/PRF.06; used only by non-packable AOT probes. It declares no "
        "net10.0 dependency.",
        False,
    ),
}


def nuspec(coordinate: str) -> tuple[str, str]:
    package, version = coordinate.rsplit("/", 1)
    path = NUGET_CACHE / package / version / f"{package}.nuspec"
    raw = path.read_bytes()
    text = raw.decode("utf-8-sig")
    licence = re.search(r'<license type="expression">([^<]+)</license>', text)
    if licence is None:
        raise SystemExit(f"No licence expression in {path}")
    return hashlib.sha256(raw).hexdigest(), licence.group(1)


def insert_row(rows: dict, key: str, row: dict) -> dict:
    """Add or replace one row without reordering any existing row (the current file is not strictly sorted)."""
    if key in rows:
        rows[key] = row
        return rows
    before = [name for name in rows if name < key]
    anchor = max(before) if before else None
    result: dict = {}
    if anchor is None:
        result[key] = row
    for name, value in rows.items():
        result[name] = value
        if name == anchor:
            result[key] = row
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="the 40 hex digit main commit this receipt is based on")
    args = parser.parse_args()
    if not re.fullmatch("[0-9a-f]{40}", args.baseline):
        raise SystemExit("--baseline must be a full commit SHA")

    policy_path = ROOT / "eng/policy/dependency-policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    already_generated = policy["reviewReceipt"] == RECEIPT
    previous = policy["review"]["previousReceipt"] if already_generated else policy["reviewReceipt"]
    if not (ROOT / previous).is_file():
        raise SystemExit(f"Missing predecessor receipt {previous}")

    locked = dependency_policy.closure(ROOT)
    for coordinate, (expected_licence, classification, internal) in NEW_COORDINATES.items():
        if coordinate not in locked:
            raise SystemExit(f"Expected PRF.06 coordinate missing from the locked graph: {coordinate}")
        sha, licence = nuspec(coordinate)
        if licence != expected_licence:
            raise SystemExit(f"Unexpected licence {licence} for {coordinate}")
        package, version = coordinate.rsplit("/", 1)
        row = {
            "contentHash": locked[coordinate],
            "licence": licence,
            "nuspecSha256": sha,
            "source": f"https://api.nuget.org/v3-flatcontainer/{package}/{version}/{package}.nuspec",
            "classification": classification,
        }
        if internal:
            row["internalPublisher"] = {
                "repository": "ArcForges/Contracts",
                "workflow": "ci.yml",
                "sourceCommit": CONTRACTS_SOURCE_COMMIT,
                "feed": NUGET_FEED,
            }
        policy["nugetClosure"] = insert_row(policy["nugetClosure"], coordinate, row)

    missing = sorted(set(locked) - set(policy["nugetClosure"]))
    if missing:
        raise SystemExit("Locked coordinates that no receipt row admits: " + ", ".join(missing))

    input_hashes = dependency_policy.hashes(ROOT)
    global_json = json.loads((ROOT / "global.json").read_text(encoding="utf-8"))
    policy["inputHashes"] = input_hashes
    policy["reviewReceipt"] = RECEIPT
    policy["review"].update(
        {
            "owner": "w-c20261002-prf06",
            "reviewer": "Pending independent exact-head dependency-admission review before merge.",
            "reviewedOn": "2026-10-02",
            "baselineCommit": args.baseline,
            "maintenanceAssessment": (
                "PRF.06 adds one non-packable Native AOT probe, tests/ReleaseArtifactTests/Realtime/RealtimeAotProbe.csproj, "
                "that consumes the generated annex 10 EventService and ExecutionService clients. It admits exactly four new "
                "locked coordinates: ArcForges.Contracts.Events, ArcForges.Contracts.PublicApi and ArcForges.Contracts.Foundation "
                "at the CON.11 candidate 1.0.0-ci.270.1 (Contracts source 4047930, all Apache-2.0, each pinned only for the project "
                "named RealtimeAotProbe so no other project's resolution changes), and the single Grpc.Net.Client.Web 2.84.0 pin "
                "shared with PRF.05 (Apache-2.0, no net10.0 dependency). Google.Protobuf 3.36.1, Grpc.Core.Api 2.84.0, Grpc.Net.Client "
                "2.84.0, Grpc.Net.Common 2.84.0 and the Microsoft.Extensions 8.0.1 abstractions are unchanged admitted rows. This "
                "immutable successor chains from the active receipt on main, preserves every earlier receipt and changes no other "
                "dependency coordinate, version, framework, native or Android posture."
            ),
            "upgradeChecks": {
                "compilation": (
                    "Locked restore on the pinned .NET SDK 10.0.400 (the user-level installation, not the machine SDK) and Release "
                    "build with warnings as errors pass locally; hosted CI repeats restore, build and format on the exact head."
                ),
                "aot-trim": (
                    "The project imports the shared full-trim/AOT posture with IL2026 and IL3050 as errors and suppresses nothing. "
                    "The Native AOT publish is run locally on win-x64 and compiled for win-x64 and linux-x64 by the locked "
                    "realtime-aot package-validation job; the job never executes the binary."
                ),
                "compatibility": (
                    "Only generated Contracts records and clients are used; no wire DTO is copied. The CON.11 candidate contains the "
                    "published EventService.Watch/Poll and ExecutionService.WatchOutput/ReadOutput contract. Nothing here claims that "
                    "any deployed server implements them."
                ),
                "licence-provenance": (
                    "All four new coordinates have exact locked content hashes and Apache-2.0 nuspec expressions; the three Contracts "
                    "packages record source commit 4047930ef2207e8a4c6de9e7ef679f0d9359a8e4 from their nuspec repository element. "
                    "Apache-2.0 is permitted inside the AGPL repository and the probe is non-packable."
                ),
                "security-sbom": (
                    "The complete locked graph is admitted and CI retains NuGet audit. No claim of absent advisories is made beyond "
                    "what the hosted audit reports."
                ),
                "runtime-performance-migration": (
                    "The probe's offline self-test covers its own client logic and the replayed binary gRPC-Web wire; it is not a "
                    "performance benchmark and not a deployed-service result. The live mode against a deployed Worker is local opt-in "
                    "and has never been run."
                ),
                "framework-runtime-posture": (
                    "No framework major, native ABI or Android posture change; global.json stays on .NET SDK 10.0.400."
                ),
            },
            "inputHashes": input_hashes,
            "frameworkVersions": {"dotnetSdk": global_json["sdk"]["version"]},
            "previousReceipt": previous,
        }
    )

    receipt = {key: policy[key] for key in ("review", "nugetClosure", "pythonClosure")}
    (ROOT / RECEIPT).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Wrote {RECEIPT}; predecessor {previous}; {len(locked)} locked coordinates; {len(input_hashes)} dependency inputs.")


if __name__ == "__main__":
    main()
