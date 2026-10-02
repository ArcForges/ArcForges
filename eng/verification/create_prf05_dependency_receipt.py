# SPDX-License-Identifier: AGPL-3.0-only
"""Create (or refresh after a rebase) the immutable PRF.05 dependency-admission successor.

It chains from the receipt that is ACTIVE on the base branch, admits exactly one new NuGet coordinate
(Grpc.Net.Client.Web 2.84.0) and rebinds every dependency input hash. Run it again after every rebase: the
predecessor is read from the policy (or, when this receipt is already active, from its own previousReceipt),
so it never chains from itself.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eng"))
import dependency_policy  # noqa: E402


RECEIPT = "eng/policy/dependency-reviews/prf-05-r1.json"
# The main commit the successor is reviewed against; update together with a rebase.
BASELINE_COMMIT = "d4e874374a737012b174904e25d49c8fdf05714c"
NUGET_FEED = "https://api.nuget.org/v3/index.json"
NEW_COORDINATE = "grpc.net.client.web/2.84.0"
NEW_EVIDENCE = {
    "licence": "Apache-2.0",
    "nuspecSha256": "da47ce027ddbbbf7c0b1f242b1efe64a5aeaa2959da54716a100fcc6e4520efb",
    "source": "https://api.nuget.org/v3-flatcontainer/grpc.net.client.web/2.84.0/grpc.net.client.web.nuspec",
    "classification": (
        "Exact direct gRPC-Web client handler shared by PRF.05 and PRF.06; the net10.0 dependency group is empty, so "
        "it adds no transitive coordinate. Used only by the non-packable PRF.05 Native AOT probe."
    ),
}
PUBLICAPI = "arcforges.contracts.publicapi/1.0.0-ci.216.1"
PUBLICAPI_CLASSIFICATION = (
    "Exact published Contracts candidate. It is a transitive dependency of ArcForges.Sdk.Contracts 1.0.0-ci.216.1 in the "
    "existing Capabilities and Contributions graphs, and the non-packable PRF.05 probe also references it directly for "
    "the generated HelloService client at the same version. Apache-2.0 is permitted inside AGPL consumers."
)


def main() -> None:
    policy_path = ROOT / "eng/policy/dependency-policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    active = policy["reviewReceipt"]
    previous = policy["review"]["previousReceipt"] if active == RECEIPT else active
    if previous is None or previous == RECEIPT:
        raise SystemExit(f"Unexpected dependency review predecessor: {active}")

    locked = dependency_policy.closure(ROOT)
    if NEW_COORDINATE not in locked or PUBLICAPI not in locked:
        raise SystemExit("The locked graph does not contain the expected PRF.05 coordinates.")
    policy["nugetClosure"][NEW_COORDINATE] = {"contentHash": locked[NEW_COORDINATE], **NEW_EVIDENCE}
    policy["nugetClosure"][PUBLICAPI]["classification"] = PUBLICAPI_CLASSIFICATION
    policy["nugetClosure"] = dict(sorted(policy["nugetClosure"].items()))

    input_hashes = dependency_policy.hashes(ROOT)
    global_json = json.loads((ROOT / "global.json").read_text(encoding="utf-8"))
    policy["inputHashes"] = input_hashes
    policy["reviewReceipt"] = RECEIPT
    policy["review"].update(
        {
            "owner": "w-c20261002-prf05",
            "reviewer": "Pending independent exact-head dependency-admission review before merge.",
            "reviewedOn": "2026-10-02",
            "baselineCommit": BASELINE_COMMIT,
            "maintenanceAssessment": (
                "PRF.05 adds the non-packable Native AOT probe tests/ReleaseArtifactTests/GrpcWeb/GrpcWebAotProbe.csproj. "
                "It appends the single central pin Grpc.Net.Client.Web 2.84.0 (Apache-2.0, no transitive dependencies on "
                "net10.0) and consumes the already-admitted ArcForges.Contracts.PublicApi and Foundation 1.0.0-ci.216.1 "
                "candidates through a probe-local Directory.Packages.props that imports the root pins unchanged. The "
                "locked closure gains exactly one coordinate; every other coordinate, version and content hash is "
                "unchanged. This successor chains from the active receipt and preserves all earlier receipts."
            ),
            "upgradeChecks": {
                "compilation": "Pinned SDK 10.0.400 locked-mode restore and Release build of the probe pass; the hosted grpc-web-aot job repeats the locked restore and Native AOT publish for linux-x64 and win-x64 on pull requests and main builds.",
                "aot-trim": "The probe imports the shared full-trim/AOT posture with IL2026 and IL3050 as errors; the local win-x64 Native AOT publish produced no warning, and hosted publish checks must pass without suppressed diagnostics.",
                "compatibility": "Only the generated HelloService client of the published ArcForges.Contracts.PublicApi 1.0.0-ci.216.1 candidate is used; no wire DTO is copied and no schema or contract changes.",
                "licence-provenance": "The new coordinate has an exact locked content hash and Apache-2.0 nuspec evidence; the PublicApi and Foundation candidates keep their recorded source commit and publisher evidence.",
                "security-sbom": "The complete locked graph is admitted and CI retains NuGet audit; no claim of absent current advisories is made.",
                "runtime-performance-migration": "The probe is a local opt-in diagnostic: the fixture self-test runs offline and the live mode never runs in CI. No production host, migration or performance claim is made.",
                "framework-runtime-posture": "No framework major, native ABI, Android Kotlin/JVM/ART/R8 or SDK change; global.json remains on .NET SDK 10.0.400.",
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
