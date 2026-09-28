# SPDX-License-Identifier: AGPL-3.0-only
"""Create the immutable PRF.04 dependency-admission snapshot from its locked graph."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eng"))
import dependency_policy  # noqa: E402


ACTIVE_RECEIPT = "eng/policy/dependency-reviews/plt-26-r2.json"
RECEIPT = "eng/policy/dependency-reviews/prf-04-r1.json"
BASELINE_COMMIT = "0ba78d58cb31c1226d8e0b70f2879ecc42d00699"
SOURCE_COMMIT = "eb650e5b9ef7fc06f0eb79ee167b896e4252b50e"
NUGET_FEED = "https://api.nuget.org/v3/index.json"

PACKAGE_EVIDENCE = {
    "arcforges.contracts.foundation/1.0.0-ci.216.1": {
        "licence": "Apache-2.0",
        "nuspecSha256": "b2704457f3245e4c44200ed4e8dd87054a81cbe53faa31cd384aad92db78839e",
        "source": "https://api.nuget.org/v3-flatcontainer/arcforges.contracts.foundation/1.0.0-ci.216.1/arcforges.contracts.foundation.nuspec",
        "classification": "Exact CON.05 Foundation candidate consumed only by the PRF.04 non-packable AOT probe; source commit and original candidate publication are recorded in the Plan ledger.",
        "internalPublisher": {
            "repository": "ArcForges/Contracts",
            "workflow": "ci.yml",
            "sourceCommit": SOURCE_COMMIT,
            "feed": NUGET_FEED,
        },
    },
    "arcforges.contracts.localrpc.platform/1.0.0-ci.216.1": {
        "licence": "Apache-2.0",
        "nuspecSha256": "2e9af7a67637cdff08601ce3fb2d20a445fd34c7d535dc4d3508ff10bc9a3c1b",
        "source": "https://api.nuget.org/v3-flatcontainer/arcforges.contracts.localrpc.platform/1.0.0-ci.216.1/arcforges.contracts.localrpc.platform.nuspec",
        "classification": "Exact CON.05 generated LocalRpc producer consumed only by the PRF.04 non-packable AOT probe; source commit and original candidate publication are recorded in the Plan ledger.",
        "internalPublisher": {
            "repository": "ArcForges/Contracts",
            "workflow": "ci.yml",
            "sourceCommit": SOURCE_COMMIT,
            "feed": NUGET_FEED,
        },
    },
    "grpc.aspnetcore.server/2.83.0": {
        "licence": "Apache-2.0",
        "nuspecSha256": "b9a51de789abe619de7ee4bb9ec9f30452c4bca13d514e53ac574a0bb96116e3",
        "source": "https://api.nuget.org/v3-flatcontainer/grpc.aspnetcore.server/2.83.0/grpc.aspnetcore.server.nuspec",
        "classification": "Exact permitted gRPC ASP.NET Core server candidate; used by the non-packable PRF.04 AOT proof only.",
    },
    "grpc.core.api/2.84.0": {
        "licence": "Apache-2.0",
        "nuspecSha256": "bba00f5d5be8423dd351662e313648b0abd13100ef67d55f6fc29de44c544a96",
        "source": "https://api.nuget.org/v3-flatcontainer/grpc.core.api/2.84.0/grpc.core.api.nuspec",
        "classification": "Exact CON.05 transitive and permitted gRPC client candidate dependency; used by the non-packable PRF.04 AOT proof only.",
    },
    "grpc.net.client/2.84.0": {
        "licence": "Apache-2.0",
        "nuspecSha256": "32a43f3448ab90bb71c946533db4d5135cef4728a3ee29bf88d9a0cbf1e67413",
        "source": "https://api.nuget.org/v3-flatcontainer/grpc.net.client/2.84.0/grpc.net.client.nuspec",
        "classification": "Exact permitted gRPC .NET client candidate; used by the non-packable PRF.04 AOT proof only.",
    },
    "grpc.net.common/2.84.0": {
        "licence": "Apache-2.0",
        "nuspecSha256": "f621aa566e63340b572a4f0bd2b996b934407c77b8cdf121f38578e93ee796cb",
        "source": "https://api.nuget.org/v3-flatcontainer/grpc.net.common/2.84.0/grpc.net.common.nuspec",
        "classification": "Exact shared gRPC transport dependency selected by the permitted server/client candidates; used by the non-packable PRF.04 AOT proof only.",
    },
}


def main() -> None:
    policy_path = ROOT / "eng/policy/dependency-policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    active_review = policy["reviewReceipt"] == ACTIVE_RECEIPT
    already_generated = (
        policy["reviewReceipt"] == RECEIPT
        and policy["review"].get("previousReceipt") == ACTIVE_RECEIPT
    )
    if not (active_review or already_generated):
        raise SystemExit(f"Unexpected dependency review predecessor: {policy['reviewReceipt']}")

    locked = dependency_policy.closure(ROOT)
    for coordinate, evidence in PACKAGE_EVIDENCE.items():
        if coordinate not in locked:
            raise SystemExit(f"Expected PRF.04 coordinate missing from locked graph: {coordinate}")
        policy["nugetClosure"][coordinate] = {
            "contentHash": locked[coordinate],
            **evidence,
        }
    policy["nugetClosure"] = dict(sorted(policy["nugetClosure"].items()))

    input_hashes = dependency_policy.hashes(ROOT)
    previous = ACTIVE_RECEIPT
    global_json = json.loads((ROOT / "global.json").read_text(encoding="utf-8"))
    policy["inputHashes"] = input_hashes
    policy["reviewReceipt"] = RECEIPT
    policy["review"].update(
        {
            "owner": "af-20260928-p02",
            "reviewer": "platform_capabilities/plt18_contributions (independent exact-head review pending)",
            "reviewedOn": "2026-09-28",
            "baselineCommit": BASELINE_COMMIT,
            "maintenanceAssessment": (
                "PRF.04 appends to plt-26-r2, whose immutable predecessor chain retains gov-14-naming-r4. It admits "
                "only the exact CON.05 generated LocalRpc/Foundation candidates and the permitted "
                "Grpc.AspNetCore.Server 2.83.0 / Grpc.Net.Client 2.84.0 candidates, with their exact transitive "
                "closure and Apache-2.0 nuspec evidence. Foundation 1.0.0-ci.216.1 is conditional to this probe "
                "project. The new project is non-packable; no capability package or dependency version is invented. "
                "The pinned .NET 10.0.400 SDK/runtime posture and all other dependency closures remain unchanged."
            ),
            "upgradeChecks": {
                "compilation": "Pinned SDK 10.0.400 locked restore and Release build pass; Windows/Linux Native AOT publication is enforced continuously by package-validation CI.",
                "aot-trim": "The probe imports the shared full-trim/AOT posture with IL2026 and IL3050 as errors; exact-head Windows/Linux publish checks must pass without suppressed diagnostics.",
                "compatibility": "Consumes only the exact CON.05 generated package and exercises generated LocalBootstrap calls in both directions over native OS transports; no copied wire DTOs or schema changes.",
                "licence-provenance": "All six newly recorded coordinates have exact locked content hashes and Apache-2.0 nuspec evidence; CON.05 packages bind to source eb650e5b9ef7fc06f0eb79ee167b896e4252b50e and original CI publication 36358269955.",
                "security-sbom": "The complete locked graph is admitted and CI retains NuGet audit; local audit was disabled only for deterministic offline restore, and no claim of absent current advisories is made.",
                "runtime-performance-migration": "The isolated probe covers cancellation, malformed input, unauthorized same-user peer, 4 MiB receive refusal, disconnect and fresh-instance reattach. It is not a production lease/launcher or performance benchmark.",
                "framework-runtime-posture": "No framework major, native ABI, Android Kotlin/JVM/ART/R8, or SDK change; global.json remains on .NET SDK 10.0.400. Hosted CI compiles/publishes but never runs the runtime probe.",
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
