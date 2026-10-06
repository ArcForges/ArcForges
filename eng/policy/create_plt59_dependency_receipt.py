# SPDX-License-Identifier: AGPL-3.0-only
"""Bind PLT.59's verified Contracts peer upgrade to the actual locked closure."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eng"))
import dependency_policy  # noqa: E402

CONTRACTS_COMMIT = "330e46bd158bfbb7cdc94c7006565c87e27b1cc6"
CONTRACTS_VERSION = "1.0.0-ci.324.1"
COORDINATES = {name + "/" + CONTRACTS_VERSION for name in (
    "arcforges.contracts.foundation", "arcforges.contracts.localrpc.platform",
    "arcforges.contracts.localrpc.sandbox", "arcforges.contracts.publicapi", "arcforges.sdk.contracts")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--producer-integrity", required=True,
                        help="Actual pinned SDK NuGet signed-content integrity results; never raw signed ZIP SHA512")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.baseline):
        raise SystemExit("A full accepted main source commit is required")
    if not re.fullmatch(r"eng/policy/dependency-reviews/plt-59-r[1-9][0-9]*\.json", args.receipt):
        raise SystemExit("A task-owned immutable receipt path is required")
    receipt_path = ROOT / args.receipt
    if receipt_path.exists():
        raise SystemExit("Never overwrite an existing immutable receipt")
    path = ROOT / dependency_policy.POLICY
    policy = json.loads(path.read_text(encoding="utf-8"))
    predecessor = policy["reviewReceipt"]
    if not (ROOT / predecessor).is_file():
        raise SystemExit("The accepted predecessor receipt is missing")
    closure = dependency_policy.closure(ROOT)
    integrity = json.loads(Path(args.producer_integrity).read_text(encoding="utf-8"))
    if set(integrity) != COORDINATES:
        raise SystemExit("The exact five producer integrity observations are required")
    if not COORDINATES.issubset(closure):
        raise SystemExit("The complete reviewed Contracts peer closure is not present")
    unexpected = set(closure) - set(policy["nugetClosure"]) - COORDINATES
    if unexpected:
        raise SystemExit("Unreviewed additional coordinates: " + ", ".join(sorted(unexpected)))
    rows = {key: value for key, value in policy["nugetClosure"].items() if key in closure}
    for coordinate in sorted(COORDINATES):
        package, version = coordinate.rsplit("/", 1)
        directory = Path.home() / ".nuget/packages" / package / version
        archive = directory / (package + "." + version + ".nupkg")
        observed = integrity[coordinate]
        archive_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
        if (set(observed) != {"contentHash", "archiveSha256", "integrity"}
                or observed["contentHash"] != closure[coordinate]
                or observed["archiveSha256"] != archive_sha256 or observed["integrity"] != "passed"):
            raise SystemExit("Actual signed-content identity/integrity differs from the locked producer: " + coordinate)
        raw = (directory / (package + ".nuspec")).read_bytes()
        metadata = ET.fromstring(raw).find("{*}metadata")
        licence = metadata.find("{*}license")
        repository = metadata.find("{*}repository")
        if (metadata.findtext("{*}id").lower() != package or metadata.findtext("{*}version") != version
                or licence is None or licence.get("type") != "expression" or licence.text != "Apache-2.0"
                or repository is None or repository.get("url") != "https://github.com/ArcForges/Contracts"
                or repository.get("commit") != CONTRACTS_COMMIT):
            raise SystemExit("Producer identity/licence/source mismatch: " + coordinate)
        row = {"contentHash": closure[coordinate], "licence": "Apache-2.0",
               "archiveSha256": archive_sha256,
               "nuspecSha256": hashlib.sha256(raw).hexdigest(),
               "source": f"https://api.nuget.org/v3-flatcontainer/{package}/{version}/{package}.nuspec",
               "classification": "Exact published production Contracts peer; Apache-2.0. Retained actual NuGet repository signature verification, owned publisher source and generated contract closure.",
               "internalPublisher": {"repository": "ArcForges/Contracts", "workflow": "ci.yml",
                                     "sourceCommit": CONTRACTS_COMMIT, "feed": "https://api.nuget.org/v3/index.json"}}
        if coordinate in rows and rows[coordinate] != row:
            raise SystemExit("An existing admitted producer row must not be rewritten")
        rows[coordinate] = row
    policy["nugetClosure"] = dict(sorted(rows.items()))
    input_hashes = dependency_policy.hashes(ROOT)
    policy["inputHashes"] = input_hashes
    policy["reviewReceipt"] = args.receipt
    policy["review"].update({
        "owner": "w-codex-20261006-coord",
        "reviewer": "Independent exact-head source and dependency-admission approval required before merge.",
        "reviewedOn": "2026-10-06", "baselineCommit": args.baseline, "previousReceipt": predecessor,
        "maintenanceAssessment": "PLT.59 activates seven implemented managed packages and upgrades only the affected production Contracts peer selectors to verified publication324.1/source330e46bd. Existing Foundation/Persistence216.1 dependencies cannot compose with ArcScope's actual Scope324 DTO producer. Preserve exact owned lockstep versions, old113 fixtures and270 realtime probe, all immutable previous receipts and unrelated versions. Native/helper executables and OS acceptance remain separate producers.",
        "upgradeChecks": {
            "compilation": "Actual full DesktopPlatform.slnx locked restore and Release build on SDK10.0.400 passed with zero warnings/errors; applicable exact-head CI must pass before merge.",
            "aot-trim": "Existing AOT/trim library posture is preserved without suppressions. Applicable retained LocalRpc/helper/generated transport win-x64 and linux-x64 AOT compile gates are required on the exact reviewed head; no new hosted runtime execution.",
            "compatibility": "Actual generated managed nuspecs must match the exact reviewed catalogue closure. Only current production peers change; historical fixtures remain unchanged. Product source uses exact published packages, never sibling references.",
            "licence-provenance": "Actual pinned SDK NuGet signed-content hash and integrity verification binds all five locked SHA512 identities to observed archive SHA256; a signed archive's raw ZIP SHA512 is not its NuGet content hash. Nuspec Apache-2.0/source330e46bd verified. Retained actual NuGet repository-signature verification covers the cached producer; generated legal assets and independent source/provenance gates remain required.",
            "security-sbom": "Complete actual locked closure is admitted, with historical immutable hashes preserved. NuGet audit and current licence/source/native gates remain required; no advisory absence or OS isolation inferred from component results.",
            "runtime-performance-migration": "Existing security, durable audit, capability and helper components are tested against the actual upgraded contracts. No business migration or performance claim; full product/OS acceptance stays with APP02/03, PLT46 and NAT22/25.",
            "framework-runtime-posture": "No SDK major/native ABI/Android change. SDK10.0.400 and existing compilation/publishing profiles remain unchanged."},
        "inputHashes": input_hashes,
        "frameworkVersions": {"dotnetSdk": json.loads((ROOT / "global.json").read_text())["sdk"]["version"]}})
    with receipt_path.open("x", encoding="utf-8", newline="\n") as receipt:
        receipt.write(json.dumps({key: policy[key] for key in ("review", "nugetClosure", "pythonClosure")}, indent=2) + "\n")
    path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Bound {len(closure)} coordinates and {len(input_hashes)} inputs; immutable predecessor {predecessor}")


if __name__ == "__main__":
    main()
