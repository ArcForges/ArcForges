# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed invariant accounting from the current catalog and owner receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CATALOG_REL = "eng/policy/invariants.json"
ROSTER_REL = "eng/accounting/invariant-test-cases.json"
AUDIT_REL = "eng/accounting/registration-audit.json"
RESULT_SCHEMA_REL = "eng/accounting/owner-results.schema.json"
DESKTOP_REPOSITORY = "ArcForges/DesktopPlatform"
INVARIANT_ID = re.compile(r"^I-[0-9]{3}$")
CASE_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
CI_RUN = re.compile(r"^[1-9][0-9]*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TRX_NAMESPACE = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"

TRX_SUITES = (
    ("architecture-tests", "tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj"),
    ("foundation-tests", "src/BuildingBlocks/ArcForges.Foundation/Tests/ArcForges.Foundation.Tests.csproj"),
    (
        "persistence-resources-tests",
        "src/BuildingBlocks/ArcForges.Persistence.Resources/Tests/ArcForges.Persistence.Resources.Tests.csproj",
    ),
    (
        "persistence-derived-tests",
        "src/BuildingBlocks/ArcForges.Persistence.Derived/Tests/ArcForges.Persistence.Derived.Tests.csproj",
    ),
    ("capabilities-tests", "src/BuildingBlocks/ArcForges.Capabilities/Tests/ArcForges.Capabilities.Tests.csproj"),
    ("security-tests", "src/BuildingBlocks/ArcForges.Security/Tests/ArcForges.Security.Tests.csproj"),
    ("persistence-tests", "tests/PersistenceTests/ArcForges.Tests.PersistenceTests.csproj"),
)

OWNER_RESULT_FIELDS = {
    "invariantId",
    "caseId",
    "sourceId",
    "outcome",
    "repository",
    "sourceCommit",
    "ciRun",
    "attempt",
}
SOURCE_FIELDS = {
    "sourceId",
    "source",
    "resultFile",
    "sha256",
    "total",
    "passed",
    "failed",
    "skipped",
    "summaryOutcome",
}
AUDIT_FIELDS = {
    "schemaVersion",
    "catalogSha256",
    "reviewedAtSourceCommit",
    "semanticOwner",
    "obligationOwner",
    "candidatePackageId",
    "candidateFilter",
    "reviewMethod",
    "reviewedSuiteIds",
    "candidates",
}
PASS = "Passed"
FAIL = "Failed"


class AccountingError(ValueError):
    """An input is incomplete, inconsistent, unknown, or untrusted."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AccountingError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise AccountingError(f"Non-standard JSON constant is not accepted: {value}")


def _write_json(path: Path, value: Any) -> bytes:
    data = _json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)
    return data


def _load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    data = path.read_bytes()
    try:
        value = json.loads(data, object_pairs_hook=_unique_object, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AccountingError(f"Malformed JSON: {path}") from error
    if not isinstance(value, dict):
        raise AccountingError(f"JSON root must be an object: {path}")
    return value, data


def _ids_hash(ids: list[str]) -> str:
    return _sha256(json.dumps(sorted(ids), separators=(",", ":")).encode("ascii"))


def _safe_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise AccountingError(f"{label} must be a non-empty repository-relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AccountingError(f"Unsafe {label}: {value}")
    return path.as_posix()


def _load_catalog(path: Path) -> tuple[dict[str, Any], bytes, list[dict[str, Any]], list[str]]:
    catalog, data = _load_json(path)
    records = catalog.get("records")
    if type(catalog.get("schemaVersion")) is not int or catalog["schemaVersion"] != 1 or not isinstance(records, list) or not records:
        raise AccountingError("Invariant catalog has an unsupported or incomplete schema")
    ids: list[str] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise AccountingError("Invariant catalog contains a non-object record")
        invariant_id = record.get("id")
        if not isinstance(invariant_id, str) or not INVARIANT_ID.fullmatch(invariant_id):
            raise AccountingError(f"Invalid invariant ID in catalog: {invariant_id!r}")
        if invariant_id in seen:
            raise AccountingError(f"Duplicate invariant ID in catalog: {invariant_id}")
        seen.add(invariant_id)
        ids.append(invariant_id)
    return catalog, data, records, ids


def _validate_case_binding(binding: Any, invariant_id: str) -> dict[str, str]:
    if not isinstance(binding, dict):
        raise AccountingError(f"{invariant_id} has a non-object case registration")
    required = {"caseId", "repository", "sourceId", "testSource", "plannedVerificationRationale"}
    if set(binding) != required:
        raise AccountingError(f"{invariant_id} case registration fields must be exactly {sorted(required)}")
    case_id = binding["caseId"]
    repository = binding["repository"]
    source_id = binding["sourceId"]
    rationale = binding["plannedVerificationRationale"]
    if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
        raise AccountingError(f"Invalid stable case ID for {invariant_id}: {case_id!r}")
    if not isinstance(repository, str) or not re.fullmatch(r"ArcForges/[A-Za-z0-9._-]+", repository):
        raise AccountingError(f"Invalid owner repository for {invariant_id}: {repository!r}")
    if not isinstance(source_id, str) or not source_id.strip():
        raise AccountingError(f"Missing result source ID for {invariant_id}")
    if not isinstance(rationale, str) or not rationale.strip():
        raise AccountingError(f"Missing plannedVerification rationale for {invariant_id}/{case_id}")
    return {
        "caseId": case_id,
        "repository": repository,
        "sourceId": source_id,
        "testSource": _safe_relative_path(binding["testSource"], "testSource"),
        "plannedVerificationRationale": rationale.strip(),
    }


def _load_roster(path: Path, catalog_bytes: bytes, catalog_records: list[dict[str, Any]], catalog_ids: list[str]):
    roster, roster_bytes = _load_json(path)
    catalog_binding = roster.get("catalog")
    if type(roster.get("schemaVersion")) is not int or roster["schemaVersion"] != 1 or not isinstance(catalog_binding, dict):
        raise AccountingError("Invariant-to-test roster has an unsupported schema")
    expected_catalog_binding = {
        "path": CATALOG_REL,
        "sha256": _sha256(catalog_bytes),
        "recordCount": len(catalog_records),
        "idSetSha256": _ids_hash(catalog_ids),
    }
    if catalog_binding != expected_catalog_binding:
        raise AccountingError("Roster catalog identity/count/hash does not match the complete current export")
    roster_records = roster.get("records")
    if not isinstance(roster_records, list):
        raise AccountingError("Roster records must be an array, including entries with empty expectedCases")
    by_id: dict[str, dict[str, Any]] = {}
    registrations: dict[tuple[str, str, str], dict[str, str]] = {}
    for item in roster_records:
        if not isinstance(item, dict) or set(item) != {"invariantId", "expectedCases"}:
            raise AccountingError("Roster entries must contain exactly invariantId and expectedCases")
        invariant_id = item["invariantId"]
        expected_cases = item["expectedCases"]
        if not isinstance(invariant_id, str) or not INVARIANT_ID.fullmatch(invariant_id):
            raise AccountingError(f"Invalid invariant ID in roster: {invariant_id!r}")
        if invariant_id in by_id:
            raise AccountingError(f"Duplicate invariant ID in roster: {invariant_id}")
        if not isinstance(expected_cases, list):
            raise AccountingError(f"expectedCases must be an array for {invariant_id}")
        seen_cases: set[tuple[str, str]] = set()
        for raw_binding in expected_cases:
            binding = _validate_case_binding(raw_binding, invariant_id)
            case_key = (binding["repository"], binding["caseId"])
            if case_key in seen_cases:
                raise AccountingError(f"Duplicate expected case for {invariant_id}: {case_key}")
            seen_cases.add(case_key)
            registrations[(invariant_id, *case_key)] = binding
        by_id[invariant_id] = {"invariantId": invariant_id, "expectedCases": expected_cases}
    if set(by_id) != set(catalog_ids) or len(by_id) != len(catalog_ids):
        missing = sorted(set(catalog_ids) - set(by_id))
        extra = sorted(set(by_id) - set(catalog_ids))
        raise AccountingError(f"Roster is not a complete catalog scan; missing={missing}, extra={extra}")
    return roster, roster_bytes, by_id, registrations


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children_named(node: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(node) if _local_name(child.tag) == name]


def _descendants_named(node: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in node.iter() if _local_name(child.tag) == name]


def _parse_trx(path: Path, suite_id: str, project: str) -> dict[str, Any]:
    data = path.read_bytes()
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise AccountingError(f"DTD/entity declarations are not accepted in TRX input: {path.name}")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise AccountingError(f"Malformed TRX input: {path.name}") from error
    if _local_name(root.tag) != "TestRun" or not root.attrib.get("id"):
        raise AccountingError(f"TRX root is incomplete: {path.name}")

    results_nodes = _children_named(root, "Results")
    definitions_nodes = _children_named(root, "TestDefinitions")
    summary_nodes = _children_named(root, "ResultSummary")
    if len(results_nodes) != 1 or len(definitions_nodes) != 1 or len(summary_nodes) != 1:
        raise AccountingError(f"TRX must have one Results, TestDefinitions and ResultSummary: {path.name}")
    test_results = _children_named(results_nodes[0], "UnitTestResult")
    definitions = _children_named(definitions_nodes[0], "UnitTest")
    if not test_results or not definitions:
        raise AccountingError(f"TRX is empty or incomplete: {path.name}")

    definitions_by_id: dict[str, str] = {}
    for definition in definitions:
        test_id = definition.attrib.get("id")
        method_nodes = _children_named(definition, "TestMethod")
        if not test_id or test_id in definitions_by_id or len(method_nodes) != 1:
            raise AccountingError(f"TRX contains a missing or duplicate test definition: {path.name}")
        class_name = method_nodes[0].attrib.get("className")
        method_name = method_nodes[0].attrib.get("name")
        case_id = f"{class_name}.{method_name}" if class_name and method_name else ""
        if not CASE_ID.fullmatch(case_id):
            raise AccountingError(f"TRX contains an invalid stable test identity: {path.name}")
        definitions_by_id[test_id] = case_id

    case_outcomes: dict[str, list[str]] = defaultdict(list)
    outcome_counts: Counter[str] = Counter()
    result_counts: Counter[str] = Counter()
    for result in test_results:
        test_id = result.attrib.get("testId")
        outcome = result.attrib.get("outcome")
        if not test_id or test_id not in definitions_by_id:
            raise AccountingError(f"TRX result refers to an unknown test ID: {path.name}")
        if not outcome or outcome not in {"Passed", "Failed", "NotExecuted", "Inconclusive", "Aborted", "NotRunnable", "Timeout", "Error", "Disconnected", "Warning", "PassedButRunAborted", "Pending", "InProgress"}:
            raise AccountingError(f"TRX result has an unknown outcome {outcome!r}: {path.name}")
        case_outcomes[definitions_by_id[test_id]].append(outcome)
        outcome_counts[outcome] += 1
        result_counts[test_id] += 1

    summary = summary_nodes[0]
    counters_nodes = _children_named(summary, "Counters")
    summary_outcome = summary.attrib.get("outcome")
    if len(counters_nodes) != 1 or summary_outcome not in {"Completed", "Failed"}:
        raise AccountingError(f"TRX summary is incomplete or inconclusive: {path.name}")
    counters = counters_nodes[0].attrib
    try:
        total = int(counters["total"])
        executed = int(counters["executed"])
        passed = int(counters["passed"])
        failed = int(counters["failed"])
    except (KeyError, ValueError) as error:
        raise AccountingError(f"TRX counters are incomplete: {path.name}") from error
    result_test_ids = set(result_counts)
    if (
        total != len(test_results)
        or result_test_ids != set(definitions_by_id)
        or any(count != 1 for count in result_counts.values())
    ):
        raise AccountingError(f"TRX result/definition mapping is not one-to-one: {path.name}")
    if passed != outcome_counts[PASS] or failed != outcome_counts[FAIL]:
        raise AccountingError(f"TRX passed/failed counters do not reconcile: {path.name}")
    if executed != passed + failed:
        raise AccountingError(f"TRX executed counter does not reconcile: {path.name}")
    skipped = total - passed - failed
    if skipped < 0 or (summary_outcome == "Completed" and failed) or (summary_outcome == "Failed" and not failed):
        raise AccountingError(f"TRX summary contradicts test outcomes: {path.name}")

    return {
        "sourceId": suite_id,
        "project": project,
        "resultPath": path,
        "sha256": _sha256(data),
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "summaryOutcome": summary_outcome.lower(),
        "caseOutcomes": dict(case_outcomes),
    }


def _validate_commit(value: Any) -> str:
    if not isinstance(value, str) or not COMMIT.fullmatch(value):
        raise AccountingError(f"sourceCommit must be a full lowercase Git SHA: {value!r}")
    return value


def _validate_run(value: Any) -> str:
    if not isinstance(value, str) or not CI_RUN.fullmatch(value):
        raise AccountingError(f"ciRun must be a positive CI run ID: {value!r}")
    return value


def _validate_source(item: Any, where: str) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) != SOURCE_FIELDS:
        raise AccountingError(f"{where} source fields do not match the normalized schema")
    source_id = item["sourceId"]
    if not isinstance(source_id, str) or not source_id.strip():
        raise AccountingError(f"{where} has an empty sourceId")
    source = _safe_relative_path(item["source"], f"{where}.source")
    result_file = _safe_relative_path(item["resultFile"], f"{where}.resultFile")
    if not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"]):
        raise AccountingError(f"{where} has an invalid SHA-256")
    for key in ("total", "passed", "failed", "skipped"):
        if isinstance(item[key], bool) or not isinstance(item[key], int) or item[key] < 0:
            raise AccountingError(f"{where}.{key} must be a non-negative integer")
    if item["total"] < 1 or item["total"] != item["passed"] + item["failed"] + item["skipped"]:
        raise AccountingError(f"{where} test counts do not reconcile")
    if not isinstance(item["summaryOutcome"], str) or item["summaryOutcome"] not in {"completed", "failed"}:
        raise AccountingError(f"{where} has an inconclusive summary")
    if (item["summaryOutcome"] == "completed" and item["failed"] != 0) or (item["summaryOutcome"] == "failed" and item["failed"] == 0):
        raise AccountingError(f"{where} summary outcome contradicts counts")
    return {
        "sourceId": source_id,
        "source": source,
        "resultFile": result_file,
        "sha256": item["sha256"],
        "total": item["total"],
        "passed": item["passed"],
        "failed": item["failed"],
        "skipped": item["skipped"],
        "summaryOutcome": item["summaryOutcome"],
    }


def _validate_owner_receipt(receipt: Any, known_ids: set[str], where: str) -> dict[str, Any]:
    required = {"schemaVersion", "repository", "sourceCommit", "ciRun", "attempt", "sources", "results"}
    if not isinstance(receipt, dict) or set(receipt) != required or type(receipt.get("schemaVersion")) is not int or receipt["schemaVersion"] != 1:
        raise AccountingError(f"{where} does not match owner-results schema version 1")
    repository = receipt["repository"]
    if not isinstance(repository, str) or not re.fullmatch(r"ArcForges/[A-Za-z0-9._-]+", repository):
        raise AccountingError(f"{where} has invalid repository identity")
    source_commit = _validate_commit(receipt["sourceCommit"])
    ci_run = _validate_run(receipt["ciRun"])
    attempt = receipt["attempt"]
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise AccountingError(f"{where} attempt must be a positive integer")
    sources = receipt["sources"]
    results = receipt["results"]
    if not isinstance(sources, list) or not sources or not isinstance(results, list):
        raise AccountingError(f"{where} must contain sources and results arrays")
    validated_sources = [_validate_source(source, f"{where}.sources[{index}]") for index, source in enumerate(sources)]
    if len({source["sourceId"] for source in validated_sources}) != len(validated_sources):
        raise AccountingError(f"{where} has duplicate result source IDs")
    validated_results = []
    result_keys: set[tuple[str, str]] = set()
    for index, row in enumerate(results):
        if not isinstance(row, dict) or set(row) != OWNER_RESULT_FIELDS:
            raise AccountingError(f"{where}.results[{index}] does not match the normalized schema")
        invariant_id = row["invariantId"]
        case_id = row["caseId"]
        if not isinstance(invariant_id, str) or not INVARIANT_ID.fullmatch(invariant_id) or invariant_id not in known_ids:
            raise AccountingError(f"{where} contains an unknown invariant ID: {invariant_id!r}")
        if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
            raise AccountingError(f"{where} contains an invalid case ID: {case_id!r}")
        if not isinstance(row["outcome"], str) or row["outcome"] not in {"passed", "failed"}:
            raise AccountingError(f"{where} contains a skipped or inconclusive mapped result")
        key = (invariant_id, case_id)
        if key in result_keys:
            raise AccountingError(f"{where} contains duplicate invariant/case results: {key}")
        result_keys.add(key)
        if row["repository"] != repository or _validate_commit(row["sourceCommit"]) != source_commit:
            raise AccountingError(f"{where} result repository/source commit disagrees with receipt")
        if _validate_run(row["ciRun"]) != ci_run or row["attempt"] != attempt:
            raise AccountingError(f"{where} result CI run/attempt disagrees with receipt")
        validated_results.append(dict(row))
        if not isinstance(row["sourceId"], str) or row["sourceId"] not in {source["sourceId"] for source in validated_sources}:
            raise AccountingError(f"{where} result refers to an unknown source ID: {row['sourceId']!r}")
    return {
        "schemaVersion": 1,
        "repository": repository,
        "sourceCommit": source_commit,
        "ciRun": ci_run,
        "attempt": attempt,
        "sources": validated_sources,
        "results": validated_results,
    }


def _normalize_desktop(
    trx_dir: Path,
    registrations: dict[tuple[str, str, str], dict[str, str]],
    all_ids: set[str],
    audit: dict[str, Any],
    source_commit: str,
    ci_run: str,
    attempt: int,
) -> dict[str, Any]:
    try:
        trx_dir.resolve().relative_to(ROOT.resolve())
    except ValueError as error:
        raise AccountingError(f"TRX directory must be inside the checked-out repository: {trx_dir}") from error
    expected_files = {f"{suite_id}.trx" for suite_id, _ in TRX_SUITES}
    actual_files = {path.name for path in trx_dir.glob("*.trx")}
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        extra = sorted(actual_files - expected_files)
        raise AccountingError(f"Expected exactly seven unique TRX inputs; missing={missing}, extra={extra}")

    parsed_suites: dict[str, dict[str, Any]] = {}
    source_rows: list[dict[str, Any]] = []
    for suite_id, project in TRX_SUITES:
        result_path = trx_dir / f"{suite_id}.trx"
        parsed = _parse_trx(result_path, suite_id, project)
        parsed_suites[suite_id] = parsed
        relative_result = result_path.resolve().relative_to(ROOT.resolve()).as_posix()
        source_rows.append(
            {
                "sourceId": suite_id,
                "source": project,
                "resultFile": relative_result,
                "sha256": parsed["sha256"],
                "total": parsed["total"],
                "passed": parsed["passed"],
                "failed": parsed["failed"],
                "skipped": parsed["skipped"],
                "summaryOutcome": parsed["summaryOutcome"],
            }
        )

    for candidate in audit["candidates"]:
        for partial in candidate["nearestCases"]:
            suite_id = partial["sourceId"]
            case_id = partial["caseId"]
            suite = parsed_suites[suite_id]
            if case_id not in suite["caseOutcomes"]:
                raise AccountingError(f"Audited nearest case is missing from its TRX: {candidate['invariantId']}/{case_id}")
            source_file = ROOT / partial["testSource"]
            project_dir = (ROOT / suite["project"]).parent.resolve()
            if not source_file.is_file() or not source_file.resolve().is_relative_to(project_dir):
                raise AccountingError(f"Audited nearest-case source is absent or outside its project: {case_id}")

    rows: list[dict[str, Any]] = []
    for (invariant_id, repository, case_id), binding in sorted(registrations.items()):
        if repository != DESKTOP_REPOSITORY:
            continue
        source_id = binding["sourceId"]
        if source_id not in parsed_suites:
            raise AccountingError(f"DesktopPlatform case has no declared TRX source: {invariant_id}/{case_id}")
        suite = parsed_suites[source_id]
        if binding["testSource"] != suite["project"] and not binding["testSource"].endswith(".cs"):
            raise AccountingError(f"Registered testSource does not identify a test source file: {case_id}")
        source_file = ROOT / binding["testSource"]
        project_dir = (ROOT / suite["project"]).parent.resolve()
        if not source_file.is_file() or not source_file.resolve().is_relative_to(project_dir):
            raise AccountingError(f"Registered testSource is absent or outside its declared test project: {case_id}")
        outcomes = suite["caseOutcomes"].get(case_id)
        if not outcomes:
            raise AccountingError(f"Registered case is missing from its declared TRX: {invariant_id}/{case_id}")
        unknown = [outcome for outcome in outcomes if outcome not in {PASS, FAIL}]
        if unknown:
            raise AccountingError(f"Registered case was skipped/inconclusive: {invariant_id}/{case_id}: {unknown}")
        rows.append(
            {
                "invariantId": invariant_id,
                "caseId": case_id,
                "sourceId": source_id,
                "outcome": "failed" if FAIL in outcomes else "passed",
                "repository": DESKTOP_REPOSITORY,
                "sourceCommit": source_commit,
                "ciRun": ci_run,
                "attempt": attempt,
            }
        )

    receipt = {
        "schemaVersion": 1,
        "repository": DESKTOP_REPOSITORY,
        "sourceCommit": source_commit,
        "ciRun": ci_run,
        "attempt": attempt,
        "sources": source_rows,
        "results": rows,
    }
    return _validate_owner_receipt(receipt, all_ids, "DesktopPlatform normalized results")


def _load_audit(path: Path, catalog_bytes: bytes, records: list[dict[str, Any]]) -> tuple[dict[str, Any], bytes]:
    audit, data = _load_json(path)
    if set(audit) != AUDIT_FIELDS or type(audit.get("schemaVersion")) is not int or audit["schemaVersion"] != 1:
        raise AccountingError("Registration audit has an unsupported schema")
    if audit.get("catalogSha256") != _sha256(catalog_bytes):
        raise AccountingError("Registration audit is not bound to the current invariant export")
    _validate_commit(audit.get("reviewedAtSourceCommit"))
    if audit.get("semanticOwner") != DESKTOP_REPOSITORY or audit.get("obligationOwner") != "GOV.04":
        raise AccountingError("Registration audit has the wrong semantic or obligation owner")
    if audit.get("candidatePackageId") != "05":
        raise AccountingError("Registration audit must use the exact package-05 candidate filter")
    expected_filter = "invariants.json record owningPackages includes exact string 05; candidate generation only, not evidence of enforcement"
    if audit.get("candidateFilter") != expected_filter or not isinstance(audit.get("reviewMethod"), str) or not audit["reviewMethod"].strip():
        raise AccountingError("Registration audit candidate methodology is missing or changed")
    if audit.get("reviewedSuiteIds") != [suite_id for suite_id, _ in TRX_SUITES]:
        raise AccountingError("Registration audit must cover exactly the seven normalized owner suites")
    candidates = []
    for record in records:
        owning_packages = record.get("owningPackages")
        if not isinstance(owning_packages, list) or any(not isinstance(package, str) for package in owning_packages):
            raise AccountingError(f"Invariant has malformed owningPackages: {record['id']}")
        if "05" in owning_packages:
            candidates.append(record)
    expected_ids = sorted(record["id"] for record in candidates)
    audited = audit.get("candidates")
    if (
        not isinstance(audited, list)
        or len(audited) != len(expected_ids)
        or any(not isinstance(row, dict) for row in audited)
        or [row.get("invariantId") for row in audited] != expected_ids
    ):
        raise AccountingError("Registration audit does not cover the exact package-05 candidate set")
    for record, row in zip(sorted(candidates, key=lambda value: value["id"]), audited, strict=True):
        if not isinstance(row, dict) or set(row) != {"invariantId", "plannedVerificationSha256", "completionGateSha256", "disposition", "nearestCases"}:
            raise AccountingError(f"Malformed candidate audit for {record['id']}")
        planned = record.get("plannedVerification")
        completion = record.get("completionGate")
        if not isinstance(planned, str) or not planned.strip() or not isinstance(completion, str) or not completion.strip():
            raise AccountingError(f"Candidate lacks a full verification/completion obligation: {record['id']}")
        if row["plannedVerificationSha256"] != _sha256(planned.encode("utf-8")):
            raise AccountingError(f"Candidate audit plannedVerification drift: {record['id']}")
        if row["completionGateSha256"] != _sha256(completion.encode("utf-8")):
            raise AccountingError(f"Candidate audit completionGate drift: {record['id']}")
        if row["disposition"] != "no-complete-current-case" or not isinstance(row["nearestCases"], list):
            raise AccountingError(f"Candidate audit disposition is not explicit for {record['id']}")
        seen_nearest: set[tuple[str, str]] = set()
        for partial in row["nearestCases"]:
            if not isinstance(partial, dict) or set(partial) != {"sourceId", "caseId", "testSource", "whyInsufficient"}:
                raise AccountingError(f"Malformed nearest-case audit for {record['id']}")
            if partial["sourceId"] not in {suite_id for suite_id, _ in TRX_SUITES} or not CASE_ID.fullmatch(partial["caseId"]):
                raise AccountingError(f"Unknown nearest-case identity for {record['id']}")
            _safe_relative_path(partial["testSource"], "nearestCase.testSource")
            if not isinstance(partial["whyInsufficient"], str) or not partial["whyInsufficient"].strip():
                raise AccountingError(f"Nearest-case rationale is empty for {record['id']}")
            key = (partial["sourceId"], partial["caseId"])
            if key in seen_nearest:
                raise AccountingError(f"Duplicate nearest-case audit entry for {record['id']}: {key}")
            seen_nearest.add(key)
    return audit, data


def _make_report(
    records: list[dict[str, Any]],
    ids: list[str],
    roster_by_id: dict[str, dict[str, Any]],
    registrations: dict[tuple[str, str, str], dict[str, str]],
    receipts: list[dict[str, Any]],
    current_run: dict[str, Any],
    catalog_sha: str,
    roster_sha: str,
    audit_sha: str,
    audit: dict[str, Any],
    receipt_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    registration_keys = set(registrations)
    outcomes_by_registration: dict[tuple[str, str, str], list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    source_identity_keys: set[tuple[str, str, str, str, str]] = set()
    for receipt in receipts:
        for source in receipt["sources"]:
            key = (receipt["repository"], receipt["sourceCommit"], receipt["ciRun"], str(receipt["attempt"]), source["sourceId"])
            if key in source_identity_keys:
                raise AccountingError(f"Duplicate owner result source/run/attempt: {key}")
            source_identity_keys.add(key)
        for result in receipt["results"]:
            key = (result["invariantId"], result["repository"], result["caseId"])
            if key not in registration_keys:
                raise AccountingError(f"Result is not authorized by the owner registration roster: {key}")
            outcomes_by_registration[key].append((result, receipt))

    if len(ids) != len(set(ids)) or set(ids) != set(roster_by_id):
        raise AccountingError("Cannot report against an incomplete catalog/roster scan")
    output_rows = []
    counts = Counter()
    for record in records:
        invariant_id = record["id"]
        expected = roster_by_id[invariant_id]["expectedCases"]
        evidence = []
        for binding in expected:
            key = (invariant_id, binding["repository"], binding["caseId"])
            matches = outcomes_by_registration.get(key, [])
            if len(matches) != 1:
                raise AccountingError(f"Expected exactly one accepted result for registered case {key}, found {len(matches)}")
            result, receipt = matches[0]
            if result["sourceId"] != binding["sourceId"] or binding["sourceId"] not in {source["sourceId"] for source in receipt["sources"]}:
                raise AccountingError(f"Registered case result came from the wrong test source: {key}")
            evidence.append(result)
        if expected:
            classification = "enforced-and-failing" if any(row["outcome"] == "failed" for row in evidence) else "enforced-and-passing"
        else:
            classification = "not-yet-implemented"
        counts[classification] += 1
        output_rows.append(
            {
                "invariantId": invariant_id,
                "catalogStatus": record.get("status"),
                "classification": classification,
                "registeredCases": [binding["caseId"] for binding in expected],
                "evidence": evidence,
            }
        )

    expected_sum = len(records)
    if len(output_rows) != expected_sum or sum(counts.values()) != expected_sum:
        raise AccountingError("Generated accounting report is not one row per current catalog ID")
    return {
        "schemaVersion": 1,
        "catalog": {"source": CATALOG_REL, "sha256": catalog_sha, "recordCount": len(records), "idSetSha256": _ids_hash(ids)},
        "registrationRoster": {
            "source": ROSTER_REL,
            "sha256": roster_sha,
            "recordCount": len(roster_by_id),
            "registeredCaseCount": len(registrations),
        },
        "registrationAudit": {
            "source": AUDIT_REL,
            "sha256": audit_sha,
            "candidatePackageId": "05",
            "candidateCount": len(audit["candidates"]),
            "baselineReviewedAtSourceCommit": audit["reviewedAtSourceCommit"],
        },
        "currentRun": current_run,
        "ownerResultReceipts": receipt_evidence,
        "registrationScan": {
            "complete": True,
            "catalogIdCount": len(ids),
            "rosterIdCount": len(roster_by_id),
            "registeredCaseCount": len(registrations),
            "acceptedOwnerReceiptCount": len(receipts),
            "acceptedResultCount": sum(len(receipt["results"]) for receipt in receipts),
            "unregisteredInvariantCount": sum(not roster_by_id[invariant_id]["expectedCases"] for invariant_id in ids),
        },
        "summary": {
            "total": expected_sum,
            "enforced-and-passing": counts["enforced-and-passing"],
            "enforced-and-failing": counts["enforced-and-failing"],
            "not-yet-implemented": counts["not-yet-implemented"],
        },
        "invariants": output_rows,
    }


def generate_report(
    catalog_path: Path,
    roster_path: Path,
    audit_path: Path,
    trx_dir: Path,
    owner_results: list[Path],
    owner_results_output: Path,
    report_output: Path,
    source_commit: str,
    ci_run: str,
    attempt: int,
    verify_checkout: bool = True,
) -> dict[str, Any]:
    source_commit = _validate_commit(source_commit)
    ci_run = _validate_run(ci_run)
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise AccountingError("attempt must be a positive integer")
    if verify_checkout:
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        if actual != source_commit:
            raise AccountingError(f"CI sourceCommit {source_commit} does not match checked out HEAD {actual}")

    catalog, catalog_bytes, records, ids = _load_catalog(catalog_path)
    roster, roster_bytes, roster_by_id, registrations = _load_roster(roster_path, catalog_bytes, records, ids)
    audit, audit_bytes = _load_audit(audit_path, catalog_bytes, records)
    known_ids = set(ids)
    desktop_receipt = _normalize_desktop(trx_dir, registrations, known_ids, audit, source_commit, ci_run, attempt)
    desktop_bytes = _write_json(owner_results_output, desktop_receipt)
    receipts = [desktop_receipt]
    receipt_evidence = [
        {
            "path": owner_results_output.resolve().relative_to(ROOT.resolve()).as_posix(),
            "sha256": _sha256(desktop_bytes),
            "repository": desktop_receipt["repository"],
            "sourceCommit": desktop_receipt["sourceCommit"],
            "ciRun": desktop_receipt["ciRun"],
            "attempt": desktop_receipt["attempt"],
        }
    ]
    for path in owner_results:
        external, external_bytes = _load_json(path)
        accepted = _validate_owner_receipt(external, known_ids, str(path))
        receipts.append(accepted)
        try:
            receipt_path = path.resolve().relative_to(ROOT.resolve()).as_posix()
        except ValueError as error:
            raise AccountingError(f"Owner receipt must be inside the checked-out repository: {path}") from error
        receipt_evidence.append(
            {
                "path": receipt_path,
                "sha256": _sha256(external_bytes),
                "repository": accepted["repository"],
                "sourceCommit": accepted["sourceCommit"],
                "ciRun": accepted["ciRun"],
                "attempt": accepted["attempt"],
            }
        )

    report = _make_report(
        records,
        ids,
        roster_by_id,
        registrations,
        receipts,
        {"repository": DESKTOP_REPOSITORY, "sourceCommit": source_commit, "ciRun": ci_run, "attempt": attempt},
        _sha256(catalog_bytes),
        _sha256(roster_bytes),
        _sha256(audit_bytes),
        audit,
        receipt_evidence,
    )
    _write_json(report_output, report)
    return report


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a fail-closed current-invariant accounting report from test receipts.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    report_parser = subparsers.add_parser("report", help="validate the seven DesktopPlatform TRX inputs and emit normalized receipt/report artifacts")
    report_parser.add_argument("--catalog", type=Path, default=ROOT / CATALOG_REL)
    report_parser.add_argument("--roster", type=Path, default=ROOT / ROSTER_REL)
    report_parser.add_argument("--audit", type=Path, default=ROOT / AUDIT_REL)
    report_parser.add_argument("--trx-dir", type=Path, default=ROOT / "artifacts/evidence/test-results")
    report_parser.add_argument("--owner-result", type=Path, action="append", default=[], help="accepted normalized receipt from another owner; repeat as needed")
    report_parser.add_argument("--owner-results-output", type=Path, default=ROOT / "artifacts/evidence/test-results/desktopplatform-owner-results.json")
    report_parser.add_argument("--report-output", type=Path, default=ROOT / "artifacts/evidence/invariant-accounting.json")
    report_parser.add_argument("--source-commit", default=os.environ.get("GITHUB_SHA"))
    report_parser.add_argument("--ci-run", default=os.environ.get("GITHUB_RUN_ID"))
    report_parser.add_argument("--attempt", type=int, default=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")))
    args = parser.parse_args(argv)
    if args.command == "report":
        try:
            report = generate_report(
                args.catalog,
                args.roster,
                args.audit,
                args.trx_dir,
                args.owner_result,
                args.owner_results_output,
                args.report_output,
                args.source_commit,
                args.ci_run,
                args.attempt,
            )
        except (AccountingError, OSError, subprocess.SubprocessError) as error:
            print(f"invariant accounting failed closed: {error}", file=sys.stderr)
            return 2
        print(json.dumps(report["summary"], sort_keys=True))
        return 0
    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(_main())
