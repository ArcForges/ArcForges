# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for fail-closed invariant accounting and normalized TRX receipts."""

from __future__ import annotations

import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import accounting


class AccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog, cls.catalog_bytes, cls.records, cls.ids = accounting._load_catalog(
            accounting.ROOT / accounting.CATALOG_REL
        )
        cls.roster, cls.roster_bytes, cls.roster_by_id, cls.registrations = accounting._load_roster(
            accounting.ROOT / accounting.ROSTER_REL,
            cls.catalog_bytes,
            cls.records,
            cls.ids,
        )
        cls.audit, cls.audit_bytes = accounting._load_audit(
            accounting.ROOT / accounting.AUDIT_REL,
            cls.catalog_bytes,
            cls.records,
        )
        cls.nearest = {
            (row["sourceId"], row["caseId"]): row
            for candidate in cls.audit["candidates"]
            for row in candidate["nearestCases"]
        }

    def _trx_dir(self, outcomes: dict[tuple[str, str], str] | None = None) -> Path:
        outcomes = outcomes or {}
        parent = accounting.ROOT / "artifacts/evidence/test-results"
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="accounting-test-", dir=parent)
        self.addCleanup(temporary.cleanup)
        trx_dir = Path(temporary.name)

        cases_by_suite: dict[str, set[str]] = {suite_id: set() for suite_id, _ in accounting.TRX_SUITES}
        for source_id, case_id in self.nearest:
            cases_by_suite[source_id].add(case_id)

        for suite_id, _project in accounting.TRX_SUITES:
            cases = sorted(cases_by_suite[suite_id]) or ["ArcForges.Accounting.Tests.SyntheticCase.Completes"]
            results = ET.Element("Results")
            definitions = ET.Element("TestDefinitions")
            counts: dict[str, int] = {"Passed": 0, "Failed": 0, "NotExecuted": 0}
            for index, case_id in enumerate(cases, start=1):
                test_id = f"test-{index}"
                class_name, _, method_name = case_id.rpartition(".")
                definition = ET.SubElement(definitions, "UnitTest", {"id": test_id})
                ET.SubElement(definition, "TestMethod", {"className": class_name, "name": method_name})
                outcome = outcomes.get((suite_id, case_id), "Passed")
                counts[outcome] = counts.get(outcome, 0) + 1
                ET.SubElement(results, "UnitTestResult", {"testId": test_id, "outcome": outcome})

            total = len(cases)
            failed = counts["Failed"]
            executed = counts["Passed"] + failed
            root = ET.Element("TestRun", {"id": f"run-{suite_id}"})
            root.append(results)
            root.append(definitions)
            summary = ET.SubElement(root, "ResultSummary", {"outcome": "Failed" if failed else "Completed"})
            ET.SubElement(
                summary,
                "Counters",
                {
                    "total": str(total),
                    "executed": str(executed),
                    "passed": str(counts["Passed"]),
                    "failed": str(failed),
                },
            )
            (trx_dir / f"{suite_id}.trx").write_bytes(ET.tostring(root, encoding="utf-8", xml_declaration=True))
        return trx_dir

    def _registration_for(self, case_id: str) -> dict[tuple[str, str, str], dict[str, str]]:
        audited = self.nearest[("architecture-tests", case_id)]
        return {
            (
                "I-001",
                accounting.DESKTOP_REPOSITORY,
                case_id,
            ): {
                "caseId": case_id,
                "repository": accounting.DESKTOP_REPOSITORY,
                "sourceId": "architecture-tests",
                "testSource": audited["testSource"],
                "plannedVerificationRationale": "Unit fixture only: exercise outcome normalization without changing the checked-in roster.",
            }
        }

    def test_current_roster_is_complete_and_truthfully_nyi(self) -> None:
        self.assertEqual(406, len(self.ids))
        self.assertEqual(406, len(self.roster_by_id))
        self.assertEqual(0, len(self.registrations))
        self.assertEqual(44, len(self.audit["candidates"]))
        trx_dir = self._trx_dir()
        output_dir = trx_dir
        report = accounting.generate_report(
            accounting.ROOT / accounting.CATALOG_REL,
            accounting.ROOT / accounting.ROSTER_REL,
            accounting.ROOT / accounting.AUDIT_REL,
            trx_dir,
            [],
            output_dir / "owner-results.json",
            output_dir / "report.json",
            "784f238c4c01590e8de6fe5e1472ed79b70ac222",
            "12345",
            1,
            verify_checkout=False,
        )
        self.assertEqual(
            {"total": 406, "enforced-and-passing": 0, "enforced-and-failing": 0, "not-yet-implemented": 406},
            report["summary"],
        )
        self.assertEqual(406, len(report["invariants"]))
        self.assertTrue(report["registrationScan"]["complete"])
        self.assertEqual(0, report["registrationScan"]["registeredCaseCount"])

    def test_all_six_mtp_suites_parse_and_report_skips(self) -> None:
        trx_dir = self._trx_dir()
        parsed = [
            accounting._parse_trx(trx_dir / f"{suite_id}.trx", suite_id, project)
            for suite_id, project in accounting.TRX_SUITES
        ]
        self.assertEqual(6, len(parsed))
        self.assertTrue(all(item["summaryOutcome"] == "completed" for item in parsed))

    def test_trx_rejects_duplicate_results_for_one_test_id(self) -> None:
        trx_dir = self._trx_dir()
        path = trx_dir / "architecture-tests.trx"
        root = ET.parse(path).getroot()
        results = next(node for node in root if node.tag == "Results")
        first_result = next(node for node in results if node.tag == "UnitTestResult")
        duplicate = ET.Element(first_result.tag, first_result.attrib)
        results.append(duplicate)

        counters = next(node for node in next(node for node in root if node.tag == "ResultSummary") if node.tag == "Counters")
        counters.set("total", str(int(counters.attrib["total"]) + 1))
        if first_result.attrib["outcome"] == "Passed":
            counters.set("passed", str(int(counters.attrib["passed"]) + 1))
            counters.set("executed", str(int(counters.attrib["executed"]) + 1))
        elif first_result.attrib["outcome"] == "Failed":
            counters.set("failed", str(int(counters.attrib["failed"]) + 1))
            counters.set("executed", str(int(counters.attrib["executed"]) + 1))
        path.write_bytes(ET.tostring(root, encoding="utf-8", xml_declaration=True))

        with self.assertRaisesRegex(accounting.AccountingError, "result/definition mapping is not one-to-one"):
            accounting._parse_trx(
                path,
                "architecture-tests",
                dict(accounting.TRX_SUITES)["architecture-tests"],
            )

    def test_report_rejects_missing_and_unexpected_trx_inputs(self) -> None:
        trx_dir = self._trx_dir()
        (trx_dir / "security-tests.trx").unlink()
        with self.assertRaisesRegex(accounting.AccountingError, "exactly six unique TRX"):
            accounting._normalize_desktop(trx_dir, {}, set(self.ids), self.audit, "784f238c4c01590e8de6fe5e1472ed79b70ac222", "12345", 1)

        trx_dir = self._trx_dir()
        (trx_dir / "unexpected.trx").write_text("<TestRun id='extra'/>", encoding="utf-8")
        with self.assertRaisesRegex(accounting.AccountingError, "exactly six unique TRX"):
            accounting._normalize_desktop(trx_dir, {}, set(self.ids), self.audit, "784f238c4c01590e8de6fe5e1472ed79b70ac222", "12345", 1)

    def test_registered_case_must_have_exactly_one_executed_result(self) -> None:
        case_id = "ArcForges.Tests.ArchitectureTests.SharedPolicyTests.BannedCategoriesUseCompiledSymbols"
        registration = self._registration_for(case_id)
        trx_dir = self._trx_dir()
        receipt = accounting._normalize_desktop(
            trx_dir,
            registration,
            set(self.ids),
            self.audit,
            "784f238c4c01590e8de6fe5e1472ed79b70ac222",
            "12345",
            1,
        )
        self.assertEqual("passed", receipt["results"][0]["outcome"])

        failed = self._trx_dir({("architecture-tests", case_id): "Failed"})
        failed_receipt = accounting._normalize_desktop(
            failed,
            registration,
            set(self.ids),
            self.audit,
            "784f238c4c01590e8de6fe5e1472ed79b70ac222",
            "12345",
            1,
        )
        self.assertEqual("failed", failed_receipt["results"][0]["outcome"])

        skipped = self._trx_dir({("architecture-tests", case_id): "NotExecuted"})
        with self.assertRaisesRegex(accounting.AccountingError, "skipped/inconclusive"):
            accounting._normalize_desktop(
                skipped,
                registration,
                set(self.ids),
                self.audit,
                "784f238c4c01590e8de6fe5e1472ed79b70ac222",
                "12345",
                1,
            )

    def test_registered_case_missing_from_trx_fails_closed(self) -> None:
        case_id = "ArcForges.Tests.ArchitectureTests.SharedPolicyTests.BannedCategoriesUseCompiledSymbols"
        trx_dir = self._trx_dir()
        path = trx_dir / "architecture-tests.trx"
        root = ET.parse(path).getroot()
        definitions = next(node for node in root if node.tag == "TestDefinitions")
        missing_test_id = next(
            definition.attrib["id"]
            for definition in definitions
            if next(child for child in definition if child.tag == "TestMethod").attrib["className"]
            + "."
            + next(child for child in definition if child.tag == "TestMethod").attrib["name"]
            == case_id
        )
        ET.SubElement(definitions, "UnitTest", {"id": "preserved-filler"})
        filler_definition = definitions[-1]
        ET.SubElement(
            filler_definition,
            "TestMethod",
            {"className": "ArcForges.Accounting.Tests.SyntheticCase", "name": "Preserved"},
        )
        results = next(node for node in root if node.tag == "Results")
        ET.SubElement(results, "UnitTestResult", {"testId": "preserved-filler", "outcome": "Passed"})
        for container_name in ("Results", "TestDefinitions"):
            container = next(node for node in root if node.tag == container_name)
            for child in list(container):
                if child.attrib.get("testId", child.attrib.get("id")) == missing_test_id:
                    container.remove(child)
        summary = next(node for node in root if node.tag == "ResultSummary")
        counters = next(node for node in summary if node.tag == "Counters")
        path.write_bytes(ET.tostring(root, encoding="utf-8", xml_declaration=True))
        audit_without_case = json.loads(json.dumps(self.audit))
        for candidate in audit_without_case["candidates"]:
            candidate["nearestCases"] = [
                row
                for row in candidate["nearestCases"]
                if not (row["sourceId"] == "architecture-tests" and row["caseId"] == case_id)
            ]
        with self.assertRaisesRegex(accounting.AccountingError, "Registered case is missing from its declared TRX"):
            accounting._normalize_desktop(
                trx_dir,
                self._registration_for(case_id),
                set(self.ids),
                audit_without_case,
                "784f238c4c01590e8de6fe5e1472ed79b70ac222",
                "12345",
                1,
            )

    def test_owner_receipt_rejects_unknown_case_and_nonexecuted_outcome(self) -> None:
        case_id = "ArcForges.Tests.ArchitectureTests.SharedPolicyTests.BannedCategoriesUseCompiledSymbols"
        receipt = {
            "schemaVersion": 1,
            "repository": accounting.DESKTOP_REPOSITORY,
            "sourceCommit": "784f238c4c01590e8de6fe5e1472ed79b70ac222",
            "ciRun": "12345",
            "attempt": 1,
            "sources": [
                {
                    "sourceId": "architecture-tests",
                    "source": "tests/ArchitectureTests/ArcForges.Tests.ArchitectureTests.csproj",
                    "resultFile": "artifacts/evidence/test-results/architecture-tests.trx",
                    "sha256": "0" * 64,
                    "total": 1,
                    "passed": 1,
                    "failed": 0,
                    "skipped": 0,
                    "summaryOutcome": "completed",
                }
            ],
            "results": [
                {
                    "invariantId": "I-001",
                    "caseId": case_id,
                    "sourceId": "architecture-tests",
                    "outcome": "passed",
                    "repository": accounting.DESKTOP_REPOSITORY,
                    "sourceCommit": "784f238c4c01590e8de6fe5e1472ed79b70ac222",
                    "ciRun": "12345",
                    "attempt": 1,
                }
            ],
        }
        normalized = accounting._validate_owner_receipt(receipt, set(self.ids), "fixture")
        self.assertEqual(case_id, normalized["results"][0]["caseId"])

        wrong_source = json.loads(json.dumps(receipt))
        wrong_source["results"][0]["sourceId"] = "unknown-suite"
        with self.assertRaisesRegex(accounting.AccountingError, "unknown source ID"):
            accounting._validate_owner_receipt(wrong_source, set(self.ids), "fixture")

        wrong_commit = json.loads(json.dumps(receipt))
        wrong_commit["results"][0]["sourceCommit"] = "1" * 40
        with self.assertRaisesRegex(accounting.AccountingError, "disagrees with receipt"):
            accounting._validate_owner_receipt(wrong_commit, set(self.ids), "fixture")

        receipt["results"][0]["outcome"] = "skipped"
        with self.assertRaisesRegex(accounting.AccountingError, "skipped or inconclusive"):
            accounting._validate_owner_receipt(receipt, set(self.ids), "fixture")

        unknown = json.loads(json.dumps(normalized))
        unknown["results"][0]["caseId"] = "ArcForges.Unknown.Tests.FakeCase.DoesNotExist"
        with self.assertRaisesRegex(accounting.AccountingError, "not authorized by the owner registration"):
            accounting._make_report(
                self.records,
                self.ids,
                self.roster_by_id,
                self.registrations,
                [unknown],
                {"repository": accounting.DESKTOP_REPOSITORY, "sourceCommit": receipt["sourceCommit"], "ciRun": "12345", "attempt": 1},
                accounting._sha256(self.catalog_bytes),
                accounting._sha256(self.roster_bytes),
                accounting._sha256(self.audit_bytes),
                self.audit,
                [],
            )

    def test_duplicate_definition_ids_are_rejected(self) -> None:
        trx_dir = self._trx_dir()
        path = trx_dir / "architecture-tests.trx"
        root = ET.parse(path).getroot()
        definitions = next(node for node in root if node.tag == "TestDefinitions")
        duplicate = json.loads(json.dumps({"id": definitions[0].attrib["id"]}))
        duplicate_definition = ET.SubElement(definitions, "UnitTest", duplicate)
        ET.SubElement(
            duplicate_definition,
            "TestMethod",
            {"className": "ArcForges.Accounting.Tests.SyntheticCase", "name": "Duplicate"},
        )
        path.write_bytes(ET.tostring(root, encoding="utf-8", xml_declaration=True))
        with self.assertRaisesRegex(accounting.AccountingError, "duplicate test definition"):
            accounting._parse_trx(path, "architecture-tests", accounting.TRX_SUITES[0][1])

    def test_duplicate_roster_invariant_is_rejected(self) -> None:
        mutated = json.loads(json.dumps(self.roster))
        mutated["records"].append(json.loads(json.dumps(mutated["records"][0])))
        parent = accounting.ROOT / "artifacts/evidence/test-results"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="accounting-roster-", dir=parent) as temporary:
            path = Path(temporary) / "roster.json"
            path.write_text(json.dumps(mutated), encoding="utf-8")
            with self.assertRaisesRegex(accounting.AccountingError, "Duplicate invariant ID in roster"):
                accounting._load_roster(path, self.catalog_bytes, self.records, self.ids)

    def test_duplicate_json_fields_and_nonstandard_constants_are_rejected(self) -> None:
        parent = accounting.ROOT / "artifacts/evidence/test-results"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="accounting-json-", dir=parent) as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schemaVersion": 1, "schemaVersion": 1}', encoding="utf-8")
            with self.assertRaisesRegex(accounting.AccountingError, "Duplicate JSON field"):
                accounting._load_json(path)
            path.write_text('{"value": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(accounting.AccountingError, "Non-standard JSON constant"):
                accounting._load_json(path)


if __name__ == "__main__":
    unittest.main()
