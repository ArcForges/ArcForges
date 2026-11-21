# SPDX-License-Identifier: AGPL-3.0-only
"""Actual SQLite and native file-lock tests; all writes belong to temporary fixtures."""

import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("node_preflight", Path(__file__).with_name("preflight.py"))
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def record_expansion(connection, step, source, unresolved):
    cohort = "private-fixture-cohort"
    backup = "a" * 64 if source else "fresh:no-predecessor"
    intent = f"AFV2-DATA-01|{source}|16|{step['sha256']}|{backup}|{unresolved}|{cohort}"
    receipt = hashlib.sha256(intent.encode("utf-8")).hexdigest()
    connection.execute("""INSERT INTO schema_version
        SELECT 1,schema_version,min_reader_version,?,? FROM store_meta WHERE singleton=1""", (cohort, receipt))
    connection.execute("""INSERT INTO migration_checkpoint
        VALUES('AFV2-DATA-01/schema16',?,16,?,'EXPANDED_LEGACY_RECONCILIATION_PRESERVED',?,?,?,'2026-01-01T00:00:00Z')""",
        (source, backup, cohort, unresolved, receipt))


def fixture(path, journal=False, version=15, fresh=False):
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.create_function("arcforges_store_reader_version", 0, lambda: version)
        steps = preflight.migration_sources()[:version]
        for step in steps:
            connection.executescript(step["sql"])
            if journal and step["version"] == 7:
                # A retained UNKNOWN metadata record from schema7, carried through the actual
                # later migrations. This claims no native target validation or file effect.
                connection.execute("INSERT INTO workspace(workspace_id,kind,state,name,root_path,created_at,last_used_at,rev) VALUES(?,1,1,'fixture','fixture',1,1,0)", (b"w" * 16,))
                connection.execute("INSERT INTO command_dedup VALUES(?,'fixture',?,1,NULL,1,2)", (b"c" * 16, b"d" * 32))
                connection.execute("""INSERT INTO file_operation_journal(command_id,kind,phase,request_sha256,caller,
                    correlation_id,workspace_id,relative_path,identity_platform,root_identity,parent_identity,
                    expected_absent,created_at,updated_at,held,acknowledged)
                    VALUES(?,3,3,?,?,?,?,'fixture',1,?,?,1,1,1,1,0)""",
                    (b"c" * 16, b"d" * 32, b"fixture", b"i" * 16, b"w" * 16, b"r" * 33, b"p" * 33))
                connection.commit()
            elif not fresh and step["version"] == 15:
                connection.execute("INSERT INTO store_meta VALUES(1,15,15,?,1,1,'fixture',1,1)", (b"n" * 16,))
            elif not fresh and step["version"] > 15:
                connection.execute("UPDATE store_meta SET schema_version=?,min_reader_version=?",
                                   (step["version"], step["minReaderVersion"]))
                if step["version"] == 16:
                    record_expansion(connection, step, source=15, unresolved=int(journal))
        if fresh:
            connection.execute("INSERT INTO store_meta VALUES(1,?,?,?,1,1,'fixture',1,1)", (version, version, b"n" * 16))
            record_expansion(connection, steps[15], source=0, unresolved=0)
        connection.commit()


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="afv2-node-preflight-")
        self.root = Path(self.temporary.name)
        self.database = self.root / "node.db"

    def tearDown(self):
        self.temporary.cleanup()

    def test_missing_store_is_fresh_without_creating_any_file(self):
        result = preflight.inventory(self.database)
        self.assertEqual("fresh", result["database"]["classification"])
        self.assertEqual([], list(self.root.iterdir()))
        self.assertFalse(result["destructive_contraction_allowed"])

    def test_real_schema15_snapshot_is_unchanged_and_cohort_stays_unknown(self):
        fixture(self.database)
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        result = preflight.inventory(self.database)
        self.assertEqual("node15", result["database"]["classification"])
        self.assertTrue(result["database"]["schema_objects_match"])
        self.assertEqual("not_available_in_node15", result["database"]["applied_migration_checksum_ledger"])
        self.assertEqual(list(range(1, 16)), [step["version"] for step in result["source"]["migrations"]])
        self.assertTrue(all(value == 0 for value in result["counts"].values()))
        self.assertIn("installed_cohort_unknown", result["blockers"])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_unknown_journal_survives_real_migrations_and_blocks_contraction(self):
        fixture(self.database, journal=True)
        result = preflight.inventory(self.database)
        self.assertEqual("node15", result["database"]["classification"])
        self.assertEqual(1, result["counts"]["unsettled_file_journals"])
        self.assertIn("unsettled_commands", result["blockers"])
        self.assertIn("unsettled_file_journals", result["blockers"])

    def test_newer_store_is_not_opened_as_supported(self):
        fixture(self.database)
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            connection.create_function("arcforges_store_reader_version", 0, lambda: 20)
            connection.execute("UPDATE store_meta SET schema_version=20,min_reader_version=20")
            connection.commit()
        result = preflight.inventory(self.database)
        self.assertEqual("newer", result["database"]["classification"])
        self.assertEqual({}, result["counts"])

    def test_expanded_prefixes_keep_legacy_reconciliation_and_leave_snapshot_unchanged(self):
        for version in range(16, 20):
            with self.subTest(version=version):
                database = self.root / f"upgraded-{version}.db"
                fixture(database, journal=True, version=version)
                before = {p.name: p.read_bytes() for p in self.root.iterdir()}
                result = preflight.inventory(database)
                self.assertEqual("node_v2_expanded", result["database"]["classification"])
                self.assertEqual(version, result["database"]["schema_version"])
                self.assertEqual(min(version, 18), result["database"]["expansion_metadata_schema_version"])
                self.assertEqual("step16_checkpoint_only", result["database"]["applied_migration_checksum_ledger"])
                self.assertEqual(list(range(1, version + 1)), [step["version"] for step in result["source"]["migrations"]])
                self.assertEqual(1, result["counts"]["unsettled_commands"])
                self.assertEqual(1, result["counts"]["unsettled_file_journals"])
                self.assertIn("native_scope_and_exclusive_owner_proof_required", result["blockers"])
                self.assertFalse(result["destructive_contraction_allowed"])
                self.assertNotIn("private-fixture-cohort", json.dumps(result))
                self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_fresh_schema19_store_has_current_expansion_metadata(self):
        fixture(self.database, version=19, fresh=True)
        result = preflight.inventory(self.database)
        self.assertEqual("node_v2_expanded", result["database"]["classification"])
        self.assertEqual(19, result["database"]["expansion_metadata_schema_version"])
        self.assertTrue(result["database"]["expansion_checkpoint_matches"])
        self.assertTrue(all(value == 0 for value in result["counts"].values()))

    def test_post_read_snapshot_identity_failure_discards_inventory(self):
        fixture(self.database, journal=True, version=18)
        binary = self.root / "fixture-node"
        binary.write_bytes(b"test-only binary bytes")
        with self.database.open("rb") as stream:
            before = preflight.stream_identity(stream)
        changed = (*before[:-1], "0" * 64)
        with mock.patch.object(preflight, "stream_identity", side_effect=[before, changed]) as identity:
            result = preflight.inventory(self.database, binary)
        self.assertEqual(2, identity.call_count)
        self.assertEqual({"classification": "unknown", "schema_version": None, "min_reader_version": None},
                         result["database"])
        self.assertEqual({}, result["counts"])
        self.assertEqual(["snapshot_changed_during_inspection"], result["blockers"])
        self.assertFalse(result["destructive_contraction_allowed"])
        self.assertEqual(list(range(1, 20)), [step["version"] for step in result["source"]["migrations"]])
        self.assertEqual({"state": "bytes_observed_provenance_unproven", "binary_sha256": preflight.digest_file(binary)},
                         result["installation"])

    def test_expanded_metadata_cannot_describe_a_legacy_layout(self):
        fixture(self.database)
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            connection.create_function("arcforges_store_reader_version", 0, lambda: 16)
            connection.execute("UPDATE store_meta SET schema_version=16,min_reader_version=16")
            connection.commit()
        result = preflight.inventory(self.database)
        self.assertEqual("unknown", result["database"]["classification"])
        self.assertIn("schema_objects_differ_from_released_node_v2_prefix", result["blockers"])
        self.assertEqual({}, result["counts"])

    def test_inconsistent_or_missing_expansion_checkpoint_is_refused(self):
        for name, statements in {
            "missing": "DELETE FROM migration_checkpoint",
            "mirror": "UPDATE schema_version SET version=17,min_reader=17",
            "mutated": "UPDATE migration_checkpoint SET unresolved_count=13",
        }.items():
            with self.subTest(name=name):
                database = self.root / f"{name}.db"
                fixture(database, version=19)
                with contextlib.closing(sqlite3.connect(database)) as connection:
                    connection.executescript(statements)
                result = preflight.inventory(database)
                self.assertEqual("unknown", result["database"]["classification"])
                self.assertIn("inconsistent_v2_expansion_checkpoint", result["blockers"])
                self.assertEqual({}, result["counts"])

    def test_queued_legacy_task_without_an_attempt_blocks_contraction(self):
        fixture(self.database, version=19)
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            connection.executemany("""INSERT INTO task(task_id,state,kind,title,command_summary,spec,spec_digest,owner,
                owner_origin,pool,priority,effective_priority,side_effect,side_effect_source,command_fingerprint,
                command_digest,created_at,rev)
                VALUES(?,?,1,'fixture','fixture',x'',zeroblob(32),x'00',1,'fixture',1,1,1,1,'fixture',zeroblob(32),1,0)""",
                [(b"q" * 16, 2), (b"s" * 16, 7)])
            connection.commit()
        result = preflight.inventory(self.database)
        self.assertEqual(1, result["counts"]["nonterminal_tasks"])
        self.assertEqual(0, result["counts"]["live_attempt_records"])
        self.assertIn("nonterminal_tasks", result["blockers"])
        self.assertFalse(result["destructive_contraction_allowed"])

    def test_legacy_approval_stage_and_removal_custody_is_counted_without_changing_the_snapshot(self):
        for version, classification in [(15, "node15"), (19, "node_v2_expanded")]:
            with self.subTest(version=version):
                database = self.root / f"custody-{version}.db"
                fixture(database, version=version)
                workspace = b"w" * 16
                active_stage, retained_stage = b"a" * 16, b"r" * 16
                with contextlib.closing(sqlite3.connect(database)) as connection:
                    connection.execute("PRAGMA foreign_keys=ON")
                    connection.execute("""INSERT INTO workspace
                        (workspace_id,kind,state,name,root_path,created_at,last_used_at,rev)
                        VALUES(?,1,1,'fixture','fixture',1,1,0)""", (workspace,))
                    # Pending and approved records do not need an executing or completed command.
                    connection.executemany("""INSERT INTO approval
                        (approval_id,state,operation,summary,details_json,risk,requester,command_id,request,
                         request_digest,created_at,expires_at,rev)
                        VALUES(?,?,'TaskService.RetryTask','fixture','{}',1,x'01',?,x'01',zeroblob(32),0,1,0)""",
                        [(bytes([state]) * 16, state, bytes([state + 8]) * 16) for state in (1, 2, 3, 4, 5)])
                    connection.executemany("""INSERT INTO command_dedup
                        VALUES(?,'arcforges.node.v1.FileService/WriteFile',zeroblob(32),4,NULL,0,1)""",
                        [(active_stage,), (retained_stage,)])
                    connection.executemany("""INSERT INTO file_private_stage_reservation
                        (command_id,workspace_id,kind,correlation_id,relative_path,expected_absent,
                         request_sha256,caller,reserved_bytes,created_at)
                        VALUES(?,?,1,zeroblob(16),'fixture-private-stage',1,zeroblob(32),x'01',16,0)""",
                        [(active_stage, workspace), (retained_stage, workspace)])
                    # A terminal pre-effect reservation can still hold its named object after releasing its active slot.
                    connection.execute("""INSERT INTO file_private_stage_object
                        (command_id,slot,stage_path,expected_size,expected_sha256,phase,
                         identity_platform,native_identity,parent_identity)
                        VALUES(?,1,'fixture-private-stage',16,zeroblob(32),2,1,zeroblob(33),zeroblob(33))""",
                        (retained_stage,))
                    connection.execute("INSERT INTO file_private_stage_terminal VALUES(?,1,1)", (retained_stage,))
                    connection.execute("UPDATE file_private_stage_reservation SET active=0 WHERE command_id=?", (retained_stage,))
                    connection.execute("UPDATE command_dedup SET outcome=x'01' WHERE command_id=?", (retained_stage,))
                    connection.executemany("""INSERT INTO cleanup_plan
                        (plan_id,state,digest,planned_by,total_bytes,item_count,created_at,expires_at,rev)
                        VALUES(?,?,zeroblob(32),x'01',1,1,0,1,0)""",
                        [(bytes([state + 16]) * 16, state) for state in range(1, 8)] + [(b"g" * 16, 3)])
                    connection.executemany("""INSERT INTO file_removal_plan
                        (plan_id,command_id,request_sha256,caller,target_kind,workspace_id,workspace_path,
                         root_platform,root_identity,requires_approval,quarantine_available)
                        VALUES(?,?,zeroblob(32),x'01',1,?,'fixture',1,zeroblob(33),0,0)""",
                        [(bytes([state + 16]) * 16, bytes([state + 24]) * 16, workspace) for state in range(1, 8)])
                    connection.commit()
                before = {file.name: file.read_bytes() for file in self.root.iterdir()}
                result = preflight.inventory(database)
                self.assertEqual(classification, result["database"]["classification"])
                expected = {
                    "unsettled_commands": 1,
                    "unsettled_approvals": 2,
                    "active_private_stage_reservations": 1,
                    "retained_inactive_private_stage_reservations": 1,
                    "unsettled_removal_plans": 3,
                    "retained_removal_plans": 7,
                }
                self.assertEqual({key: value for key, value in result["counts"].items() if value}, expected)
                self.assertTrue(expected.keys() <= set(result["blockers"]))
                self.assertIn("native_scope_and_exclusive_owner_proof_required", result["blockers"])
                self.assertFalse(result["destructive_contraction_allowed"])
                self.assertNotIn("fixture-private-stage", json.dumps(result))
                self.assertEqual(before, {file.name: file.read_bytes() for file in self.root.iterdir()})

    def test_schema_drift_is_not_hidden_by_version15(self):
        fixture(self.database)
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            connection.execute("CREATE TABLE sqliteUnexpected(value TEXT)")
            connection.commit()
        result = preflight.inventory(self.database)
        self.assertEqual("unknown", result["database"]["classification"])
        self.assertIn("schema_objects_differ_from_released_node15", result["blockers"])
        self.assertEqual({}, result["counts"])

    def test_oversized_snapshot_is_refused_before_reading_contents(self):
        with self.database.open("wb") as stream:
            stream.truncate(preflight.MAX_SNAPSHOT_BYTES + 1)
        result = preflight.inventory(self.database)
        self.assertEqual("unknown", result["database"]["classification"])
        self.assertIn("snapshot_exceeds_512_mib_inspection_bound", result["blockers"])

    def test_corrupt_store_does_not_leak_its_contents(self):
        marker = b"private fixture marker that must not enter JSON"
        self.database.write_bytes(marker)
        result = preflight.inventory(self.database)
        self.assertEqual("unknown", result["database"]["classification"])
        self.assertNotIn(marker.decode(), json.dumps(result))

    def test_wal_and_sidecars_are_refused_without_any_write(self):
        fixture(self.database)
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE active_wal(value)")
            connection.commit()
            before = {p.name: p.read_bytes() for p in self.root.iterdir()}
            result = preflight.inventory(self.database)
            self.assertEqual("unknown", result["database"]["classification"])
            self.assertIn("live_or_uncheckpointed_store_requires_consistent_offline_backup", result["blockers"])
            self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})
        finally:
            connection.close()

    def test_wal_header_without_sidecar_is_not_treated_as_offline_snapshot(self):
        fixture(self.database)
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
        result = preflight.inventory(self.database)
        self.assertEqual("unknown", result["database"]["classification"])
        self.assertIn("wal_mode_requires_consistent_offline_backup", result["blockers"])

    def test_real_other_process_locks_are_refused(self):
        fixture(self.database)
        for kind in ("IMMEDIATE", "EXCLUSIVE"):
            with self.subTest(kind=kind):
                program = "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN '+sys.argv[2]); print('locked',flush=True); sys.stdin.readline(); c.close()"
                process = subprocess.Popen([sys.executable, "-c", program, str(self.database), kind],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
                try:
                    self.assertEqual("locked", process.stdout.readline().strip())
                    result = preflight.inventory(self.database)
                    self.assertIn("inspection_failed_or_locked" if os.name != "nt" else "snapshot_locked_or_unreadable", result["blockers"])
                    self.assertEqual("unknown", result["database"]["classification"])
                finally:
                    process.communicate("release\n", timeout=10)
                    self.assertEqual(0, process.returncode)

    def test_read_protection_blocks_a_real_new_writer(self):
        fixture(self.database)
        with preflight.offline_database(self.database):
            program = "import sqlite3,sys; c=sqlite3.connect(sys.argv[1],timeout=0); c.execute('CREATE TABLE should_not_exist(value)'); c.commit()"
            result = subprocess.run([sys.executable, "-c", program, str(self.database)], capture_output=True)
            self.assertNotEqual(0, result.returncode)
        self.assertEqual("node15", preflight.inventory(self.database)["database"]["classification"])

    @unittest.skipIf(os.name == "nt", "Windows read handle already denies rename/delete sharing")
    def test_rename_replacement_does_not_redirect_the_protected_snapshot(self):
        fixture(self.database)
        replacement = self.root / "replacement.db"
        fixture(replacement, version=16)
        with self.assertRaisesRegex(preflight.InspectionRefused, "snapshot_path_identity_changed"):
            with preflight.offline_database(self.database) as connection:
                self.database.rename(self.root / "original.db")
                replacement.rename(self.database)
                # Reads remain bound to the protected old inode, never the new version16 path.
                self.assertEqual(15, connection.execute("SELECT schema_version FROM store_meta").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
