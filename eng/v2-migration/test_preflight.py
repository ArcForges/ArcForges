# SPDX-License-Identifier: AGPL-3.0-only
"""Actual SQLite and native file-lock tests; all writes belong to temporary fixtures."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("node_preflight", Path(__file__).with_name("preflight.py"))
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def fixture(path, journal=False):
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.create_function("arcforges_store_reader_version", 0, lambda: 20)
        for step in preflight.migration_sources():
            connection.executescript((preflight.SCHEMA / step["file"]).read_text(encoding="utf-8"))
            if journal and step["version"] == 7:
                # A retained UNKNOWN metadata record from schema7, carried through the actual
                # 8..15 migrations. This claims no native target validation or file effect.
                connection.execute("INSERT INTO workspace(workspace_id,kind,state,name,root_path,created_at,last_used_at,rev) VALUES(?,1,1,'fixture','fixture',1,1,0)", (b"w" * 16,))
                connection.execute("INSERT INTO command_dedup VALUES(?,'fixture',?,1,NULL,1,2)", (b"c" * 16, b"d" * 32))
                connection.execute("""INSERT INTO file_operation_journal(command_id,kind,phase,request_sha256,caller,
                    correlation_id,workspace_id,relative_path,identity_platform,root_identity,parent_identity,
                    expected_absent,created_at,updated_at,held,acknowledged)
                    VALUES(?,3,3,?,?,?,?,'fixture',1,?,?,1,1,1,1,0)""",
                    (b"c" * 16, b"d" * 32, b"fixture", b"i" * 16, b"w" * 16, b"r" * 33, b"p" * 33))
                connection.commit()
        connection.execute("INSERT INTO store_meta VALUES(1,15,15,?,1,1,'fixture',1,1)", (b"n" * 16,))
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
            connection.create_function("arcforges_store_reader_version", 0, lambda: 16)
            connection.execute("UPDATE store_meta SET schema_version=16,min_reader_version=16")
            connection.commit()
        result = preflight.inventory(self.database)
        self.assertEqual("newer", result["database"]["classification"])
        self.assertEqual({}, result["counts"])

    def test_schema_drift_is_not_hidden_by_version15(self):
        fixture(self.database)
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            connection.execute("CREATE TABLE unexpected(value TEXT)")
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
        fixture(replacement)
        with contextlib.closing(sqlite3.connect(replacement)) as connection:
            connection.create_function("arcforges_store_reader_version", 0, lambda: 16)
            connection.execute("UPDATE store_meta SET schema_version=16,min_reader_version=16")
            connection.commit()
        with self.assertRaisesRegex(preflight.InspectionRefused, "snapshot_path_identity_changed"):
            with preflight.offline_database(self.database) as connection:
                self.database.rename(self.root / "original.db")
                replacement.rename(self.database)
                # Reads remain bound to the protected old inode, never the new version16 path.
                self.assertEqual(15, connection.execute("SELECT schema_version FROM store_meta").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
