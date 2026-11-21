# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only V2 migration inventory. This command never admits or performs a migration."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "src/ArcForges.Node.Store/Schema"
LEGACY_VERSION = 15
LATEST_VERSION = 19
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
COUNTS = {
    "unsettled_commands": "SELECT count(*) FROM command_dedup WHERE outcome IS NULL",
    "nonterminal_tasks": "SELECT count(*) FROM task WHERE state IN (1, 2, 3, 4, 5, 6)",
    "live_attempt_records": "SELECT count(*) FROM attempt WHERE state BETWEEN 1 AND 8 OR leftover_count > 0",
    "unsettled_file_journals": "SELECT count(*) FROM file_operation_journal WHERE phase <> 2 OR held = 1",
    "live_file_workers": "SELECT count(*) FROM file_effect_worker WHERE ended = 0",
    "active_stage_production": "SELECT count(*) FROM file_stage_production WHERE active = 1 OR released = 0",
    "live_stage_workers": "SELECT count(*) FROM file_stage_worker WHERE ended = 0",
    "retained_quarantine": "SELECT count(*) FROM quarantine_entry WHERE restored_at IS NULL AND purged_at IS NULL",
    "retained_removal_plans": "SELECT count(*) FROM file_removal_plan",
}
PREREQUISITES = [
    "exclusive offline store/control ownership and native process-scope drain proof",
    "consistent database/owned-path backup with tested restore and cohort manifest",
    "preserve unresolved receipts, journals, quarantine, worker identities and recovery floors",
    "retain applied 0001..0015 SQL and published package bytes",
    "qualify both MXC profiles and new Core before retiring the old executor",
    "review consumer inventory before source/schema contraction",
]


class InspectionRefused(Exception):
    """A fixed diagnostic code, never a database/server exception string."""


@contextlib.contextmanager
def offline_file(path: Path):
    """Hold native read protection without opening a writable handle or creating a lock file."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                      wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        # GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT.
        handle = kernel.CreateFileW(str(path.resolve()), 0x80000000, 1, None, 3, 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise InspectionRefused("snapshot_locked_or_unreadable")
        try:
            with path.open("rb") as stream:
                yield stream
        finally:
            kernel.CloseHandle(handle)
    else:
        import fcntl

        with path.open("rb") as stream:
            # The pending/reserved/shared lock bytes used by rollback-journal writers.
            # WAL mode is refused separately because its writers coordinate through shm.
            fcntl.lockf(stream.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB, 512, 0x40000000, os.SEEK_SET)
            try:
                yield stream
            finally:
                fcntl.lockf(stream.fileno(), fcntl.LOCK_UN, 512, 0x40000000, os.SEEK_SET)


def stream_identity(stream) -> tuple:
    stream.seek(0)
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
    stat = os.fstat(stream.fileno())
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, digest.hexdigest()


@contextlib.contextmanager
def offline_database(path: Path):
    with offline_file(path) as snapshot:
        if os.fstat(snapshot.fileno()).st_size > MAX_SNAPSHOT_BYTES:
            raise InspectionRefused("snapshot_exceeds_512_mib_inspection_bound")
        header = snapshot.read(20)
        if len(header) < 20 or header[:16] != b"SQLite format 3\x00":
            raise InspectionRefused("database_header_invalid")
        if header[18:20] != b"\x01\x01":
            raise InspectionRefused("wal_mode_requires_consistent_offline_backup")
        before = stream_identity(snapshot)
        if before[2] > MAX_SNAPSHOT_BYTES:
            raise InspectionRefused("snapshot_exceeds_512_mib_inspection_bound")
        if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-journal")):
            raise InspectionRefused("live_or_uncheckpointed_store_requires_consistent_offline_backup")
        # Deserialize bytes read from the protected handle, never reopen the path in SQLite.
        # A concurrent rename cannot redirect the inspected database to an unprotected inode.
        snapshot.seek(0)
        content = snapshot.read(MAX_SNAPSHOT_BYTES + 1)
        if len(content) != before[2] or hashlib.sha256(content).hexdigest() != before[4]:
            raise InspectionRefused("snapshot_changed_during_inspection")
        with contextlib.closing(sqlite3.connect(":memory:")) as connection:
            connection.deserialize(content)
            yield connection
            if before != stream_identity(snapshot):
                raise InspectionRefused("snapshot_changed_during_inspection")
            current = path.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) != before[:2] or path.is_symlink():
                raise InspectionRefused("snapshot_path_identity_changed")


def digest_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def source_identity() -> dict:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    return {"repository": "ArcForges", "revision": result.stdout.strip() if result.returncode == 0 else None}


def migration_sources() -> list[dict]:
    steps = json.loads((SCHEMA / "schema-history.json").read_text(encoding="utf-8"))["steps"]
    if [step["version"] for step in steps] != list(range(1, LATEST_VERSION + 1)):
        raise ValueError("source_migration_sequence_invalid")
    for step in steps:
        content = (SCHEMA / step["file"]).read_bytes()
        if hashlib.sha256(content).hexdigest() != step["sha256"]:
            raise ValueError("source_migration_checksum_mismatch")
        step["sql"] = content.decode("utf-8")
    return steps


def schema_objects(connection: sqlite3.Connection) -> dict:
    return {(kind, name): sql for kind, name, sql in connection.execute(
        "SELECT type, name, sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*'"
    )}


def expected_schema(steps: list[dict]) -> dict:
    with contextlib.closing(sqlite3.connect(":memory:")) as connection:
        for step in steps:
            connection.executescript(step["sql"])
        return schema_objects(connection)


def expansion_checkpoint_version(connection: sqlite3.Connection, version: int, reader: int, source_sha256: str) -> int | None:
    row = connection.execute("""
        SELECT s.version, s.min_reader, m.source_schema, m.backup_identity, m.unresolved_count, m.cohort, m.receipt_sha256
        FROM schema_version s JOIN migration_checkpoint m
            ON m.migration_id = 'AFV2-DATA-01/schema16' AND m.target_schema = 16
            AND m.state = 'EXPANDED_LEGACY_RECONCILIATION_PRESERVED'
            AND m.cohort = s.cohort AND m.receipt_sha256 = s.migration_receipt
        WHERE s.singleton = 1
        """).fetchone()
    if row is None:
        return None
    mirror, mirror_reader, source, backup, unresolved, cohort, receipt = row
    # Applied step 19 does not update this mirror on upgrade. Fresh creation inserts
    # the mirror after the full chain, so only those stores record 19 in both tables.
    if version == 19:
        if (mirror, mirror_reader) != (18, 18) and not (source == 0 and (mirror, mirror_reader) == (19, 19)):
            return None
    elif (mirror, mirror_reader) != (version, reader):
        return None
    if source == 0:
        if backup != "fresh:no-predecessor" or unresolved != 0:
            return None
    elif not 1 <= source <= LEGACY_VERSION or re.fullmatch(r"[0-9a-f]{64}", backup) is None:
        return None
    # Match NodeStore.RecordV2Migration's step-16 receipt. Internal consistency does
    # not establish the identity of the installed binary or an independent backup.
    expected = hashlib.sha256(f"AFV2-DATA-01|{source}|16|{source_sha256}|{backup}|{unresolved}|{cohort}".encode("utf-8")).hexdigest()
    return mirror if receipt == expected else None


def inventory(database: Path, binary: Path | None = None) -> dict:
    report = {
        "schema": 1,
        "kind": "arcforges-v2-node-preflight",
        "source": source_identity(),
        "installation": {"state": "unknown", "binary_sha256": None},
        "database": {"classification": "unknown", "schema_version": None, "min_reader_version": None},
        "counts": {},
        "blockers": [],
        "destructive_contraction_allowed": False,
        "prerequisites": PREREQUISITES,
    }
    blockers = report["blockers"]
    if binary is not None:
        if binary.is_symlink() or not binary.is_file():
            blockers.append("installed_binary_unreadable")
        else:
            try:
                report["installation"] = {"state": "bytes_observed_provenance_unproven", "binary_sha256": digest_file(binary)}
            except OSError:
                blockers.append("installed_binary_unreadable")
    else:
        blockers.append("installed_cohort_unknown")
    try:
        steps = migration_sources()
        report["source"]["migrations"] = [
            {key: step[key] for key in ("version", "minReaderVersion", "file", "sha256")} for step in steps
        ]
        if database.is_symlink():
            blockers.append("database_symlink_refused")
            return report
        if not database.exists():
            report["database"]["classification"] = "fresh"
            blockers.append("fresh_store_requires_initialization_not_contraction")
            return report
        if not database.is_file():
            blockers.append("database_not_regular_file")
            return report
        # A WAL/hot rollback journal needs the product's consistent backup procedure. An immutable
        # connection would ignore its commits, while a normal WAL reader may create/change sidecars.
        # Refuse both here, preserving every source byte and never reporting stale main-file data.
        if any(Path(str(database) + suffix).exists() for suffix in ("-wal", "-journal")):
            blockers.append("live_or_uncheckpointed_store_requires_consistent_offline_backup")
            return report
        # The supplied file is an operator-selected offline snapshot. SQLite receives only
        # protected-handle bytes in memory: it never opens, recovers or checkpoints the source.
        # This does not prove process absence, hence contraction is never authorized here.
        with offline_database(database) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                blockers.append("database_integrity_failed")
                return report
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
            if not tables:
                report["database"]["classification"] = "fresh"
                blockers.append("fresh_store_requires_initialization_not_contraction")
                return report
            if "store_meta" not in tables:
                blockers.append("not_a_node_store")
                return report
            rows = connection.execute(
                "SELECT schema_version, min_reader_version, clean_shutdown_at IS NOT NULL FROM store_meta WHERE singleton=1"
            ).fetchall()
            if len(rows) != 1 or any(type(value) is not int for value in rows[0]):
                blockers.append("invalid_store_metadata")
                return report
            version, reader, clean = rows[0]
            report["database"].update(schema_version=version, min_reader_version=reader, clean_shutdown_recorded=bool(clean))
            if version > LATEST_VERSION or reader > LATEST_VERSION:
                report["database"]["classification"] = "newer"
                blockers.append("newer_store_refused")
                return report
            if version < LEGACY_VERSION or reader != steps[version - 1]["minReaderVersion"]:
                blockers.append("unsupported_store_version")
                return report
            if schema_objects(connection) != expected_schema(steps[:version]):
                blockers.append("schema_objects_differ_from_released_node15" if version == LEGACY_VERSION
                                else "schema_objects_differ_from_released_node_v2_prefix")
                return report
            if version == LEGACY_VERSION:
                report["database"]["classification"] = "node15"
                report["database"]["applied_migration_checksum_ledger"] = "not_available_in_node15"
            else:
                mirror = expansion_checkpoint_version(connection, version, reader, steps[LEGACY_VERSION]["sha256"])
                if mirror is None:
                    blockers.append("inconsistent_v2_expansion_checkpoint")
                    return report
                report["database"].update(classification="node_v2_expanded", expansion_metadata_schema_version=mirror,
                                          expansion_checkpoint_matches=True,
                                          applied_migration_checksum_ledger="step16_checkpoint_only")
            report["source"]["migrations"] = report["source"]["migrations"][:version]
            report["database"]["schema_objects_match"] = True
            if not clean:
                blockers.append("node_running_or_unclean_shutdown")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                blockers.append("foreign_key_integrity_failed")
            for name, query in COUNTS.items():
                count = connection.execute(query).fetchone()[0]
                report["counts"][name] = count
                if count:
                    blockers.append(name)
            blockers.append("native_scope_and_exclusive_owner_proof_required")
    except InspectionRefused as error:
        blockers.append(str(error))
        report["database"]["classification"] = "unknown"
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, AttributeError):
        # Database errors can quote data/path values; never include them in a report.
        blockers.append("inspection_failed_or_locked")
        report["database"]["classification"] = "unknown"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path, help="Explicit operator-selected offline database or consistent backup")
    parser.add_argument("--binary", type=Path, help="Optional installed binary to hash; this does not establish provenance")
    args = parser.parse_args()
    report = inventory(args.database, args.binary)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if report["database"]["classification"] in {"unknown", "newer"} else 0


if __name__ == "__main__":
    sys.exit(main())
