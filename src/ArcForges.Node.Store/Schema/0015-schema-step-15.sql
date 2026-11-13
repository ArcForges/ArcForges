-- AF-CTR-06: pre-target stage production is not a target PREPARED operation.
-- Every production reservation and object contains metadata only. A live producer
-- retains its quota/fence until the original native process is actually observed ended.
CREATE TABLE file_stage_production (
  command_id BLOB NOT NULL PRIMARY KEY CHECK (length(command_id) = 16),
  producer_nonce BLOB NOT NULL UNIQUE CHECK (length(producer_nonce) = 16),
  storage_kind INTEGER NOT NULL CHECK (storage_kind IN (1, 2)), -- anonymous, retained named
  workspace_id BLOB NOT NULL REFERENCES workspace (workspace_id) CHECK (length(workspace_id) = 16),
  operation_kind INTEGER NOT NULL CHECK (operation_kind IN (1, 2)),
  correlation_id BLOB NOT NULL CHECK (length(correlation_id) = 16),
  relative_path TEXT NOT NULL CHECK (length(CAST(relative_path AS BLOB)) BETWEEN 1 AND 4096),
  expected_absent INTEGER NOT NULL CHECK (expected_absent IN (0, 1)),
  expected_sha256 BLOB CHECK (expected_sha256 IS NULL OR length(expected_sha256) = 32),
  expected_occurrences INTEGER CHECK (expected_occurrences IS NULL OR expected_occurrences BETWEEN 1 AND 1000),
  target_identity BLOB CHECK (target_identity IS NULL OR length(target_identity) BETWEEN 16 AND 256),
  request_sha256 BLOB NOT NULL CHECK (length(request_sha256) = 32),
  caller BLOB NOT NULL CHECK (length(caller) BETWEEN 1 AND 256),
  identity_platform INTEGER NOT NULL CHECK (identity_platform IN (1, 2)),
  root_identity BLOB NOT NULL CHECK (length(root_identity) BETWEEN 16 AND 256),
  parent_identity BLOB NOT NULL CHECK (length(parent_identity) BETWEEN 16 AND 256),
  object_count INTEGER NOT NULL CHECK (object_count BETWEEN 1 AND 2),
  reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes BETWEEN 0 AND 8388608),
  deadline_clock INTEGER NOT NULL CHECK (deadline_clock IN (1, 2)), -- Linux MONOTONIC ns, Windows QPC ticks
  deadline_ticks INTEGER NOT NULL CHECK (deadline_ticks > 0),
  expiry_microseconds INTEGER NOT NULL CHECK (expiry_microseconds > 0),
  created_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  released INTEGER NOT NULL DEFAULT 0 CHECK (released IN (0, 1)),
  CHECK ((expected_absent = 1 AND expected_sha256 IS NULL AND target_identity IS NULL AND object_count = 1) OR
         (expected_absent = 0 AND expected_sha256 IS NOT NULL AND target_identity IS NOT NULL AND object_count = 2)),
  CHECK ((identity_platform = 2 AND deadline_clock = 1) OR (identity_platform = 1 AND deadline_clock = 2)),
  CHECK ((operation_kind = 1 AND expected_occurrences IS NULL) OR
         (operation_kind = 2 AND expected_absent = 0 AND expected_occurrences IS NOT NULL))
) STRICT;

CREATE TABLE file_stage_produced_object (
  command_id BLOB NOT NULL REFERENCES file_stage_production (command_id),
  slot INTEGER NOT NULL CHECK (slot IN (1, 2)),
  stage_path TEXT CHECK (stage_path IS NULL OR length(CAST(stage_path AS BLOB)) BETWEEN 1 AND 4096),
  expected_size INTEGER NOT NULL CHECK (expected_size BETWEEN 0 AND 4194304),
  expected_sha256 BLOB NOT NULL CHECK (length(expected_sha256) = 32),
  identity_platform INTEGER NOT NULL CHECK (identity_platform IN (1, 2)),
  native_identity BLOB CHECK (native_identity IS NULL OR length(native_identity) BETWEEN 16 AND 256),
  parent_identity BLOB NOT NULL CHECK (length(parent_identity) BETWEEN 16 AND 256),
  phase INTEGER NOT NULL DEFAULT 0 CHECK (phase IN (0, 1, 2)), -- RESERVED, EMPTY_IDENTITY_BOUND, PRODUCED
  CHECK ((phase = 0 AND native_identity IS NULL) OR (phase IN (1, 2) AND native_identity IS NOT NULL)),
  PRIMARY KEY (command_id, slot),
  UNIQUE (identity_platform, native_identity)
) STRICT;

CREATE TABLE file_stage_worker (
  command_id BLOB NOT NULL,
  slot INTEGER NOT NULL CHECK (slot IN (1, 2)),
  worker_nonce BLOB NOT NULL UNIQUE CHECK (length(worker_nonce) = 16),
  producer_nonce BLOB NOT NULL CHECK (length(producer_nonce) = 16),
  identity_platform INTEGER NOT NULL CHECK (identity_platform IN (1, 2)),
  boot_identity TEXT NOT NULL CHECK (length(boot_identity) BETWEEN 1 AND 256),
  pid_namespace TEXT,
  process_id INTEGER NOT NULL CHECK (process_id > 1),
  start_ticks INTEGER NOT NULL CHECK (start_ticks > 0),
  ended INTEGER NOT NULL DEFAULT 0 CHECK (ended IN (0, 1)),
  PRIMARY KEY (command_id, slot),
  FOREIGN KEY (command_id, slot) REFERENCES file_stage_produced_object (command_id, slot),
  CHECK ((identity_platform = 2 AND pid_namespace IS NOT NULL AND length(pid_namespace) BETWEEN 1 AND 256) OR
         (identity_platform = 1 AND pid_namespace IS NULL))
) STRICT;

CREATE INDEX ix_file_stage_production_workspace ON file_stage_production (workspace_id, active);

CREATE TRIGGER tr_file_stage_production_immutable
BEFORE UPDATE OF command_id, producer_nonce, storage_kind, workspace_id, operation_kind, correlation_id,
                 relative_path, expected_absent, expected_sha256, expected_occurrences, target_identity, request_sha256, caller, identity_platform, root_identity, parent_identity,
                 object_count, reserved_bytes, deadline_clock, deadline_ticks, expiry_microseconds, created_at ON file_stage_production
BEGIN
  SELECT RAISE(ABORT, 'file_stage_production_bound');
END;

CREATE TRIGGER tr_file_stage_produced_object_immutable
BEFORE UPDATE OF command_id, slot, stage_path, expected_size, expected_sha256,
                 identity_platform, parent_identity ON file_stage_produced_object
BEGIN
  SELECT RAISE(ABORT, 'file_stage_production_object_bound');
END;

CREATE TRIGGER tr_file_stage_object_identity_once BEFORE UPDATE OF native_identity ON file_stage_produced_object
WHEN NOT (OLD.phase = 0 AND OLD.native_identity IS NULL AND NEW.phase = 1 AND NEW.native_identity IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_production_identity_bound');
END;

CREATE TRIGGER tr_file_stage_worker_immutable
BEFORE UPDATE OF command_id, slot, worker_nonce, producer_nonce, identity_platform,
                 boot_identity, pid_namespace, process_id, start_ticks ON file_stage_worker
BEGIN
  SELECT RAISE(ABORT, 'file_stage_worker_bound');
END;

CREATE TRIGGER tr_file_stage_worker_ended_once BEFORE UPDATE OF ended ON file_stage_worker
WHEN NOT (OLD.ended = 0 AND NEW.ended = 1)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_worker_invalid_phase');
END;

CREATE TRIGGER tr_file_stage_worker_matching_production BEFORE INSERT ON file_stage_worker
WHEN NOT EXISTS
  (SELECT 1 FROM file_stage_production p JOIN file_stage_produced_object o ON o.command_id = p.command_id
   WHERE p.command_id = NEW.command_id AND p.producer_nonce = NEW.producer_nonce AND p.active = 1 AND p.released = 0
     AND p.identity_platform = NEW.identity_platform AND o.slot = NEW.slot AND o.phase = 0
     AND o.identity_platform = NEW.identity_platform)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_worker_reservation_mismatch');
END;

CREATE TRIGGER tr_file_stage_object_matching_production BEFORE INSERT ON file_stage_produced_object
WHEN NOT EXISTS
  (SELECT 1 FROM file_stage_production p WHERE p.command_id = NEW.command_id AND p.active = 1 AND p.released = 0
   AND p.identity_platform = NEW.identity_platform AND p.parent_identity = NEW.parent_identity
   AND ((p.storage_kind = 1 AND NEW.stage_path IS NULL) OR (p.storage_kind = 2 AND NEW.stage_path IS NOT NULL))) OR
     NEW.expected_size >
       (SELECT reserved_bytes FROM file_stage_production WHERE command_id = NEW.command_id) -
       COALESCE((SELECT sum(expected_size) FROM file_stage_produced_object WHERE command_id = NEW.command_id), 0)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_production_object_mismatch');
END;

CREATE TRIGGER tr_file_stage_object_ready_after_exit BEFORE UPDATE OF phase ON file_stage_produced_object
WHEN NOT ((OLD.phase = 0 AND NEW.phase = 1 AND NEW.native_identity IS NOT NULL) OR
          (OLD.phase = 1 AND NEW.phase = 2 AND EXISTS
           (SELECT 1 FROM file_stage_worker w WHERE w.command_id = OLD.command_id AND w.slot = OLD.slot AND w.ended = 1)))
BEGIN
  SELECT RAISE(ABORT, 'file_stage_worker_not_ended');
END;

CREATE TRIGGER tr_file_stage_named_ready_after_exit BEFORE UPDATE OF phase ON file_private_stage_object
WHEN NEW.phase = 3 AND EXISTS (SELECT 1 FROM file_stage_production p WHERE p.command_id = OLD.command_id) AND
     NOT EXISTS (SELECT 1 FROM file_stage_worker w WHERE w.command_id = OLD.command_id AND w.slot = OLD.slot AND w.ended = 1)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_worker_not_ended');
END;

CREATE TRIGGER tr_file_stage_production_release_after_exit BEFORE UPDATE OF active, released ON file_stage_production
WHEN (NEW.active < OLD.active OR NEW.released > OLD.released) AND
     (EXISTS (SELECT 1 FROM file_stage_worker w WHERE w.command_id = OLD.command_id AND w.ended = 0) OR
      EXISTS (SELECT 1 FROM file_effect_worker w WHERE w.command_id = OLD.command_id AND w.ended = 0))
BEGIN
  SELECT RAISE(ABORT, 'file_stage_worker_not_ended');
END;

CREATE TRIGGER tr_file_stage_named_release_after_exit BEFORE UPDATE OF active ON file_private_stage_reservation
WHEN NEW.active = 0 AND EXISTS
  (SELECT 1 FROM file_stage_worker w WHERE w.command_id = OLD.command_id AND w.ended = 0)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_worker_not_ended');
END;

CREATE TRIGGER tr_file_stage_worker_no_delete BEFORE DELETE ON file_stage_worker
BEGIN
  SELECT RAISE(IGNORE);
END;

CREATE TRIGGER tr_file_stage_object_no_delete BEFORE DELETE ON file_stage_produced_object
BEGIN
  SELECT RAISE(IGNORE);
END;

CREATE TRIGGER tr_file_stage_production_no_delete BEFORE DELETE ON file_stage_production
BEGIN
  SELECT RAISE(IGNORE);
END;

-- Keep every installed view and trigger unchanged. The new reader selects this additive
-- view; supplementary triggers enforce its accounting even for direct writer statements.
-- A command is counted once; byte deduplication requires platform, slot, object and size.
CREATE VIEW file_stage_capacity_totals_v15 AS
SELECT
  (SELECT count(*) FROM
    (SELECT command_id FROM file_private_stage_reservation WHERE active = 1
     UNION SELECT command_id FROM file_operation_journal WHERE held = 1
     UNION SELECT command_id FROM file_stage_production WHERE active = 1)) AS active_mutations,
  COALESCE((SELECT sum(reserved_bytes) FROM file_private_stage_reservation), 0) +
  COALESCE((SELECT sum(reserved_bytes) FROM file_stage_production WHERE storage_kind = 1 AND released = 0), 0) +
  COALESCE((SELECT sum(
    (CASE WHEN j.original_size IS NULL OR EXISTS
      (SELECT 1 FROM file_private_stage_object o WHERE o.command_id = j.command_id AND o.slot = 1
       AND o.identity_platform = j.identity_platform AND o.native_identity = j.original_stage_identity
       AND o.expected_size = j.original_size) OR EXISTS
      (SELECT 1 FROM file_stage_produced_object o JOIN file_stage_production p ON p.command_id = o.command_id
       WHERE o.command_id = j.command_id AND o.slot = 1 AND p.storage_kind = 1 AND p.released = 0
       AND o.identity_platform = j.identity_platform AND o.native_identity = j.original_stage_identity
       AND o.expected_size = j.original_size) THEN 0 ELSE j.original_size END) +
    (CASE WHEN j.intended_size IS NULL OR EXISTS
      (SELECT 1 FROM file_private_stage_object o WHERE o.command_id = j.command_id AND o.slot = 2
       AND o.identity_platform = j.identity_platform AND o.native_identity = j.intended_stage_identity
       AND o.expected_size = j.intended_size) OR EXISTS
      (SELECT 1 FROM file_stage_produced_object o JOIN file_stage_production p ON p.command_id = o.command_id
       WHERE o.command_id = j.command_id AND o.slot = 2 AND p.storage_kind = 1 AND p.released = 0
       AND o.identity_platform = j.identity_platform AND o.native_identity = j.intended_stage_identity
       AND o.expected_size = j.intended_size) THEN 0 ELSE j.intended_size END))
    FROM file_operation_journal j WHERE j.held = 1), 0) AS reserved_bytes;

CREATE TRIGGER tr_file_stage_production_capacity BEFORE INSERT ON file_stage_production
WHEN (NOT EXISTS (SELECT 1 FROM file_private_stage_reservation WHERE command_id = NEW.command_id AND active = 1) AND
      NOT EXISTS (SELECT 1 FROM file_operation_journal WHERE command_id = NEW.command_id AND held = 1) AND
      (SELECT active_mutations FROM file_stage_capacity_totals_v15) >= 64) OR
     (NEW.storage_kind = 1 AND NEW.reserved_bytes > 268435456 - (SELECT reserved_bytes FROM file_stage_capacity_totals_v15))
BEGIN
  SELECT RAISE(ABORT, 'file_stage_capacity');
END;

CREATE TRIGGER tr_file_stage_named_reservation_binding BEFORE INSERT ON file_stage_production
WHEN NEW.storage_kind = 2 AND NOT EXISTS
  (SELECT 1 FROM file_private_stage_reservation r WHERE r.command_id = NEW.command_id AND r.active = 1
   AND r.workspace_id = NEW.workspace_id AND r.kind = NEW.operation_kind AND r.correlation_id = NEW.correlation_id
   AND r.relative_path = NEW.relative_path AND r.request_sha256 = NEW.request_sha256 AND r.caller = NEW.caller
   AND r.expected_absent = NEW.expected_absent AND r.expected_sha256 IS NEW.expected_sha256
   AND r.expected_occurrences IS NEW.expected_occurrences
   AND r.reserved_bytes = NEW.reserved_bytes)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_production_reservation_mismatch');
END;

CREATE TRIGGER tr_file_stage_production_unregister BEFORE UPDATE OF removed_at ON workspace
WHEN NEW.removed_at IS NOT NULL AND EXISTS
  (SELECT 1 FROM file_stage_production p WHERE p.workspace_id = OLD.workspace_id AND p.active = 1)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_production_pending');
END;

-- Supplement the installed journal triggers without replacing their historical definitions.
-- The old view omits anonymous producer reservations; a new journal's full allocation fits
-- its old accounting whenever its already reserved allocation fits the complete v15 view.
CREATE VIEW file_stage_reserved_identity AS
SELECT command_id, slot, identity_platform, native_identity, expected_size
FROM file_private_stage_object WHERE native_identity IS NOT NULL
UNION
SELECT o.command_id, o.slot, o.identity_platform, o.native_identity, o.expected_size
FROM file_stage_produced_object o JOIN file_stage_production p ON p.command_id = o.command_id
WHERE p.storage_kind = 1 AND p.released = 0 AND o.native_identity IS NOT NULL;

CREATE TRIGGER tr_file_journal_stage_capacity_v15 BEFORE INSERT ON file_operation_journal
WHEN NEW.held = 1 AND
 ((NOT EXISTS (SELECT 1 FROM file_private_stage_reservation r WHERE r.command_id = NEW.command_id AND r.active = 1) AND
   NOT EXISTS (SELECT 1 FROM file_stage_production p WHERE p.command_id = NEW.command_id AND p.active = 1) AND
   (SELECT active_mutations FROM file_stage_capacity_totals_v15) >= 64) OR
  ((CASE WHEN NEW.original_size IS NULL OR EXISTS
     (SELECT 1 FROM file_stage_reserved_identity o WHERE o.command_id = NEW.command_id AND o.slot = 1
      AND o.identity_platform = NEW.identity_platform AND o.native_identity = NEW.original_stage_identity
      AND o.expected_size = NEW.original_size) THEN 0 ELSE NEW.original_size END) +
   (CASE WHEN NEW.intended_size IS NULL OR EXISTS
     (SELECT 1 FROM file_stage_reserved_identity o WHERE o.command_id = NEW.command_id AND o.slot = 2
      AND o.identity_platform = NEW.identity_platform AND o.native_identity = NEW.intended_stage_identity
      AND o.expected_size = NEW.intended_size) THEN 0 ELSE NEW.intended_size END)) >
    268435456 - (SELECT reserved_bytes FROM file_stage_capacity_totals_v15))
BEGIN
  SELECT RAISE(ABORT, 'file_stage_capacity');
END;

CREATE TRIGGER tr_file_journal_stage_reactivate_capacity_v15 BEFORE UPDATE OF held ON file_operation_journal
WHEN OLD.held = 0 AND NEW.held = 1 AND
 ((NOT EXISTS (SELECT 1 FROM file_private_stage_reservation r WHERE r.command_id = NEW.command_id AND r.active = 1) AND
   NOT EXISTS (SELECT 1 FROM file_stage_production p WHERE p.command_id = NEW.command_id AND p.active = 1) AND
   (SELECT active_mutations FROM file_stage_capacity_totals_v15) >= 64) OR
  ((CASE WHEN NEW.original_size IS NULL OR EXISTS
     (SELECT 1 FROM file_stage_reserved_identity o WHERE o.command_id = NEW.command_id AND o.slot = 1
      AND o.identity_platform = NEW.identity_platform AND o.native_identity = NEW.original_stage_identity
      AND o.expected_size = NEW.original_size) THEN 0 ELSE NEW.original_size END) +
   (CASE WHEN NEW.intended_size IS NULL OR EXISTS
     (SELECT 1 FROM file_stage_reserved_identity o WHERE o.command_id = NEW.command_id AND o.slot = 2
      AND o.identity_platform = NEW.identity_platform AND o.native_identity = NEW.intended_stage_identity
      AND o.expected_size = NEW.intended_size) THEN 0 ELSE NEW.intended_size END)) >
    268435456 - (SELECT reserved_bytes FROM file_stage_capacity_totals_v15))
BEGIN
  SELECT RAISE(ABORT, 'file_stage_capacity');
END;

-- Existing named-stage writers must also respect an anonymous producer's reserved capacity.
CREATE TRIGGER tr_file_stage_named_capacity_v15 BEFORE INSERT ON file_private_stage_reservation
WHEN (NOT EXISTS (SELECT 1 FROM file_operation_journal j WHERE j.command_id = NEW.command_id AND j.held = 1) AND
      NOT EXISTS (SELECT 1 FROM file_stage_production p WHERE p.command_id = NEW.command_id AND p.active = 1) AND
      (SELECT active_mutations FROM file_stage_capacity_totals_v15) >= 64) OR
     NEW.reserved_bytes > 268435456 - (SELECT reserved_bytes FROM file_stage_capacity_totals_v15)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_capacity');
END;

CREATE TRIGGER tr_file_stage_named_reactivate_capacity_v15 BEFORE UPDATE OF active ON file_private_stage_reservation
WHEN OLD.active = 0 AND NEW.active = 1 AND
     NOT EXISTS (SELECT 1 FROM file_operation_journal j WHERE j.command_id = NEW.command_id AND j.held = 1) AND
     NOT EXISTS (SELECT 1 FROM file_stage_production p WHERE p.command_id = NEW.command_id AND p.active = 1) AND
     (SELECT active_mutations FROM file_stage_capacity_totals_v15) >= 64
BEGIN
  SELECT RAISE(ABORT, 'file_stage_capacity');
END;

CREATE TRIGGER tr_file_stage_production_terminal_once BEFORE UPDATE OF active, released ON file_stage_production
WHEN NEW.active > OLD.active OR NEW.released < OLD.released
BEGIN
  SELECT RAISE(ABORT, 'file_stage_production_invalid_phase');
END;

-- An old binary can have cached its Inspect result and open its writer after an
-- exclusive migration guard is released. Its real Start must fail before publishing
-- boot identity or serving effects. This is not retirement of an already open writer.
CREATE TRIGGER tr_file_stage_store_reader_admission BEFORE UPDATE ON store_meta
WHEN arcforges_store_reader_version() < NEW.min_reader_version
  OR arcforges_store_reader_version() < 15
BEGIN
  SELECT RAISE(ABORT, 'node_store_reader_too_old');
END;
