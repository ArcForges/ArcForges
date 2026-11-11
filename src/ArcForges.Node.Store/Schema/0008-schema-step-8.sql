-- AF-CTR-06: bounded, metadata-only reservations for private named file stages.
-- A reservation is durable before a stage may contain file bytes. Identity rows protect
-- the opened object, independent of its name; no file content belongs in this database.
-- Identifies this unmerged draft layout on open; it is not a user-provided authorization marker.
CREATE TABLE file_private_stage_layout (
  singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
  layout TEXT NOT NULL CHECK (layout = 'ctr06-stage-combined-v3')
) STRICT;
INSERT INTO file_private_stage_layout (singleton, layout) VALUES (1, 'ctr06-stage-combined-v3');

CREATE TABLE file_private_stage_reservation (
  command_id BLOB NOT NULL PRIMARY KEY REFERENCES command_dedup (command_id) CHECK (length(command_id) = 16),
  workspace_id BLOB NOT NULL REFERENCES workspace (workspace_id) CHECK (length(workspace_id) = 16),
  kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
  correlation_id BLOB NOT NULL CHECK (length(correlation_id) = 16),
  relative_path TEXT NOT NULL CHECK (length(CAST(relative_path AS BLOB)) BETWEEN 1 AND 4096),
  expected_absent INTEGER NOT NULL CHECK (expected_absent IN (0, 1)),
  expected_sha256 BLOB CHECK (expected_sha256 IS NULL OR length(expected_sha256) = 32),
  expected_occurrences INTEGER CHECK (expected_occurrences IS NULL OR expected_occurrences BETWEEN 1 AND 1000),
  request_sha256 BLOB NOT NULL CHECK (length(request_sha256) = 32),
  caller BLOB NOT NULL CHECK (length(caller) BETWEEN 1 AND 256),
  reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes BETWEEN 0 AND 8388608),
  created_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  delete_permitted INTEGER NOT NULL DEFAULT 0 CHECK (delete_permitted IN (0, 1)),
  CHECK ((kind = 1 AND expected_occurrences IS NULL) OR (kind = 2 AND expected_occurrences IS NOT NULL)),
  CHECK ((kind = 1 AND expected_absent = 1 AND expected_sha256 IS NULL) OR
         (expected_absent = 0 AND expected_sha256 IS NOT NULL))
) STRICT;

CREATE TABLE file_private_stage_object (
  command_id BLOB NOT NULL REFERENCES file_private_stage_reservation (command_id),
  slot INTEGER NOT NULL CHECK (slot IN (1, 2)),
  stage_path TEXT NOT NULL CHECK (length(CAST(stage_path AS BLOB)) BETWEEN 1 AND 4096),
  expected_size INTEGER NOT NULL CHECK (expected_size BETWEEN 0 AND 4194304),
  expected_sha256 BLOB NOT NULL CHECK (length(expected_sha256) = 32),
  phase INTEGER NOT NULL DEFAULT 1 CHECK (phase IN (1, 2, 3)), -- RESERVED, IDENTITY_BOUND, READY
  identity_platform INTEGER CHECK (identity_platform IS NULL OR identity_platform IN (1, 2)),
  native_identity BLOB CHECK (native_identity IS NULL OR length(native_identity) BETWEEN 16 AND 256),
  parent_identity BLOB CHECK (parent_identity IS NULL OR length(parent_identity) BETWEEN 16 AND 256),
  PRIMARY KEY (command_id, slot),
  UNIQUE (identity_platform, native_identity),
  CHECK ((phase = 1 AND identity_platform IS NULL AND native_identity IS NULL AND parent_identity IS NULL) OR
         (phase IN (2, 3) AND identity_platform IS NOT NULL AND native_identity IS NOT NULL AND parent_identity IS NOT NULL))
) STRICT;

-- Metadata-only approval binding. The existing approval row contains a versioned command reference, never file bytes.
CREATE TABLE file_private_approval_binding (
  command_id BLOB NOT NULL PRIMARY KEY REFERENCES file_private_stage_reservation (command_id),
  approval_id BLOB NOT NULL UNIQUE CHECK (length(approval_id) = 16),
  identity_platform INTEGER NOT NULL CHECK (identity_platform IN (1, 2)),
  root_identity BLOB NOT NULL CHECK (length(root_identity) BETWEEN 16 AND 256),
  parent_identity BLOB NOT NULL CHECK (length(parent_identity) BETWEEN 16 AND 256),
  target_identity BLOB CHECK (target_identity IS NULL OR length(target_identity) BETWEEN 16 AND 256)
) STRICT;

CREATE TRIGGER tr_file_private_approval_binding_no_update BEFORE UPDATE ON file_private_approval_binding
BEGIN
  SELECT RAISE(ABORT, 'file_approval_binding_immutable');
END;

CREATE TRIGGER tr_file_private_approval_binding_no_delete BEFORE DELETE ON file_private_approval_binding
WHEN EXISTS (SELECT 1 FROM file_private_stage_reservation r WHERE r.command_id = OLD.command_id AND r.delete_permitted = 0)
BEGIN
  SELECT RAISE(IGNORE);
END;

-- Count a command once while it is active. Charge every retained named reservation, plus every held journal
-- stage whose exact platform, slot, native identity and size are not already represented by that reservation.
-- A shared command ID alone never proves two allocations are the same object.
CREATE VIEW file_stage_capacity_totals AS
SELECT
  (SELECT count(*) FROM file_private_stage_reservation WHERE active = 1) +
  (SELECT count(*) FROM file_operation_journal j WHERE j.held = 1 AND NOT EXISTS
    (SELECT 1 FROM file_private_stage_reservation r WHERE r.command_id = j.command_id AND r.active = 1)) AS active_mutations,
  COALESCE((SELECT sum(reserved_bytes) FROM file_private_stage_reservation), 0) +
  COALESCE((SELECT sum((CASE WHEN j.original_size IS NULL OR EXISTS
     (SELECT 1 FROM file_private_stage_object o WHERE o.command_id = j.command_id AND o.slot = 1
      AND o.identity_platform = j.identity_platform AND o.native_identity = j.original_stage_identity
      AND o.expected_size = j.original_size) THEN 0 ELSE j.original_size END) +
    (CASE WHEN j.intended_size IS NULL OR EXISTS
     (SELECT 1 FROM file_private_stage_object o WHERE o.command_id = j.command_id AND o.slot = 2
      AND o.identity_platform = j.identity_platform AND o.native_identity = j.intended_stage_identity
      AND o.expected_size = j.intended_size) THEN 0 ELSE j.intended_size END)) FROM file_operation_journal j WHERE j.held = 1), 0) AS reserved_bytes;

-- Older compatible writers cannot bypass the same durable active and byte limits.
CREATE TRIGGER tr_file_private_stage_capacity BEFORE INSERT ON file_private_stage_reservation
WHEN (NEW.active = 1 AND NOT EXISTS
       (SELECT 1 FROM file_operation_journal j WHERE j.command_id = NEW.command_id AND j.held = 1) AND
       (SELECT active_mutations FROM file_stage_capacity_totals) >= 64) OR
     NEW.reserved_bytes > 268435456 - (SELECT reserved_bytes FROM file_stage_capacity_totals)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_capacity');
END;

CREATE TRIGGER tr_file_private_stage_reactivate_capacity BEFORE UPDATE OF active ON file_private_stage_reservation
WHEN OLD.active = 0 AND NEW.active = 1 AND NOT EXISTS
       (SELECT 1 FROM file_operation_journal j WHERE j.command_id = NEW.command_id AND j.held = 1) AND
       (SELECT active_mutations FROM file_stage_capacity_totals) >= 64
BEGIN
  SELECT RAISE(ABORT, 'file_stage_capacity');
END;

CREATE TRIGGER tr_file_journal_stage_capacity BEFORE INSERT ON file_operation_journal
WHEN NEW.held = 1 AND
     ((NOT EXISTS (SELECT 1 FROM file_private_stage_reservation r WHERE r.command_id = NEW.command_id AND r.active = 1) AND
       (SELECT active_mutations FROM file_stage_capacity_totals) >= 64) OR
      ((CASE WHEN NEW.original_size IS NULL OR EXISTS
     (SELECT 1 FROM file_private_stage_object o WHERE o.command_id = NEW.command_id AND o.slot = 1
      AND o.identity_platform = NEW.identity_platform AND o.native_identity = NEW.original_stage_identity
      AND o.expected_size = NEW.original_size) THEN 0 ELSE NEW.original_size END) +
    (CASE WHEN NEW.intended_size IS NULL OR EXISTS
     (SELECT 1 FROM file_private_stage_object o WHERE o.command_id = NEW.command_id AND o.slot = 2
      AND o.identity_platform = NEW.identity_platform AND o.native_identity = NEW.intended_stage_identity
      AND o.expected_size = NEW.intended_size) THEN 0 ELSE NEW.intended_size END)) > 268435456 - (SELECT reserved_bytes FROM file_stage_capacity_totals))
BEGIN
  SELECT RAISE(ABORT, 'file_stage_capacity');
END;

CREATE TRIGGER tr_file_journal_stage_reactivate_capacity BEFORE UPDATE OF held ON file_operation_journal
WHEN OLD.held = 0 AND NEW.held = 1 AND
     ((NOT EXISTS (SELECT 1 FROM file_private_stage_reservation r WHERE r.command_id = NEW.command_id AND r.active = 1) AND
       (SELECT active_mutations FROM file_stage_capacity_totals) >= 64) OR
      ((CASE WHEN NEW.original_size IS NULL OR EXISTS
     (SELECT 1 FROM file_private_stage_object o WHERE o.command_id = NEW.command_id AND o.slot = 1
      AND o.identity_platform = NEW.identity_platform AND o.native_identity = NEW.original_stage_identity
      AND o.expected_size = NEW.original_size) THEN 0 ELSE NEW.original_size END) +
    (CASE WHEN NEW.intended_size IS NULL OR EXISTS
     (SELECT 1 FROM file_private_stage_object o WHERE o.command_id = NEW.command_id AND o.slot = 2
      AND o.identity_platform = NEW.identity_platform AND o.native_identity = NEW.intended_stage_identity
      AND o.expected_size = NEW.intended_size) THEN 0 ELSE NEW.intended_size END)) > 268435456 - (SELECT reserved_bytes FROM file_stage_capacity_totals))
BEGIN
  SELECT RAISE(ABORT, 'file_stage_capacity');
END;

CREATE TRIGGER tr_file_private_stage_guard_identity BEFORE UPDATE OF identity_platform, native_identity, parent_identity ON file_private_stage_object
WHEN OLD.native_identity IS NOT NULL AND
     (NEW.identity_platform IS NOT OLD.identity_platform OR NEW.native_identity IS NOT OLD.native_identity OR
      NEW.parent_identity IS NOT OLD.parent_identity)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_identity_bound');
END;

CREATE TRIGGER tr_file_private_stage_guard_object_delete BEFORE DELETE ON file_private_stage_object
WHEN EXISTS (SELECT 1 FROM file_private_stage_reservation r WHERE r.command_id = OLD.command_id AND r.delete_permitted = 0)
BEGIN
  SELECT RAISE(IGNORE);
END;

CREATE TRIGGER tr_file_private_stage_guard_reservation_delete BEFORE DELETE ON file_private_stage_reservation
WHEN OLD.delete_permitted = 0 OR EXISTS (SELECT 1 FROM file_private_stage_object o WHERE o.command_id = OLD.command_id)
BEGIN
  SELECT RAISE(IGNORE);
END;

CREATE TRIGGER tr_file_private_stage_guard_command_delete BEFORE DELETE ON command_dedup
WHEN EXISTS (SELECT 1 FROM file_private_stage_reservation r WHERE r.command_id = OLD.command_id)
BEGIN
  SELECT RAISE(IGNORE);
END;

CREATE TRIGGER tr_file_private_stage_guard_unregister BEFORE UPDATE OF removed_at ON workspace
WHEN NEW.removed_at IS NOT NULL AND EXISTS
  (SELECT 1 FROM file_private_stage_reservation r WHERE r.workspace_id = OLD.workspace_id AND r.active = 1)
BEGIN
  SELECT RAISE(ABORT, 'file_approval_pending');
END;

CREATE TRIGGER tr_file_private_stage_guard_reservation_binding
BEFORE UPDATE OF command_id, workspace_id, kind, correlation_id, relative_path, expected_absent,
                 expected_sha256, expected_occurrences, request_sha256, caller, reserved_bytes, created_at
ON file_private_stage_reservation
BEGIN
  SELECT RAISE(ABORT, 'file_stage_reservation_bound');
END;

CREATE TRIGGER tr_file_private_stage_guard_object_binding
BEFORE UPDATE OF command_id, slot, stage_path, expected_size, expected_sha256 ON file_private_stage_object
BEGIN
  SELECT RAISE(ABORT, 'file_stage_object_bound');
END;

CREATE TRIGGER tr_file_private_stage_object_capacity BEFORE INSERT ON file_private_stage_object
WHEN NEW.expected_size >
     (SELECT reserved_bytes FROM file_private_stage_reservation WHERE command_id = NEW.command_id) -
     COALESCE((SELECT sum(expected_size) FROM file_private_stage_object WHERE command_id = NEW.command_id), 0)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_capacity');
END;

CREATE TRIGGER tr_file_private_stage_guard_phase BEFORE UPDATE OF phase ON file_private_stage_object
WHEN NOT ((OLD.phase = 1 AND NEW.phase = 2) OR (OLD.phase = 2 AND NEW.phase = 3))
BEGIN
  SELECT RAISE(ABORT, 'file_stage_invalid_phase');
END;
