-- AF-CTR-06: metadata-only journal for checked file effects.
-- A row is written in the same FULL transaction as the command reservation. File bytes are never stored here.
-- Stage identities describe anonymous on-volume objects whose handles must be held and flushed by the effect code.
-- They do not assert that a stage or a filesystem guard is available after restart.
CREATE TABLE file_operation_journal (
  command_id BLOB NOT NULL PRIMARY KEY REFERENCES command_dedup (command_id) CHECK (length(command_id) = 16),
  kind INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),
  phase INTEGER NOT NULL CHECK (phase IN (1, 2, 3)), -- PREPARED, COMPLETED, UNKNOWN
  request_sha256 BLOB NOT NULL CHECK (length(request_sha256) = 32),
  caller BLOB NOT NULL CHECK (length(caller) BETWEEN 1 AND 256),
  correlation_id BLOB NOT NULL CHECK (length(correlation_id) = 16),
  workspace_id BLOB REFERENCES workspace (workspace_id) CHECK (workspace_id IS NULL OR length(workspace_id) = 16),
  relative_path TEXT CHECK (relative_path IS NULL OR length(CAST(relative_path AS BLOB)) BETWEEN 1 AND 4096),
  attempt_id BLOB CHECK (attempt_id IS NULL OR length(attempt_id) = 16),
  identity_platform INTEGER NOT NULL CHECK (identity_platform IN (1, 2)),
  root_identity BLOB NOT NULL CHECK (length(root_identity) BETWEEN 16 AND 256),
  parent_identity BLOB NOT NULL CHECK (length(parent_identity) BETWEEN 16 AND 256),
  target_identity BLOB CHECK (target_identity IS NULL OR length(target_identity) BETWEEN 16 AND 256),
  expected_absent INTEGER NOT NULL CHECK (expected_absent IN (0, 1)),
  original_size INTEGER CHECK (original_size IS NULL OR original_size BETWEEN 0 AND 4194304),
  original_sha256 BLOB CHECK (original_sha256 IS NULL OR length(original_sha256) = 32),
  intended_size INTEGER CHECK (intended_size IS NULL OR intended_size BETWEEN 0 AND 4194304),
  intended_sha256 BLOB CHECK (intended_sha256 IS NULL OR length(intended_sha256) = 32),
  original_stage_identity BLOB CHECK (original_stage_identity IS NULL OR length(original_stage_identity) BETWEEN 16 AND 256),
  intended_stage_identity BLOB CHECK (intended_stage_identity IS NULL OR length(intended_stage_identity) BETWEEN 16 AND 256),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
  held INTEGER NOT NULL CHECK (held IN (0, 1)),
  acknowledged INTEGER NOT NULL CHECK (acknowledged IN (0, 1)),
  delete_permitted INTEGER NOT NULL DEFAULT 0 CHECK (delete_permitted IN (0, 1)),
  CHECK ((workspace_id IS NOT NULL AND relative_path IS NOT NULL AND attempt_id IS NULL) OR
         (workspace_id IS NULL AND relative_path IS NULL AND attempt_id IS NOT NULL)),
  CHECK ((phase = 1 AND held = 1 AND acknowledged = 0) OR
         (phase = 2 AND held = 0 AND acknowledged = 0) OR
         (phase = 3 AND ((held = 1 AND acknowledged = 0) OR (held = 0 AND acknowledged = 1)))),
  CHECK (kind = 3 OR (workspace_id IS NOT NULL AND intended_size IS NOT NULL AND intended_sha256 IS NOT NULL
                       AND intended_stage_identity IS NOT NULL)),
  CHECK (kind = 3 OR (expected_absent = 1 AND target_identity IS NULL AND original_size IS NULL
                       AND original_sha256 IS NULL AND original_stage_identity IS NULL) OR
                     (expected_absent = 0 AND target_identity IS NOT NULL AND original_size IS NOT NULL
                       AND original_sha256 IS NOT NULL AND original_stage_identity IS NOT NULL)),
  CHECK (kind <> 2 OR expected_absent = 0)
) STRICT;
CREATE INDEX ix_file_operation_journal__workspace_hold ON file_operation_journal (workspace_id) WHERE held = 1;
CREATE INDEX ix_file_operation_journal__attempt_hold ON file_operation_journal (attempt_id) WHERE held = 1;
CREATE TRIGGER tr_file_operation_journal__guard_delete BEFORE DELETE ON file_operation_journal
WHEN OLD.delete_permitted = 0
BEGIN
  SELECT RAISE(IGNORE);
END;
CREATE TRIGGER tr_file_operation_journal__guard_command_delete BEFORE DELETE ON command_dedup
WHEN EXISTS (SELECT 1 FROM file_operation_journal WHERE command_id = OLD.command_id)
BEGIN
  SELECT RAISE(IGNORE);
END;
-- Compatible earlier writers cannot unregister a workspace while a journal hold names it.
CREATE TRIGGER tr_file_operation_journal__guard_unregister BEFORE UPDATE OF removed_at ON workspace
WHEN NEW.removed_at IS NOT NULL AND EXISTS
  (SELECT 1 FROM file_operation_journal WHERE workspace_id = OLD.workspace_id AND held = 1)
BEGIN
  SELECT RAISE(ABORT, 'file_recovery_pending');
END;
