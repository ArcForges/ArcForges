-- AF-CTR-06: persistent validation-time floor and elapsed-retention evidence.
-- Existing file/workspace command and verified-call records are protected before any older writer can prune them.
-- The new node may release a hold only in the same transaction that has established the required time evidence.
CREATE TABLE routed_file_validation_time (
  singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
  highwater INTEGER
) STRICT;
INSERT INTO routed_file_validation_time (singleton, highwater)
SELECT 1, MAX(
  COALESCE((SELECT MAX(received_at) FROM routed_file_call_log WHERE call_id IS NOT NULL), 0),
  COALESCE((SELECT MAX(created_at) FROM command_dedup WHERE
    method GLOB 'arcforges.node.v1.FileService/*' OR
    method IN ('arcforges.node.v1.WorkspaceService/RegisterWorkspace', 'arcforges.node.v1.WorkspaceService/UnregisterWorkspace')), 0)
);

CREATE TABLE routed_file_command_retention (
  command_id BLOB NOT NULL PRIMARY KEY CHECK (length(command_id) = 16),
  process_epoch BLOB CHECK (process_epoch IS NULL OR length(process_epoch) = 16),
  monotonic_start INTEGER,
  delete_permitted INTEGER NOT NULL DEFAULT 0 CHECK (delete_permitted IN (0, 1)),
  CHECK ((process_epoch IS NULL) = (monotonic_start IS NULL))
) STRICT;
INSERT INTO routed_file_command_retention (command_id)
SELECT command_id FROM command_dedup WHERE method GLOB 'arcforges.node.v1.FileService/*' OR
  method IN ('arcforges.node.v1.WorkspaceService/RegisterWorkspace', 'arcforges.node.v1.WorkspaceService/UnregisterWorkspace');
CREATE TRIGGER tr_file_command_retention_insert AFTER INSERT ON command_dedup
WHEN NEW.method GLOB 'arcforges.node.v1.FileService/*' OR
  NEW.method IN ('arcforges.node.v1.WorkspaceService/RegisterWorkspace', 'arcforges.node.v1.WorkspaceService/UnregisterWorkspace')
BEGIN
  INSERT INTO routed_file_command_retention (command_id) VALUES (NEW.command_id);
END;
CREATE TRIGGER tr_file_command_retention_guard_insert BEFORE INSERT ON command_dedup
WHEN EXISTS (SELECT 1 FROM routed_file_command_retention WHERE command_id = NEW.command_id)
BEGIN
  SELECT RAISE(ABORT, 'file_command_retained');
END;
CREATE TRIGGER tr_file_command_retention_guard_delete BEFORE DELETE ON command_dedup
WHEN EXISTS (SELECT 1 FROM routed_file_command_retention WHERE command_id = OLD.command_id AND delete_permitted = 0)
BEGIN
  SELECT RAISE(IGNORE);
END;
CREATE TRIGGER tr_file_command_retention_guard_update BEFORE UPDATE OF command_id, method, payload_digest, created_at, expires_at ON command_dedup
WHEN EXISTS (SELECT 1 FROM routed_file_command_retention WHERE command_id = OLD.command_id)
BEGIN
  SELECT RAISE(ABORT, 'file_command_retained');
END;
CREATE TRIGGER tr_file_command_retention_release AFTER DELETE ON command_dedup
BEGIN
  DELETE FROM routed_file_command_retention WHERE command_id = OLD.command_id;
END;

CREATE TABLE routed_file_call_retention (
  log_id INTEGER NOT NULL PRIMARY KEY,
  process_epoch BLOB CHECK (process_epoch IS NULL OR length(process_epoch) = 16),
  monotonic_start INTEGER,
  delete_permitted INTEGER NOT NULL DEFAULT 0 CHECK (delete_permitted IN (0, 1)),
  CHECK ((process_epoch IS NULL) = (monotonic_start IS NULL))
) STRICT;
INSERT INTO routed_file_call_retention (log_id)
SELECT log_id FROM routed_file_call_log WHERE call_id IS NOT NULL;
CREATE TRIGGER tr_file_call_retention_insert AFTER INSERT ON routed_file_call_log WHEN NEW.call_id IS NOT NULL
BEGIN
  INSERT INTO routed_file_call_retention (log_id) VALUES (NEW.log_id);
END;
CREATE TRIGGER tr_file_call_retention_guard_delete BEFORE DELETE ON routed_file_call_log
WHEN EXISTS (SELECT 1 FROM routed_file_call_retention WHERE log_id = OLD.log_id AND delete_permitted = 0)
BEGIN
  SELECT RAISE(IGNORE);
END;
CREATE TRIGGER tr_file_call_retention_guard_time BEFORE UPDATE OF received_at ON routed_file_call_log
WHEN EXISTS (SELECT 1 FROM routed_file_call_retention WHERE log_id = OLD.log_id)
BEGIN
  SELECT RAISE(ABORT, 'file_call_retained');
END;
CREATE TRIGGER tr_file_call_retention_release AFTER DELETE ON routed_file_call_log
BEGIN
  DELETE FROM routed_file_call_retention WHERE log_id = OLD.log_id;
END;

-- The metadata-only file/workspace audit is retained for its own real elapsed lifetime. Unknown old rows
-- begin the conservative interval again when the new process opens the store.
CREATE TABLE routed_file_audit_retention (
  audit_seq INTEGER NOT NULL PRIMARY KEY,
  process_epoch BLOB CHECK (process_epoch IS NULL OR length(process_epoch) = 16),
  monotonic_start INTEGER,
  delete_permitted INTEGER NOT NULL DEFAULT 0 CHECK (delete_permitted IN (0, 1)),
  CHECK ((process_epoch IS NULL) = (monotonic_start IS NULL))
) STRICT;
INSERT INTO routed_file_audit_retention (audit_seq) SELECT audit_seq FROM file_workspace_audit;
INSERT INTO routed_file_audit_retention (audit_seq)
SELECT a.seq FROM audit_log a WHERE a.target_kind = 'routed_command_owner' AND EXISTS
  (SELECT 1 FROM routed_file_command_retention c WHERE c.command_id = a.remote_command_id)
  AND NOT EXISTS (SELECT 1 FROM routed_file_audit_retention h WHERE h.audit_seq = a.seq);
CREATE TRIGGER tr_file_audit_retention_insert AFTER INSERT ON file_workspace_audit
BEGIN
  INSERT INTO routed_file_audit_retention (audit_seq)
    SELECT NEW.audit_seq WHERE NOT EXISTS (SELECT 1 FROM routed_file_audit_retention WHERE audit_seq = NEW.audit_seq);
END;
CREATE TRIGGER tr_file_owner_audit_retention_insert AFTER INSERT ON audit_log
WHEN NEW.target_kind = 'routed_command_owner' AND EXISTS
  (SELECT 1 FROM routed_file_command_retention WHERE command_id = NEW.remote_command_id)
BEGIN
  INSERT INTO routed_file_audit_retention (audit_seq) VALUES (NEW.seq);
END;
CREATE TRIGGER tr_file_audit_retention_guard_delete BEFORE DELETE ON audit_log
WHEN EXISTS (SELECT 1 FROM routed_file_audit_retention WHERE audit_seq = OLD.seq AND delete_permitted = 0) OR
  (OLD.target_kind = 'routed_command_owner' AND OLD.remote_command_id IS NOT NULL AND
   EXISTS (SELECT 1 FROM routed_file_command_retention WHERE command_id = OLD.remote_command_id AND delete_permitted = 0))
BEGIN
  SELECT RAISE(IGNORE);
END;
CREATE TRIGGER tr_file_audit_retention_release AFTER DELETE ON audit_log
BEGIN
  DELETE FROM routed_file_audit_retention WHERE audit_seq = OLD.seq;
END;
