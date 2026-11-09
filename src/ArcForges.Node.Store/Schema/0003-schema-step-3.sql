-- ------------------------------------------------------------------ schema step 3
-- AF-CTR-06: expand-only verified-call namespace and registered-root identity.
-- Steps 1 and 2 remain byte-identical. The migration runner holds its immediate writer transaction
-- while backfilling and installing triggers, excluding old and new concurrent receipt writers.

CREATE TABLE routed_file_call_log (
  log_id INTEGER NOT NULL PRIMARY KEY,
  received_at INTEGER NOT NULL,
  frame_sha256 BLOB NOT NULL CHECK (length(frame_sha256) = 32),
  decision INTEGER NOT NULL CHECK (decision BETWEEN 1 AND 5),
  refusal_step TEXT CHECK (refusal_step IS NULL OR length(refusal_step) BETWEEN 1 AND 40),
  refusal_code TEXT CHECK (refusal_code IS NULL OR length(refusal_code) BETWEEN 3 AND 80),
  call_id BLOB CHECK (call_id IS NULL OR length(call_id) = 16),
  signature_kid TEXT CHECK (signature_kid IS NULL OR length(signature_kid) BETWEEN 1 AND 128),
  method INTEGER CHECK (method IS NULL OR method BETWEEN 9 AND 20),
  caller BLOB CHECK (caller IS NULL OR length(caller) BETWEEN 1 AND 1024),
  command_id BLOB CHECK (command_id IS NULL OR length(command_id) = 16),
  workspace_id BLOB CHECK (workspace_id IS NULL OR length(workspace_id) = 16),
  risk INTEGER CHECK (risk IS NULL OR risk BETWEEN 1 AND 3),
  request_sha256 BLOB CHECK (request_sha256 IS NULL OR length(request_sha256) = 32),
  request_size INTEGER CHECK (request_size IS NULL OR request_size BETWEEN 1 AND 245760),
  response_sha256 BLOB CHECK (response_sha256 IS NULL OR length(response_sha256) = 32),
  response_size INTEGER CHECK (response_size IS NULL OR response_size BETWEEN 1 AND 1040384),
  CHECK ((decision = 3) = (call_id IS NULL)),
  CHECK (decision <> 3 OR (signature_kid IS NULL AND method IS NULL AND caller IS NULL AND command_id IS NULL
                          AND workspace_id IS NULL AND risk IS NULL AND request_sha256 IS NULL AND request_size IS NULL
                          AND response_sha256 IS NULL AND response_size IS NULL)),
  CHECK ((decision = 3) = (refusal_step IS NOT NULL)),
  CHECK (decision IN (1, 5) OR refusal_code IS NOT NULL),
  CHECK (decision = 3 OR (signature_kid IS NOT NULL AND method IS NOT NULL AND caller IS NOT NULL
                         AND request_sha256 IS NOT NULL AND request_size IS NOT NULL)),
  CHECK ((response_sha256 IS NULL) = (response_size IS NULL)),
  CHECK ((decision = 1) = (response_sha256 IS NOT NULL)),
  CHECK (decision = 3 OR ((method IN (10, 11, 14, 15, 17, 18)) = (command_id IS NOT NULL)))
) STRICT;
CREATE INDEX ix_routed_file_call_log__received ON routed_file_call_log (received_at);
CREATE UNIQUE INDEX ux_routed_file_call_log__call ON routed_file_call_log (call_id) WHERE call_id IS NOT NULL;
CREATE INDEX ix_routed_file_call_log__command ON routed_file_call_log (command_id) WHERE command_id IS NOT NULL;

-- A call ID is global across the immutable task log and the new file log. Never reserve an unverified frame's IDs.
CREATE TABLE routed_verified_call_id (
  call_id BLOB NOT NULL PRIMARY KEY CHECK (length(call_id) = 16),
  log_kind INTEGER NOT NULL CHECK (log_kind IN (1, 2)), -- 1 task, 2 file/workspace
  log_id INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  UNIQUE (log_kind, log_id)
) STRICT;
CREATE INDEX ix_routed_verified_call_id__received ON routed_verified_call_id (received_at);
INSERT INTO routed_verified_call_id (call_id, log_kind, log_id, received_at)
  SELECT call_id, 1, log_id, received_at FROM routed_call_log WHERE call_id IS NOT NULL;

-- SQLite can propagate INSERT OR IGNORE/REPLACE into an AFTER trigger and silently defeat a unique index.
-- Explicit RAISE(ABORT) before either receipt insert protects every retained row and the shared call ID, regardless of conflict policy.
-- In a BEFORE trigger SQLite exposes the auto-rowid sentinel as -1, indistinguishable from an explicit -1.
-- If an old receipt actually has log_id=-1, fail closed until that receipt's normal retention removes it.
CREATE TRIGGER tr_routed_call_log__guard BEFORE INSERT ON routed_call_log
BEGIN
  SELECT RAISE(ABORT, 'routed_log_id_retained') WHERE EXISTS (SELECT 1 FROM routed_call_log WHERE log_id = NEW.log_id);
  SELECT RAISE(ABORT, 'verified_call_id_replayed') WHERE NEW.call_id IS NOT NULL
    AND EXISTS (SELECT 1 FROM routed_verified_call_id WHERE call_id = NEW.call_id);
END;
CREATE TRIGGER tr_routed_file_call_log__guard BEFORE INSERT ON routed_file_call_log
BEGIN
  SELECT RAISE(ABORT, 'routed_log_id_retained') WHERE EXISTS (SELECT 1 FROM routed_file_call_log WHERE log_id = NEW.log_id);
  SELECT RAISE(ABORT, 'verified_call_id_replayed') WHERE NEW.call_id IS NOT NULL
    AND EXISTS (SELECT 1 FROM routed_verified_call_id WHERE call_id = NEW.call_id);
END;

-- AFTER INSERT sees the allocated INTEGER PRIMARY KEY. Check the owner key with an explicit abort too, so a corrupt/orphan registry
-- cannot be ignored or replaced by an outer conflict policy. Compatible older writers need not write the registry themselves.
CREATE TRIGGER tr_routed_call_log__reserve AFTER INSERT ON routed_call_log WHEN NEW.call_id IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'verified_registry_owner_conflict')
    WHERE EXISTS (SELECT 1 FROM routed_verified_call_id WHERE log_kind = 1 AND log_id = NEW.log_id);
  INSERT INTO routed_verified_call_id (call_id, log_kind, log_id, received_at)
    VALUES (NEW.call_id, 1, NEW.log_id, NEW.received_at);
END;
CREATE TRIGGER tr_routed_file_call_log__reserve AFTER INSERT ON routed_file_call_log WHEN NEW.call_id IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'verified_registry_owner_conflict')
    WHERE EXISTS (SELECT 1 FROM routed_verified_call_id WHERE log_kind = 2 AND log_id = NEW.log_id);
  INSERT INTO routed_verified_call_id (call_id, log_kind, log_id, received_at)
    VALUES (NEW.call_id, 2, NEW.log_id, NEW.received_at);
END;
CREATE TRIGGER tr_routed_call_log__immutable_id BEFORE UPDATE ON routed_call_log
WHEN NEW.call_id IS NOT OLD.call_id OR NEW.log_id IS NOT OLD.log_id
BEGIN
  SELECT RAISE(ABORT, 'verified_receipt_identity_immutable');
END;
CREATE TRIGGER tr_routed_file_call_log__immutable_id BEFORE UPDATE ON routed_file_call_log
WHEN NEW.call_id IS NOT OLD.call_id OR NEW.log_id IS NOT OLD.log_id
BEGIN
  SELECT RAISE(ABORT, 'verified_receipt_identity_immutable');
END;
-- Log retention removes only its own registry member, atomically. The existing receipt retention policy remains authoritative.
CREATE TRIGGER tr_routed_call_log__release AFTER DELETE ON routed_call_log WHEN OLD.call_id IS NOT NULL
BEGIN
  DELETE FROM routed_verified_call_id WHERE call_id = OLD.call_id AND log_kind = 1 AND log_id = OLD.log_id;
END;
CREATE TRIGGER tr_routed_file_call_log__release AFTER DELETE ON routed_file_call_log WHEN OLD.call_id IS NOT NULL
BEGIN
  DELETE FROM routed_verified_call_id WHERE call_id = OLD.call_id AND log_kind = 2 AND log_id = OLD.log_id;
END;

-- Existing registrations without an identity must be explicitly registered again; no identity is invented during migration.
-- native_identity is a versioned, bounded platform representation (metadata only), including instance generation where available.
CREATE TABLE workspace_root_identity (
  workspace_id BLOB NOT NULL PRIMARY KEY REFERENCES workspace (workspace_id) ON DELETE CASCADE CHECK (length(workspace_id) = 16),
  format_version INTEGER NOT NULL CHECK (format_version = 1),
  platform INTEGER NOT NULL CHECK (platform IN (1, 2)), -- 1 Windows, 2 Linux
  native_identity BLOB NOT NULL CHECK (length(native_identity) BETWEEN 16 AND 256),
  canonical_path TEXT NOT NULL CHECK (length(CAST(canonical_path AS BLOB)) BETWEEN 1 AND 4096),
  registered_at INTEGER NOT NULL,
  released_at INTEGER CHECK (released_at IS NULL OR released_at >= registered_at)
) STRICT;
CREATE UNIQUE INDEX ux_workspace_root_identity__active ON workspace_root_identity (platform, native_identity) WHERE released_at IS NULL;
