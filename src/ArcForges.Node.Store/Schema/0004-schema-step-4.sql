-- AF-CTR-06 metadata-only audit details. Never stores file bodies, search patterns, match text or replacement text.
-- An audit scope is attached to one existing audit_log row and is removed with that row's existing retention.
CREATE TABLE file_workspace_audit (
  audit_seq INTEGER NOT NULL PRIMARY KEY REFERENCES audit_log (seq) ON DELETE CASCADE,
  workspace_id BLOB CHECK (workspace_id IS NULL OR length(workspace_id) = 16),
  attempt_id BLOB CHECK (attempt_id IS NULL OR length(attempt_id) = 16),
  path TEXT CHECK (path IS NULL OR length(CAST(path AS BLOB)) <= 4096),
  CHECK (workspace_id IS NULL OR attempt_id IS NULL)
) STRICT;

-- One bounded scope/count/digest per kind. A refusal before any observation has no invented observation row.
CREATE TABLE file_workspace_audit_observation (
  audit_seq INTEGER NOT NULL REFERENCES file_workspace_audit (audit_seq) ON DELETE CASCADE,
  kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 7),
  size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
  digest_input_bytes INTEGER NOT NULL CHECK (digest_input_bytes >= 0),
  item_count INTEGER CHECK (item_count IS NULL OR item_count BETWEEN 0 AND 10001),
  sha256 BLOB NOT NULL CHECK (length(sha256) = 32),
  PRIMARY KEY (audit_seq, kind)
) STRICT;

CREATE TRIGGER tr_file_workspace_audit_observation__bound BEFORE INSERT ON file_workspace_audit_observation
WHEN (SELECT count(*) FROM file_workspace_audit_observation WHERE audit_seq = NEW.audit_seq) >= 4
BEGIN
  SELECT RAISE(ABORT, 'file_audit_observation_limit');
END;
