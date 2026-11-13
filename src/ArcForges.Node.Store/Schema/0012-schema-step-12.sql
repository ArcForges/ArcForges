-- AF-CTR-06: metadata-only exact removal plans, in addition to the existing cleanup ledger.
-- The named target, verified caller and every checked native identity are retained independently of receipts.
CREATE TABLE file_removal_plan (
  plan_id BLOB NOT NULL PRIMARY KEY REFERENCES cleanup_plan (plan_id) ON DELETE CASCADE CHECK (length(plan_id) = 16),
  command_id BLOB NOT NULL CHECK (length(command_id) = 16),
  request_sha256 BLOB NOT NULL CHECK (length(request_sha256) = 32),
  caller BLOB NOT NULL CHECK (length(caller) BETWEEN 1 AND 512),
  target_kind INTEGER NOT NULL CHECK (target_kind IN (1, 2)),
  workspace_id BLOB CHECK (workspace_id IS NULL OR length(workspace_id) = 16),
  workspace_path TEXT,
  attempt_id BLOB CHECK (attempt_id IS NULL OR length(attempt_id) = 16),
  root_platform INTEGER NOT NULL CHECK (root_platform IN (1, 2)),
  root_identity BLOB NOT NULL CHECK (length(root_identity) BETWEEN 16 AND 256),
  requires_approval INTEGER NOT NULL CHECK (requires_approval IN (0, 1)),
  quarantine_available INTEGER NOT NULL CHECK (quarantine_available IN (0, 1)),
  CHECK ((target_kind = 1 AND workspace_id IS NOT NULL AND workspace_path IS NOT NULL AND attempt_id IS NULL)
      OR (target_kind = 2 AND workspace_id IS NULL AND workspace_path IS NULL AND attempt_id IS NOT NULL))
) STRICT;
CREATE INDEX ix_file_removal_plan__command ON file_removal_plan (command_id);

CREATE TABLE file_removal_plan_item (
  plan_id BLOB NOT NULL,
  item_id BLOB NOT NULL CHECK (length(item_id) = 16),
  ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 1000),
  relative_path TEXT NOT NULL,
  entry_kind INTEGER NOT NULL CHECK (entry_kind IN (1, 2)),
  native_platform INTEGER NOT NULL CHECK (native_platform IN (1, 2)),
  native_identity BLOB NOT NULL CHECK (length(native_identity) BETWEEN 16 AND 256),
  identity_sha256 BLOB NOT NULL CHECK (length(identity_sha256) = 32),
  fingerprint_sha256 BLOB NOT NULL CHECK (length(fingerprint_sha256) = 32),
  stamp_size INTEGER NOT NULL,
  stamp_mtime INTEGER NOT NULL,
  stamp_mtime_nsec INTEGER NOT NULL,
  stamp_change INTEGER NOT NULL,
  stamp_change_nsec INTEGER NOT NULL,
  mode INTEGER NOT NULL,
  link_count INTEGER NOT NULL CHECK (link_count > 0),
  owner_verified INTEGER NOT NULL CHECK (owner_verified IN (0, 1)),
  PRIMARY KEY (plan_id, item_id),
  UNIQUE (plan_id, ordinal),
  FOREIGN KEY (plan_id, item_id) REFERENCES cleanup_item (plan_id, item_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- The same exact caller binding is required for successful and refused command receipts.
CREATE TABLE file_removal_command_owner (
  command_id BLOB NOT NULL PRIMARY KEY REFERENCES command_dedup (command_id) ON DELETE CASCADE CHECK (length(command_id) = 16),
  caller BLOB NOT NULL CHECK (length(caller) BETWEEN 1 AND 512),
  policy_reason TEXT CHECK (policy_reason IS NULL OR length(policy_reason) BETWEEN 1 AND 128)
) STRICT;
