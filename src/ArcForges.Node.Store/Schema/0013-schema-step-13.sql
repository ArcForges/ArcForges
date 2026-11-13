-- AF-CTR-06: provenance for the exact temporary directory returned by a native exclusive create.
-- This metadata does not itself authorize cleanup or prove native whole-tree protection.
CREATE TABLE file_attempt_temp_identity (
  attempt_id BLOB NOT NULL PRIMARY KEY REFERENCES attempt (attempt_id) ON DELETE CASCADE CHECK (length(attempt_id) = 16),
  directory_id BLOB NOT NULL UNIQUE REFERENCES managed_directory (directory_id) ON DELETE CASCADE CHECK (length(directory_id) = 16),
  task_id BLOB NOT NULL REFERENCES task (task_id) ON DELETE CASCADE CHECK (length(task_id) = 16),
  owner BLOB NOT NULL CHECK (length(owner) BETWEEN 1 AND 4096),
  root_platform INTEGER NOT NULL CHECK (root_platform IN (1, 2)),
  root_identity BLOB NOT NULL CHECK (length(root_identity) BETWEEN 16 AND 256),
  directory_identity BLOB NOT NULL CHECK (length(directory_identity) BETWEEN 16 AND 256),
  recorded_at INTEGER NOT NULL
) STRICT;
