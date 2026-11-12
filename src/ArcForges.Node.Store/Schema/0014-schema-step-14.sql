-- AF-CTR-06: content-free evidence of a successful, exclusive API-created file.
-- A record is not an unattended-removal authorization. Native identity, marker, hash,
-- specific caller and the cleanup policy must be rechecked on the held object.
CREATE TABLE file_ownership_generation (
  singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
  generation INTEGER NOT NULL CHECK (generation >= 0)
) STRICT;
INSERT INTO file_ownership_generation (singleton, generation) VALUES (1, 0);

CREATE TABLE file_ownership_object_generation (
  object_platform INTEGER NOT NULL CHECK (object_platform IN (1, 2)),
  object_key BLOB NOT NULL CHECK (
    (object_platform = 1 AND length(object_key) = 25) OR
    (object_platform = 2 AND length(object_key) = 32)),
  generation INTEGER NOT NULL CHECK (generation >= 0),
  PRIMARY KEY (object_platform, object_key)
) STRICT, WITHOUT ROWID;

CREATE TABLE file_creation_ownership (
  workspace_id BLOB NOT NULL REFERENCES workspace (workspace_id) ON DELETE CASCADE CHECK (length(workspace_id) = 16),
  relative_path TEXT NOT NULL CHECK (length(CAST(relative_path AS BLOB)) BETWEEN 1 AND 4096),
  caller BLOB NOT NULL CHECK (length(caller) BETWEEN 1 AND 256),
  creation_command_id BLOB NOT NULL CHECK (length(creation_command_id) = 16),
  creation_request_sha256 BLOB NOT NULL CHECK (length(creation_request_sha256) = 32),
  root_platform INTEGER NOT NULL CHECK (root_platform IN (1, 2)),
  root_identity BLOB NOT NULL CHECK (length(root_identity) BETWEEN 16 AND 256),
  object_platform INTEGER NOT NULL CHECK (object_platform IN (1, 2)),
  object_identity BLOB NOT NULL CHECK (length(object_identity) BETWEEN 16 AND 256),
  object_key BLOB NOT NULL CHECK (
    (object_platform = 1 AND length(object_key) = 25) OR
    (object_platform = 2 AND length(object_key) = 32)),
  creation_marker BLOB NOT NULL CHECK (length(creation_marker) = 32),
  last_written_size INTEGER NOT NULL CHECK (last_written_size BETWEEN 0 AND 4194304),
  last_written_sha256 BLOB NOT NULL CHECK (length(last_written_sha256) = 32),
  global_generation INTEGER NOT NULL CHECK (global_generation >= 0),
  object_generation INTEGER NOT NULL CHECK (object_generation >= 0),
  recorded_at INTEGER NOT NULL,
  PRIMARY KEY (workspace_id, relative_path),
  FOREIGN KEY (object_platform, object_key) REFERENCES file_ownership_object_generation (object_platform, object_key)
) STRICT;
CREATE INDEX ix_file_creation_ownership__object ON file_creation_ownership (object_platform, object_key);
