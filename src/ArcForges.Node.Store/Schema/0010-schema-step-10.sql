-- AF-CTR-06: persistent lifetime fence for a Linux file-effect worker.
-- This records process identity only, not file content, credentials, or authority to start a worker.
CREATE TABLE file_effect_worker (
  command_id BLOB NOT NULL PRIMARY KEY REFERENCES file_operation_journal (command_id) ON DELETE CASCADE CHECK (length(command_id) = 16),
  boot_id TEXT NOT NULL CHECK (length(boot_id) = 36),
  pid_namespace TEXT NOT NULL CHECK (length(pid_namespace) BETWEEN 7 AND 32),
  process_id INTEGER NOT NULL CHECK (process_id > 1),
  start_ticks INTEGER NOT NULL CHECK (start_ticks > 0),
  ended INTEGER NOT NULL DEFAULT 0 CHECK (ended IN (0, 1))
) STRICT;

CREATE TRIGGER tr_file_effect_worker_insert_prepared BEFORE INSERT ON file_effect_worker
WHEN NEW.ended <> 0 OR NOT EXISTS (SELECT 1 FROM file_operation_journal j
                 WHERE j.command_id = NEW.command_id AND j.phase = 1 AND j.held = 1 AND j.kind IN (1, 2))
BEGIN
  SELECT RAISE(ABORT, 'file_worker_requires_prepared');
END;

CREATE TRIGGER tr_file_effect_worker_identity_immutable
BEFORE UPDATE OF command_id, boot_id, pid_namespace, process_id, start_ticks ON file_effect_worker
BEGIN
  SELECT RAISE(ABORT, 'file_worker_identity_immutable');
END;

CREATE TRIGGER tr_file_effect_worker_no_reactivate BEFORE UPDATE OF ended ON file_effect_worker
WHEN OLD.ended = 1 AND NEW.ended <> 1
BEGIN
  SELECT RAISE(ABORT, 'file_worker_ended');
END;

CREATE TRIGGER tr_file_effect_worker_no_delete BEFORE DELETE ON file_effect_worker
WHEN OLD.ended = 0
BEGIN
  SELECT RAISE(IGNORE);
END;

-- A compatible old writer cannot release the target while the worker may still act.
CREATE TRIGGER tr_file_effect_worker_hold BEFORE UPDATE OF held ON file_operation_journal
WHEN NEW.held = 0 AND EXISTS
  (SELECT 1 FROM file_effect_worker w WHERE w.command_id = NEW.command_id AND w.ended = 0)
BEGIN
  SELECT RAISE(ABORT, 'file_worker_still_running');
END;
