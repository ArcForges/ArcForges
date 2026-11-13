-- AF-CTR-06: durable terminal fence for pre-effect staging and terminal rejected approvals.
-- No staged bytes or credential material is stored here; prior steps remain byte-for-byte unchanged.
CREATE TABLE file_private_stage_terminal (
  command_id BLOB NOT NULL PRIMARY KEY REFERENCES file_private_stage_reservation (command_id) CHECK (length(command_id) = 16),
  completed_at INTEGER NOT NULL,
  reason INTEGER NOT NULL CHECK (reason IN (1, 2, 3, 4)) -- unraised, denied, expired, cancelled
) STRICT;

CREATE TRIGGER tr_file_private_stage_terminal_no_update BEFORE UPDATE ON file_private_stage_terminal
BEGIN
  SELECT RAISE(ABORT, 'file_stage_fence_immutable');
END;

CREATE TRIGGER tr_file_private_stage_terminal_no_delete BEFORE DELETE ON file_private_stage_terminal
WHEN EXISTS (SELECT 1 FROM file_private_stage_reservation r WHERE r.command_id = OLD.command_id AND r.delete_permitted = 0)
BEGIN
  SELECT RAISE(IGNORE);
END;

-- Compatible older writers cannot reactivate or prepare an operation after recovery fenced its reservation.
CREATE TRIGGER tr_file_private_stage_fence_no_reactivate BEFORE UPDATE OF active ON file_private_stage_reservation
WHEN NEW.active = 1 AND EXISTS (SELECT 1 FROM file_private_stage_terminal a WHERE a.command_id = NEW.command_id)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_fenced');
END;

CREATE TRIGGER tr_file_private_stage_fence_no_journal BEFORE INSERT ON file_operation_journal
WHEN EXISTS (SELECT 1 FROM file_private_stage_terminal a WHERE a.command_id = NEW.command_id)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_fenced');
END;

CREATE TRIGGER tr_file_private_stage_fence_no_approval BEFORE INSERT ON file_private_approval_binding
WHEN EXISTS (SELECT 1 FROM file_private_stage_terminal a WHERE a.command_id = NEW.command_id)
BEGIN
  SELECT RAISE(ABORT, 'file_stage_fenced');
END;
