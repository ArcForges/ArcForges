-- AF-CTR-06: serialize a held file target across workspace aliases and compatible older writers.
-- The current writer may supply an in-memory, transaction-scoped witness only after the opened parent
-- and actual filesystem name lookup established that two existing objects are distinct. The witness
-- is not a persisted row, public input or general authority to perform an effect. A connection that
-- cannot provide this function cannot insert a file journal and fails closed.
CREATE TRIGGER tr_file_operation_journal__target_hold BEFORE INSERT ON file_operation_journal
WHEN NEW.held = 1 AND (
  (NEW.identity_platform = 1 AND
    (length(NEW.parent_identity) <> 33 OR substr(NEW.parent_identity, 1, 1) <> x'01' OR
     (NEW.target_identity IS NOT NULL AND (length(NEW.target_identity) <> 33 OR substr(NEW.target_identity, 1, 1) <> x'01')))) OR
  (NEW.identity_platform = 2 AND
    (length(NEW.parent_identity) <> 53 OR substr(NEW.parent_identity, 1, 1) <> x'01' OR
     (NEW.target_identity IS NOT NULL AND (length(NEW.target_identity) <> 53 OR substr(NEW.target_identity, 1, 1) <> x'01')))) OR
  EXISTS (
  SELECT 1 FROM file_operation_journal h
  WHERE h.held = 1 AND (
    h.kind = 3 OR NEW.kind = 3 OR h.identity_platform <> NEW.identity_platform OR
    (h.identity_platform = 1 AND
      (length(h.parent_identity) <> 33 OR substr(h.parent_identity, 1, 1) <> x'01' OR
       (h.target_identity IS NOT NULL AND (length(h.target_identity) <> 33 OR substr(h.target_identity, 1, 1) <> x'01')))) OR
    (h.identity_platform = 2 AND
      (length(h.parent_identity) <> 53 OR substr(h.parent_identity, 1, 1) <> x'01' OR
       (h.target_identity IS NOT NULL AND (length(h.target_identity) <> 53 OR substr(h.target_identity, 1, 1) <> x'01')))) OR
    (h.target_identity IS NOT NULL AND NEW.target_identity IS NOT NULL AND (
      (h.identity_platform = 1 AND substr(h.target_identity, 1, 25) = substr(NEW.target_identity, 1, 25)) OR
      (h.identity_platform = 2 AND substr(h.target_identity, 1, 9) = substr(NEW.target_identity, 1, 9)
       AND substr(h.target_identity, 22, 32) = substr(NEW.target_identity, 22, 32))
    )) OR
    ((
      (h.identity_platform = 1 AND substr(h.parent_identity, 1, 25) = substr(NEW.parent_identity, 1, 25)) OR
      (h.identity_platform = 2 AND substr(h.parent_identity, 1, 9) = substr(NEW.parent_identity, 1, 9)
       AND substr(h.parent_identity, 22, 32) = substr(NEW.parent_identity, 22, 32))
    ) AND (
      NEW.target_identity IS NULL OR h.relative_path IS NULL OR
      arcforges_file_hold_witness(NEW.command_id, h.command_id, NEW.workspace_id, NEW.relative_path,
        NEW.root_identity, NEW.parent_identity, NEW.target_identity, NEW.request_sha256, NEW.caller, NEW.kind) <> 1
    ))
  )
))
BEGIN
  SELECT RAISE(ABORT, 'file_recovery_pending');
END;

-- A completed or acknowledged operation cannot be repurposed as a fresh effect.
CREATE TRIGGER tr_file_operation_journal__no_reactivate BEFORE UPDATE OF held ON file_operation_journal
WHEN OLD.held = 0 AND NEW.held = 1
BEGIN
  SELECT RAISE(ABORT, 'file_recovery_pending');
END;
