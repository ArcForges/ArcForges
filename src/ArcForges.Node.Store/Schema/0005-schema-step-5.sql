-- AF-CTR-06 workspace inventory cursors: a monotonic generation changes with catalogue metadata,
-- including writes made by an older compatible node. Access timestamps and revision-only use updates
-- deliberately do not invalidate an inventory page.
CREATE TABLE workspace_inventory_revision (
  singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
  revision INTEGER NOT NULL CHECK (revision >= 0)
) STRICT;
INSERT INTO workspace_inventory_revision (singleton, revision) VALUES (1, 0);

CREATE TRIGGER tr_workspace_inventory_insert AFTER INSERT ON workspace
BEGIN
  UPDATE workspace_inventory_revision SET revision = revision + 1 WHERE singleton = 1;
END;
CREATE TRIGGER tr_workspace_inventory_delete AFTER DELETE ON workspace
BEGIN
  UPDATE workspace_inventory_revision SET revision = revision + 1 WHERE singleton = 1;
END;
CREATE TRIGGER tr_workspace_inventory_update AFTER UPDATE OF workspace_id, kind, state, name, root_path,
  repository_identity, base_workspace_id, base_ref, branch, owner, origin_node_id, origin_workspace_key,
  routing_mode, concurrency_mode, remote_slot, leased_by_attempt_id, created_at, removed_at ON workspace
BEGIN
  UPDATE workspace_inventory_revision SET revision = revision + 1 WHERE singleton = 1;
END;
