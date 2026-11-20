-- SPDX-License-Identifier: AGPL-3.0-only
CREATE TABLE remote_command_binding (
 owner_id TEXT NOT NULL, owner_epoch BLOB NOT NULL CHECK(length(owner_epoch)=16),
 command_id TEXT NOT NULL CHECK(length(command_id)=32 AND command_id NOT GLOB '*[^0-9a-f]*'),
 account_id TEXT NOT NULL CHECK(length(account_id)=32 AND account_id NOT GLOB '*[^0-9a-f]*'),
 actor_id TEXT NOT NULL CHECK(length(actor_id)=32 AND actor_id NOT GLOB '*[^0-9a-f]*'),
 enrollment_id TEXT NOT NULL CHECK(length(enrollment_id)=32 AND enrollment_id NOT GLOB '*[^0-9a-f]*'),
 protocol_epoch TEXT NOT NULL CHECK(length(protocol_epoch)=32 AND protocol_epoch NOT GLOB '*[^0-9a-f]*'),
 grant_id TEXT NOT NULL CHECK(length(grant_id)=32 AND grant_id NOT GLOB '*[^0-9a-f]*'),
 grant_revision INTEGER NOT NULL CHECK(grant_revision>0),
 scope_kind TEXT NOT NULL CHECK(scope_kind IN ('sandbox','provision')),
 sandbox_id TEXT CHECK(length(sandbox_id)=32 AND sandbox_id NOT GLOB '*[^0-9a-f]*'),
 PRIMARY KEY(owner_id,owner_epoch,command_id),
 FOREIGN KEY(owner_id,owner_epoch,command_id) REFERENCES command_receipt(owner_id,owner_epoch,command_id) ON DELETE CASCADE,
 CHECK((scope_kind='sandbox')=(sandbox_id IS NOT NULL))
) STRICT;
CREATE TRIGGER remote_command_binding_first_admission
 BEFORE INSERT ON remote_command_binding WHEN EXISTS (
  SELECT 1 FROM remote_command_binding
  WHERE owner_id=NEW.owner_id AND owner_epoch=NEW.owner_epoch AND command_id=NEW.command_id)
 OR NOT EXISTS (
  SELECT 1 FROM command_receipt AS c JOIN owner_epoch AS e USING(owner_id,owner_epoch)
  WHERE c.owner_id=NEW.owner_id AND c.owner_epoch=NEW.owner_epoch AND c.command_id=NEW.command_id
    AND c.state='ACCEPTED' AND e.state='ACTIVE' AND c.admission_sequence=e.admission_sequence)
 BEGIN SELECT RAISE(ABORT,'remote binding requires first command admission'); END;
CREATE TRIGGER remote_command_binding_immutable
 BEFORE UPDATE ON remote_command_binding
 BEGIN SELECT RAISE(ABORT,'admitted remote command binding is immutable'); END;
CREATE TRIGGER remote_command_binding_active_identity_retained
 BEFORE DELETE ON remote_command_binding WHEN EXISTS (
  SELECT 1 FROM owner_epoch WHERE owner_id=OLD.owner_id AND owner_epoch=OLD.owner_epoch AND state='ACTIVE')
 BEGIN SELECT RAISE(ABORT,'active owner epoch retains remote command binding'); END;
UPDATE schema_version SET version=18, min_reader=18 WHERE singleton=1;
