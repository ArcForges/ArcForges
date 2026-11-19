-- SPDX-License-Identifier: AGPL-3.0-only
CREATE TABLE run_recovery (
 run_id TEXT PRIMARY KEY REFERENCES run(run_id),
 run_epoch TEXT NOT NULL CHECK(length(run_epoch)=32),
 boot_id TEXT NOT NULL CHECK(length(boot_id) BETWEEN 1 AND 256),
 supervisor_path TEXT NOT NULL CHECK(length(supervisor_path) BETWEEN 1 AND 32767),
 supervisor_sha256 TEXT NOT NULL CHECK(length(supervisor_sha256)=64),
 installation_root TEXT NOT NULL CHECK(length(installation_root) BETWEEN 1 AND 32767),
 prepare_started INTEGER NOT NULL DEFAULT 0 CHECK(prepare_started IN (0,1)),
 control_generation INTEGER NOT NULL DEFAULT 0 CHECK(control_generation>=0)
) STRICT;
CREATE TABLE run_stop_intent (
 run_id TEXT PRIMARY KEY REFERENCES run(run_id),
 run_epoch TEXT NOT NULL CHECK(length(run_epoch)=32),
 owner_id TEXT NOT NULL, owner_epoch BLOB NOT NULL CHECK(length(owner_epoch)=16),
 command_id TEXT NOT NULL CHECK(length(command_id)=32),
 accepted_utc TEXT NOT NULL, deadline_utc TEXT NOT NULL CHECK(deadline_utc>=accepted_utc),
 pressure INTEGER NOT NULL CHECK(pressure IN (0,1)),
 FOREIGN KEY(owner_id,owner_epoch,command_id) REFERENCES command_receipt(owner_id,owner_epoch,command_id)
) STRICT;
UPDATE schema_version SET version=17, min_reader=17 WHERE singleton=1;
