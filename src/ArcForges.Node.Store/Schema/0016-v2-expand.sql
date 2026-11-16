-- SPDX-License-Identifier: AGPL-3.0-only
-- AFV2-DATA-01 forward expand; target source493022fb, exact adaptation recorded in eng/v2-migration.
-- All V1 tables and applied0001..0015 remain intact. V2 resource_sample uses v2_resource_sample.
CREATE TABLE schema_version (
 singleton INTEGER PRIMARY KEY CHECK (singleton=1), version INTEGER NOT NULL,
 min_reader INTEGER NOT NULL, cohort TEXT NOT NULL, migration_receipt TEXT NOT NULL
) STRICT;
-- Persistent durable-mutation identity, unrelated to Node event or Run epochs.
-- digest_key_ref names protected HMAC key material; the key itself is not in SQL.
CREATE TABLE owner_epoch (
 owner_id TEXT NOT NULL, owner_epoch BLOB NOT NULL CHECK(length(owner_epoch)=16),
 digest_key_ref TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('ACTIVE','RETIRED')),
 created_utc TEXT NOT NULL, retired_utc TEXT,
 admission_sequence INTEGER NOT NULL DEFAULT 0 CHECK(admission_sequence>=0),
 history_hmac_sha256 TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' CHECK(length(history_hmac_sha256)=64),
 PRIMARY KEY(owner_id,owner_epoch),
 CHECK((state='ACTIVE' AND retired_utc IS NULL) OR (state='RETIRED' AND retired_utc IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX owner_epoch_one_active ON owner_epoch(owner_id) WHERE state='ACTIVE';
-- BEFORE INSERT guards also reject INSERT OR REPLACE; its implicit delete must
-- not become a way to rotate or rekey authority when recursive triggers are off.
CREATE TRIGGER owner_epoch_no_replacement
 BEFORE INSERT ON owner_epoch WHEN EXISTS (
  SELECT 1 FROM owner_epoch e WHERE e.owner_id=NEW.owner_id
   AND (e.owner_epoch=NEW.owner_epoch OR (e.state='ACTIVE' AND NEW.state='ACTIVE')))
 BEGIN SELECT RAISE(ABORT,'owner epoch cannot be implicitly replaced'); END;
CREATE TRIGGER owner_epoch_identity_immutable
 BEFORE UPDATE OF owner_id,owner_epoch,digest_key_ref,created_utc ON owner_epoch
 BEGIN SELECT RAISE(ABORT,'owner epoch identity is immutable'); END;
CREATE TRIGGER owner_epoch_retirement_final
 BEFORE UPDATE ON owner_epoch WHEN OLD.state='RETIRED'
 BEGIN SELECT RAISE(ABORT,'retired owner epoch cannot be reactivated'); END;
CREATE TRIGGER owner_epoch_no_delete
 BEFORE DELETE ON owner_epoch
 BEGIN SELECT RAISE(ABORT,'owner epoch metadata is retained'); END;
CREATE TABLE sandbox (
 sandbox_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, display_name TEXT NOT NULL,
 normalized_name TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
 state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 6), root_relative TEXT NOT NULL UNIQUE,
 root_identity TEXT NOT NULL, root_generation INTEGER NOT NULL CHECK(root_generation>0),
 created_utc TEXT NOT NULL, updated_utc TEXT NOT NULL,
 UNIQUE(owner_id, normalized_name)
) STRICT;
CREATE TABLE sandbox_config (
 sandbox_id TEXT NOT NULL REFERENCES sandbox(sandbox_id), revision INTEGER NOT NULL,
 profile_id TEXT NOT NULL, profile_version TEXT NOT NULL, config_json TEXT NOT NULL CHECK(json_valid(config_json)),
 config_sha256 TEXT NOT NULL CHECK(length(config_sha256)=64), created_utc TEXT NOT NULL,
 PRIMARY KEY(sandbox_id, revision)
) STRICT;
CREATE TABLE run (
 run_id TEXT PRIMARY KEY, sandbox_id TEXT NOT NULL REFERENCES sandbox(sandbox_id),
 sandbox_revision INTEGER NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
 state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 7), epoch TEXT NOT NULL,
 launch_sha256 TEXT NOT NULL CHECK(length(launch_sha256)=64), snapshot_json TEXT NOT NULL CHECK(json_valid(snapshot_json)),
 payload_started INTEGER NOT NULL CHECK(payload_started BETWEEN 1 AND 3),
 created_utc TEXT NOT NULL, started_utc TEXT, ended_utc TEXT,
 raw_exit_code INTEGER, exit_source TEXT, termination_reason TEXT,
 effect_certainty INTEGER NOT NULL CHECK(effect_certainty BETWEEN 1 AND 3),
 FOREIGN KEY(sandbox_id,sandbox_revision) REFERENCES sandbox_config(sandbox_id,revision)
) STRICT;
CREATE INDEX run_by_sandbox_state ON run(sandbox_id,state,created_utc);
CREATE TABLE supervisor_identity (
 run_id TEXT PRIMARY KEY REFERENCES run(run_id), instance_id TEXT NOT NULL, boot_id TEXT NOT NULL,
 process_id INTEGER NOT NULL, creation_identity TEXT NOT NULL, endpoint TEXT NOT NULL,
 boundary_identity TEXT NOT NULL, backend_id TEXT NOT NULL, cohort TEXT NOT NULL,
 control_epoch TEXT NOT NULL, last_seen_utc TEXT NOT NULL
) STRICT;
CREATE TABLE command_receipt (
 owner_id TEXT NOT NULL, owner_epoch BLOB NOT NULL CHECK(length(owner_epoch)=16), command_id TEXT NOT NULL,
 method TEXT NOT NULL CHECK(method NOT IN ('RunService.AcquireTerminal','RunService.WriteTerminal',
                                         'RunService.ResizeTerminal','RunService.DetachTerminal')),
 request_hmac_sha256 TEXT NOT NULL CHECK(length(request_hmac_sha256)=64),
 aggregate_kind TEXT, aggregate_id TEXT,
 state TEXT NOT NULL CHECK(state IN ('ACCEPTED','SUCCEEDED','FAILED','UNKNOWN')),
 effect_certainty INTEGER NOT NULL CHECK(effect_certainty BETWEEN 1 AND 3),
 response_json TEXT CHECK(response_json IS NULL OR json_valid(response_json)),
 created_utc TEXT NOT NULL, updated_utc TEXT NOT NULL, resolved_utc TEXT,
 admission_sequence INTEGER NOT NULL CHECK(admission_sequence>0),
 safety_parent_command_id TEXT, reserved_response BLOB NOT NULL DEFAULT X'',
 expires_utc TEXT, response_compacted_utc TEXT,
 PRIMARY KEY(owner_id,owner_epoch,command_id),
 FOREIGN KEY(owner_id,owner_epoch) REFERENCES owner_epoch(owner_id,owner_epoch),
 CHECK((aggregate_kind IS NULL)=(aggregate_id IS NULL)),
 CHECK((state IN ('ACCEPTED','UNKNOWN') OR effect_certainty=3)
       AND resolved_utc IS NULL AND expires_utc IS NULL AND response_compacted_utc IS NULL
       OR (state IN ('SUCCEEDED','FAILED') AND effect_certainty IN (1,2) AND resolved_utc IS NOT NULL)),
 CHECK(response_json IS NOT NULL OR response_compacted_utc IS NOT NULL),
 CHECK(response_compacted_utc IS NULL OR
       (response_json IS NULL AND expires_utc IS NOT NULL AND julianday(response_compacted_utc) IS NOT NULL
        AND julianday(response_compacted_utc)>=julianday(expires_utc))),
 CHECK(expires_utc IS NULL OR
       (julianday(resolved_utc) IS NOT NULL AND julianday(expires_utc) IS NOT NULL
        AND julianday(expires_utc)>=julianday(resolved_utc)+1.0))
) STRICT;
-- expires_utc permits known response-body compaction only, at least 24 h after
-- resolved_utc. The admitted identity/keyed digest/effect/aggregate never expires
-- while the owner epoch is ACTIVE. These guards are not an epoch-retirement API.
CREATE TRIGGER command_receipt_active_epoch
 BEFORE INSERT ON command_receipt WHEN NOT EXISTS (
  SELECT 1 FROM owner_epoch WHERE owner_id=NEW.owner_id AND owner_epoch=NEW.owner_epoch AND state='ACTIVE')
 BEGIN SELECT RAISE(ABORT,'owner epoch is retired or unknown'); END;
CREATE TRIGGER command_receipt_no_replacement
 BEFORE INSERT ON command_receipt WHEN EXISTS (
  SELECT 1 FROM command_receipt r WHERE r.owner_id=NEW.owner_id AND r.owner_epoch=NEW.owner_epoch
   AND r.command_id=NEW.command_id)
 BEGIN SELECT RAISE(ABORT,'admitted command identity already exists'); END;
CREATE TRIGGER command_receipt_identity_immutable
 BEFORE UPDATE OF owner_id,owner_epoch,command_id,method,request_hmac_sha256,aggregate_kind,aggregate_id,created_utc
 ON command_receipt
 BEGIN SELECT RAISE(ABORT,'admitted command identity is immutable'); END;
CREATE TRIGGER command_receipt_known_result_immutable
 BEFORE UPDATE OF state,effect_certainty ON command_receipt
 WHEN OLD.state IN ('SUCCEEDED','FAILED') AND OLD.effect_certainty IN (1,2)
      AND (NEW.state<>OLD.state OR NEW.effect_certainty<>OLD.effect_certainty)
 BEGIN SELECT RAISE(ABORT,'known command outcome is immutable'); END;
CREATE TRIGGER command_receipt_active_identity_retained
 BEFORE DELETE ON command_receipt WHEN EXISTS (
  SELECT 1 FROM owner_epoch WHERE owner_id=OLD.owner_id AND owner_epoch=OLD.owner_epoch AND state='ACTIVE')
 BEGIN SELECT RAISE(ABORT,'active owner epoch retains command identity'); END;
CREATE TABLE resource_policy (
 scope_kind TEXT NOT NULL CHECK(scope_kind IN ('node','sandbox','run')), scope_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0), policy_json TEXT NOT NULL CHECK(json_valid(policy_json)),
 PRIMARY KEY(scope_kind,scope_id)
) STRICT;
CREATE TABLE limit_application (
 run_id TEXT NOT NULL REFERENCES run(run_id), dimension TEXT NOT NULL, unit TEXT NOT NULL,
 desired_revision INTEGER NOT NULL, desired_value TEXT NOT NULL, applied_value TEXT, readback_value TEXT,
 applied_utc TEXT, readback_utc TEXT, state TEXT NOT NULL CHECK(state IN ('pending','effective','degraded','failed','unsupported')),
 reason TEXT NOT NULL, boundary_identity TEXT NOT NULL, PRIMARY KEY(run_id,dimension)
) STRICT;
CREATE TABLE v2_resource_sample (
 scope_kind TEXT NOT NULL, scope_id TEXT NOT NULL, observed_utc TEXT NOT NULL,
 epoch TEXT NOT NULL, sample_json TEXT NOT NULL CHECK(json_valid(sample_json)),
 PRIMARY KEY(scope_kind,scope_id,observed_utc)
) STRICT;
CREATE TABLE output_segment (
 run_id TEXT NOT NULL REFERENCES run(run_id), epoch TEXT NOT NULL,
 offset_start INTEGER NOT NULL CHECK(offset_start>=0), length_bytes INTEGER NOT NULL CHECK(length_bytes>=0),
 relative_path TEXT NOT NULL, stream_kind TEXT NOT NULL CHECK(stream_kind IN ('terminal','stdout','stderr')),
 created_utc TEXT NOT NULL, PRIMARY KEY(run_id,epoch,offset_start,stream_kind)
) STRICT;
CREATE TABLE remote_grant (
 grant_id TEXT PRIMARY KEY, sandbox_id TEXT REFERENCES sandbox(sandbox_id),
 scope_kind TEXT NOT NULL CHECK(scope_kind IN ('sandbox','provision')), parent_grant_id TEXT REFERENCES remote_grant(grant_id),
 template_revision INTEGER, creation_template_json TEXT CHECK(creation_template_json IS NULL OR json_valid(creation_template_json)),
 enrollment_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
 state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 3), policy_json TEXT NOT NULL CHECK(json_valid(policy_json)),
 created_local_utc TEXT NOT NULL, expires_utc TEXT, revoked_utc TEXT,
 CHECK((scope_kind='sandbox' AND sandbox_id IS NOT NULL) OR (scope_kind='provision' AND sandbox_id IS NULL AND creation_template_json IS NOT NULL AND template_revision>0))
) STRICT;
CREATE TABLE transfer (
 transfer_id TEXT PRIMARY KEY, sandbox_id TEXT NOT NULL REFERENCES sandbox(sandbox_id),
 owner_id TEXT NOT NULL, owner_epoch BLOB NOT NULL CHECK(length(owner_epoch)=16), command_id TEXT NOT NULL,
 direction TEXT NOT NULL CHECK(direction IN ('import','export')),
 state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 5), manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
 staging_identity TEXT NOT NULL, byte_length INTEGER NOT NULL CHECK(byte_length>=0),
 verified_offset INTEGER NOT NULL CHECK(verified_offset>=0), expected_sha256 TEXT NOT NULL,
 expires_utc TEXT NOT NULL, closed_utc TEXT,
 close_reason TEXT CHECK(close_reason IN ('explicit_close','expiry')),
 effect_certainty INTEGER NOT NULL CHECK(effect_certainty BETWEEN 1 AND 3),
 FOREIGN KEY(owner_id,owner_epoch,command_id) REFERENCES command_receipt(owner_id,owner_epoch,command_id),
 CHECK((closed_utc IS NULL)=(close_reason IS NULL)),
 CHECK(closed_utc IS NULL OR (state IN (3,4) AND effect_certainty<>3))
) STRICT;
CREATE TABLE deletion_journal (
 deletion_id TEXT PRIMARY KEY, sandbox_id TEXT NOT NULL REFERENCES sandbox(sandbox_id),
 owner_id TEXT NOT NULL, owner_epoch BLOB NOT NULL CHECK(length(owner_epoch)=16),
 command_id TEXT NOT NULL, latest_resume_command_id TEXT, latest_resume_expected_revision INTEGER,
 expected_revision INTEGER NOT NULL, root_identity TEXT NOT NULL,
 quarantine_identity TEXT, phase TEXT NOT NULL CHECK(phase IN ('planned','locked','quarantined','removing','complete','recovery_required')),
 effect_certainty INTEGER NOT NULL CHECK(effect_certainty BETWEEN 1 AND 3), updated_utc TEXT NOT NULL,
 FOREIGN KEY(owner_id,owner_epoch,command_id) REFERENCES command_receipt(owner_id,owner_epoch,command_id),
 FOREIGN KEY(owner_id,owner_epoch,latest_resume_command_id) REFERENCES command_receipt(owner_id,owner_epoch,command_id),
 UNIQUE(owner_id,owner_epoch,command_id),
 CHECK((latest_resume_command_id IS NULL)=(latest_resume_expected_revision IS NULL))
) STRICT;
CREATE TRIGGER deletion_journal_no_replacement
 BEFORE INSERT ON deletion_journal WHEN EXISTS (
  SELECT 1 FROM deletion_journal d WHERE d.deletion_id=NEW.deletion_id
   OR (d.owner_id=NEW.owner_id AND d.owner_epoch=NEW.owner_epoch AND d.command_id=NEW.command_id))
 BEGIN SELECT RAISE(ABORT,'original deletion journal already exists'); END;
CREATE TRIGGER deletion_journal_original_identity_immutable
 BEFORE UPDATE OF deletion_id,sandbox_id,owner_id,owner_epoch,command_id,expected_revision,root_identity
 ON deletion_journal
 BEGIN SELECT RAISE(ABORT,'original deletion identity is immutable'); END;
CREATE TRIGGER command_receipt_unresolved_effect_body_retained
 BEFORE UPDATE OF response_json,response_compacted_utc ON command_receipt
 WHEN NEW.response_compacted_utc IS NOT NULL AND (
  EXISTS (SELECT 1 FROM transfer t WHERE t.owner_id=OLD.owner_id AND t.owner_epoch=OLD.owner_epoch
          AND t.command_id=OLD.command_id AND (t.state IN (1,2,5) OR t.effect_certainty=3))
  OR EXISTS (SELECT 1 FROM deletion_journal d WHERE d.owner_id=OLD.owner_id AND d.owner_epoch=OLD.owner_epoch
             AND (d.command_id=OLD.command_id OR d.latest_resume_command_id=OLD.command_id)
             AND (d.phase<>'complete' OR d.effect_certainty=3)))
 BEGIN SELECT RAISE(ABORT,'unresolved effect retains its receipt body'); END;
CREATE TABLE event (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, epoch TEXT NOT NULL, kind TEXT NOT NULL,
 aggregate_id TEXT NOT NULL, revision INTEGER NOT NULL, created_utc TEXT NOT NULL,
 body_json TEXT NOT NULL CHECK(json_valid(body_json))
) STRICT;
CREATE TABLE audit (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT NOT NULL, origin TEXT NOT NULL,
 command_id TEXT, method TEXT NOT NULL, aggregate_id TEXT, effect_certainty INTEGER NOT NULL,
 reason_code TEXT NOT NULL, created_utc TEXT NOT NULL, metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json))
) STRICT;
CREATE TABLE migration_checkpoint (
 migration_id TEXT PRIMARY KEY, source_schema INTEGER NOT NULL, target_schema INTEGER NOT NULL,
 backup_identity TEXT NOT NULL, state TEXT NOT NULL, cohort TEXT NOT NULL,
 unresolved_count INTEGER NOT NULL CHECK(unresolved_count>=0), receipt_sha256 TEXT NOT NULL,
 created_utc TEXT NOT NULL
) STRICT;

-- Store admission budget and a preallocated SQLite safety lane; no raw input is stored.
CREATE TABLE owner_epoch_capacity (
 owner_id TEXT NOT NULL, owner_epoch BLOB NOT NULL, maximum_receipts INTEGER NOT NULL CHECK(maximum_receipts>0),
 safety_receipts INTEGER NOT NULL CHECK(safety_receipts>0 AND safety_receipts<maximum_receipts),
 maximum_response_bytes INTEGER NOT NULL CHECK(maximum_response_bytes BETWEEN 1024 AND 1048576),
 maximum_journal_bytes INTEGER NOT NULL CHECK(maximum_journal_bytes>0),
 reserve_storage BLOB NOT NULL, PRIMARY KEY(owner_id,owner_epoch),
 FOREIGN KEY(owner_id,owner_epoch) REFERENCES owner_epoch(owner_id,owner_epoch)
) STRICT;
CREATE UNIQUE INDEX command_receipt_sequence ON command_receipt(owner_id,owner_epoch,admission_sequence);
CREATE UNIQUE INDEX command_receipt_one_safety_intent ON command_receipt(owner_id,owner_epoch,safety_parent_command_id)
 WHERE safety_parent_command_id IS NOT NULL;

-- A settled response can only lose its body through eligible compaction, never acquire a different result/window.
CREATE TRIGGER command_receipt_known_body_immutable
 BEFORE UPDATE OF response_json ON command_receipt
 WHEN OLD.state IN ('SUCCEEDED','FAILED') AND OLD.effect_certainty IN (1,2)
  AND NEW.response_json IS NOT OLD.response_json AND NEW.response_json IS NOT NULL
 BEGIN SELECT RAISE(ABORT,'known command body is immutable'); END;
CREATE TRIGGER command_receipt_known_window_immutable
 BEFORE UPDATE OF resolved_utc,expires_utc ON command_receipt
 WHEN OLD.state IN ('SUCCEEDED','FAILED') AND OLD.effect_certainty IN (1,2)
  AND (NEW.resolved_utc IS NOT OLD.resolved_utc OR NEW.expires_utc IS NOT OLD.expires_utc)
 BEGIN SELECT RAISE(ABORT,'known command retention window is immutable'); END;
