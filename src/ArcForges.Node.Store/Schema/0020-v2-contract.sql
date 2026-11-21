-- SPDX-License-Identifier: AGPL-3.0-only
-- Withdrawn physical schemas. The writer applies this step only to a fresh store or
-- to a privately owned migration copy with a verified independent archive.

-- The shared local command namespace still rejects reuse of these original protected IDs.
CREATE TABLE contracted_command_hold (
  command_id BLOB NOT NULL PRIMARY KEY CHECK (length(command_id) = 16),
  FOREIGN KEY (command_id) REFERENCES command_dedup(command_id) ON DELETE RESTRICT
) STRICT;
INSERT INTO contracted_command_hold (command_id) SELECT command_id FROM routed_file_command_retention;
CREATE TRIGGER contracted_command_hold_immutable_update BEFORE UPDATE ON contracted_command_hold
BEGIN
  SELECT RAISE(ABORT, 'original command hold is immutable');
END;
CREATE TRIGGER contracted_command_hold_immutable_delete BEFORE DELETE ON contracted_command_hold
BEGIN
  SELECT RAISE(ABORT, 'original command hold is immutable');
END;
CREATE TRIGGER contracted_command_hold_command_update BEFORE UPDATE ON command_dedup
WHEN EXISTS (SELECT 1 FROM contracted_command_hold WHERE command_id = OLD.command_id)
BEGIN
  SELECT RAISE(ABORT, 'original held command is immutable');
END;

-- Legacy triggers on shared tables must be removed before their referenced objects.
DROP TRIGGER tr_file_audit_retention_guard_delete;
DROP TRIGGER tr_file_audit_retention_release;
DROP TRIGGER tr_file_command_retention_guard_delete;
DROP TRIGGER tr_file_command_retention_guard_insert;
DROP TRIGGER tr_file_command_retention_guard_update;
DROP TRIGGER tr_file_command_retention_insert;
DROP TRIGGER tr_file_command_retention_release;
DROP TRIGGER tr_file_operation_journal__guard_command_delete;
DROP TRIGGER tr_file_owner_audit_retention_insert;
DROP TRIGGER tr_file_private_stage_guard_command_delete;

DROP VIEW file_stage_capacity_totals;
DROP VIEW file_stage_capacity_totals_v15;
DROP VIEW file_stage_reserved_identity;

-- Drop children before parents. Shared tables have no foreign keys into these tables.
DROP TABLE account_link;
DROP TABLE attempt_cache_usage;
DROP TABLE cache_stat;
DROP TABLE cache_store_ledger;
DROP TABLE cache_walk;
DROP TABLE cas_blob;
DROP TABLE fact;
DROP TABLE file_attempt_temp_identity;
DROP TABLE file_creation_ownership;
DROP TABLE file_digest_cache;
DROP TABLE file_effect_worker;
DROP TABLE file_ownership_generation;
DROP TABLE file_private_approval_binding;
DROP TABLE file_private_stage_layout;
DROP TABLE file_private_stage_object;
DROP TABLE file_private_stage_terminal;
DROP TABLE file_removal_command_owner;
DROP TABLE file_removal_plan;
DROP TABLE file_removal_plan_item;
DROP TABLE file_stage_worker;
DROP TABLE file_workspace_audit_observation;
DROP TABLE guest_grant;
DROP TABLE guest_link;
DROP TABLE hook_event;
DROP TABLE host_link;
DROP TABLE integration_write;
DROP TABLE manifest;
DROP TABLE pairing;
DROP TABLE phase_event;
DROP TABLE phone_pairing;
DROP TABLE probe_result;
DROP TABLE probe_ticket;
DROP TABLE process_record;
DROP TABLE push_outbox;
DROP TABLE quarantine_entry;
DROP TABLE remote_attempt;
DROP TABLE remote_command_log;
DROP TABLE resource_sample;
DROP TABLE result_cache_observation;
DROP TABLE root_location;
DROP TABLE routed_call_log;
DROP TABLE routed_file_audit_retention;
DROP TABLE routed_file_call_log;
DROP TABLE routed_file_call_retention;
DROP TABLE routed_file_command_retention;
DROP TABLE routed_file_validation_time;
DROP TABLE routed_verified_call_id;
DROP TABLE session_subagent;
DROP TABLE sign_in_flow;
DROP TABLE size_cache;
DROP TABLE storage_analysis_item;
DROP TABLE support_bundle;
DROP TABLE task_concurrency_key;
DROP TABLE task_dependency;
DROP TABLE task_secret;
DROP TABLE timeline_segment;
DROP TABLE toolchain;
DROP TABLE update_state;
DROP TABLE workspace_inventory_revision;
DROP TABLE workspace_root_identity;
DROP TABLE worktree_archive;
DROP TABLE attempt;
DROP TABLE cache_instance;
DROP TABLE cache_usage_window;
DROP TABLE cleanup_item;
DROP TABLE file_operation_journal;
DROP TABLE file_ownership_object_generation;
DROP TABLE file_private_stage_reservation;
DROP TABLE file_stage_produced_object;
DROP TABLE file_workspace_audit;
DROP TABLE integration_plan;
DROP TABLE managed_directory;
DROP TABLE offer;
DROP TABLE cleanup_plan;
DROP TABLE file_stage_production;
DROP TABLE peer;
DROP TABLE task;
DROP TABLE env_snapshot;
DROP TABLE session;
DROP TABLE storage_analysis;
DROP TABLE workspace;

UPDATE schema_version SET version = 20, min_reader = 20 WHERE singleton = 1;
