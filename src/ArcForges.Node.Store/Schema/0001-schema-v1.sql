-- ArcForges node store, schema version 1 (specification; see node-store.md).
-- SQLite 3.37+ (STRICT tables), WAL journal, foreign_keys=ON, synchronous=NORMAL (FULL for command_dedup commits).
-- Conventions:
--   ids        BLOB(16) UUIDv7, CHECK (length(x) = 16)
--   instants   INTEGER microseconds since the Unix epoch (same unit as the Cloud D1 physical model)
--   enums      INTEGER = the arcforges.node.v1 proto enum number (0 never stored)
--   payloads   BLOB = serialized arcforges.node.v1 / peer.v1 / fleet.v1 messages named per column
--   json       TEXT with json_valid checks, only for small, display-only structures
--   rev        INTEGER >= 0, incremented on every update (optimistic concurrency, Revision in contracts)

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------ store

CREATE TABLE store_meta (
  singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
  min_reader_version INTEGER NOT NULL CHECK (min_reader_version >= 1 AND min_reader_version <= schema_version),
  node_id BLOB NOT NULL CHECK (length(node_id) = 16),
  node_role INTEGER NOT NULL CHECK (node_role IN (1, 2)),
  created_at INTEGER NOT NULL,
  boot_identity TEXT NOT NULL,
  clean_shutdown_at INTEGER,
  journal_generation INTEGER NOT NULL CHECK (journal_generation >= 1)
) STRICT;

CREATE TABLE node_setting (
  name TEXT NOT NULL PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 100),
  value_json TEXT NOT NULL CHECK (json_valid(value_json)),
  updated_at INTEGER NOT NULL,
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;

CREATE TABLE policy_document (
  revision INTEGER NOT NULL PRIMARY KEY CHECK (revision >= 1),
  document BLOB NOT NULL,                       -- PolicyDocument
  digest BLOB NOT NULL CHECK (length(digest) = 32),
  created_at INTEGER NOT NULL,
  actor BLOB NOT NULL,                          -- ActorRef
  comment TEXT CHECK (comment IS NULL OR length(comment) <= 500),
  approval_id BLOB CHECK (approval_id IS NULL OR length(approval_id) = 16),
  is_current INTEGER NOT NULL CHECK (is_current IN (0, 1))
) STRICT;
CREATE UNIQUE INDEX ux_policy_document__current ON policy_document (is_current) WHERE is_current = 1;

CREATE TABLE command_dedup (
  command_id BLOB NOT NULL PRIMARY KEY CHECK (length(command_id) = 16),
  method TEXT NOT NULL,
  payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
  origin INTEGER NOT NULL,
  outcome BLOB,                                 -- serialized <Method>Response; NULL while executing
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX ix_command_dedup__expires_at ON command_dedup (expires_at);

CREATE TABLE event_journal (
  seq INTEGER NOT NULL PRIMARY KEY,
  generation INTEGER NOT NULL,
  at INTEGER NOT NULL,
  topic INTEGER NOT NULL,                       -- EventTopic
  payload BLOB NOT NULL                         -- NodeEvent
) STRICT;
CREATE INDEX ix_event_journal__at ON event_journal (at);

CREATE TABLE audit_log (
  seq INTEGER NOT NULL PRIMARY KEY,
  at INTEGER NOT NULL,
  actor BLOB NOT NULL,                          -- ActorRef
  operation TEXT NOT NULL,
  target_kind TEXT,
  target_id BLOB,
  decision INTEGER NOT NULL,                    -- PermissionDecision applied
  approval_id BLOB CHECK (approval_id IS NULL OR length(approval_id) = 16),
  remote_command_id BLOB CHECK (remote_command_id IS NULL OR length(remote_command_id) = 16),
  outcome_summary TEXT NOT NULL
) STRICT;
CREATE INDEX ix_audit_log__at ON audit_log (at);

CREATE TABLE job (
  job_id BLOB NOT NULL PRIMARY KEY CHECK (length(job_id) = 16),
  kind INTEGER NOT NULL,                        -- JobKind
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),
  progress_percent INTEGER NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
  progress_text TEXT,
  task_id BLOB CHECK (task_id IS NULL OR length(task_id) = 16),
  requested_by BLOB NOT NULL,                   -- ActorRef
  command_id BLOB CHECK (command_id IS NULL OR length(command_id) = 16),
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  error BLOB,                                   -- ArcError
  result_kind TEXT,
  result_id BLOB,
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;
CREATE INDEX ix_job__state_created ON job (state, created_at);

-- ------------------------------------------------------------- workspaces

CREATE TABLE workspace (
  workspace_id BLOB NOT NULL PRIMARY KEY CHECK (length(workspace_id) = 16),
  kind INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),      -- WorkspaceKind
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 7), -- WorkspaceState (7 ARCHIVING)
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  root_path TEXT NOT NULL,
  repository_identity TEXT,
  base_workspace_id BLOB REFERENCES workspace (workspace_id) ON DELETE RESTRICT,
  base_ref TEXT,
  branch TEXT,
  owner BLOB,                                   -- ActorRef
  origin_node_id BLOB CHECK (origin_node_id IS NULL OR length(origin_node_id) = 16),
  origin_workspace_key TEXT,
  routing_mode INTEGER NOT NULL DEFAULT 0,      -- RoutingMode; 0 = inherit
  concurrency_mode INTEGER NOT NULL DEFAULT 0 CHECK (concurrency_mode BETWEEN 0 AND 3),  -- WorkspaceConcurrency; 0 = inherit (ADAPTER_KEYS)
  remote_slot INTEGER CHECK (remote_slot IS NULL OR remote_slot >= 1),  -- REMOTE: slot number under the origin workspace (09 section 6)
  leased_by_attempt_id BLOB CHECK (leased_by_attempt_id IS NULL OR length(leased_by_attempt_id) = 16),  -- REMOTE: the remote attempt holding the slot; NULL = free
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  removed_at INTEGER,
  rev INTEGER NOT NULL CHECK (rev >= 0),
  CHECK (kind <> 2 OR (base_workspace_id IS NOT NULL AND branch IS NOT NULL)),
  CHECK (kind <> 3 OR (origin_node_id IS NOT NULL AND origin_workspace_key IS NOT NULL AND remote_slot IS NOT NULL)),
  CHECK (kind = 3 OR (remote_slot IS NULL AND leased_by_attempt_id IS NULL))
) STRICT;
CREATE UNIQUE INDEX ux_workspace__root_active ON workspace (root_path) WHERE removed_at IS NULL;
CREATE UNIQUE INDEX ux_workspace__branch_active ON workspace (base_workspace_id, branch) WHERE kind = 2 AND removed_at IS NULL;
CREATE UNIQUE INDEX ux_workspace__remote_slot ON workspace (origin_node_id, origin_workspace_key, remote_slot) WHERE kind = 3 AND removed_at IS NULL;
CREATE UNIQUE INDEX ux_workspace__slot_lease ON workspace (leased_by_attempt_id) WHERE leased_by_attempt_id IS NOT NULL;

CREATE TABLE worktree_archive (
  archive_id BLOB NOT NULL PRIMARY KEY CHECK (length(archive_id) = 16),
  workspace_id BLOB NOT NULL CHECK (length(workspace_id) = 16),  -- the removed managed worktree; no foreign key, its row is purged first
  base_workspace_id BLOB NOT NULL CHECK (length(base_workspace_id) = 16),  -- repository holding refs/arcforges/archive/<archive_id>/*
  branch TEXT,
  head_commit TEXT NOT NULL,
  index_commit TEXT NOT NULL,                   -- I: the staged state
  worktree_commit TEXT NOT NULL,                -- W: tracked and untracked (not ignored) files, parent I
  bundle_path TEXT NOT NULL,                    -- records/worktree-archives/<archive_id>.bundle
  ignored_archive_path TEXT,                    -- ignored files the user chose to include
  ignored_decision INTEGER NOT NULL DEFAULT 0 CHECK (ignored_decision IN (0, 1, 2)),  -- IgnoredFilesDecision; 0 = none listed
  raw_archive_path TEXT,                        -- files kept byte for byte (filters, LFS)
  intent_to_add_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(intent_to_add_json)),  -- paths re-applied with git add -N
  file_count INTEGER NOT NULL CHECK (file_count >= 0),
  size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
  created_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL,                 -- written only after the bundle round trip matched (06 section 3)
  expires_at INTEGER NOT NULL,                  -- created_at + 90 days
  last_restored_at INTEGER,
  removed_at INTEGER                            -- retention removed the refs and the bundle
) STRICT;
CREATE INDEX ix_worktree_archive__expires ON worktree_archive (expires_at) WHERE removed_at IS NULL;
CREATE INDEX ix_worktree_archive__base_created ON worktree_archive (base_workspace_id, created_at);

-- --------------------------------------------------------------- sessions

CREATE TABLE session (
  session_id BLOB NOT NULL PRIMARY KEY CHECK (length(session_id) = 16),
  client INTEGER NOT NULL CHECK (client IN (1, 2, 3)),  -- AiClient
  client_name TEXT,
  client_version TEXT,
  client_session_id TEXT,
  source INTEGER NOT NULL CHECK (source IN (1, 2)),     -- SessionSource
  state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),    -- SessionState
  cwd TEXT,
  workspace_id BLOB REFERENCES workspace (workspace_id) ON DELETE SET NULL,
  agent_root_pid INTEGER,
  agent_root_start INTEGER,
  transcript_path TEXT,
  model TEXT,
  routing_mode INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL,
  ended_at INTEGER,
  end_reason TEXT,
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;
CREATE UNIQUE INDEX ux_session__client_session ON session (client, client_session_id) WHERE client_session_id IS NOT NULL;
CREATE INDEX ix_session__agent_root ON session (agent_root_pid, agent_root_start) WHERE state <> 3;
CREATE INDEX ix_session__state_activity ON session (state, last_activity_at);

CREATE TABLE session_subagent (
  session_id BLOB NOT NULL REFERENCES session (session_id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL,
  agent_type TEXT,
  started_at INTEGER NOT NULL,
  stopped_at INTEGER,
  PRIMARY KEY (session_id, agent_id)
) STRICT;

CREATE TABLE hook_event (
  hook_event_id BLOB NOT NULL PRIMARY KEY CHECK (length(hook_event_id) = 16),
  session_id BLOB REFERENCES session (session_id) ON DELETE CASCADE,
  kind INTEGER NOT NULL,                        -- HookEventKind
  at INTEGER NOT NULL,
  dedup_key TEXT NOT NULL,
  tool_name TEXT,
  tool_use_id TEXT,
  command_summary TEXT,                         -- redacted, <= 500 chars
  decision INTEGER,                             -- RoutingDecisionKind
  failed INTEGER NOT NULL DEFAULT 0 CHECK (failed IN (0, 1))
) STRICT;
CREATE UNIQUE INDEX ux_hook_event__dedup ON hook_event (dedup_key);
CREATE INDEX ix_hook_event__session_at ON hook_event (session_id, at);

CREATE TABLE probe_result (
  client INTEGER NOT NULL,
  environment TEXT NOT NULL,
  result INTEGER NOT NULL,                      -- ProbeResult
  at INTEGER NOT NULL,
  client_version TEXT,
  observation BLOB,                             -- ProbeObservation
  PRIMARY KEY (client, environment)
) STRICT;

CREATE TABLE probe_ticket (
  token_hash BLOB NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
  client INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
) STRICT;

-- ------------------------------------------------------------------ tasks

CREATE TABLE env_snapshot (
  env_digest BLOB NOT NULL PRIMARY KEY CHECK (length(env_digest) = 32),  -- SHA-256 of the canonical (sorted, UTF-8) entries
  entries BLOB NOT NULL,                        -- EnvSnapshot (store.proto): name/value pairs without secret-shaped values, compressed
  entry_count INTEGER NOT NULL CHECK (entry_count BETWEEN 0 AND 4096),
  byte_size INTEGER NOT NULL CHECK (byte_size BETWEEN 0 AND 1048576),  -- uncompressed
  ref_count INTEGER NOT NULL CHECK (ref_count >= 0),  -- tasks referencing the snapshot; maintained by the scheduler
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL
) STRICT;
CREATE INDEX ix_env_snapshot__unreferenced ON env_snapshot (last_used_at) WHERE ref_count = 0;

CREATE TABLE task (
  task_id BLOB NOT NULL PRIMARY KEY CHECK (length(task_id) = 16),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 10),  -- TaskState
  state_reason TEXT,
  kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 5),     -- TaskKind
  title TEXT NOT NULL CHECK (length(title) <= 200),
  command_summary TEXT NOT NULL,
  spec BLOB NOT NULL,                           -- TaskSpec without caller_environment (see env_digest) and without secret-shaped values (see task_secret)
  env_digest BLOB REFERENCES env_snapshot (env_digest) ON DELETE RESTRICT,  -- inherited caller environment, when inherit = CALLER
  spec_digest BLOB NOT NULL CHECK (length(spec_digest) = 32),
  owner BLOB NOT NULL,                          -- ActorRef
  owner_origin INTEGER NOT NULL,
  owner_session_id BLOB REFERENCES session (session_id) ON DELETE SET NULL,
  workspace_id BLOB REFERENCES workspace (workspace_id) ON DELETE SET NULL,
  pool TEXT NOT NULL,
  priority INTEGER NOT NULL CHECK (priority BETWEEN 1 AND 5),
  effective_priority INTEGER NOT NULL CHECK (effective_priority BETWEEN 1 AND 5),
  side_effect INTEGER NOT NULL CHECK (side_effect BETWEEN 1 AND 4),
  side_effect_source INTEGER NOT NULL CHECK (side_effect_source BETWEEN 1 AND 4),  -- SideEffectSource (AD-0006 section 4)
  side_effect_suggestion INTEGER CHECK (side_effect_suggestion IS NULL OR side_effect_suggestion BETWEEN 1 AND 4),  -- the adapter's suggestion; display only
  command_fingerprint TEXT NOT NULL,
  command_digest BLOB NOT NULL CHECK (length(command_digest) = 32),  -- SHA-256 of program and arguments (or the shell string), working directory, environment digest and stdin: the join_existing identity
  input_fingerprint_submit TEXT,
  created_at INTEGER NOT NULL,
  queued_at INTEGER,
  started_at INTEGER,
  finished_at INTEGER,
  retry_at INTEGER,
  aged_at INTEGER,
  reserved_for_large INTEGER NOT NULL DEFAULT 0 CHECK (reserved_for_large IN (0, 1)),
  reserved_since INTEGER,                       -- large-task reservation start (03 section 4)
  reservation_lapsed_at INTEGER,                -- a lapsed reservation is not retaken for large_task_reservation_max
  caller_released_at INTEGER,                   -- ReleaseCallerBinding ran: cancel_when_caller_gone no longer applies
  current_attempt_id BLOB CHECK (current_attempt_id IS NULL OR length(current_attempt_id) = 16),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  ready INTEGER NOT NULL DEFAULT 0 CHECK (ready IN (0, 1)),
  pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
  labels_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(labels_json)),
  remote_command_id BLOB CHECK (remote_command_id IS NULL OR length(remote_command_id) = 16),
  purged_at INTEGER,
  rev INTEGER NOT NULL CHECK (rev >= 0),
  CHECK (reserved_for_large = 0 OR reserved_since IS NOT NULL)
) STRICT;
CREATE INDEX ix_task__queue ON task (state, effective_priority, queued_at) WHERE state IN (1, 2, 3, 6);
CREATE INDEX ix_task__join ON task (owner_session_id, command_digest) WHERE state IN (1, 2, 3);  -- SubmitTask join_existing: tasks not yet started
CREATE INDEX ix_task__session_created ON task (owner_session_id, created_at);
CREATE INDEX ix_task__workspace_created ON task (workspace_id, created_at);
CREATE INDEX ix_task__created ON task (created_at);
CREATE INDEX ix_task__pool_state ON task (pool, state);
CREATE INDEX ix_task__fingerprint ON task (command_fingerprint, finished_at);

CREATE TABLE task_concurrency_key (
  task_id BLOB NOT NULL REFERENCES task (task_id) ON DELETE CASCADE,
  concurrency_key TEXT NOT NULL CHECK (length(concurrency_key) BETWEEN 1 AND 512),  -- ws:<w>[/<dir>][:purpose], tool:<name>:<scope>, name:<text>
  mode INTEGER NOT NULL CHECK (mode IN (1, 2)),         -- 1 exclusive (writer), 2 shared (reader)
  source INTEGER NOT NULL CHECK (source IN (1, 2, 3)),  -- 1 caller, 2 adapter, 3 workspace access or mode
  released_at INTEGER,                                  -- run operations and ready services release keys early (03 section 4)
  PRIMARY KEY (task_id, concurrency_key)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_task_concurrency_key__key ON task_concurrency_key (concurrency_key) WHERE released_at IS NULL;

CREATE TABLE task_secret (
  task_id BLOB NOT NULL PRIMARY KEY REFERENCES task (task_id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,                         -- version of the node data key held in the OS secret store
  nonce BLOB NOT NULL CHECK (length(nonce) = 12),
  ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 1 AND 1048576),  -- AES-256-GCM of SecretEnvironment (store.proto); AAD = task_id
  tag BLOB NOT NULL CHECK (length(tag) = 16),
  names_json TEXT NOT NULL CHECK (json_valid(names_json)),  -- the sealed variable names (presence only, shown in records)
  purge_after INTEGER,                          -- set when the task becomes terminal: finished_at + storage.secret_retention_hours
  created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX ix_task_secret__purge_after ON task_secret (purge_after) WHERE purge_after IS NOT NULL;

CREATE TABLE task_dependency (
  task_id BLOB NOT NULL REFERENCES task (task_id) ON DELETE CASCADE,
  depends_on_task_id BLOB NOT NULL REFERENCES task (task_id) ON DELETE RESTRICT,
  condition INTEGER NOT NULL CHECK (condition IN (1, 2, 3)),
  PRIMARY KEY (task_id, depends_on_task_id),
  CHECK (task_id <> depends_on_task_id)
) STRICT;
CREATE INDEX ix_task_dependency__depends_on ON task_dependency (depends_on_task_id);

CREATE TABLE attempt (
  attempt_id BLOB NOT NULL PRIMARY KEY CHECK (length(attempt_id) = 16),
  task_id BLOB NOT NULL REFERENCES task (task_id) ON DELETE CASCADE,
  number INTEGER NOT NULL CHECK (number >= 1),
  kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 4),       -- AttemptKind
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 9),     -- AttemptState
  executor_node_id BLOB NOT NULL CHECK (length(executor_node_id) = 16),
  remote_attempt_id BLOB CHECK (remote_attempt_id IS NULL OR length(remote_attempt_id) = 16),
  container_name TEXT,                          -- Windows job name or Linux unit name
  root_pid INTEGER,
  root_start INTEGER,
  boot_identity TEXT,
  request_cpu_millicores INTEGER NOT NULL CHECK (request_cpu_millicores > 0),
  request_mem_expected_bytes INTEGER NOT NULL CHECK (request_mem_expected_bytes > 0),
  request_mem_ceiling_bytes INTEGER NOT NULL,
  request_source INTEGER NOT NULL CHECK (request_source BETWEEN 1 AND 5),  -- EstimateSource (5 LIGHT)
  accounted_mem_bytes INTEGER NOT NULL,         -- max(mem_expected, peak observed without reclaimable cache); never decreases while running (03 section 3)
  cpu_weight INTEGER,
  guest_grant_id BLOB CHECK (guest_grant_id IS NULL OR length(guest_grant_id) = 16),
  tool TEXT,
  operation TEXT,
  tool_parallelism INTEGER,
  unenforced INTEGER NOT NULL DEFAULT 0 CHECK (unenforced IN (0, 1)),
  node_gap INTEGER NOT NULL DEFAULT 0 CHECK (node_gap IN (0, 1)),
  repeat_flag INTEGER NOT NULL DEFAULT 0 CHECK (repeat_flag IN (0, 1)),
  stale_flag INTEGER NOT NULL DEFAULT 0 CHECK (stale_flag IN (0, 1)),
  input_fingerprint_start TEXT,
  input_fingerprint_end TEXT,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  exit_code INTEGER,
  signal INTEGER,
  core_dumped INTEGER CHECK (core_dumped IS NULL OR core_dumped IN (0, 1)),
  windows_status INTEGER,
  termination_reason INTEGER CHECK (termination_reason IS NULL OR termination_reason BETWEEN 1 AND 16),  -- 14 OUTPUT_LIMIT, 15 DISK_LIMIT, 16 ENDPOINT_TAKEN
  effect INTEGER CHECK (effect IS NULL OR effect BETWEEN 1 AND 3),   -- EffectCertainty
  detail TEXT,
  leftover_count INTEGER NOT NULL DEFAULT 0,
  leftover_images_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(leftover_images_json)),
  cpu_time_ms INTEGER NOT NULL DEFAULT 0,
  mem_peak_bytes INTEGER NOT NULL DEFAULT 0,
  io_read_bytes INTEGER NOT NULL DEFAULT 0,
  io_write_bytes INTEGER NOT NULL DEFAULT 0,
  stdout_bytes INTEGER NOT NULL DEFAULT 0,
  stderr_bytes INTEGER NOT NULL DEFAULT 0,
  stdout_offset INTEGER NOT NULL DEFAULT 0,     -- tail position for re-attach
  stderr_offset INTEGER NOT NULL DEFAULT 0,
  index_offset INTEGER NOT NULL DEFAULT 0,
  output_retained_until INTEGER,
  output_compressed INTEGER NOT NULL DEFAULT 0 CHECK (output_compressed IN (0, 1)),
  output_purged INTEGER NOT NULL DEFAULT 0 CHECK (output_purged IN (0, 1)),
  limit_enforced_by TEXT CHECK (limit_enforced_by IS NULL OR limit_enforced_by IN ('NODE', 'GUARD')),  -- who stopped it for OUTPUT_LIMIT or DISK_LIMIT (06 section 5)
  guard_lost INTEGER NOT NULL DEFAULT 0 CHECK (guard_lost IN (0, 1)),  -- ran without a disk guard while the node was down
  downloaded_bytes INTEGER CHECK (downloaded_bytes IS NULL OR downloaded_bytes >= 0),  -- sum of tool-reported download sizes; NULL unless every download-cache binding reported one; never cache growth (07 section 1.5)
  output_base_manifest BLOB CHECK (output_base_manifest IS NULL OR length(output_base_manifest) = 32),  -- REMOTE, origin side: digest or absence of each declared output at submission (09 section 6)
  outputs BLOB,                                 -- OutputApplyResult, once returned outputs are applied
  rev INTEGER NOT NULL CHECK (rev >= 0),
  CHECK (state <> 9 OR termination_reason IS NOT NULL)
) STRICT;
CREATE UNIQUE INDEX ux_attempt__task_number ON attempt (task_id, number);
CREATE INDEX ix_attempt__live ON attempt (state) WHERE state BETWEEN 1 AND 8;
CREATE INDEX ix_attempt__finished ON attempt (finished_at);

CREATE TABLE result_cache_observation (
  attempt_id BLOB NOT NULL PRIMARY KEY REFERENCES attempt (attempt_id) ON DELETE CASCADE,
  workspace_id BLOB CHECK (workspace_id IS NULL OR length(workspace_id) = 16),
  action_key BLOB NOT NULL CHECK (length(action_key) = 32),        -- 04 section 11
  output_manifest_digest BLOB NOT NULL CHECK (length(output_manifest_digest) = 32),
  succeeded INTEGER NOT NULL CHECK (succeeded IN (0, 1)),
  would_hit INTEGER NOT NULL CHECK (would_hit IN (0, 1)),            -- an earlier success had the same key and output digest
  observed_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_result_cache_observation__key ON result_cache_observation (action_key, observed_at);

CREATE TABLE attempt_cache_usage (
  attempt_id BLOB NOT NULL REFERENCES attempt (attempt_id) ON DELETE CASCADE,
  cache_id BLOB NOT NULL CHECK (length(cache_id) = 16),
  kind TEXT NOT NULL,                           -- nuget | npm | pnpm | cargo | pip | sccache | ccache | fastbuild | cas
  bytes_added INTEGER CHECK (bytes_added IS NULL OR bytes_added >= 0),  -- COUNTED: bytes written to the store the node serves; SOLE_BINDER: growth by file birth and change times
  hits INTEGER CHECK (hits IS NULL OR hits >= 0),          -- the attempt's own tool counters (per-attempt sccache server, ccache stats log)
  misses INTEGER CHECK (misses IS NULL OR misses >= 0),
  cache_writes INTEGER CHECK (cache_writes IS NULL OR cache_writes >= 0),
  packages_installed INTEGER CHECK (packages_installed IS NULL OR packages_installed >= 0),  -- parsed from the attempt's own output
  packages_reused INTEGER CHECK (packages_reused IS NULL OR packages_reused >= 0),
  downloaded_bytes INTEGER CHECK (downloaded_bytes IS NULL OR downloaded_bytes >= 0),  -- only when the tool reports download sizes
  peer_filled_bytes INTEGER CHECK (peer_filled_bytes IS NULL OR peer_filled_bytes >= 0),  -- fetched from LAN peers into the node's store for this attempt's reads
  counters_source TEXT,                         -- e.g. sccache-server, ccache-stats-log, adapter-output; NULL when the tool reports none
  attribution INTEGER NOT NULL CHECK (attribution IN (1, 2, 3, 4)),  -- of bytes_added: 1 SOLE_BINDER, 2 SHARED, 3 UNKNOWN, 4 COUNTED (07 section 1.5)
  window_id BLOB REFERENCES cache_usage_window (window_id),     -- SHARED only
  measured_at INTEGER,                          -- the walk that finalized bytes_added; NULL while provisional
  CHECK ((attribution = 2) = (window_id IS NOT NULL)),
  CHECK (attribution IN (1, 4) OR bytes_added IS NULL),
  PRIMARY KEY (attempt_id, cache_id)
) STRICT, WITHOUT ROWID;

-- A window: a maximal interval in which two or more attempts bind a cache at overlapping times; an attempt alone in its run is in no window. Totals are recorded once, when it closes (07 section 1.5).
CREATE TABLE cache_usage_window (
  window_id BLOB NOT NULL PRIMARY KEY CHECK (length(window_id) = 16),
  cache_id BLOB NOT NULL CHECK (length(cache_id) = 16),
  started_at INTEGER NOT NULL,
  ended_at INTEGER,                             -- NULL while open; totals are provisional until then
  added_bytes INTEGER CHECK (added_bytes IS NULL OR added_bytes >= 0),  -- files born or grown during the window; NULL until measured
  hits INTEGER CHECK (hits IS NULL OR hits >= 0),   -- sum of its attempts' tool counters
  misses INTEGER CHECK (misses IS NULL OR misses >= 0),
  attempt_count INTEGER NOT NULL CHECK (attempt_count >= 2),
  measured_at INTEGER
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_cache_usage_window__cache ON cache_usage_window (cache_id, started_at);

-- The node-served sccache store's own ledger per period: first-writer bytes, peer fills and evictions. The store is never walked (05 section 5, 07 section 1.5).
CREATE TABLE cache_store_ledger (
  cache_id BLOB NOT NULL CHECK (length(cache_id) = 16),
  period_start INTEGER NOT NULL,
  period_end INTEGER NOT NULL,
  written_bytes INTEGER NOT NULL DEFAULT 0 CHECK (written_bytes >= 0),       -- first PUT of each key, also in the writing attempts' COUNTED entries
  peer_filled_bytes INTEGER NOT NULL DEFAULT 0 CHECK (peer_filled_bytes >= 0),  -- fetched from peers, also in the reading attempts' entries
  evicted_bytes INTEGER NOT NULL DEFAULT 0 CHECK (evicted_bytes >= 0),
  PRIMARY KEY (cache_id, period_start)
) STRICT, WITHOUT ROWID;

-- One walk of a managed cache by the size cache: removals and growth outside any attempt (07 section 1.5). The sccache store is not walked.
CREATE TABLE cache_walk (
  cache_id BLOB NOT NULL CHECK (length(cache_id) = 16),
  started_at INTEGER NOT NULL,
  ended_at INTEGER NOT NULL,
  full_walk INTEGER NOT NULL CHECK (full_walk IN (0, 1)),
  truncated INTEGER NOT NULL CHECK (truncated IN (0, 1)),
  removed_bytes INTEGER NOT NULL CHECK (removed_bytes >= 0),      -- files gone since the previous walk (eviction)
  unattributed_added_bytes INTEGER NOT NULL CHECK (unattributed_added_bytes >= 0),  -- born while no managed attempt bound the cache
  PRIMARY KEY (cache_id, started_at)
) STRICT, WITHOUT ROWID;

CREATE TABLE timeline_segment (
  attempt_id BLOB NOT NULL REFERENCES attempt (attempt_id) ON DELETE CASCADE,
  start_at INTEGER NOT NULL,
  end_at INTEGER NOT NULL,
  category TEXT NOT NULL,                       -- architecture 07 section 1.1
  confidence INTEGER NOT NULL CHECK (confidence BETWEEN 1 AND 3),
  evidence TEXT NOT NULL,
  PRIMARY KEY (attempt_id, start_at),
  CHECK (end_at >= start_at)
) STRICT, WITHOUT ROWID;

CREATE TABLE phase_event (
  attempt_id BLOB NOT NULL REFERENCES attempt (attempt_id) ON DELETE CASCADE,
  at INTEGER NOT NULL,
  phase TEXT NOT NULL,
  source TEXT NOT NULL,
  PRIMARY KEY (attempt_id, at, phase)
) STRICT, WITHOUT ROWID;

CREATE TABLE process_record (
  attempt_id BLOB NOT NULL REFERENCES attempt (attempt_id) ON DELETE CASCADE,
  pid INTEGER NOT NULL,
  start_at INTEGER NOT NULL,
  parent_pid INTEGER,
  executable TEXT NOT NULL,
  arguments_redacted TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  mem_peak_bytes INTEGER NOT NULL DEFAULT 0,
  label INTEGER NOT NULL,                       -- ProcessLabel
  PRIMARY KEY (attempt_id, pid, start_at)
) STRICT, WITHOUT ROWID;

-- scope: 1 machine, 2 managed total, 3 attempt (SampleScope); subject = attempt_id or zero blob
CREATE TABLE resource_sample (
  scope INTEGER NOT NULL CHECK (scope IN (1, 2, 3)),
  subject_id BLOB NOT NULL CHECK (length(subject_id) = 16),
  at INTEGER NOT NULL,
  resolution_ms INTEGER NOT NULL CHECK (resolution_ms IN (1000, 5000, 10000, 60000)),
  cpu_millicores INTEGER NOT NULL,
  cpu_time_ms INTEGER NOT NULL,
  mem_bytes INTEGER NOT NULL,
  mem_peak_bytes INTEGER NOT NULL,
  process_count INTEGER NOT NULL,
  io_read_bytes INTEGER NOT NULL,
  io_write_bytes INTEGER NOT NULL,
  PRIMARY KEY (scope, subject_id, at)
) STRICT, WITHOUT ROWID;

-- ---------------------------------------------------- findings, approvals

CREATE TABLE finding (
  finding_id BLOB NOT NULL PRIMARY KEY CHECK (length(finding_id) = 16),
  kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 26),     -- FindingKind (25 TASK_INFEASIBLE, 26 OUTPUT_CONFLICT)
  severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 3),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),    -- FindingState
  subject_kind TEXT NOT NULL,
  subject_id BLOB NOT NULL,
  title TEXT NOT NULL,
  explanation TEXT NOT NULL,
  evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
  actions BLOB NOT NULL,                        -- repeated RemedyAction (FindingActions wrapper)
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  occurrences INTEGER NOT NULL CHECK (occurrences >= 1),
  resolved_at INTEGER,
  muted_until INTEGER,
  clear_checks INTEGER NOT NULL DEFAULT 0,      -- consecutive checks with the condition cleared
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;
CREATE UNIQUE INDEX ux_finding__open_subject ON finding (kind, subject_kind, subject_id) WHERE state IN (1, 2, 5);
CREATE INDEX ix_finding__state_severity ON finding (state, severity, last_seen);

CREATE TABLE approval (
  approval_id BLOB NOT NULL PRIMARY KEY CHECK (length(approval_id) = 16),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 7),    -- ApprovalState
  operation TEXT NOT NULL,
  summary TEXT NOT NULL,
  details_json TEXT NOT NULL CHECK (json_valid(details_json)),
  risk INTEGER NOT NULL CHECK (risk BETWEEN 1 AND 3),
  requester BLOB NOT NULL,                      -- ActorRef
  command_id BLOB NOT NULL CHECK (length(command_id) = 16),
  request BLOB NOT NULL,                        -- serialized original <Method>Request
  request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
  finding_id BLOB REFERENCES finding (finding_id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  decided_by BLOB,                              -- ActorRef
  decided_at INTEGER,
  comment TEXT,
  outcome BLOB,                                 -- serialized <Method>Response
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;
CREATE INDEX ix_approval__state_expires ON approval (state, expires_at);
CREATE UNIQUE INDEX ux_approval__command ON approval (command_id);

CREATE TABLE notification (
  notification_id BLOB NOT NULL PRIMARY KEY CHECK (length(notification_id) = 16),
  kind TEXT NOT NULL,
  severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 3),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  link TEXT,                                    -- arcforges:// deep link
  created_at INTEGER NOT NULL,
  read_at INTEGER
) STRICT;
CREATE INDEX ix_notification__created ON notification (created_at);

-- ---------------------------------------------------- operational memory

CREATE TABLE fact (
  fact_id BLOB NOT NULL PRIMARY KEY CHECK (length(fact_id) = 16),
  kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 6),      -- FactKind
  project_id TEXT NOT NULL,
  environment TEXT NOT NULL,
  toolchain TEXT NOT NULL,
  command_fingerprint TEXT NOT NULL,
  input_key TEXT NOT NULL DEFAULT '',
  state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),       -- FactState
  confidence INTEGER NOT NULL CHECK (confidence BETWEEN 1 AND 3),
  observations INTEGER NOT NULL CHECK (observations >= 0),
  value BLOB NOT NULL,                          -- Fact (value oneof only)
  reservoir BLOB NOT NULL,                      -- last 50 observations, packed
  first_observed INTEGER NOT NULL,
  last_observed INTEGER NOT NULL,
  superseded_by BLOB REFERENCES fact (fact_id) ON DELETE SET NULL,
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;
CREATE UNIQUE INDEX ux_fact__active_scope ON fact (kind, project_id, environment, toolchain, command_fingerprint, input_key) WHERE state = 1;
CREATE INDEX ix_fact__last_observed ON fact (state, last_observed);

-- ---------------------------------------------------------------- storage

CREATE TABLE managed_directory (
  directory_id BLOB NOT NULL PRIMARY KEY CHECK (length(directory_id) = 16),
  owner_kind INTEGER NOT NULL CHECK (owner_kind BETWEEN 1 AND 7),
  owner_id BLOB NOT NULL,
  root_class TEXT NOT NULL CHECK (root_class IN ('store', 'work', 'tmp', 'cache', 'out', 'logs', 'records', 'downloads', 'staging', 'run')),
  relative_path TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
  size_bytes INTEGER,
  size_measured_at INTEGER,
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;
CREATE UNIQUE INDEX ux_managed_directory__path ON managed_directory (root_class, relative_path) WHERE state <> 5;
CREATE INDEX ix_managed_directory__owner ON managed_directory (owner_kind, owner_id);

CREATE TABLE root_location (
  root_class TEXT NOT NULL PRIMARY KEY,
  path TEXT NOT NULL,
  relocated_at INTEGER,
  previous_path TEXT
) STRICT;

CREATE TABLE size_cache (
  path_hash BLOB NOT NULL PRIMARY KEY CHECK (length(path_hash) = 32),
  path TEXT NOT NULL,
  mtime INTEGER NOT NULL,
  file_identity TEXT NOT NULL,                  -- inode or Windows file ID
  size_bytes INTEGER NOT NULL,
  measured_at INTEGER NOT NULL
) STRICT;

CREATE TABLE file_digest_cache (
  path_hash BLOB NOT NULL PRIMARY KEY CHECK (length(path_hash) = 32),
  size_bytes INTEGER NOT NULL,
  mtime INTEGER NOT NULL,
  file_identity TEXT NOT NULL,
  sha256 BLOB NOT NULL CHECK (length(sha256) = 32),
  computed_at INTEGER NOT NULL
) STRICT;

CREATE TABLE storage_analysis (
  analysis_id BLOB NOT NULL PRIMARY KEY CHECK (length(analysis_id) = 16),
  job_id BLOB NOT NULL REFERENCES job (job_id) ON DELETE CASCADE,
  scope_json TEXT NOT NULL CHECK (json_valid(scope_json)),
  truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1)),
  truncation_reason TEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  reclaimable_low_risk_bytes INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE storage_analysis_item (
  analysis_id BLOB NOT NULL REFERENCES storage_analysis (analysis_id) ON DELETE CASCADE,
  item_id BLOB NOT NULL CHECK (length(item_id) = 16),
  item_class INTEGER NOT NULL CHECK (item_class BETWEEN 1 AND 10),
  path TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  risk INTEGER NOT NULL CHECK (risk BETWEEN 1 AND 3),
  reason TEXT NOT NULL,
  suggested_action INTEGER NOT NULL CHECK (suggested_action BETWEEN 1 AND 6),
  workspace_id BLOB,
  cache_kind TEXT,
  PRIMARY KEY (analysis_id, item_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE cleanup_plan (
  plan_id BLOB NOT NULL PRIMARY KEY CHECK (length(plan_id) = 16),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 7),    -- CleanupPlanState
  digest BLOB NOT NULL CHECK (length(digest) = 32),
  source_analysis_id BLOB REFERENCES storage_analysis (analysis_id) ON DELETE SET NULL,
  planned_by BLOB NOT NULL,                     -- ActorRef
  approval_id BLOB REFERENCES approval (approval_id) ON DELETE SET NULL,
  total_bytes INTEGER NOT NULL,
  item_count INTEGER NOT NULL CHECK (item_count BETWEEN 1 AND 10000),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  executed_at INTEGER,
  rev INTEGER NOT NULL CHECK (rev >= 0),
  CHECK (total_bytes <= 2199023255552)          -- 2 TiB bound (R-STOR-008)
) STRICT;

CREATE TABLE cleanup_item (
  plan_id BLOB NOT NULL REFERENCES cleanup_plan (plan_id) ON DELETE CASCADE,
  item_id BLOB NOT NULL CHECK (length(item_id) = 16),
  path TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  item_class INTEGER NOT NULL,
  reason TEXT NOT NULL,
  risk INTEGER NOT NULL CHECK (risk BETWEEN 1 AND 3),
  action INTEGER NOT NULL CHECK (action BETWEEN 1 AND 6),
  fp_mtime INTEGER NOT NULL,
  fp_size INTEGER NOT NULL,
  fp_owner_state TEXT NOT NULL,
  external INTEGER NOT NULL DEFAULT 0 CHECK (external IN (0, 1)),
  outcome INTEGER NOT NULL DEFAULT 1 CHECK (outcome BETWEEN 1 AND 8),
  outcome_detail TEXT,
  acted_at INTEGER,
  PRIMARY KEY (plan_id, item_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE quarantine_entry (
  plan_id BLOB NOT NULL,
  item_id BLOB NOT NULL,
  original_path TEXT NOT NULL,
  quarantine_path TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  quarantined_at INTEGER NOT NULL,
  purge_at INTEGER NOT NULL,
  restored_at INTEGER,
  purged_at INTEGER,
  PRIMARY KEY (plan_id, item_id),
  FOREIGN KEY (plan_id, item_id) REFERENCES cleanup_item (plan_id, item_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_quarantine_entry__purge ON quarantine_entry (purge_at) WHERE restored_at IS NULL AND purged_at IS NULL;

-- ------------------------------------------------------ caches, toolchains

CREATE TABLE cache_instance (
  cache_id BLOB NOT NULL PRIMARY KEY CHECK (length(cache_id) = 16),
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  compat_key TEXT NOT NULL,
  quota_bytes INTEGER,
  size_bytes INTEGER,
  observed_only INTEGER NOT NULL DEFAULT 0 CHECK (observed_only IN (0, 1)),
  lan_shared INTEGER NOT NULL DEFAULT 0 CHECK (lan_shared IN (0, 1)),
  maintenance_lease_holder BLOB,
  maintenance_lease_expires_at INTEGER,
  last_maintenance_at INTEGER,
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;
CREATE UNIQUE INDEX ux_cache_instance__kind_key ON cache_instance (kind, compat_key);

CREATE TABLE cache_stat (
  cache_id BLOB NOT NULL REFERENCES cache_instance (cache_id) ON DELETE CASCADE,
  period_start INTEGER NOT NULL,                -- hourly buckets
  hits INTEGER NOT NULL DEFAULT 0,
  misses INTEGER NOT NULL DEFAULT 0,
  hit_bytes INTEGER NOT NULL DEFAULT 0,
  written_bytes INTEGER NOT NULL DEFAULT 0,
  restores_reused INTEGER NOT NULL DEFAULT 0,
  restores_installed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (cache_id, period_start)
) STRICT, WITHOUT ROWID;

CREATE TABLE cas_blob (
  sha256 BLOB NOT NULL PRIMARY KEY CHECK (length(sha256) = 32),
  size_bytes INTEGER NOT NULL,
  stored_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  ref_count INTEGER NOT NULL DEFAULT 0 CHECK (ref_count >= 0)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_cas_blob__lru ON cas_blob (ref_count, last_used_at);

CREATE TABLE manifest (
  digest BLOB NOT NULL PRIMARY KEY CHECK (length(digest) = 32),
  kind INTEGER NOT NULL CHECK (kind IN (1, 2, 3)), -- 1 input, 2 output, 3 output bases
  entry_count INTEGER NOT NULL CHECK (entry_count BETWEEN 0 AND 2000000),
  total_bytes INTEGER NOT NULL,
  owner_attempt_id BLOB,
  published_for_node_id BLOB,                   -- the peer allowed to read it
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;                        -- pages are stored as CAS blobs

CREATE TABLE toolchain (
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  version TEXT NOT NULL,
  identity_json TEXT NOT NULL CHECK (json_valid(identity_json)),
  detected_at INTEGER NOT NULL,
  missing INTEGER NOT NULL DEFAULT 0 CHECK (missing IN (0, 1)),
  PRIMARY KEY (kind, path)
) STRICT, WITHOUT ROWID;

-- --------------------------------------------------------- LAN and guests

CREATE TABLE peer (
  peer_node_id BLOB NOT NULL PRIMARY KEY CHECK (length(peer_node_id) = 16),
  name TEXT NOT NULL,
  addresses_json TEXT NOT NULL CHECK (json_valid(addresses_json)),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 7),    -- PeerState
  trust INTEGER NOT NULL CHECK (trust BETWEEN 1 AND 3),    -- PeerTrust
  fingerprint BLOB CHECK (fingerprint IS NULL OR length(fingerprint) = 32),
  same_account INTEGER NOT NULL DEFAULT 0 CHECK (same_account IN (0, 1)),  -- account-based trust (roadmap RM-01); always 0 in release 1
  policy BLOB NOT NULL,                         -- PeerPolicy (ours)
  offered BLOB,                                 -- PeerPolicy (theirs, read-only)
  status BLOB,                                  -- PeerStatusSummary
  cpu_class REAL,
  throughput_ewma REAL,
  paired_at INTEGER,
  last_seen INTEGER,
  incompatibility TEXT,
  manually_added INTEGER NOT NULL DEFAULT 0 CHECK (manually_added IN (0, 1)),
  blocked INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1)),
  rev INTEGER NOT NULL CHECK (rev >= 0),
  CHECK (trust <> 2 OR fingerprint IS NOT NULL)
) STRICT;

CREATE TABLE pairing (
  pairing_id BLOB NOT NULL PRIMARY KEY CHECK (length(pairing_id) = 16),
  peer_node_id BLOB NOT NULL,
  role INTEGER NOT NULL CHECK (role IN (1, 2)),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 11),   -- PairingState
  local_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (local_confirmed IN (0, 1)),
  remote_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (remote_confirmed IN (0, 1)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  failure_reason TEXT
) STRICT;                                       -- nonces, commitment and SAS live in memory only
CREATE INDEX ix_pairing__peer_created ON pairing (peer_node_id, created_at);

CREATE TABLE offer (
  offer_id BLOB NOT NULL PRIMARY KEY CHECK (length(offer_id) = 16),
  peer_node_id BLOB NOT NULL REFERENCES peer (peer_node_id) ON DELETE CASCADE,
  direction INTEGER NOT NULL CHECK (direction IN (1, 2)),  -- 1 we requested, 2 we offered
  decision INTEGER NOT NULL CHECK (decision IN (1, 2)),
  origin_task_id BLOB NOT NULL,
  reservation_cpu_millicores INTEGER,
  reservation_mem_bytes INTEGER,
  accept_by INTEGER NOT NULL,
  accepted_at INTEGER,
  released_at INTEGER
) STRICT;

CREATE TABLE remote_attempt (
  remote_attempt_id BLOB NOT NULL PRIMARY KEY CHECK (length(remote_attempt_id) = 16),
  origin_node_id BLOB NOT NULL,
  origin_attempt_id BLOB NOT NULL,
  local_task_id BLOB NOT NULL REFERENCES task (task_id) ON DELETE RESTRICT,  -- kind REMOTE
  offer_id BLOB REFERENCES offer (offer_id) ON DELETE SET NULL,
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 9),    -- RemoteAttemptState
  lease_expires_at INTEGER NOT NULL,
  lease_expiry_action INTEGER NOT NULL CHECK (lease_expiry_action IN (1, 2)),
  remote_workspace_id BLOB REFERENCES workspace (workspace_id) ON DELETE SET NULL,
  input_manifest_digest BLOB,
  output_manifest_digest BLOB,
  retained_until INTEGER,
  released_at INTEGER,
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;
CREATE INDEX ix_remote_attempt__lease ON remote_attempt (state, lease_expires_at);

CREATE TABLE guest_link (
  distro TEXT NOT NULL PRIMARY KEY,
  guest_node_id BLOB UNIQUE CHECK (guest_node_id IS NULL OR length(guest_node_id) = 16),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 7),    -- GuestLinkState
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  link_token_ref TEXT NOT NULL,                 -- name of the secret in the OS secret store
  guest_version TEXT,
  capabilities BLOB,                            -- CapabilityReport
  linked_at INTEGER,
  last_heartbeat INTEGER,
  reason TEXT,
  alloc_seq INTEGER,                            -- last pushed allocation_seq
  acked_seq INTEGER,                            -- last allocation the guest acknowledged; capacity it gave back is reused only from here
  alloc_cpu_millicores INTEGER,                 -- last allocation pushed with SetGuestBudget (03 section 6)
  alloc_mem_high_bytes INTEGER,
  alloc_mem_max_bytes INTEGER,
  acked_cpu_millicores INTEGER,                 -- the allocation the guest last acknowledged
  acked_mem_high_bytes INTEGER,
  acked_mem_max_bytes INTEGER,
  reserved_cpu_millicores INTEGER,              -- the larger of the acknowledged allocation and every unacknowledged push; written before each push (03 section 6)
  reserved_mem_high_bytes INTEGER,
  reserved_mem_max_bytes INTEGER,
  lease_until INTEGER,
  standalone_cpu_millicores INTEGER,            -- the guest's admission limit after the lease lapses; the host keeps the whole acknowledged allocation reserved (03 section 6)
  standalone_mem_bytes INTEGER,
  reservation_released_at INTEGER,              -- set when the distribution or the VM was observed stopped during an outage
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;

CREATE TABLE host_link (
  singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
  host_node_id BLOB NOT NULL CHECK (length(host_node_id) = 16),
  link_token_hash BLOB NOT NULL CHECK (length(link_token_hash) = 32),
  pinned_at INTEGER NOT NULL,
  last_seen INTEGER,
  refused_host_node_id BLOB CHECK (refused_host_node_id IS NULL OR length(refused_host_node_id) = 16),  -- last link refused: different host
  refused_at INTEGER,
  accept_host_node_id BLOB CHECK (accept_host_node_id IS NULL OR length(accept_host_node_id) = 16),  -- set by TrustHost; its next link is pinned
  applied_seq INTEGER,                          -- allocation_seq of the allocation in force
  alloc_cpu_millicores INTEGER,                 -- last allocation received and applied (03 section 6)
  alloc_mem_high_bytes INTEGER,
  alloc_mem_max_bytes INTEGER,
  lease_until INTEGER,                          -- after it, only the standalone allocation applies
  standalone_cpu_millicores INTEGER,
  standalone_mem_bytes INTEGER,
  distro_boot_marker TEXT                       -- ID of the marker in the distribution's runtime directory when the allocation was applied (03 section 6)
) STRICT;

CREATE TABLE guest_grant (
  grant_id BLOB NOT NULL PRIMARY KEY CHECK (length(grant_id) = 16),
  request_id BLOB NOT NULL UNIQUE CHECK (length(request_id) = 16),
  guest_node_id BLOB NOT NULL,
  attempt_id BLOB NOT NULL,                     -- the guest's attempt
  proxy_task_id BLOB REFERENCES task (task_id) ON DELETE SET NULL,  -- host-side queue entry
  demand_cpu_millicores INTEGER NOT NULL,
  demand_mem_bytes INTEGER NOT NULL,
  priority INTEGER NOT NULL,
  pool TEXT NOT NULL,
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5), -- 1 requested, 2 granted, 3 released, 4 revoked, 5 denied
  requested_at INTEGER NOT NULL,
  granted_at INTEGER,
  released_at INTEGER
) STRICT;
CREATE INDEX ix_guest_grant__state ON guest_grant (state);

-- ------------------------------------------------- account, cloud, updates

CREATE TABLE account_link (
  singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
  account_id BLOB NOT NULL CHECK (length(account_id) = 16),
  display_name TEXT,
  email_masked TEXT,
  plan TEXT,
  installation_id BLOB NOT NULL CHECK (length(installation_id) = 16),
  credential_ref TEXT NOT NULL,                 -- secret store entry holding the refresh token
  cloud_link_enabled INTEGER NOT NULL DEFAULT 1 CHECK (cloud_link_enabled IN (0, 1)),
  entitlement_token BLOB,                       -- SignedBlob
  entitlement_not_after INTEGER,
  entitlement_version INTEGER,
  entitlement_refreshed_at INTEGER,
  node_certificate_chain BLOB,                  -- reserved for account-based LAN trust (roadmap RM-01); empty in release 1
  node_certificate_expires_at INTEGER,
  command_keys BLOB,                            -- repeated PublicKey (KeySet wrapper)
  entitlement_keys BLOB,
  revoked_nodes BLOB,                           -- reserved for account-based LAN trust (roadmap RM-01); empty in release 1
  last_contact_at INTEGER,
  linked_at INTEGER NOT NULL,
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;

CREATE TABLE sign_in_flow (
  flow_id BLOB NOT NULL PRIMARY KEY CHECK (length(flow_id) = 16),
  method INTEGER NOT NULL CHECK (method IN (1, 2)),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 7),
  authorize_url TEXT,
  user_code TEXT,
  verification_uri TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  error BLOB
) STRICT;                                       -- code_verifier and device_code are memory-only

CREATE TABLE phone_pairing (
  pairing_id BLOB NOT NULL PRIMARY KEY CHECK (length(pairing_id) = 16),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 6),
  phone_model TEXT,
  phone_os TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  claimed_at INTEGER
) STRICT;                                       -- the QR secret is memory-only

CREATE TABLE remote_command_log (
  command_id BLOB NOT NULL PRIMARY KEY CHECK (length(command_id) = 16),
  received_at INTEGER NOT NULL,
  kind TEXT NOT NULL,
  risk INTEGER NOT NULL CHECK (risk BETWEEN 1 AND 3),
  actor_user_id BLOB,
  signature_kid TEXT NOT NULL,
  decision INTEGER NOT NULL CHECK (decision IN (1, 2, 3)),  -- 1 executed, 2 rejected by policy, 3 expired
  result BLOB                                   -- NodeCommandResult
) STRICT;
CREATE INDEX ix_remote_command_log__received ON remote_command_log (received_at);

CREATE TABLE push_outbox (
  outbox_id INTEGER NOT NULL PRIMARY KEY,
  event BLOB NOT NULL,                          -- relay.v1 PushEvent
  created_at INTEGER NOT NULL,
  sent_at INTEGER
) STRICT;

CREATE TABLE update_state (
  singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
  current_version TEXT NOT NULL,
  previous_version TEXT,
  staged_version TEXT,
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 10),   -- UpdateState
  channel TEXT NOT NULL CHECK (channel IN ('stable', 'beta', 'dev')),
  last_check_at INTEGER,
  last_manifest_published_at INTEGER,           -- rollback protection
  bad_versions_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(bad_versions_json)),
  restart_at INTEGER,
  switch_phase TEXT,
  last_error BLOB,
  rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;

-- ------------------------------------------------ integrations and support

CREATE TABLE integration_plan (
  plan_id BLOB NOT NULL PRIMARY KEY CHECK (length(plan_id) = 16),
  plan BLOB NOT NULL,                           -- IntegrationPlan
  digest BLOB NOT NULL CHECK (length(digest) = 32),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  applied_at INTEGER
) STRICT;

CREATE TABLE integration_write (
  write_id BLOB NOT NULL PRIMARY KEY CHECK (length(write_id) = 16),
  plan_id BLOB NOT NULL REFERENCES integration_plan (plan_id) ON DELETE RESTRICT,
  client INTEGER NOT NULL,
  scope INTEGER NOT NULL CHECK (scope IN (1, 2, 3)),
  path TEXT NOT NULL,
  action INTEGER NOT NULL CHECK (action IN (1, 2, 3)),
  before_sha256 BLOB,
  after_sha256 BLOB,
  backup_path TEXT,
  written_entries_json TEXT NOT NULL CHECK (json_valid(written_entries_json)),  -- keys ArcForges added, for exact removal
  written_at INTEGER NOT NULL,
  removed_at INTEGER
) STRICT;
CREATE INDEX ix_integration_write__client_path ON integration_write (client, path);

CREATE TABLE support_bundle (
  bundle_id BLOB NOT NULL PRIMARY KEY CHECK (length(bundle_id) = 16),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 6),
  file_path TEXT,
  size_bytes INTEGER,
  files BLOB,                                   -- repeated BundleFile (BundleFiles wrapper)
  redaction_summary TEXT,
  case_reference TEXT,
  consent_at INTEGER,
  created_at INTEGER NOT NULL,
  uploaded_at INTEGER,
  expires_at INTEGER NOT NULL
) STRICT;
