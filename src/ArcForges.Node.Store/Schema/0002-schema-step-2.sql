-- ------------------------------------------------------------------ schema step 2
-- AF-CTR-05 target, not built (Plan decisions PN-7 and Q8, 2026-11-05; node-store.md "Schema step 2").
-- Step 1 is this file above the blank line before this block, unchanged since 4823296 (ArcForges step 1, verbatim).
-- Step 2 is this block, from its line of dashes to the end of the file. Expand-only (13 section 6).

ALTER TABLE task ADD COLUMN local_diagnostic INTEGER NOT NULL DEFAULT 0 CHECK (local_diagnostic IN (0, 1));
                                                -- 1: a diagnostic local submission (AD-0021 section 5); a routed call never sets it

CREATE TABLE routed_call_log (                  -- center-routed calls; remote_command_log stays for the unserved command kinds
  log_id INTEGER NOT NULL PRIMARY KEY,
  received_at INTEGER NOT NULL,
  frame_sha256 BLOB NOT NULL CHECK (length(frame_sha256) = 32),  -- the received call frame; names a refused frame without trusting its IDs
  decision INTEGER NOT NULL CHECK (decision BETWEEN 1 AND 5),
                                                -- 1 executed, 2 refused by policy, 3 refused at verification, 4 expired before the effect,
                                                -- 5 verified, outcome pending (written at verification, before any effect)
  refusal_step TEXT CHECK (refusal_step IS NULL OR length(refusal_step) BETWEEN 1 AND 40),  -- decision 3: the failed step (closed vocabulary)
  refusal_code TEXT CHECK (refusal_code IS NULL OR length(refusal_code) BETWEEN 3 AND 80),  -- CATEGORY/code only; never a message or details
  call_id BLOB CHECK (call_id IS NULL OR length(call_id) = 16),  -- verified calls only
  signature_kid TEXT CHECK (signature_kid IS NULL OR length(signature_kid) BETWEEN 1 AND 128),
  method INTEGER CHECK (method IS NULL OR method BETWEEN 1 AND 6),  -- 1 submit, 2 get, 3 list, 4 wait, 5 read output, 6 cancel
  caller BLOB CHECK (caller IS NULL OR length(caller) BETWEEN 1 AND 1024),  -- node.v1 CenterCaller, as signed in the call header
  command_id BLOB CHECK (command_id IS NULL OR length(command_id) = 16),  -- submit and cancel
  task_id BLOB CHECK (task_id IS NULL OR length(task_id) = 16),
  risk INTEGER CHECK (risk IS NULL OR risk BETWEEN 1 AND 3),
  request_sha256 BLOB CHECK (request_sha256 IS NULL OR length(request_sha256) = 32),
  request_size INTEGER CHECK (request_size IS NULL OR request_size >= 0),
  response_sha256 BLOB CHECK (response_sha256 IS NULL OR length(response_sha256) = 32),
  response_size INTEGER CHECK (response_size IS NULL OR response_size >= 0),
  CHECK ((decision = 3) = (call_id IS NULL)),
  CHECK (decision <> 3 OR (signature_kid IS NULL AND method IS NULL AND caller IS NULL AND command_id IS NULL
                           AND task_id IS NULL AND risk IS NULL AND request_sha256 IS NULL AND request_size IS NULL
                           AND response_sha256 IS NULL AND response_size IS NULL)),
  CHECK ((decision = 3) = (refusal_step IS NOT NULL)),
  CHECK (decision IN (1, 5) OR refusal_code IS NOT NULL),
  CHECK (decision = 3 OR (signature_kid IS NOT NULL AND method IS NOT NULL AND caller IS NOT NULL
                          AND request_sha256 IS NOT NULL AND request_size IS NOT NULL))
) STRICT;
CREATE INDEX ix_routed_call_log__received ON routed_call_log (received_at);
CREATE UNIQUE INDEX ux_routed_call_log__call ON routed_call_log (call_id) WHERE call_id IS NOT NULL;  -- a logged call ID is a replay
CREATE INDEX ix_routed_call_log__command ON routed_call_log (command_id) WHERE command_id IS NOT NULL;
