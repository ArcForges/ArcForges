<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Owned Sandbox data

Use the local Node to inspect, import and export data under the Sandbox's private root. Paths such as `work/result.bin` are relative to that root. The local source and export destination are paths on the machine running the CLI.

```sh
arcforges sandbox usage "$SANDBOX_ID" --json
arcforges sandbox files "$SANDBOX_ID" work --limit 50 --json
arcforges sandbox files "$SANDBOX_ID" work --cursor "$NEXT_CURSOR" --json
```

Usage reports owned logical bytes, file count, observation time and excluded external grant roots. Allocated bytes appear when the platform can measure them. A partial result describes the data observed so far. Listing returns metadata, including a file's version token, and an opaque cursor for the same Sandbox and directory.

## Import one file

```sh
arcforges sandbox import "$SANDBOX_ID" ./artifact.bin --to work/artifact.bin --json
```

Import records the length and SHA-256 of the opened local regular file. The Node verifies contiguous chunks and the complete staged file before publishing it. Wait for active Runs to drain before starting an import.

The initial Windows and Linux profiles publish to fresh destinations. `--overwrite` requires the exact version shown by `sandbox files` and a qualified native replacement guard. A changed target returns `CONFLICT/identity_changed`. A matching version with an unavailable guard returns `EXECUTION/unsupported_combination` before touching the target.

The Node admits up to 256 MiB per file and reserves up to 1 GiB across the owner's retained transfers. Transfer expiry defaults to one hour. An unresolved effect or unconfirmed stage release holds its reservation until verified reconciliation.

A durable failure or lost response includes the exact command ID and owner epoch when available. Inspect that command with `arcforges operation inspect "$COMMAND_ID" --owner-epoch "$OWNER_EPOCH"`. If you need to replay Begin, supply those same values as `--command-id` and `--owner-epoch`, the original `--expected-revision`, and the original file and options.

To continue an already identified open import, use the same local file and transfer:

```sh
arcforges sandbox import "$SANDBOX_ID" ./artifact.bin --to work/artifact.bin \
  --resume "$TRANSFER_ID" --owner-epoch "$OWNER_EPOCH"
```

Resume reads the verified upload offset from the Node. An unresolved commit requires inspection and reconciliation before any further publication.

## Export one file

```sh
arcforges sandbox export "$SANDBOX_ID" work/artifact.bin --to ./download.bin --json
arcforges sandbox export "$SANDBOX_ID" work/artifact.bin --to ./another-download.bin \
  --resume "$TRANSFER_ID" --owner-epoch "$OWNER_EPOCH"
```

Start an export while the Sandbox is quiescent. The CLI waits for the Node to verify a complete private snapshot. It checks the snapshot's ranges, length and SHA-256, then publishes the local file in the destination directory. Choose a new local destination. An existing file produces a conflict and leaves the snapshot available.

Resuming reads the same retained snapshot, including any final range whose response was lost. Later changes to the source do not change those bytes. After successful local publication the CLI closes the transfer. If closure fails, the result still reports whether the local file was published.

## Inspect or close a transfer

```sh
arcforges sandbox transfer inspect "$TRANSFER_ID" --json
arcforges sandbox transfer close "$TRANSFER_ID" --owner-epoch "$OWNER_EPOCH" --json
```

Inspect shows current progress, completion and `closedAt` for a safely released transfer. An export can remain readable after completion until closure or safe expiry. An interrupted command leaves the identified transfer available for inspection. Explicit close releases a safely settled snapshot or cancels known unused staging. A transfer requiring recovery preserves its evidence.

To replay a Close whose response was lost, also pass its original `--command-id` and `--expected-revision`.

## Preview and delete a Sandbox

```sh
arcforges sandbox delete "$SANDBOX_ID" --plan-only --json
arcforges sandbox delete "$SANDBOX_ID" --plan "$PLAN_ID" \
  --expected-revision "$PLAN_REVISION" --yes --json
```

Review the preview's Sandbox ID, revision, expiry, owned data estimate and
blocking Run and transfer IDs. Excluded host grants remain outside the
deletion. A preview can be abandoned without deleting data. Stop active Runs
or explicitly close retained transfers before requesting a new preview.

The preview is valid for five minutes in the Node instance that issued it.
Request a new preview after expiry or a Node restart. In an interactive
terminal, type the Sandbox ID when prompted. For JSON output or redirected
input, pass `--yes` after reviewing the plan. The Node rechecks the revision,
owned root and managed use at execution. The receipt reports acceptance or
the observed effect. Only a successful receipt confirms deletion.

The default per-user Linux configuration reports `VALIDATION/path_rejected`
with reason `linux_exact_directory_mutation_unavailable` before admitting a
deletion effect. The optional protected storage configuration requires a
dedicated service account and fresh ext4 storage.

### Linux protected storage

This development profile is awaiting installed native qualification. Use a
disposable development instance while the protected Linux qualification is open.

The host administrator reserves a persistent, locked, non-login UID for one
Node. Install the fixed Node and CLI in a root-controlled location. Protect the
service configuration and native systemd user manager from ordinary accounts.
Run the Node and trusted local CLI under that UID with its native user manager.
The existing owner-only socket authenticates the service UID. This profile is
offline. The official Linux MXC executor still runs Sandbox workloads.

Set `ARCFORGES_LINUX_PROTECTED_STORAGE=1` in the protected Node service
configuration and set `dataRoot` in its Node configuration to
`/var/lib/arcforges/<instance>/data`. Use a new instance name with ASCII
letters, digits, hyphens or underscores, starting with a letter or digit.
The administrator owns the enclosing directories and grants ordinary accounts
no write access to them. The instance and data directories must use the same
local ext4 mount. Provision a fresh service-owned `data` directory with mode
`0700` and its regular `node.lock` file with mode `0600`. In the instance
directory create a root-owned `sandbox-deletion-owner.v1` record with one line
`arcforges-sandbox-deletion-v1 <uid>` followed by a newline. Only root may
modify the record. Give the service UID read access, for example with mode
`0444`. At first startup the Node checks that `data` contains only the lock
and records the identity of the new store before initializing it.

Keep existing stores, private roots and journals in their original location.
Create new Sandboxes in the protected store, then export and import selected
data by copy. Restart or resume through the same protected configuration.

## Resume an accepted deletion

```sh
arcforges operation inspect "$ORIGINAL_COMMAND_ID" --owner-epoch "$OWNER_EPOCH" --json
arcforges sandbox inspect "$SANDBOX_ID" --json
arcforges sandbox delete "$SANDBOX_ID" --resume "$ORIGINAL_COMMAND_ID" \
  --expected-revision "$CURRENT_SANDBOX_REVISION" --json
```

Use resume locally when inspection shows that the original deletion needs a
continuation. It creates a new command in the current owner epoch and uses
the original deletion journal. The value passed to `--resume` stays the
original command ID even when an earlier successor was interrupted.
An explicit successor can finalize the Sandbox tombstone from retained
durable native proof of removal. An absent path without that proof leaves the
outcome `UNKNOWN`.

Cancellation or a deadline ends the CLI's wait. Inspect the receipt to
determine the outcome. To replay the exact apply or successor, keep its
original `--plan` or `--resume` selection and supply that mutation's own
`--command-id`, `--owner-epoch` and `--expected-revision`.
