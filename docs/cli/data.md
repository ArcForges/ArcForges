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
