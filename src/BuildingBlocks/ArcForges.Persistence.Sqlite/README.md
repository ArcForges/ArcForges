# ArcForges.Persistence.Sqlite

PLT.01 implements the shared local store mechanism: one authorized atomic write path,
owner-bound version tokens, durable command receipts, payload/origin co-commit and outbox.
PLT.02 supplies the journal and PLT.04 supplies ordered schema migrations through restricted
internal transaction contexts. Products retain their own files and schemas.

`SqliteStore` is an owner-repository mechanism. Applications expose domain DTOs through
their repository ports. `Write` validates a payload's typed content-origin carrier,
authorizes the caller, checks the complete materialized version, and atomically writes
the payload/origin, checksummed journal record, next version, publication outbox and
command receipt. Reusing a command ID with different semantic content refuses. A retry
of the same authorized command returns the durable receipt without another effect.

Notifications run only after commit. A notification exception or interrupted return
does not prove that the effect failed: reconcile using the same command ID. Reads use
independent snapshots; SQLite serializes writers across separate store instances too.
The file's durable store identity prevents opening it under a different owner identity.

Origin records preserve protobuf unknown fields. Unsupported origin profiles are
read-only; exact payload hashes, immutable origin identities and inherited kind unions
are enforced. The newest 64 aggregate versions pin origin history. Persistent reference
counts retain transitive lineage, and each commit collects at most 64 expired history
roots and 64 unreferenced origins, each with at most 32 parent edges. Immutable origin
hash identities remain after collection to prevent reassigning an old ID.

`Migrations` applies trusted owner-authored SQL before normal work with one physical
exclusive schema session and a transaction per numbered step. The SQL authorizer fences
mechanism tables, transaction controls and temporary schema shadows; it is not a sandbox
for untrusted SQL. No provider connection or transaction is part of the public API.

PLT.03 completes journal retention with policy-triggered, self-describing SQLite snapshots.
The snapshot envelope binds the owner identity, sequence, storage schema version,
journal-boundary checksum and full database bytes under SHA-256 checksums. It is written and flushed as a sibling temporary file,
atomically published, reopened and verified, then authorizes truncation of only its exact
committed journal prefix. Two verified generations are retained. A failed snapshot never
changes an already durable write receipt or truncates its journal prefix; `LastSnapshotFailure`
reports the post-commit maintenance failure.

On open, the owner validates SQLite integrity and the retained checksummed journal. If repair
is needed, it preserves the original database and sidecars, restores the newest verifiable
snapshot, and replays the contiguous valid journal suffix. `Recovery` exposes a typed outcome;
when any tail is unavailable the store enters read-first safe start and refuses canonical
writes. If no snapshot can verify, `StoreRecoveryException.Report` identifies the untouched
database as evidence and opening fails without replacing it. A healthy canonical database is
never rolled back just because a snapshot file is damaged.

Offline real-file tests cover policy publication/truncation, clean reopen, corrupt snapshot,
corrupt journal tail with verified-prefix replay, evidence preservation, orphaned SQLite
sidecars, injected `SQLITE_FULL` transaction rollback, snapshot-stage interruption and
numbered-migration interruption. These tests do not claim to simulate power loss, device
filesystems or real hardware. Native process-kill validation remains an explicit local opt-in;
it is not run as part of normal CI.
