# AFV2-DATA-01: SQLite owner-command primitives

This is a store-layer expand implementation against Design
`493022fbf643b484665b2713c9eb8670f2fb2234`. It registers no V2 Node IPC, CLI,
Run, Stop, grant-revocation or native executor. Those consumers and their real
effect observations belong to their later Core/recovery tasks. Installed cohorts
and deployment state are not inferred from these fixtures.

Schema16 raises the reader floor to16. The applied0001–0015 SQL, recorded hashes,
legacy tables, key ring, unknown file journals and their protection triggers stay
intact. `schema_version` and the permanent migration checkpoint bind the actual
pre-migration backup digest, migration source digest, supplied build cohort and
retained unresolved legacy journal count. Fresh creation records that no prior
backup exists. The caller's cohort defaults to the honest local-development
identity `local`; it is not a claim of a released artifact.

The target DDL is a logical model, not an upgrade script. Only the existing V1
name collision is adapted: logical V2 `resource_sample` is physically
`v2_resource_sample`. The old `resource_sample` columns, primary key and consumers
are unchanged. The source manifest records this fixed mapping; there is no
configurable naming layer.

## Commands, observations and capacity

`DurableCommandStore` uses the existing single writer and FULL SQLite
transactions. It is composed with the existing protected `NodeSecretStore`.
Tests use its actual file-backed data-root backend, never a real OS secret store.
The initial epoch is random16 bytes and its32-byte HMAC key is kept only in that
backend/in memory. SQL stores the exact backend/key reference. Missing key, wrong
backend, missing DB with existing authority, corrupt or inconsistent history
cannot become a fresh epoch. There is no automatic rotation or retirement API.
Schema16 rejects SQL updates of owner state/retirement time: a DB-only retirement
cannot be acknowledged without the future qualified offline guard and independent
fence protocol. Preexisting retired metadata still refuses admission and remains
in maintenance; this expand does not authorize creating or reactivating authority.

The schema16 canonical version is1. The caller supplies its original authorized,
effect-bearing canonical request bytes, including admitted config/profile/grant
revisions and argv/env/path differences. Retry correlation/deadline metadata is
outside this store intent. The store length-frames and HMAC-binds every supplied
byte plus owner, original epoch, canonical method, aggregate identity, expected
Sandbox revision and linked safety parent. It persists neither the raw canonical
request nor a bare input digest. Future Core adapters must construct this typed
intent before admission and authorize every result disclosure.

`Admit` returns `Execute` only after durable admission. Its optional callback
changes SQLite metadata in that same transaction, not a native/network effect.
Matching accepted/unknown commands return `InProgress`; settled commands replay;
conflicting method/content returns `Conflict`. An old/different epoch is refused.
Sandbox revision preconditions and their metadata changes share the transaction.
`SetResult` accepts explicit bounded redacted effect observations; it never infers
native success. An unresolved transfer/delete cannot be settled as known. Its
optional metadata callback records the corresponding observation atomically.

Each admission and subsequent effect observation first fsyncs a signed,
append-only owner-history fence outside SQLite, then commits the corresponding
sequence/history in FULL mode. A torn/prepared-but-uncommitted fence requires
maintenance. A committed-but-unacknowledged admission cannot be executed again.
Duplicate observations do not append history. This is a conservative replay and
restore boundary, not a new native authority protocol or proof of power-loss
behavior on every filesystem.

Persisted receipt-count/response-byte budgets reserve actual SQLite BLOB space
and future receipt slots for the already admitted command's one convergent
linked safety/completion intent. A safety intent has the same owner/epoch and
aggregate, cannot be nested, and repeated requests converge on its recorded
identity. New nonsafety work cannot consume this lane. Accepted/unknown responses
retain their bounded completion reservation. Known safety completion replenishes
the reserve only within the persisted byte budget. These are real SQLite
admission budgets, not a guarantee against arbitrary external host disk writes;
actual Stop/revoke/reconciliation under saturation is AFV2-REC-01 evidence.

Known response bodies compact no earlier than24 hours after known resolution;
the original identity, method, keyed intent, aggregate, state and effect remain.
Compacted mutation replay returns `Compacted` with that retained result, never
`Execute` or a reconstructed success. `Inspect` returns the retained operation
projection. Unknown/accepted/unresolved bodies remain. The old V1
`CommandDeduplication` expiry path is separate and cannot delete V2 identities.
Transient terminal-control methods are refused by both the canonical API and
the SQL method guard.

## Backup and restore

`CreateBackup` takes the fixed owner-root catalogue gate before reading its full
owner set, then the owner gates, uses SQLite online backup and the existing
legacy sealed-value sanitization, copies every referenced epoch key to the
explicit protected backup backend, and signs a complete DB/key/history manifest.
Partial packages without a valid manifest are not ready backups. It does not
overwrite an existing backup root.

`RestoreBackup` requires a new destination and a separately retained latest
authority root/backend. A backup's own old fence cannot prove its freshness.
The independently retained latest DB must be readable and its complete owner/
epoch/state/history catalogue and exact external fence set must match the
manifest under the catalogue gate. A newly created owner cannot be omitted
because its identity was absent from an old manifest. When this latest catalogue
is missing or corrupt, reconciliation remains required; no old backup catalogue
is substituted. The exact backup DB digest, complete epoch-key closure and every
admission/effect-history fence must agree. A post-backup admission **or later settlement of an already
accepted command** prevents activation under the old epoch. Missing/corrupt
DB/key/fence or absent latest authority refuses restore and preserves maintenance
and reconciliation; no new epoch is silently created. Source and destination
keys/metadata keep the same epoch and backend references. Offline retirement
requires separately authorized guards and is not implemented as routine cleanup.

An independent review of the earlier `1e02e335` candidate reproduced a DB-only
retirement followed by latest-DB rollback which made the old active catalogue and
fence match again. The retirement-state SQL guard closes that unsupported write
path before any state change. Its regression uses a known `DID_NOT_HAPPEN` result,
real backup, rejected retirement, controlled DB rollback and replay; it does not
claim a successful retirement or a native offline-authority check.

## Reproducible author checks

```powershell
python eng/check_toolchain.py
dotnet restore tests/ArcForges.Node.Store.Tests/ArcForges.Node.Store.Tests.csproj --locked-mode
dotnet build tests/ArcForges.Node.Store.Tests/ArcForges.Node.Store.Tests.csproj -c Release --no-restore -warnaserror
dotnet test --project tests/ArcForges.Node.Store.Tests/ArcForges.Node.Store.Tests.csproj -c Release --no-build --filter-class ArcForges.Node.Store.Tests.DurableCommandStoreTests
```

The same exact pushed source is checked independently on H-22. The process case
invokes the existing built test project twice with one exact method filter and
test-local phase/root values. Both children use real SQLite and file keys. Only
the admission counter and supplied intent/effect observations are synthetic;
the fixture clock advances compaction time. Parent and children retain the
original command/epoch, verify exits/cleanup and detect a second admission.
This is not a real Start, RunSupervisor, Node IPC, CLI or live safety-operation
test. Author diagnostics, required exact-head host profiles, review, merge and
publication remain separate evidence in Plan.
