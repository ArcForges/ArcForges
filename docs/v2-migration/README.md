<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# V2 read-only migration preflight

AFV2-BASE-01 prepares an inventory. It does not migrate, initialize, drain,
delete, admit a binary, or establish that an installation is safe to contract.
The existing executor and all applied SQL remain unchanged.

```sh
python eng/v2-migration/preflight.py --database /explicit/offline/node.db > node-preflight.json
python -m unittest discover -s eng/v2-migration -v
```

The database must be an operator-selected offline SQLite snapshot. Do not point
this command at arbitrary credential/configuration files. A missing file is
reported `fresh` without creating it. A recognized schema15 snapshot is
`node15`; unsupported/corrupt/drifted/locked inputs are `unknown`; a newer schema
or reader floor is `newer`. Exit code 2 means unknown/newer inspection, and 0
means a recognized inventory result. Neither exit code authorizes migration.

The tool holds native read protection, reads a bounded snapshot into memory and
queries that copy. It does not open the source through SQLite, recover a journal,
checkpoint WAL, or create sidecars. WAL/hot-journal inputs are refused; obtain a
consistent offline backup using the existing operational backup procedure first.
The limit is 512 MiB; larger stores require a separately reviewed inspection path.
Windows denies writers and rename/delete sharing; Linux uses SQLite's rollback
locking bytes and verifies the opened inode and final path identity. These locks
are a diagnostic boundary, not proof of exclusive native process ownership.

Reports contain version/reader metadata, source SQL hashes and aggregate counts
of unsettled receipts, attempts, journals, workers, stages and quarantine. They
exclude row contents, commands, paths stored in rows and exception text. Node15
has no installed migration checksum ledger: a source hash is distinguished from
the separate exact schema-object comparison. `--binary /explicit/arcforges`
optionally hashes installed bytes without executing them. Its provenance stays
unproven; no binary input leaves the installed cohort `unknown`.

Run the Center companion in Cloud, `eng/v2-migration/preflight.py`, and the
Contracts consumer inventory, `eng/v2-consumers/inventory.py --workspace <root>`,
separately. Their revisions and installation/authority limitations remain visible.
Shared `arcforges.local.sandbox.v1` is DesktopPlatform ContentSandbox. Independent
Mobile, AI, ArcScope, ArcSlate and ArcNotes are protected consumers, outside V2
deletion scope. BASE-01 removes no executor, runtime route, applied migration or
published package.

## Backup, restore and cutover prerequisites

Before a later destructive migration, an operator must establish H-03 with the
actual installed cohort and approved backup venue. This script never supplies
that missing authority. Follow the current Design `docs/data/migrations.md` and
the owning later task; do not improvise a live SQL transition from this report.

1. Stop new V1 submissions and drain or explicitly stop owned Task/Attempt
   processes. Record native group-empty/exclusive control evidence. A clean
   database shutdown marker alone is insufficient. Never relabel an executing
   Attempt as a V2 Run.
2. Preserve all unresolved command/file receipts, journals, quarantine, worker
   identities, recovery floors, protected keys and pending audits. Any unresolved
   effect blocks contraction until settled or copied into retained reconciliation
   storage. Inventory zero counts does not waive native ownership checks.
3. Create a coherent backup through the existing store backup operation, with
   database, owned data roots, protected operational files and cohort manifest.
   Keep external host grants outside owned deletion scope. Record hashes in the
   approved venue; never export credentials into this JSON or source repository.
4. Restore into a separate approved fixture and test it before cutover. Node
   fresh/schema15 migration and epoch/key/receipt preservation belong to DATA-01;
   actual Start/recovery and incomplete-backup rejection belong to CORE-02/REC-01.
   Preserve immutable 0001..0015 SQL. Qualify both MXC profiles before executor
   retirement. This preparation has no V2 migration implementation.
5. Center fresh/schema10/schema11 guarded transition belongs to CENTER-01. Keep
   0011's credential/restore floor and every applied checksum. Replaying its DDL
   in an inventory fixture proves neither deployed schema11 nor provider/runtime
   authority. Appending 0012 alone is not an admitted upgrade.
6. Review the current consumer/module inventory before source/route/schema
   contraction. Complete replacement and typed caller cutover under their owning
   tasks, then remove old runtime paths in MIG-01/MIG-02.

Before any V2 effect, rollback uses the last accepted cohort and its coherent
backup. After any V2 effect, keep every admitted owner-epoch command/effect identity
and protected key; an older backup missing later effects must remain in
maintenance. Do not rotate the epoch or downgrade the binary to bypass this.
After irreversible deletion, restoration needs explicit data-loss accounting.
Failed inventory leaves existing product behavior and all source data intact.
