# Prepare and stage an offline Node migration

Stop the original Node cleanly on its original host. Run the migration as the
same local owner, on that same boot, with the verified predecessor's schema 15
data root. Keep its database, owner lock, records and native custody evidence
together. Resolve any reported custody blockers before proceeding.

```text
arcforges-migrate-node prepare SOURCE EXPANDED BACKUP
arcforges-migrate-node stage EXPANDED BACKUP STAGE
```

Choose three distinct, nonexistent output directories whose parents already
exist. Keep them outside the original data root. `prepare` verifies the closed
source and copies its exact database bytes while holding the native owner scope.
Only that copy opens for the schema 15 to 19 upgrade. It keeps the original
Node ID and creates the local owner's protected V2 epoch. `BACKUP` contains
the independently authenticated database, owner fence and backup manifest. Its
keys remain in the configured protected backing store. Keep both prepared roots
and that key authority together.

`stage` rechecks the detached expanded copy and restores the authenticated
backup into `STAGE` before applying schema 20. The result is an offline migration
artifact for the separately controlled cutover. Keep the original root and
backup. If a command fails after creating an output directory, retain it for
diagnosis and choose fresh paths for a subsequent attempt.

For isolated verification only, pass `--test-mode` to both commands and use
disposable test roots. That option keeps key access inside those roots.
