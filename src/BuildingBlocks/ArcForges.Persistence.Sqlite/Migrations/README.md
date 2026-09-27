<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Numbered storage migrations

PLT.04 owns the migration runner and its migration fixtures. Product owners supply their own numbered schema steps; the mechanism does not claim product schema compatibility from synthetic fixtures.

Each successful step and its migration-history record commit together. Interruption rolls back the current step; a later run skips completed steps. The reported StorageSchemaVersion is the highest applied step. Unsupported downgrades are rejected before any changes.

The shared SQLite provider, dependency admission and transaction context are owned by PLT.01. Migration operations run exclusively before the normal application write path opens, without advancing a business revision or substituting for its journal.
