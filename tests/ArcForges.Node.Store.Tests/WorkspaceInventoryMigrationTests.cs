// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store.Tests;

/// <summary>Real SQLite upgrade and compatible old-writer behavior for workspace inventory cursors.</summary>
public sealed class WorkspaceInventoryMigrationTests
{
    [Fact]
    public void StepFivePreservesExistingRowsAndTracksCompatibleWriterChangesWithoutUseUpdates()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var oldPlan = new MigrationPlan(StoreMigrations.Released.Steps.Take(4));
        byte[] id = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        using (var old = root.Open(clock, oldPlan))
        {
            old.Write(transaction => transaction.Execute("""
                INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                VALUES ($id, 1, 2, 'kept', '/synthetic/kept', 1, 1, 0);
                """, ("$id", id)));
        }

        using (var current = root.Open(clock))
        {
            Assert.Equal(4, current.Opening.MigratedFrom);
            Assert.Equal(5, current.Metadata.SchemaVersion);
            Assert.Equal(1, current.Metadata.MinReaderVersion);
            Assert.Equal("kept", current.Read(reader => reader.Scalar("SELECT name FROM workspace WHERE workspace_id = $id;", ("$id", id))));
            Assert.Equal(0L, current.Read(reader => reader.Scalar("SELECT revision FROM workspace_inventory_revision WHERE singleton = 1;")));
            current.Write(transaction => transaction.Execute("UPDATE workspace SET last_used_at = 2, rev = rev + 1 WHERE workspace_id = $id;", ("$id", id)));
            Assert.Equal(0L, current.Read(reader => reader.Scalar("SELECT revision FROM workspace_inventory_revision WHERE singleton = 1;")));
            current.Write(transaction => transaction.Execute("UPDATE workspace SET name = 'changed' WHERE workspace_id = $id;", ("$id", id)));
            Assert.Equal(1L, current.Read(reader => reader.Scalar("SELECT revision FROM workspace_inventory_revision WHERE singleton = 1;")));
            Assert.Single(StoreBackups.List(root.Path));
        }

        // The older binary still opens the expanded schema, and its ordinary writes invoke the persisted triggers.
        using (var older = root.Open(clock, oldPlan))
        {
            Assert.Equal(5, older.Metadata.SchemaVersion);
            older.Write(transaction => transaction.Execute("UPDATE workspace SET state = 3 WHERE workspace_id = $id;", ("$id", id)));
        }

        using var reopened = root.Open(clock);
        Assert.Equal(2L, reopened.Read(reader => reader.Scalar("SELECT revision FROM workspace_inventory_revision WHERE singleton = 1;")));
        Assert.Equal(3L, reopened.Read(reader => reader.Scalar("SELECT state FROM workspace WHERE workspace_id = $id;", ("$id", id))));
    }
}
