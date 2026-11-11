// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Actual SQLite migration and compatible earlier-writer guards for private stage metadata.</summary>
[Trait("check", "schema")]
public sealed class PrivateStageMigrationTests
{
    [Fact]
    public void StepEightPreservesEarlierRowsAndGuardsPendingStagesAgainstOlderWriters()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var legacy = new MigrationPlan(StoreMigrations.Released.Steps.Take(7));
        var workspace = StoreIds.NewUuid7(clock);
        var command = StoreIds.NewUuid7(clock);
        var correlation = StoreIds.NewUuid7(clock);
        using (var old = root.Open(clock, legacy))
        {
            old.Write(t =>
            {
                t.Execute("""
                    INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                    VALUES ($workspace, 1, 2, 'owned fixture', '/fixture', 0, 0, 0);
                    """, ("$workspace", workspace));
                t.Execute("""
                    INSERT INTO command_dedup (command_id, method, payload_digest, origin, created_at, expires_at)
                    VALUES ($command, 'arcforges.node.v1.FileService/WriteFile', zeroblob(32), 4, 0, 1);
                    """, ("$command", command));
            }, CommitDurability.Full);
        }

        using (var current = root.Open(clock))
        {
            Assert.Equal(7, current.Opening.MigratedFrom);
            Assert.Equal(8, current.Metadata.SchemaVersion);
            current.Write(t =>
            {
                t.Execute("""
                    INSERT INTO file_private_stage_reservation
                      (command_id, workspace_id, kind, correlation_id, relative_path, expected_absent, request_sha256,
                       caller, reserved_bytes, created_at)
                    VALUES ($command, $workspace, 1, $correlation, 'target', 1, zeroblob(32), x'01', 10, 0);
                    """, ("$command", command), ("$workspace", workspace), ("$correlation", correlation));
                t.Execute("""
                    INSERT INTO file_private_stage_object
                      (command_id, slot, stage_path, expected_size, expected_sha256, phase, identity_platform, native_identity, parent_identity)
                    VALUES ($command, 2, '/fixture/stage', 10, zeroblob(32), 2, 1, zeroblob(33), zeroblob(33));
                    """, ("$command", command));
            }, CommitDurability.Full);
        }

        using var older = root.Open(clock, legacy); // Actual new-schema DB with the supported older migration plan.
        Assert.Equal(8, older.Metadata.SchemaVersion);
        Assert.Equal(1, older.Metadata.MinReaderVersion);
        Assert.Equal(19, Assert.Throws<SqliteException>(() => older.Write(t => t.Execute(
            "UPDATE workspace SET removed_at = 1 WHERE workspace_id = $id;", ("$id", workspace)))).SqliteErrorCode);
        Assert.Equal(0, older.Write(t => t.Execute("DELETE FROM command_dedup WHERE command_id = $id;", ("$id", command))));
        Assert.Equal(0, older.Write(t => t.Execute("DELETE FROM file_private_stage_object WHERE command_id = $id;", ("$id", command))));
        Assert.Equal(19, Assert.Throws<SqliteException>(() => older.Write(t => t.Execute(
            "UPDATE file_private_stage_object SET native_identity = randomblob(33) WHERE command_id = $id;", ("$id", command)))).SqliteErrorCode);
        Assert.Equal(19, Assert.Throws<SqliteException>(() => older.Write(t => t.Execute(
            "UPDATE file_private_stage_object SET parent_identity = randomblob(33) WHERE command_id = $id;", ("$id", command)))).SqliteErrorCode);
        Assert.Equal(19, Assert.Throws<SqliteException>(() => older.Write(t => t.Execute(
            "UPDATE file_private_stage_reservation SET reserved_bytes = 0 WHERE command_id = $id;", ("$id", command)))).SqliteErrorCode);
        Assert.Equal(1L, older.Read(r => r.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal(1L, older.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_object;")));
    }
}
