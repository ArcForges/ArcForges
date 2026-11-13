// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Upgrade an actual step-eight database and exercise step-nine fences through an older writer.</summary>
[Trait("check", "schema")]
public sealed class StageTerminalMigrationTests
{
    [Fact]
    public void StepNinePreservesStagesAndFencesAnOlderWriter()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var stepEight = new MigrationPlan(StoreMigrations.Released.Steps.Take(8));
        var workspace = StoreIds.NewUuid7(clock);
        var command = StoreIds.NewUuid7(clock);
        var correlation = StoreIds.NewUuid7(clock);
        var stagePath = Path.Combine(root.Path, "owned-stage");
        var content = new byte[] { 17, 23, 31, 47, 59, 71 };
        var identity = Enumerable.Range(1, 33).Select(i => (byte)i).ToArray();
        var parent = Enumerable.Range(34, 33).Select(i => (byte)i).ToArray();
        Directory.CreateDirectory(root.Path);
        File.WriteAllBytes(stagePath, content);
        using (var old = root.Open(clock, stepEight))
        {
            Assert.Equal(8, old.Metadata.SchemaVersion);
            old.Write(t =>
            {
                t.Execute("""
                    INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                    VALUES ($workspace, 1, 2, 'owned fixture', $root, 0, 0, 0);
                    """, ("$workspace", workspace), ("$root", root.Path));
                t.Execute("""
                    INSERT INTO command_dedup (command_id, method, payload_digest, origin, created_at, expires_at)
                    VALUES ($command, 'arcforges.node.v1.FileService/WriteFile', zeroblob(32), 4, 0, 1);
                    """, ("$command", command));
                t.Execute("""
                    INSERT INTO file_private_stage_reservation
                      (command_id, workspace_id, kind, correlation_id, relative_path, expected_absent, request_sha256,
                       caller, reserved_bytes, created_at)
                    VALUES ($command, $workspace, 1, $correlation, 'target', 1, zeroblob(32), x'01', 6, 0);
                    """, ("$command", command), ("$workspace", workspace), ("$correlation", correlation));
                t.Execute("""
                    INSERT INTO file_private_stage_object
                      (command_id, slot, stage_path, expected_size, expected_sha256, phase, identity_platform, native_identity, parent_identity)
                    VALUES ($command, 2, $path, 6, zeroblob(32), 2, 1, $identity, $parent);
                    """, ("$command", command), ("$path", stagePath), ("$identity", identity), ("$parent", parent));
            }, CommitDurability.Full);
        }

        using (var current = root.Open(clock, new MigrationPlan(StoreMigrations.Released.Steps.Take(9))))
        {
            Assert.Equal(8, current.Opening.MigratedFrom);
            Assert.Equal(9, current.Metadata.SchemaVersion);
            Assert.Equal(1, current.Metadata.MinReaderVersion);
            Assert.Equal(0L, current.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_terminal;")));
            AssertRetained(current, command, stagePath, identity, parent, content);
            // Exercise the SQLite fence itself; the actual recovery transaction is tested in Node.Core.
            current.Write(t =>
            {
                t.Execute("INSERT INTO file_private_stage_terminal (command_id, completed_at, reason) VALUES ($id, 1, 1);", ("$id", command));
                t.Execute("UPDATE file_private_stage_reservation SET active = 0 WHERE command_id = $id;", ("$id", command));
            }, CommitDurability.Full);
        }

        using var older = root.Open(clock, stepEight);
        Assert.Equal(9, older.Metadata.SchemaVersion);
        var reactivation = Assert.Throws<SqliteException>(() => older.Write(t => t.Execute(
            "UPDATE file_private_stage_reservation SET active = 1 WHERE command_id = $id;", ("$id", command)), CommitDurability.Full));
        Assert.Contains("file_stage_fenced", reactivation.Message, StringComparison.Ordinal);
        var journal = Assert.Throws<SqliteException>(() => older.Write(t => t.Execute("""
            INSERT INTO file_operation_journal
              (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
               identity_platform, root_identity, parent_identity, expected_absent, intended_size, intended_sha256,
               intended_stage_identity, created_at, updated_at, held, acknowledged)
            VALUES ($id, 1, 1, zeroblob(32), x'01', $correlation, $workspace, 'target', 1, zeroblob(33), zeroblob(33),
                    1, 6, zeroblob(32), $identity, 0, 0, 1, 0);
            """, ("$id", command), ("$correlation", correlation), ("$workspace", workspace), ("$identity", identity)), CommitDurability.Full));
        Assert.Contains("file_stage_fenced", journal.Message, StringComparison.Ordinal);
        var binding = Assert.Throws<SqliteException>(() => older.Write(t => t.Execute("""
            INSERT INTO file_private_approval_binding
              (command_id, approval_id, identity_platform, root_identity, parent_identity, target_identity)
            VALUES ($id, $approval, 1, zeroblob(33), zeroblob(33), NULL);
            """, ("$id", command), ("$approval", StoreIds.NewUuid7(clock))), CommitDurability.Full));
        Assert.Contains("file_stage_fenced", binding.Message, StringComparison.Ordinal);
        var changed = Assert.Throws<SqliteException>(() => older.Write(t => t.Execute(
            "UPDATE file_private_stage_terminal SET reason = 2 WHERE command_id = $id;", ("$id", command)), CommitDurability.Full));
        Assert.Contains("file_stage_fence_immutable", changed.Message, StringComparison.Ordinal);
        Assert.Equal(0, older.Write(t => t.Execute("DELETE FROM file_private_stage_terminal WHERE command_id = $id;", ("$id", command)),
            CommitDurability.Full));
        Assert.Equal(0L, older.Read(r => r.Scalar("SELECT active FROM file_private_stage_reservation WHERE command_id = $id;", ("$id", command))));
        Assert.Equal(1L, older.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_terminal WHERE command_id = $id;", ("$id", command))));
        Assert.Equal(0L, older.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(0L, older.Read(r => r.Scalar("SELECT count(*) FROM file_private_approval_binding;")));
        AssertRetained(older, command, stagePath, identity, parent, content);
    }

    private static void AssertRetained(NodeStore store, byte[] command, string stagePath, byte[] identity, byte[] parent, byte[] content)
    {
        Assert.Equal(content, File.ReadAllBytes(stagePath));
        store.Read(r =>
        {
            using var query = r.CreateCommand("""
                SELECT r.reserved_bytes, o.stage_path, o.expected_size, o.native_identity, o.parent_identity
                FROM file_private_stage_reservation r JOIN file_private_stage_object o ON o.command_id = r.command_id
                WHERE r.command_id = $id;
                """);
            query.Parameters.AddWithValue("$id", command);
            using var row = query.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(6L, row.GetInt64(0));
            Assert.Equal(stagePath, row.GetString(1));
            Assert.Equal(6L, row.GetInt64(2));
            Assert.Equal(identity, (byte[])row.GetValue(3));
            Assert.Equal(parent, (byte[])row.GetValue(4));
            Assert.False(row.Read());
            return true;
        });
    }
}
