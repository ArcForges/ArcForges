// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Actual SQLite step-nine upgrade and old-writer checks; process lifetime is tested separately in Node.Core.</summary>
[Trait("check", "schema")]
public sealed class WorkerMigrationTests
{
    [Fact]
    public void StepTenPreservesPreparedJournalAndStopsAnOlderWriterReleasingItsHold()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var stepNine = new MigrationPlan(StoreMigrations.Released.Steps.Take(9));
        var workspace = StoreIds.NewUuid7(clock);
        var command = StoreIds.NewUuid7(clock);
        var correlation = StoreIds.NewUuid7(clock);
        using (var old = root.Open(clock, stepNine))
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
                t.Execute("""
                    INSERT INTO file_operation_journal
                      (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
                       identity_platform, root_identity, parent_identity, expected_absent, intended_size, intended_sha256,
                       intended_stage_identity, created_at, updated_at, held, acknowledged)
                    VALUES ($id, 1, 1, zeroblob(32), x'01', $correlation, $workspace, 'target', 1, zeroblob(33), zeroblob(33),
                            1, 6, zeroblob(32), zeroblob(33), 0, 0, 1, 0);
                    """, ("$id", command), ("$correlation", correlation), ("$workspace", workspace));
            }, CommitDurability.Full);
        }

        using (var current = root.Open(clock, new MigrationPlan(StoreMigrations.Released.Steps.Take(10))))
        {
            Assert.Equal(9, current.Opening.MigratedFrom);
            Assert.Equal(10, current.Metadata.SchemaVersion);
            Assert.Equal(1, current.Metadata.MinReaderVersion);
            Assert.Equal(1L, current.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal WHERE phase = 1 AND held = 1;")));
            Assert.Equal(0L, current.Read(r => r.Scalar("SELECT count(*) FROM file_effect_worker;")));
            current.Write(t => t.Execute("""
                INSERT INTO file_effect_worker (command_id, boot_id, pid_namespace, process_id, start_ticks)
                VALUES ($id, '11111111-1111-1111-1111-111111111111', 'pid:[1234]', 1234, 9001);
                """, ("$id", command)), CommitDurability.Full);
        }

        using var older = root.Open(clock, stepNine);
        Assert.Equal(10, older.Metadata.SchemaVersion);
        var blocked = Assert.Throws<SqliteException>(() => older.Write(t => t.Execute("""
            UPDATE file_operation_journal SET phase = 3, held = 0, acknowledged = 1 WHERE command_id = $id;
            """, ("$id", command)), CommitDurability.Full));
        Assert.Contains("file_worker_still_running", blocked.Message, StringComparison.Ordinal);
        Assert.Equal(0, older.Write(t => t.Execute("DELETE FROM file_effect_worker WHERE command_id = $id;", ("$id", command)), CommitDurability.Full));
        var identity = Assert.Throws<SqliteException>(() => older.Write(t => t.Execute("""
            UPDATE file_effect_worker SET process_id = 2 WHERE command_id = $id;
            """, ("$id", command)), CommitDurability.Full));
        Assert.Contains("file_worker_identity_immutable", identity.Message, StringComparison.Ordinal);
        Assert.Equal(1L, older.Read(r => r.Scalar("SELECT held FROM file_operation_journal WHERE command_id = $id;", ("$id", command))));
        // SQL-only trigger test; this does not claim the synthetic PID actually ended.
        older.Write(t => t.Execute("UPDATE file_effect_worker SET ended = 1 WHERE command_id = $id;", ("$id", command)), CommitDurability.Full);
        older.Write(t => t.Execute("""
            UPDATE file_operation_journal SET phase = 3, held = 0, acknowledged = 1 WHERE command_id = $id;
            """, ("$id", command)), CommitDurability.Full);
        var reactivated = Assert.Throws<SqliteException>(() => older.Write(t => t.Execute(
            "UPDATE file_effect_worker SET ended = 0 WHERE command_id = $id;", ("$id", command)), CommitDurability.Full));
        Assert.Contains("file_worker_ended", reactivated.Message, StringComparison.Ordinal);
        Assert.Equal(0L, older.Read(r => r.Scalar("SELECT held FROM file_operation_journal WHERE command_id = $id;", ("$id", command))));
    }
}
