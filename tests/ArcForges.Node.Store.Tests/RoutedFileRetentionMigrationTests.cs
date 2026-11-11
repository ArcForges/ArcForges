// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Real SQLite migration/legacy-writer guards; wall steps are injected over the live native clock.</summary>
public sealed class RoutedFileRetentionMigrationTests
{
    private const string Register = "arcforges.node.v1.WorkspaceService/RegisterWorkspace";
    private const string Task = "arcforges.node.v1.TaskService/SubmitTask";

    [Fact]
    public void ForwardWallStepAndRestartCannotPruneOrReuseProtectedOldReceipts()
    {
        using var root = new TemporaryDataRoot();
        var clock = new WallStepClock();
        var oldPlan = new MigrationPlan(StoreMigrations.Released.Steps.Take(5));
        var step6 = new MigrationPlan(StoreMigrations.Released.Steps.Take(6));
        var commandId = StoreIds.NewUuid7(clock);
        var unrelatedId = StoreIds.NewUuid7(clock);
        var callId = StoreIds.NewUuid7(clock);
        byte[] digest = [.. Enumerable.Repeat((byte)7, 32)];
        byte[] outcome = [8, 9];
        long originalWall;
        using (var old = root.Open(clock, oldPlan))
        {
            var first = old.Commands.Execute(commandId, Register, digest, Origin.Remote, _ => outcome);
            Assert.False(first.Replayed);
            old.Commands.Execute(unrelatedId, Task, digest, Origin.Human, _ => [1]);
            originalWall = StoreTime.NowMicroseconds(clock);
            old.Write(t =>
            {
                var logId = (long)t.Scalar("""
                    INSERT INTO routed_file_call_log (received_at, frame_sha256, decision, call_id, signature_kid, method, caller,
                      command_id, request_sha256, request_size)
                    VALUES ($at, $digest, 5, $call, 'kid', 17, $caller, $command, $digest, 1) RETURNING log_id;
                    """, ("$at", originalWall), ("$digest", digest), ("$call", callId), ("$caller", new byte[] { 1 }), ("$command", commandId))!;
                var seq = (long)t.Scalar("""
                    INSERT INTO audit_log (at, actor, operation, target_kind, decision, remote_command_id, outcome_summary)
                    VALUES ($at, $actor, 'routed.command.outcome', 'routed_command_owner', 0, $command, 'recorded') RETURNING seq;
                    """, ("$at", originalWall), ("$actor", new byte[] { 1 }), ("$command", commandId))!;
                t.Execute("INSERT INTO file_workspace_audit (audit_seq) VALUES ($seq);", ("$seq", seq));
                Assert.True(logId > 0);
            }, CommitDurability.Full);
        }

        clock.Offset = TimeSpan.FromDays(730);
        using (var upgraded = root.Open(clock, step6))
        {
            Assert.Equal(5, upgraded.Opening.MigratedFrom);
            Assert.Equal(6, upgraded.Metadata.SchemaVersion);
            Assert.Equal(originalWall, upgraded.Read(r => r.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;")));
            // Even with a plausible wall clock on a new process, an old row has not survived 24 real elapsed hours since restart.
            Assert.Equal(0, upgraded.Write(RoutedFileRetention.Prune, CommitDurability.Full));
            Assert.True((long)upgraded.Read(r => r.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;"))! > originalWall);
            Assert.Equal(1, upgraded.Commands.PurgeExpired()); // only the unrelated task receipt
            Assert.True(upgraded.Read(r => RoutedFileRetention.IsHeld(r, commandId)));
            Assert.Equal(1L, upgraded.Read(r => r.Scalar("SELECT count(*) FROM routed_verified_call_id WHERE call_id = $call;", ("$call", callId))));
            upgraded.Write(t =>
            {
                Assert.Equal(0, t.Execute("DELETE FROM routed_file_call_log WHERE received_at < $now;", ("$now", t.NowMicroseconds)));
                Assert.Equal(0, t.Execute("DELETE FROM audit_log WHERE remote_command_id = $id;", ("$id", commandId)));
            });
            Assert.Throws<SqliteException>(() => upgraded.Write(t => t.Execute("""
                INSERT OR REPLACE INTO command_dedup (command_id, method, payload_digest, origin, outcome, created_at, expires_at)
                VALUES ($id, $method, $digest, 1, X'01', $now, $now);
                """, ("$id", commandId), ("$method", Task), ("$digest", digest), ("$now", t.NowMicroseconds))));
        }

        // The precise old housekeeping statements remain harmless on the expanded schema, even after a process restart.
        using (var older = root.Open(clock, oldPlan))
        {
            older.Write(t =>
            {
                Assert.Equal(0, t.Execute("DELETE FROM command_dedup WHERE expires_at <= $now;", ("$now", t.NowMicroseconds)));
                Assert.Equal(0, t.Execute("DELETE FROM routed_file_call_log WHERE received_at < $now;", ("$now", t.NowMicroseconds)));
            });
        }

        clock.Offset = TimeSpan.Zero;
        using var restarted = root.Open(clock, step6);
        var ran = false;
        var replay = restarted.Commands.Execute(commandId, Register, digest, Origin.Remote, _ =>
        {
            ran = true;
            return [0];
        });
        Assert.True(replay.Replayed);
        Assert.False(ran);
        Assert.Equal(outcome, replay.Outcome!.Value.ToArray());
        var conflict = restarted.Commands.Execute(commandId, Register, new byte[32], Origin.Remote, _ => [0]);
        Assert.Equal("command_id_reused", conflict.Error?.Code);
        Assert.Equal(1L, restarted.Read(r => r.Scalar("SELECT count(*) FROM file_workspace_audit;")));
        Assert.Equal(1L, restarted.Read(r => r.Scalar("SELECT count(*) FROM routed_file_call_log WHERE call_id = $call;", ("$call", callId))));
    }

    [Fact]
    public void LocalAcknowledgmentReceiptCannotBePrunedByAForwardThenBackwardWallStep()
    {
        using var root = new TemporaryDataRoot();
        var clock = new WallStepClock();
        using var store = root.Open(clock);
        const string acknowledgment = "arcforges.node.v1.FileService/AcknowledgeFileOperation";
        var commandId = StoreIds.NewUuid7(clock);
        byte[] digest = [.. Enumerable.Repeat((byte)0x54, 32)];
        byte[] outcome = [4, 5, 6];
        store.Commands.Execute(commandId, acknowledgment, digest, Origin.Human, _ => outcome);

        clock.Offset = TimeSpan.FromDays(3);
        Assert.Equal(0, store.Write(RoutedFileRetention.Prune, CommitDurability.Full));
        Assert.True(store.Read(r => RoutedFileRetention.IsHeld(r, commandId)));
        clock.Offset = TimeSpan.Zero;
        Assert.Equal(0, store.Write(RoutedFileRetention.Prune, CommitDurability.Full));
        var repeated = store.Commands.Execute(commandId, acknowledgment, digest, Origin.Human, _ => throw new InvalidOperationException());
        Assert.True(repeated.Replayed);
        Assert.Equal(outcome, repeated.Outcome!.Value.ToArray());
    }

    [Fact]
    public void NewReceiptsUseOneRealProcessEpochAndActualMonotonicTicks()
    {
        using var root = new TemporaryDataRoot();
        var clock = new WallStepClock();
        using var store = root.Open(clock);
        var commandId = StoreIds.NewUuid7(clock);
        var callId = StoreIds.NewUuid7(clock);
        byte[] digest = [.. Enumerable.Repeat((byte)3, 32)];
        long effectTick = 0;
        store.Commands.Execute(commandId, Register, digest, Origin.Remote, _ =>
        {
            effectTick = Stopwatch.GetTimestamp();
            return [1];
        });
        var commandEpoch = (byte[])store.Read(r => r.Scalar("SELECT process_epoch FROM routed_file_command_retention WHERE command_id = $id;", ("$id", commandId))!);
        var commandTick = (long)store.Read(r => r.Scalar("SELECT monotonic_start FROM routed_file_command_retention WHERE command_id = $id;", ("$id", commandId))!);
        Assert.Equal(16, commandEpoch.Length);
        Assert.InRange(commandTick, effectTick, Stopwatch.GetTimestamp());
        var callLog = store.Write(t =>
        {
            var id = (long)t.Scalar("""
                INSERT INTO routed_file_call_log (received_at, frame_sha256, decision, call_id, signature_kid, method, caller,
                  command_id, request_sha256, request_size)
                VALUES ($at, $digest, 5, $call, 'kid', 17, $caller, $command, $digest, 1) RETURNING log_id;
                """, ("$at", t.NowMicroseconds), ("$digest", digest), ("$call", callId), ("$caller", new byte[] { 1 }), ("$command", commandId))!;
            RoutedFileRetention.MarkCall(t, id);
            return id;
        }, CommitDurability.Full);
        var callEpoch = (byte[])store.Read(r => r.Scalar("SELECT process_epoch FROM routed_file_call_retention WHERE log_id = $id;", ("$id", callLog))!);
        var callTick = (long)store.Read(r => r.Scalar("SELECT monotonic_start FROM routed_file_call_retention WHERE log_id = $id;", ("$id", callLog))!);
        Assert.Equal(commandEpoch, callEpoch);
        Assert.InRange(callTick, commandTick, Stopwatch.GetTimestamp());
        clock.Offset = TimeSpan.FromDays(730);
        Assert.Equal(0, store.Write(RoutedFileRetention.Prune, CommitDurability.Full));
        Assert.Equal(0, store.Commands.PurgeExpired());
        Assert.True(store.Read(r => RoutedFileRetention.IsHeld(r, commandId)));
    }

    [Fact]
    public void ValidationFloorCommitsForwardObservationAndRejectsRollbackAcrossRestart()
    {
        using var root = new TemporaryDataRoot();
        var clock = new WallStepClock();
        long advanced;
        using (var store = root.Open(clock))
        {
            var first = store.Write(RoutedFileValidationTime.Advance, CommitDurability.Full);
            Assert.True(first.Healthy);
            Assert.Equal(first.BoundaryMicroseconds, store.Read(r => r.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;")));
            Assert.Throws<InvalidOperationException>(() => store.Write(RoutedFileValidationTime.Advance));
            clock.Offset = TimeSpan.FromDays(1);
            var jumped = store.Write(RoutedFileValidationTime.Advance, CommitDurability.Full);
            Assert.False(jumped.Healthy);
            Assert.True(jumped.BoundaryMicroseconds > first.BoundaryMicroseconds + 23L * 60 * 60 * 1_000_000);
            advanced = jumped.BoundaryMicroseconds;
            Assert.Equal(advanced, store.Read(r => r.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;")));
        }

        clock.Offset = TimeSpan.Zero;
        using var restarted = root.Open(clock);
        var rollback = restarted.Write(RoutedFileValidationTime.Advance, CommitDurability.Full);
        Assert.False(rollback.Healthy);
        Assert.Equal(advanced, rollback.BoundaryMicroseconds);
        Assert.Equal(advanced, restarted.Read(r => r.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;")));
    }

    private sealed class WallStepClock : TimeProvider
    {
        internal TimeSpan Offset { get; set; }

        public override DateTimeOffset GetUtcNow() => TimeProvider.System.GetUtcNow() + Offset;

        public override long GetTimestamp() => TimeProvider.System.GetTimestamp();

        public override long TimestampFrequency => TimeProvider.System.TimestampFrequency;
    }
}
