// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Real SQLite guards and accounting for mixed stage metadata from compatible earlier writers.</summary>
[Trait("check", "schema")]
public sealed class CombinedStageCapacityMigrationTests
{
    [Fact]
    public void SameCommandDeduplicatesOnlyTheMatchingNativeStageAndOlderWritersCannotExceedActiveLimit()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var workspace = StoreIds.NewUuid7(clock);
        store.Write(t => t.Execute("""
            INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
            VALUES ($id, 1, 2, 'owned fixture', '/fixture', 0, 0, 0);
            """, ("$id", workspace)), CommitDurability.Full);
        var first = StoreIds.NewUuid7(clock);
        var second = StoreIds.NewUuid7(clock);
        var firstStage = Identity(1);
        var secondStage = Identity(2);
        var otherStage = Identity(3);
        store.Write(t =>
        {
            InsertCommand(t, first);
            InsertNamed(t, first, workspace, 3);
            InsertStage(t, first, firstStage, 3);
            InsertJournal(t, first, workspace, firstStage, 3);
        }, CommitDurability.Full);
        Assert.Equal((1, 3L), Capacity(store));
        store.Write(t =>
        {
            InsertCommand(t, second);
            InsertNamed(t, second, workspace, 3);
            InsertStage(t, second, secondStage, 3);
            InsertJournal(t, second, workspace, otherStage, 4);
        }, CommitDurability.Full);
        Assert.Equal((2, 10L), Capacity(store)); // Same command, different object: both allocations are charged.
        var ordinary = new List<byte[]>();
        store.Write(t =>
        {
            for (var index = 0; index < 62; index++)
            {
                var id = StoreIds.NewUuid7(clock);
                InsertCommand(t, id);
                InsertNamed(t, id, workspace, 0);
                ordinary.Add(id);
            }
        }, CommitDurability.Full);
        Assert.Equal((64, 10L), Capacity(store));
        var overJournal = StoreIds.NewUuid7(clock);
        var failure = Assert.Throws<SqliteException>(() => store.Write(t =>
        {
            InsertCommand(t, overJournal);
            InsertJournal(t, overJournal, workspace, Identity(4), 1);
        }, CommitDurability.Full));
        Assert.Equal(19, failure.SqliteErrorCode);
        Assert.Null(store.Read(r => r.Scalar("SELECT 1 FROM command_dedup WHERE command_id = $id;", ("$id", overJournal))));
        var overNamed = StoreIds.NewUuid7(clock);
        failure = Assert.Throws<SqliteException>(() => store.Write(t =>
        {
            InsertCommand(t, overNamed);
            InsertNamed(t, overNamed, workspace, 0);
        }, CommitDurability.Full));
        Assert.Equal(19, failure.SqliteErrorCode);
        store.Write(t => t.Execute("UPDATE file_private_stage_reservation SET active = 0 WHERE command_id = $id;", ("$id", second)), CommitDurability.Full);
        Assert.Equal((64, 10L), Capacity(store)); // Its held journal still keeps the same command active.
        store.Write(t => t.Execute("UPDATE file_private_stage_reservation SET active = 1 WHERE command_id = $id;", ("$id", second)), CommitDurability.Full);
        Assert.Equal((64, 10L), Capacity(store));
        store.Write(t => t.Execute("UPDATE file_private_stage_reservation SET active = 0 WHERE command_id = $id;", ("$id", ordinary[0])), CommitDurability.Full);
        Assert.Equal((63, 10L), Capacity(store));
        store.Write(t => { InsertCommand(t, overNamed); InsertNamed(t, overNamed, workspace, 0); }, CommitDurability.Full);
        failure = Assert.Throws<SqliteException>(() => store.Write(t => t.Execute(
            "UPDATE file_private_stage_reservation SET active = 1 WHERE command_id = $id;", ("$id", ordinary[0])), CommitDurability.Full));
        Assert.Equal(19, failure.SqliteErrorCode);
        Assert.Equal((64, 10L), Capacity(store));
    }

    [Fact]
    public void RetainedNamedBytesStillBlockAnOlderJournalWriterAtTheByteLimit()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var workspace = StoreIds.NewUuid7(clock);
        store.Write(t => t.Execute("""
            INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
            VALUES ($id, 1, 2, 'owned fixture', '/fixture', 0, 0, 0);
            """, ("$id", workspace)), CommitDurability.Full);
        store.Write(t =>
        {
            for (var index = 0; index < 32; index++)
            {
                var id = StoreIds.NewUuid7(clock);
                InsertCommand(t, id);
                InsertNamed(t, id, workspace, 8L * 1024 * 1024);
            }
            t.Execute("UPDATE file_private_stage_reservation SET active = 0;");
        }, CommitDurability.Full);
        Assert.Equal((0, 256L * 1024 * 1024), Capacity(store));
        var id = StoreIds.NewUuid7(clock);
        var failure = Assert.Throws<SqliteException>(() => store.Write(t =>
        {
            InsertCommand(t, id);
            InsertJournal(t, id, workspace, Identity(5), 1);
        }, CommitDurability.Full));
        Assert.Equal(19, failure.SqliteErrorCode);
        Assert.Null(store.Read(r => r.Scalar("SELECT 1 FROM command_dedup WHERE command_id = $id;", ("$id", id))));
        store.Write(t => { InsertCommand(t, id); InsertNamed(t, id, workspace, 0); }, CommitDurability.Full);
        Assert.Equal((1, 256L * 1024 * 1024), Capacity(store));
    }

    private static void InsertCommand(StoreTransaction t, byte[] id) => t.Execute("""
        INSERT INTO command_dedup (command_id, method, payload_digest, origin, created_at, expires_at)
        VALUES ($id, 'arcforges.node.v1.FileService/WriteFile', zeroblob(32), 4, 0, 1);
        """, ("$id", id));

    private static void InsertNamed(StoreTransaction t, byte[] id, byte[] workspace, long bytes) => t.Execute("""
        INSERT INTO file_private_stage_reservation
          (command_id, workspace_id, kind, correlation_id, relative_path, expected_absent, request_sha256,
           caller, reserved_bytes, created_at)
        VALUES ($id, $workspace, 1, $id, 'target', 1, zeroblob(32), x'01', $bytes, 0);
        """, ("$id", id), ("$workspace", workspace), ("$bytes", bytes));

    private static void InsertStage(StoreTransaction t, byte[] id, byte[] identity, long bytes) => t.Execute("""
        INSERT INTO file_private_stage_object
          (command_id, slot, stage_path, expected_size, expected_sha256, phase, identity_platform, native_identity, parent_identity)
        VALUES ($id, 2, '/fixture/stage', $bytes, zeroblob(32), 2, 1, $identity, zeroblob(33));
        """, ("$id", id), ("$bytes", bytes), ("$identity", identity));

    private static void InsertJournal(StoreTransaction t, byte[] id, byte[] workspace, byte[] identity, long bytes) => t.Execute("""
        INSERT INTO file_operation_journal
          (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
           identity_platform, root_identity, parent_identity, expected_absent, intended_size, intended_sha256,
           intended_stage_identity, created_at, updated_at, held, acknowledged)
        VALUES ($id, 1, 1, zeroblob(32), x'01', $id, $workspace, 'target', 1, $root, $identity,
                1, $bytes, zeroblob(32), $identity, 0, 0, 1, 0);
        """, ("$id", id), ("$workspace", workspace), ("$bytes", bytes), ("$identity", identity), ("$root", Identity(255)));

    private static byte[] Identity(byte marker)
    {
        var result = new byte[33];
        result[0] = 1;
        result[1] = marker;
        return result;
    }

    private static (int Active, long Bytes) Capacity(NodeStore store) => store.Read(reader =>
    {
        using var command = reader.CreateCommand("SELECT active_mutations, reserved_bytes FROM file_stage_capacity_totals;");
        using var row = command.ExecuteReader();
        Assert.True(row.Read());
        return (row.GetInt32(0), row.GetInt64(1));
    });
}
