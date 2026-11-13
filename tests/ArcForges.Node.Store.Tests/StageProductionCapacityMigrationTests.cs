// SPDX-License-Identifier: AGPL-3.0-only
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Real SQLite capacity constraints with synthetic metadata only; no filesystem, caller or worker proof.</summary>
[Trait("check", "schema")]
public sealed class StageProductionCapacityMigrationTests
{
    [Fact]
    public void InitialReservationsBlockDirectNamedAndJournalWritersAtTheCombinedActiveLimit()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var workspace = StoreIds.NewUuid7(clock);
        Workspace(store, workspace);
        var reservations = Enumerable.Range(0, 64).Select(_ => StoreIds.NewUuid7(clock)).ToArray();
        store.Write(tx =>
        {
            foreach (var id in reservations) Producer(tx, id, workspace, 0);
        }, CommitDurability.Full);
        Assert.Equal((64L, 0L), Capacity(store));
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT active_mutations FROM file_stage_capacity_totals;")));
        Reject(store, tx => Named(tx, StoreIds.NewUuid7(clock), workspace, 0));
        Reject(store, tx => Journal(tx, StoreIds.NewUuid7(clock), workspace, 0));
        Reject(store, tx => Producer(tx, StoreIds.NewUuid7(clock), workspace, 0));
        Assert.Equal((64L, 0L), Capacity(store));
        // No worker or object has been created in this SQL-only reservation fixture.
        store.Write(tx => tx.Execute("UPDATE file_stage_production SET active = 0 WHERE command_id = $id;",
            ("$id", reservations[0])), CommitDurability.Full);
        store.Write(tx => Named(tx, StoreIds.NewUuid7(clock), workspace, 0), CommitDurability.Full);
        Assert.Equal((64L, 0L), Capacity(store));
    }

    [Fact]
    public void InactiveUnreleasedAnonymousReservationsKeepTheirBytesAcrossAllWriterPaths()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var workspace = StoreIds.NewUuid7(clock);
        Workspace(store, workspace);
        var ids = Enumerable.Range(0, 32).Select(_ => StoreIds.NewUuid7(clock)).ToArray();
        store.Write(tx =>
        {
            foreach (var id in ids) Producer(tx, id, workspace, 8L * 1024 * 1024);
            tx.Execute("UPDATE file_stage_production SET active = 0;");
        }, CommitDurability.Full);
        Assert.Equal((0L, 256L * 1024 * 1024), Capacity(store));
        Reject(store, tx => Named(tx, StoreIds.NewUuid7(clock), workspace, 1));
        Reject(store, tx => Journal(tx, StoreIds.NewUuid7(clock), workspace, 1));
        Reject(store, tx => Producer(tx, StoreIds.NewUuid7(clock), workspace, 1));
        Assert.Equal((0L, 256L * 1024 * 1024), Capacity(store));
        store.Write(tx => tx.Execute("UPDATE file_stage_production SET released = 1 WHERE command_id = $id;",
            ("$id", ids[0])), CommitDurability.Full);
        store.Write(tx => Named(tx, StoreIds.NewUuid7(clock), workspace, 4L * 1024 * 1024), CommitDurability.Full);
        Assert.Equal((1L, 252L * 1024 * 1024), Capacity(store));
    }

    private static void Workspace(NodeStore store, byte[] workspace) => store.Write(tx => tx.Execute("""
        INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
        VALUES ($id, 1, 2, 'SQL-only owned fixture', '/fixture', 0, 0, 0);
        """, ("$id", workspace)), CommitDurability.Full);

    private static void Command(StoreTransaction tx, byte[] id) => tx.Execute("""
        INSERT INTO command_dedup (command_id, method, payload_digest, origin, created_at, expires_at)
        VALUES ($id, 'arcforges.node.v1.FileService/WriteFile', zeroblob(32), 4, 0, 1);
        """, ("$id", id));

    private static void Named(StoreTransaction tx, byte[] id, byte[] workspace, long bytes)
    {
        Command(tx, id);
        tx.Execute("""
            INSERT INTO file_private_stage_reservation
              (command_id, workspace_id, kind, correlation_id, relative_path, expected_absent, request_sha256,
               caller, reserved_bytes, created_at)
            VALUES ($id, $workspace, 1, $id, 'target', 1, zeroblob(32), x'01', $bytes, 0);
            """, ("$id", id), ("$workspace", workspace), ("$bytes", bytes));
    }

    private static void Producer(StoreTransaction tx, byte[] id, byte[] workspace, long bytes) => tx.Execute("""
        INSERT INTO file_stage_production
          (command_id, producer_nonce, storage_kind, workspace_id, operation_kind, correlation_id, relative_path,
           expected_absent, expected_sha256, target_identity, request_sha256, caller, identity_platform,
           root_identity, parent_identity, object_count, reserved_bytes, deadline_clock, deadline_ticks,
           expiry_microseconds, created_at)
        VALUES ($id, $id, 1, $workspace, 1, $id, 'target', 0, zeroblob(32), zeroblob(53), zeroblob(32), x'01', 2,
                zeroblob(53), zeroblob(53), 2, $bytes, 1, 1, 1, 0);
        """, ("$id", id), ("$workspace", workspace), ("$bytes", bytes));

    // Every call in these tests is expected to be rejected and rolled back. No PREPARED operation is adopted or run.
    private static void Journal(StoreTransaction tx, byte[] id, byte[] workspace, long bytes)
    {
        Command(tx, id);
        tx.Execute("""
            INSERT INTO file_operation_journal
              (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
               identity_platform, root_identity, parent_identity, expected_absent, intended_size, intended_sha256,
               intended_stage_identity, created_at, updated_at, held, acknowledged)
            VALUES ($id, 1, 1, zeroblob(32), x'01', $id, $workspace, 'target', 2, zeroblob(53), zeroblob(53),
                    1, $bytes, zeroblob(32), zeroblob(53), 0, 0, 1, 0);
            """, ("$id", id), ("$workspace", workspace), ("$bytes", bytes));
    }

    private static void Reject(NodeStore store, Action<StoreTransaction> insert)
    {
        var exception = Assert.Throws<SqliteException>(() => store.Write(insert, CommitDurability.Full));
        Assert.Equal(19, exception.SqliteErrorCode);
        Assert.Contains("file_stage_capacity", exception.Message, StringComparison.Ordinal);
    }

    private static (long Active, long Bytes) Capacity(NodeStore store) => store.Read(reader =>
    {
        using var query = reader.CreateCommand("SELECT active_mutations, reserved_bytes FROM file_stage_capacity_totals_v15;");
        using var row = query.ExecuteReader();
        Assert.True(row.Read());
        return (row.GetInt64(0), row.GetInt64(1));
    });
}
