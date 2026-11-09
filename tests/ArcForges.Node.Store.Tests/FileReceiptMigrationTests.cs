// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Real SQLite migration and old/new writer enforcement for the AF-CTR-06 call namespace.</summary>
[Trait("feature", "workspace-store")]
[Trait("check", "schema")]
public sealed class FileReceiptMigrationTests
{
    [Fact]
    public void Step3BackfillsOldCallsPreservesTheirRowsAndWorksForAnOlderWriter()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var legacy = new MigrationPlan(StoreMigrations.Released.Steps.Take(2));
        var id = StoreIds.NewUuid7(clock);
        using (var old = root.Open(clock, legacy))
        {
            Insert(old, "routed_call_log", id, 1);
        }

        using (var current = root.Open(clock))
        {
            Assert.Equal(2, current.Opening.MigratedFrom);
            Assert.Equal(3, current.Metadata.SchemaVersion);
            Assert.Equal(1L, Count(current, "routed_call_log"));
            Assert.Equal(1L, Count(current, "routed_verified_call_id"));
            Assert.Equal(1L, current.Read(r => r.Scalar("SELECT log_kind FROM routed_verified_call_id;")));
            Assert.Equal(19, Assert.Throws<SqliteException>(() => Insert(current, "routed_file_call_log", id, 9)).SqliteErrorCode);
        }

        // Emulate the older schema view and original INSERT, without any registry code in the writer.
        // This proves the database trigger behavior; separate deployed older-binary compatibility remains integration work.
        using var older = root.Open(clock, legacy);
        Assert.Equal(3, older.Metadata.SchemaVersion);
        Assert.Equal(1, older.Metadata.MinReaderVersion);
        Assert.Equal(19, Assert.Throws<SqliteException>(() => Insert(older, "routed_call_log", id, 2)).SqliteErrorCode);
        Insert(older, "routed_call_log", StoreIds.NewUuid7(clock), 2);
        Assert.Equal(2L, Count(older, "routed_verified_call_id"));
    }

    [Fact]
    public void BothInsertDirectionsCollideAndSettlementCannotChangeTheVerifiedCallId()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var id = StoreIds.NewUuid7(clock);
        Insert(store, "routed_file_call_log", id, 9);
        Assert.Equal(19, Assert.Throws<SqliteException>(() => Insert(store, "routed_call_log", id, 1)).SqliteErrorCode);
        Assert.Equal(0L, Count(store, "routed_call_log"));
        Assert.Equal(1L, Count(store, "routed_file_call_log"));
        Assert.Equal(19, Assert.Throws<SqliteException>(() => store.Write(t => t.Execute(
            "UPDATE routed_file_call_log SET call_id = randomblob(16);"))).SqliteErrorCode);
        store.Write(t => t.Execute("UPDATE routed_file_call_log SET decision = 1, response_size = 0, response_sha256 = zeroblob(32);"));
        Assert.Equal(1L, Count(store, "routed_verified_call_id"));
        Assert.Equal(1L, store.Read(r => r.Scalar("SELECT decision FROM routed_file_call_log;")));
    }

    [Fact]
    public void UnverifiedFramesDoNotReserveCallerControlledIdsAndAllNewMethodShapesAreEnforced()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        store.Write(t => t.Execute("""
            INSERT INTO routed_file_call_log (received_at, frame_sha256, decision, refusal_step, refusal_code)
            VALUES (0, zeroblob(32), 3, 'signature', 'AUTHENTICATION/invalid_signature');
            """));
        Assert.Equal(0L, Count(store, "routed_verified_call_id"));
        foreach (var method in Enumerable.Range(9, 12))
        {
            var mutation = method is 10 or 11 or 14 or 15 or 17 or 18;
            Insert(store, "routed_file_call_log", StoreIds.NewUuid7(clock), method, mutation);
            Assert.Equal(19, Assert.Throws<SqliteException>(() =>
                Insert(store, "routed_file_call_log", StoreIds.NewUuid7(clock), method, !mutation)).SqliteErrorCode);
        }

        Assert.Equal(12L, Count(store, "routed_verified_call_id"));
        Assert.Equal(13L, Count(store, "routed_file_call_log"));
        Assert.Equal(19, Assert.Throws<SqliteException>(() => Insert(store, "routed_file_call_log", StoreIds.NewUuid7(clock), 1)).SqliteErrorCode);
        Assert.Equal(19, Assert.Throws<SqliteException>(() => Insert(store, "routed_call_log", StoreIds.NewUuid7(clock), 9)).SqliteErrorCode);
    }

    [Fact]
    public async Task ConcurrentOldAndNewConnectionsCommitExactlyOneOwnerOfTheSameCallId()
    {
        var cancellation = TestContext.Current.CancellationToken;
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        root.Open(clock).Dispose();
        var id = StoreIds.NewUuid7(clock);
        using var ready = new Barrier(2);
        Task<int> Writer(string table, int method) => Task.Run(() =>
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = root.Database,
                Pooling = false,
                DefaultTimeout = 10,
            }.ToString());
            connection.Open();
            Assert.True(ready.SignalAndWait(TimeSpan.FromSeconds(10), cancellation));
            try
            {
                using var transaction = connection.BeginTransaction(deferred: false);
                using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = Statement(table);
                command.Parameters.AddWithValue("$id", id);
                command.Parameters.AddWithValue("$method", method);
                command.Parameters.AddWithValue("$command", DBNull.Value);
                command.ExecuteNonQuery();
                transaction.Commit();
                return 0;
            }
            catch (SqliteException exception)
            {
                return exception.SqliteErrorCode;
            }
        }, cancellation);
        var results = await Task.WhenAll(Writer("routed_call_log", 2), Writer("routed_file_call_log", 9));
        Assert.Equal([0, 19], results.Order());
        using var store = root.Open(clock);
        Assert.Equal(1L, Count(store, "routed_verified_call_id"));
        Assert.Equal(1L, Count(store, "routed_call_log") + Count(store, "routed_file_call_log"));
    }

    [Fact]
    public void RetentionReleasesOnlyTheDeletedLogsOwnVerifiedId()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var oldId = StoreIds.NewUuid7(clock);
        var newId = StoreIds.NewUuid7(clock);
        Insert(store, "routed_call_log", oldId, 2);
        Insert(store, "routed_file_call_log", newId, 9);
        // This tests atomic release, not a new retention duration or authorization for early production deletion.
        store.Write(t => t.Execute("DELETE FROM routed_call_log;"));
        Assert.Equal(1L, Count(store, "routed_verified_call_id"));
        Assert.Equal(2L, store.Read(r => r.Scalar("SELECT log_kind FROM routed_verified_call_id;")));
        Assert.Equal(19, Assert.Throws<SqliteException>(() => Insert(store, "routed_call_log", newId, 2)).SqliteErrorCode);
        Insert(store, "routed_file_call_log", oldId, 9);
        Assert.Equal(2L, Count(store, "routed_verified_call_id"));
    }

    [Fact]
    public void NativeRootIdentityHasOneActiveRegistrationWithoutInventingLegacyIdentities()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var first = StoreIds.NewUuid7(clock);
        var second = StoreIds.NewUuid7(clock);
        foreach (var (id, path) in new[] { (first, "/isolated-root-one"), (second, "/isolated-root-two") })
        {
            store.Write(t => t.Execute("""
                INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                VALUES ($id, 1, 1, 'isolated-sql-root', $path, 0, 0, 0);
                """, ("$id", id), ("$path", path)));
        }

        Assert.Equal(0L, Count(store, "workspace_root_identity"));
        void Register(byte[] id) => store.Write(t => t.Execute("""
            INSERT INTO workspace_root_identity (workspace_id, format_version, platform, native_identity, canonical_path, registered_at)
            VALUES ($id, 1, 1, zeroblob(32), '/isolated-canonical-root', 0);
            """, ("$id", id)));
        // The representation is a synthetic SQL input only; this does not establish native identity acquisition or registration RPC.
        Register(first);
        Assert.Equal(19, Assert.Throws<SqliteException>(() => Register(second)).SqliteErrorCode);
        store.Write(t => t.Execute("UPDATE workspace_root_identity SET released_at = 1 WHERE workspace_id = $id;", ("$id", first)));
        Register(second);
        Assert.Equal(2L, Count(store, "workspace_root_identity"));
        Assert.Equal(1L, store.Read(r => r.Scalar("SELECT count(*) FROM workspace_root_identity WHERE released_at IS NULL;")));
        store.Write(t => t.Execute("DELETE FROM workspace WHERE workspace_id = $id;", ("$id", first)));
        Assert.Equal(1L, Count(store, "workspace_root_identity"));
    }

    private static void Insert(NodeStore store, string table, byte[] id, int method, bool command = false) => store.Write(t => t.Execute(
        Statement(table), ("$id", id), ("$method", method), ("$command", command ? StoreIds.NewUuid7(t.Clock) : null)));

    private static long Count(NodeStore store, string table) => (long)store.Read(r => r.Scalar("SELECT count(*) FROM " + table + ";"))!;

    private static string Statement(string table) => table is "routed_call_log" or "routed_file_call_log"
        ? "INSERT INTO " + table + " (received_at, frame_sha256, decision, call_id, signature_kid, method, caller, command_id, request_sha256, request_size) " +
          "VALUES (0, zeroblob(32), 5, $id, 'isolated-test-kid', $method, x'01', $command, zeroblob(32), 0);"
        : throw new ArgumentOutOfRangeException(nameof(table));
}
