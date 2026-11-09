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
        store.Write(t => t.Execute("UPDATE routed_file_call_log SET decision = 1, response_size = 1, response_sha256 = zeroblob(32);"));
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
    public void AllConflictPoliciesAbortDuplicateIdsAcrossAndWithinBothLogs()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        foreach (var recursive in new[] { false, true })
        {
            using var root = new TemporaryDataRoot();
            var clock = new ManualClock();
            using var store = root.Open(clock);
            store.Write(t => t.Execute("PRAGMA recursive_triggers = " + (recursive ? "ON" : "OFF") + ";"));
            foreach (var first in new[] { "routed_call_log", "routed_file_call_log" })
            {
                foreach (var second in new[] { "routed_call_log", "routed_file_call_log" })
                {
                    foreach (var policy in new[] { "INSERT", "INSERT OR IGNORE", "INSERT OR REPLACE" })
                    {
                        var id = StoreIds.NewUuid7(clock);
                        Insert(store, first, id, first == "routed_call_log" ? 2 : 9);
                        var attempted = Statement(second).Replace("INSERT INTO", policy + " INTO", StringComparison.Ordinal);
                        var failure = Assert.Throws<SqliteException>(() => store.Write(t => t.Execute(attempted,
                            ("$id", id), ("$method", second == "routed_call_log" ? 2 : 9), ("$command", null))));
                        Assert.Equal(19, failure.SqliteErrorCode);
                        Assert.Contains("verified_call_id_replayed", failure.Message, StringComparison.Ordinal);
                        Assert.Equal(1L, Count(store, first));
                        Assert.Equal(first == second ? 1L : 0L, Count(store, second));
                        Assert.Equal(1L, Count(store, "routed_verified_call_id"));
                        Assert.Equal(first == "routed_call_log" ? 1L : 2L, store.Read(r => r.Scalar("SELECT log_kind FROM routed_verified_call_id;")));
                        Assert.Equal(id, (byte[])store.Read(r => r.Scalar("SELECT call_id FROM routed_verified_call_id;"))!);
                        store.Write(t =>
                        {
                            t.Execute("DELETE FROM routed_call_log;");
                            t.Execute("DELETE FROM routed_file_call_log;");
                        });
                        Assert.Equal(0L, Count(store, "routed_verified_call_id"));
                    }
                }
            }
        }
    }

    [Fact]
    public void ExplicitReceiptIdCannotReplaceVerifiedOrRefusedRowsUnderAnyConflictPolicy()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        foreach (var recursive in new[] { false, true })
        {
            using var root = new TemporaryDataRoot();
            var clock = new ManualClock();
            using var store = root.Open(clock);
            store.Write(t => t.Execute("PRAGMA recursive_triggers = " + (recursive ? "ON" : "OFF") + ";"));
            foreach (var table in new[] { "routed_call_log", "routed_file_call_log" })
            {
                foreach (var logId in new long[] { -1, 0, 42 })
                {
                    foreach (var verified in new[] { false, true })
                    {
                        foreach (var policy in new[] { "INSERT", "INSERT OR IGNORE", "INSERT OR REPLACE" })
                        {
                            var original = StoreIds.NewUuid7(clock);
                            if (verified)
                            {
                                var initial = ExplicitStatement(table, "INSERT");
                                store.Write(t => t.Execute(initial, ("$log", logId), ("$id", original),
                                    ("$method", table == "routed_call_log" ? 2 : 9), ("$command", null)));
                            }
                            else
                            {
                                store.Write(t => t.Execute("INSERT INTO " + table +
                                    " (log_id, received_at, frame_sha256, decision, refusal_step, refusal_code) " +
                                    "VALUES ($log, 0, zeroblob(32), 3, 'signature', 'AUTHENTICATION/signature_invalid');", ("$log", logId)));
                            }

                            var replacement = StoreIds.NewUuid7(clock);
                            var failure = Assert.Throws<SqliteException>(() => store.Write(t => t.Execute(ExplicitStatement(table, policy),
                                ("$log", logId), ("$id", replacement), ("$method", table == "routed_call_log" ? 2 : 9), ("$command", null))));
                            Assert.Equal(19, failure.SqliteErrorCode);
                            Assert.Contains("routed_log_id_retained", failure.Message, StringComparison.Ordinal);
                            Assert.Equal(1L, Count(store, table));
                            Assert.Equal(verified ? 1L : 0L, Count(store, "routed_verified_call_id"));
                            if (verified)
                            {
                                Assert.Equal(original, (byte[])store.Read(r => r.Scalar("SELECT call_id FROM " + table + ";"))!);
                                Assert.Equal(original, (byte[])store.Read(r => r.Scalar("SELECT call_id FROM routed_verified_call_id;"))!);
                            }
                            else
                            {
                                Assert.Equal(3L, store.Read(r => r.Scalar("SELECT decision FROM " + table + ";")));
                            }

                            // SQLite's BEFORE INSERT sentinel is also -1 for automatic allocation: an existing -1 receipt
                            // fails closed until its actual retention deletes that row, with no false release.
                            if (logId == -1)
                            {
                                var automatic = Assert.Throws<SqliteException>(() =>
                                    Insert(store, table, StoreIds.NewUuid7(clock), table == "routed_call_log" ? 2 : 9));
                                Assert.Contains("routed_log_id_retained", automatic.Message, StringComparison.Ordinal);
                            }

                            store.Write(t => t.Execute("DELETE FROM " + table + ";"));
                            Assert.Equal(0L, Count(store, "routed_verified_call_id"));
                            Insert(store, table, StoreIds.NewUuid7(clock), table == "routed_call_log" ? 2 : 9);
                            store.Write(t => t.Execute("DELETE FROM " + table + ";"));
                        }
                    }
                }
            }
        }
    }

    [Fact]
    public void APreexistingOrphanOwnerCannotBeIgnoredOrReplacedByAnAllocatedId()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        foreach (var table in new[] { "routed_call_log", "routed_file_call_log" })
        {
            foreach (var policy in new[] { "INSERT", "INSERT OR IGNORE", "INSERT OR REPLACE" })
            {
                // A synthetic inconsistent registry row tests fail-closed behavior; ordinary writes never create this state.
                var retained = StoreIds.NewUuid7(clock);
                store.Write(t => t.Execute("""
                    INSERT INTO routed_verified_call_id (call_id, log_kind, log_id, received_at) VALUES ($id, $kind, 1, 0);
                    """, ("$id", retained), ("$kind", table == "routed_call_log" ? 1 : 2)));
                var attempted = Statement(table).Replace("INSERT INTO", policy + " INTO", StringComparison.Ordinal);
                var failure = Assert.Throws<SqliteException>(() => store.Write(t => t.Execute(attempted,
                    ("$id", StoreIds.NewUuid7(clock)), ("$method", table == "routed_call_log" ? 2 : 9), ("$command", null))));
                Assert.Equal(19, failure.SqliteErrorCode);
                Assert.Contains("verified_registry_owner_conflict", failure.Message, StringComparison.Ordinal);
                Assert.Equal(0L, Count(store, table));
                Assert.Equal(1L, Count(store, "routed_verified_call_id"));
                Assert.Equal(retained, (byte[])store.Read(r => r.Scalar("SELECT call_id FROM routed_verified_call_id;"))!);
                store.Write(t => t.Execute("DELETE FROM routed_verified_call_id;"));
            }
        }
    }

    [Fact]
    public void BothReceiptIdentityKeysAreImmutableAndRetentionReleasesExactlyTheirOwner()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        foreach (var table in new[] { "routed_call_log", "routed_file_call_log" })
        {
            var id = StoreIds.NewUuid7(clock);
            Insert(store, table, id, table == "routed_call_log" ? 2 : 9);
            foreach (var change in new[] { "log_id = log_id + 100", "rowid = log_id + 100", "_rowid_ = log_id + 100", "oid = log_id + 100", "call_id = randomblob(16)", "call_id = NULL" })
            {
                var failure = Assert.Throws<SqliteException>(() => store.Write(t => t.Execute("UPDATE " + table + " SET " + change + ";")));
                Assert.Equal(19, failure.SqliteErrorCode);
                Assert.Contains("verified_receipt_identity_immutable", failure.Message, StringComparison.Ordinal);
            }

            Assert.Equal(id, (byte[])store.Read(r => r.Scalar("SELECT call_id FROM routed_verified_call_id;"))!);
            store.Write(t => t.Execute("DELETE FROM " + table + ";"));
            Assert.Equal(0L, Count(store, "routed_verified_call_id"));
            Insert(store, table == "routed_call_log" ? "routed_file_call_log" : "routed_call_log", id,
                table == "routed_call_log" ? 9 : 2);
            store.Write(t =>
            {
                t.Execute("DELETE FROM routed_call_log;");
                t.Execute("DELETE FROM routed_file_call_log;");
            });
            Assert.Equal(0L, Count(store, "routed_verified_call_id"));
        }

        // Unverified receipts have no ID reservation, but their receipt key must not move either.
        foreach (var table in new[] { "routed_call_log", "routed_file_call_log" })
        {
            store.Write(t => t.Execute("INSERT INTO " + table +
                " (received_at, frame_sha256, decision, refusal_step, refusal_code) VALUES (0, zeroblob(32), 3, 'signature', 'AUTHENTICATION/signature_invalid');"));
            Assert.Equal(19, Assert.Throws<SqliteException>(() => store.Write(t => t.Execute("UPDATE " + table + " SET log_id = log_id + 100;"))).SqliteErrorCode);
            store.Write(t => t.Execute("DELETE FROM " + table + ";"));
        }
    }

    [Fact]
    public void FileReceiptSizesAndOutcomePairsMatchAuthenticatedFrameShapes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        void Add(int decision, long? requestSize, byte[]? requestHash, long? responseSize, byte[]? responseHash)
        {
            store.Write(t => t.Execute("""
                INSERT INTO routed_file_call_log (received_at, frame_sha256, decision, refusal_code, call_id, signature_kid, method,
                  caller, request_sha256, request_size, response_sha256, response_size)
                VALUES (0, zeroblob(32), $decision, $code, $id, 'isolated-test-kid', 9, x'01', $request, $size, $response, $responseSize);
                """, ("$decision", decision), ("$code", decision is 2 or 4 ? "AUTHORIZATION/permission_denied" : null),
                ("$id", StoreIds.NewUuid7(clock)), ("$request", requestHash), ("$size", requestSize),
                ("$response", responseHash), ("$responseSize", responseSize)));
        }

        var sha = new byte[32];
        Add(5, 1, sha, null, null);
        Add(5, 245_760, sha, null, null);
        Add(1, 1, sha, 1, sha);
        Add(1, 245_760, sha, 1_040_384, sha);
        Add(2, 1, sha, null, null);
        Add(4, 1, sha, null, null);

        void Rejected(Action action) => Assert.Equal(19, Assert.Throws<SqliteException>(action).SqliteErrorCode);
        Rejected(() => Add(5, 0, sha, null, null));
        Rejected(() => Add(5, 245_761, sha, null, null));
        Rejected(() => Add(5, null, sha, null, null));
        Rejected(() => Add(5, 1, null, null, null));
        Rejected(() => Add(5, 1, new byte[31], null, null));
        Rejected(() => Add(1, 1, sha, 0, sha));
        Rejected(() => Add(1, 1, sha, 1_040_385, sha));
        Rejected(() => Add(1, 1, sha, null, null));
        Rejected(() => Add(1, 1, sha, 1, null));
        Rejected(() => Add(1, 1, sha, null, sha));
        Rejected(() => Add(1, 1, sha, 1, new byte[31]));
        foreach (var decision in new[] { 2, 4, 5 })
        {
            Rejected(() => Add(decision, 1, sha, 1, sha));
            Rejected(() => Add(decision, 1, sha, 1, null));
            Rejected(() => Add(decision, 1, sha, null, sha));
        }

        Assert.Equal(6L, Count(store, "routed_file_call_log"));
        Assert.Equal(6L, Count(store, "routed_verified_call_id"));
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

    private static string ExplicitStatement(string table, string policy) =>
        Statement(table).Replace("INSERT INTO", policy + " INTO", StringComparison.Ordinal)
            .Replace("(received_at,", "(log_id, received_at,", StringComparison.Ordinal)
            .Replace("VALUES (0,", "VALUES ($log, 0,", StringComparison.Ordinal);

    private static long Count(NodeStore store, string table) => (long)store.Read(r => r.Scalar("SELECT count(*) FROM " + table + ";"))!;

    private static string Statement(string table) => table is "routed_call_log" or "routed_file_call_log"
        ? "INSERT INTO " + table + " (received_at, frame_sha256, decision, call_id, signature_kid, method, caller, command_id, request_sha256, request_size) " +
          "VALUES (0, zeroblob(32), 5, $id, 'isolated-test-kid', $method, x'01', $command, zeroblob(32), 1);"
        : throw new ArgumentOutOfRangeException(nameof(table));
}
