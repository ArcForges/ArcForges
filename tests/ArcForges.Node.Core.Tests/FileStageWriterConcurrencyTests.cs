// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real independent SQLite writers with deterministic stage identity metadata.</summary>
public sealed class FileStageWriterConcurrencyTests
{
    [Fact(Timeout = 30_000)]
    public async Task OlderWriterCannotEnterBetweenStageReservationAndJournalCommit()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "legacy-stage-writer-fixture" });
        var workspace = CommandIds.New();
        store.Write(transaction => Assert.Equal(1, transaction.Execute("""
            INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
            VALUES ($id, 1, 2, 'staged history', $root, $now, $now, 1);
            """, ("$id", workspace.Value.ToByteArray()), ("$root", Path.Combine(fixture.Root, "workspace")),
            ("$now", transaction.NowMicroseconds))), CommitDurability.Full);

        var original = "prior-transaction-bytes"u8.ToArray();
        var intended = "new-transaction-bytes"u8.ToArray();
        var request = new FileServiceWriteFileRequest
        {
            Meta = Tasks.Meta(),
            Path = new FilePath { WorkspaceId = workspace, Path = "target" },
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
            Data = ByteString.CopyFrom(intended),
        };
        var id = request.Meta.CommandId.Value.ToByteArray();
        var root = Identity(11);
        var target = Identity(12);
        var originalStage = Identity(13);
        var intendedStage = Identity(14);
        var intent = new FileJournalIntent(FileOperationKind.Write, id, request.Meta.CorrelationId.Value.ToByteArray(),
            RoutedCalls.Session(), workspace.Value.ToByteArray(), request.Path.Path, root.Platform, root.Bytes, root.Bytes,
            target.Bytes, original.Length, SHA256.HashData(original), originalStage.Bytes,
            intended.Length, SHA256.HashData(intended), intendedStage.Bytes);
        var budget = new FileStageBudget();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim();
        var write = Task.Run(() =>
        {
            FileStageBudget.Lease? stage = null;
            try
            {
                return store.Write(transaction =>
                {
                    stage = Assert.IsType<FileStageBudget.Lease>(budget.TryReserveCommand(transaction, id, original.Length, intended.Length));
                    stage.BindStages(originalStage, intendedStage);
                    ready.SetResult();
                    Assert.True(release.Wait(TimeSpan.FromSeconds(12), ct));
                    var prepared = FileMutationJournal.Prepare(transaction, intent, request.ToByteArray());
                    Assert.Equal((1, (long)(original.Length + intended.Length)), budget.CombinedUsage(transaction));
                    return prepared;
                }, CommitDurability.Full);
            }
            finally
            {
                stage?.Dispose();
            }
        }, ct);

        try
        {
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(8), ct);
            Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
            using var contender = OpenOlderConnection(store.DatabasePath, defaultTimeout: 1);
            var busy = Assert.Throws<SqliteException>(() => contender.BeginTransaction(deferred: false));
            Assert.Equal(5, busy.SqliteErrorCode); // SQLITE_BUSY from the independent writer.
        }
        finally
        {
            release.Set();
            Assert.Equal(FileJournalPreparation.Prepared, await write);
        }

        OlderWriter(store.DatabasePath, workspace.Value.ToByteArray(), original.Length + intended.Length);
        Assert.Equal(64L, store.Read(reader => reader.Scalar("SELECT active_mutations FROM file_stage_capacity_totals;")));
        Assert.Equal(64L, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        Assert.Equal(1L, store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_operation_journal WHERE command_id = $id AND phase = 1 AND held = 1;
            """, ("$id", id))));
        Assert.False(Directory.Exists(Path.Combine(fixture.Root, "workspace")));
    }

    private static RegisteredWorkspaces.RootIdentity Identity(byte number) =>
        OperatingSystem.IsWindows() ? new(1, [1, number, .. new byte[31]]) : new(2, [1, number, .. new byte[51]]);

    private static SqliteConnection OpenOlderConnection(string database, int defaultTimeout)
    {
        var settings = new SqliteConnectionStringBuilder
        {
            DataSource = database,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
            DefaultTimeout = defaultTimeout,
        };
        var connection = new SqliteConnection(settings.ToString());
        connection.Open();
        return connection;
    }

    private static void OlderWriter(string database, byte[] workspace, int firstStageBytes)
    {
        using var connection = OpenOlderConnection(database, defaultTimeout: 10);
        using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA foreign_keys = ON;";
            pragma.ExecuteNonQuery();
        }
        using var transaction = connection.BeginTransaction(deferred: false);
        for (var index = 0; index < 63; index++)
        {
            var id = CommandIds.New().Value.ToByteArray();
            InsertCommand(connection, transaction, id);
            InsertNamed(connection, transaction, id, workspace);
        }
        using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = "SELECT active_mutations, reserved_bytes FROM file_stage_capacity_totals;";
            using var row = query.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(64L, row.GetInt64(0));
            Assert.Equal((long)firstStageBytes, row.GetInt64(1));
        }

        Execute(connection, transaction, "SAVEPOINT overflow;");
        var overflow = CommandIds.New().Value.ToByteArray();
        InsertCommand(connection, transaction, overflow);
        var refused = Assert.Throws<SqliteException>(() => InsertNamed(connection, transaction, overflow, workspace));
        Assert.Equal(19, refused.SqliteErrorCode);
        Assert.Contains("file_stage_capacity", refused.Message, StringComparison.Ordinal);
        Execute(connection, transaction, "ROLLBACK TO overflow; RELEASE overflow;");
        transaction.Commit();
    }

    private static void InsertCommand(SqliteConnection connection, SqliteTransaction transaction, byte[] id) => Execute(connection, transaction, """
        INSERT INTO command_dedup (command_id, method, payload_digest, origin, created_at, expires_at)
        VALUES ($id, 'arcforges.node.v1.FileService/WriteFile', zeroblob(32), 4, 0, 1);
        """, ("$id", id));

    private static void InsertNamed(SqliteConnection connection, SqliteTransaction transaction, byte[] id, byte[] workspace) => Execute(connection, transaction, """
        INSERT INTO file_private_stage_reservation
          (command_id, workspace_id, kind, correlation_id, relative_path, expected_absent, request_sha256,
           caller, reserved_bytes, created_at)
        VALUES ($id, $workspace, 1, $id, 'older-writer-target', 1, zeroblob(32), x'01', 0, 0);
        """, ("$id", id), ("$workspace", workspace));

    private static void Execute(SqliteConnection connection, SqliteTransaction transaction, string sql, params (string Name, object Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        command.ExecuteNonQuery();
    }
}
