// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Two real SQLite writer connections and native anonymous stages; routed caller is synthetic.</summary>
public sealed class FileStageWriterConcurrencyTests
{
    [Fact(Timeout = 120_000)]
    public async Task OlderWriterCannotEnterBetweenAnonymousAllocationAndJournalCommit()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var path = Directory.CreateDirectory(Path.Combine(node.Root, "mixed-writers")).FullName;
        var original = Encoding.UTF8.GetBytes("prior-transaction-bytes");
        var intended = Encoding.UTF8.GetBytes("new-transaction-bytes");
        File.WriteAllBytes(Path.Combine(path, "target"), original);
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(path, cancellationToken: ct);
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" },
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
            Data = ByteString.CopyFrom(intended),
        };
        var raw = request.ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var attempting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var effectsMayProceed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim();
        using var root = WorkspacePath.OpenRoot(path);
        WorkspaceStagePair? held = null;
        Task<FileJournalPreparation>? linux = null;
        Task<(RoutedAnswer? Answer, long LogId)>? windows = null;
        Task? oldWriter = null;
        var handler = calls.Dispatcher.FileHandlerForTests!;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                handler.AfterStageBeforeJournalForTests = () =>
                {
                    entered.TrySetResult();
                    if (!release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Owned stage coordination timed out.");
                };
                // Keep PREPARED and its real stage handles alive while the older writer gets its transaction.
                handler.AfterPreparationForTests = () => effectsMayProceed.Task;
                // This reaches the real routed WriteFile candidate and its own writer transaction on Windows.
                windows = calls.CallAsync(caller, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId);
            }
            else
            {
                // Linux target effects are still disabled. Exercise the same actual writer/stage/journal primitives,
                // without claiming a production target write or a §5 cleanup success.
                linux = node.Runtime.Processor.ExecuteAsync(command =>
                {
                    held = WorkspaceStagePair.TryCreateForCommand(root, node.Runtime.FileStages, command.Transaction,
                        id, original, intended, ct) ?? throw new InvalidOperationException("The native stage reservation failed.");
                    var rootId = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
                    var target = RegisteredWorkspaces.RootIdentity.Encode(root.InspectEntry("target").Identity, directory: false);
                    var intent = new FileJournalIntent(FileOperationKind.Write, id, request.Meta.CorrelationId.Value.ToByteArray(), caller,
                        workspace.Id, "target", rootId.Platform, rootId.Bytes, rootId.Bytes, target.Bytes,
                        original.Length, SHA256.HashData(original), held.Original!.Identity.Bytes,
                        intended.Length, SHA256.HashData(intended), held.Intended.Identity.Bytes);
                    entered.TrySetResult();
                    if (!release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Owned stage coordination timed out.");
                    return FileMutationJournal.Prepare(command.Transaction, intent, raw);
                }, CommitDurability.Full);
            }
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), ct);
            oldWriter = Task.Run(() => OlderWriter(node.Runtime.Store.DatabasePath, workspace.Id,
                original.Length + intended.Length, attempting), ct);
            await attempting.Task.WaitAsync(TimeSpan.FromSeconds(5), ct);
            Assert.NotSame(oldWriter, await Task.WhenAny(oldWriter, Task.Delay(200, ct)));
            release.Set();
            await oldWriter.WaitAsync(TimeSpan.FromSeconds(10), ct);
            effectsMayProceed.TrySetResult();
            if (windows is not null)
            {
                var result = await windows.WaitAsync(TimeSpan.FromSeconds(10), ct);
                var response = FileServiceWriteFileResponse.Parser.ParseFrom(Assert.IsType<ByteString>(result.Answer?.Response));
                Assert.Null(response.Error);
                Assert.Equal(intended, File.ReadAllBytes(Path.Combine(path, "target")));
            }
            else
            {
                Assert.Equal(FileJournalPreparation.Prepared, await linux!.WaitAsync(TimeSpan.FromSeconds(10), ct));
                Assert.Equal(original, File.ReadAllBytes(Path.Combine(path, "target")));
            }
        }
        finally
        {
            release.Set();
            effectsMayProceed.TrySetResult();
            handler.AfterStageBeforeJournalForTests = null;
            handler.AfterPreparationForTests = null;
            foreach (var pending in new Task?[] { oldWriter, linux, windows })
            {
                if (pending is null) continue;
                await AwaitOwnedCleanupAsync(pending);
            }
            if (linux is { IsCompleted: false } && held is { } pendingStage)
            {
                held = null;
                _ = DisposeAfterOwnedTaskAsync(linux, pendingStage);
            }
            held?.Dispose();
        }
    }

    // Cleanup remains bounded even after the test token is canceled; never close a stage under a live owned callback.
    private static async Task AwaitOwnedCleanupAsync(Task pending)
    {
        try { await pending.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OutOfMemoryException) { }
    }

    private static async Task DisposeAfterOwnedTaskAsync(Task pending, WorkspaceStagePair stage)
    {
        try { await pending.ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OutOfMemoryException) { }
        finally { stage.Dispose(); }
    }

    private static void OlderWriter(string database, byte[] workspace, int firstStageBytes, TaskCompletionSource attempting)
    {
        var settings = new SqliteConnectionStringBuilder { DataSource = database, Mode = SqliteOpenMode.ReadWrite, Pooling = false };
        using var connection = new SqliteConnection(settings.ToString());
        connection.Open();
        using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 10000;";
            pragma.ExecuteNonQuery();
        }
        attempting.TrySetResult();
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
