// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Real SQLite and test-owned native files for the journal component only. Fixture stages are named and do not prove
/// the future private anonymous-stage or guarded effect protocol.
/// </summary>
public sealed class FileMutationJournalTests
{
    [Fact]
    public void PreparedRecordSurvivesRestartBecomesUnknownAndNeedsExactHumanDigest()
    {
        using var fixture = new Fixture();
        var marker = Encoding.UTF8.GetBytes("sensitive-journal-body-91fd39ea5e7b");
        byte[] digest;
        byte[] original;
        FileJournalIntent intent;
        byte[] raw;
        using (var store = fixture.Open())
        {
            var registered = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(fixture.Workspace, "journal-test", cancellationToken: TestContext.Current.CancellationToken);
            (intent, raw) = fixture.WriteIntent(registered.Id, marker);
            original = File.ReadAllBytes(fixture.Target);
            digest = SHA256.HashData(raw);
            Assert.Equal(FileJournalPreparation.Prepared, store.Write(t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
            Assert.Equal(2L, store.Write(t => t.Scalar("PRAGMA synchronous;"), CommitDurability.Full));
            Assert.Equal(FileJournalPreparation.Existing, store.Write(t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
            // This lookup does not need to reopen a target or manufacture new staging for a replay.
            Assert.Equal(FileJournalPreparation.Existing,
                store.Read(r => FileMutationJournal.FindExisting(r, intent.Kind, intent.CommandId, intent.Caller, raw)));

            var sameAccount = intent.Caller.Clone();
            sameAccount.UserId = CommandIds.New();
            sameAccount.SessionId = CommandIds.New();
            Assert.NotNull(store.Read(r => FileMutationJournal.GetForCaller(r, intent.CommandId, sameAccount)));
            var foreign = intent.Caller.Clone();
            foreign.AccountId = CommandIds.New();
            Assert.Null(store.Read(r => FileMutationJournal.GetForCaller(r, intent.CommandId, foreign)));

            var changed = FileServiceWriteFileRequest.Parser.ParseFrom(raw);
            changed.Meta.CorrelationId = CommandIds.New();
            var changedIntent = intent with { CorrelationId = changed.Meta.CorrelationId.Value.ToByteArray() };
            Assert.Equal(FileJournalPreparation.Conflict,
                store.Write(t => FileMutationJournal.Prepare(t, changedIntent, changed.ToByteArray()), CommitDurability.Full));
            Assert.Equal(FileJournalPreparation.Conflict, store.Read(
                r => FileMutationJournal.FindExisting(r, intent.Kind, intent.CommandId, intent.Caller, changed.ToByteArray())));

            var another = FileServiceWriteFileRequest.Parser.ParseFrom(raw);
            another.Meta.CommandId = CommandIds.New();
            var otherIntent = intent with { CommandId = another.Meta.CommandId.Value.ToByteArray() };
            Assert.Equal(FileJournalPreparation.WorkspaceHeld,
                store.Write(t => FileMutationJournal.Prepare(t, otherIntent, another.ToByteArray()), CommitDurability.Full));

            var refusal = Assert.Throws<RegisteredWorkspaceException>(() =>
                new RegisteredWorkspaces(store).UnregisterFromVerifiedHuman(registered.Id, TestContext.Current.CancellationToken));
            Assert.Equal("workspace_in_use", refusal.Reason);
            Assert.Throws<SqliteException>(() => store.Write(t => t.Execute(
                "UPDATE workspace SET removed_at = $now WHERE workspace_id = $id;",
                ("$now", t.NowMicroseconds), ("$id", registered.Id)), CommitDurability.Full));
            Assert.Equal(0, store.Write(t => t.Execute("DELETE FROM command_dedup WHERE command_id = $id;", ("$id", intent.CommandId))));
            AssertNoContent(store.DatabasePath, marker);
        }

        using (var restarted = fixture.Open())
        {
            // This is a close/reopen with a durable PREPARED fixture, not a claim of process-crash or filesystem-effect coverage.
            Assert.Equal(1, restarted.Write(FileMutationJournal.RecoverInterrupted, CommitDurability.Full));
            var operation = restarted.Read(r => FileMutationJournal.GetForCaller(r, intent.CommandId, intent.Caller))!;
            Assert.True(NodeShapes.IsValid(operation));
            Assert.Equal(FileOperationState.Unknown, operation.State);
            Assert.Equal(digest, operation.RequestSha256.ToByteArray());
            Assert.True(operation.Held);
            Assert.False(operation.Acknowledged);
            Assert.Equal("operation_failed", operation.Error.Code);
            Assert.Equal(EffectCertainty.Unknown, operation.Error.Effect);
            Assert.Equal(RetryMode.Never, operation.Error.Retry.Mode);
            Assert.Equal("file_outcome_unknown", operation.Error.Details.State.Reason);
            Assert.Equal(intent.CorrelationId, operation.Error.CorrelationId.Value.ToByteArray());
            Assert.Equal(original, File.ReadAllBytes(fixture.Target));
            var human = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
            Assert.Equal(FileJournalAcknowledgment.DigestMismatch, restarted.Write(
                t => FileMutationJournal.AcknowledgeFromVerifiedHuman(t, intent.CommandId, new byte[32], human), CommitDurability.Full));
            Assert.True(restarted.Read(r => FileMutationJournal.HasWorkspaceHold(r, intent.WorkspaceId)));
            Assert.Equal(FileJournalAcknowledgment.Acknowledged, restarted.Write(
                t => FileMutationJournal.AcknowledgeFromVerifiedHuman(t, intent.CommandId, digest, human), CommitDurability.Full));
            operation = restarted.Read(r => FileMutationJournal.GetForVerifiedHuman(r, intent.CommandId))!;
            Assert.True(NodeShapes.IsValid(operation));
            Assert.Equal(FileOperationState.Unknown, operation.State);
            Assert.False(operation.Held);
            Assert.True(operation.Acknowledged);
            Assert.Equal(intent.CorrelationId, operation.Error.CorrelationId.Value.ToByteArray());
            Assert.Equal(FileJournalAcknowledgment.InvalidState, restarted.Write(
                t => FileMutationJournal.AcknowledgeFromVerifiedHuman(t, intent.CommandId, digest, human), CommitDurability.Full));
            Assert.Equal(FileJournalPreparation.Existing,
                restarted.Write(t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
            var auditBefore = restarted.Read(r => (long)r.Scalar("""
                SELECT count(*) FROM audit_log WHERE operation IN
                  ('file.recovery FileService.GetFileOperation', 'file.acknowledge FileService.AcknowledgeFileOperation');
                """)!);
            Assert.Equal(4, auditBefore); // recovery, wrong digest, successful acknowledgment, second invalid acknowledgment
            new RegisteredWorkspaces(restarted).UnregisterFromVerifiedHuman(intent.WorkspaceId, TestContext.Current.CancellationToken);
            var afterUnregister = restarted.Read(r => FileMutationJournal.GetForVerifiedHuman(r, intent.CommandId))!;
            Assert.Equal(digest, afterUnregister.RequestSha256.ToByteArray());
            Assert.Equal("target.txt", afterUnregister.WorkspacePath.Path);
            Assert.Equal(intent.WorkspaceId, afterUnregister.WorkspacePath.WorkspaceId.Value.ToByteArray());
            Assert.Equal(1L, restarted.Read(r => r.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", intent.CommandId))));
            Assert.Equal(auditBefore, restarted.Read(r => (long)r.Scalar("""
                SELECT count(*) FROM audit_log WHERE operation IN
                  ('file.recovery FileService.GetFileOperation', 'file.acknowledge FileService.AcknowledgeFileOperation');
                """)!));
            Assert.Equal(original, File.ReadAllBytes(fixture.Target));
            AssertNoContent(restarted.DatabasePath, marker);
        }
    }

    [Fact]
    public void APreparationRequiresFullCommitAndBindsExactBytesBeforeCreatingAnyRow()
    {
        using var fixture = new Fixture();
        using var store = fixture.Open();
        var registered = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(fixture.Workspace, "journal-test", cancellationToken: TestContext.Current.CancellationToken);
        var (intent, raw) = fixture.WriteIntent(registered.Id, Encoding.UTF8.GetBytes("bounded-new-data"));
        Assert.Throws<InvalidOperationException>(() => store.Write(t => FileMutationJournal.Prepare(t, intent, raw)));
        var changed = FileServiceWriteFileRequest.Parser.ParseFrom(raw);
        changed.Data = ByteString.CopyFromUtf8("different-data");
        Assert.Throws<ArgumentException>(() => store.Write(
            t => FileMutationJournal.Prepare(t, intent, changed.ToByteArray()), CommitDurability.Full));
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(0L, store.Read(r => r.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", intent.CommandId))));
    }

    [Fact(Timeout = 120_000)]
    public async Task NodeStartupRecoversAnExistingPreparedRecordBeforeServing()
    {
        using var fixture = new Fixture();
        await using var node = await InProcessNode.Create().StartAsync();
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(fixture.Workspace, "journal-test",
            cancellationToken: TestContext.Current.CancellationToken);
        var (intent, raw) = fixture.WriteIntent(registered.Id, Encoding.UTF8.GetBytes("restart-test-content"));
        Assert.Equal(FileJournalPreparation.Prepared, node.Runtime.Store.Write(
            t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var recovered = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, intent.CommandId, intent.Caller));
        Assert.NotNull(recovered);
        Assert.Equal(FileOperationState.Unknown, recovered.State);
        Assert.True(recovered.Held);
        Assert.Equal("file_outcome_unknown", recovered.Error.Details.State.Reason);
        Assert.Equal(SHA256.HashData(raw), recovered.RequestSha256.ToByteArray());
        Assert.Equal("original test bytes", File.ReadAllText(fixture.Target));
    }

    [Fact(Timeout = 120_000)]
    public async Task LocalRecoveryEndpointRequiresHelloHumanAndReplaysExactAcknowledgment()
    {
        using var fixture = new Fixture();
        await using var node = await InProcessNode.Create().StartAsync();
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(fixture.Workspace, "journal-test",
            cancellationToken: TestContext.Current.CancellationToken);
        var marker = Encoding.UTF8.GetBytes("local-endpoint-body-8f44651e");
        var (intent, raw) = fixture.WriteIntent(registered.Id, marker);
        Assert.Equal(FileJournalPreparation.Prepared, node.Runtime.Store.Write(
            t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var operationId = new Id { Value = ByteString.CopyFrom(intent.CommandId) };
        var get = new FileServiceGetFileOperationRequest { Meta = new RequestMeta { CorrelationId = CommandIds.New() }, OperationCommandId = operationId };
        var token = TestContext.Current.CancellationToken;

        // The in-process fixture reports an interactive terminal for this verified peer. It is not a physical-terminal acceptance test.
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(helloAsHuman: true, kind: ClientKind.McpAdapter);
        await using var noHello = NodeChannel.Create(node.Endpoint);
        foreach (var deniedClient in new[] { script.Files, agent.Files, noHello.Files })
        {
            var denied = await deniedClient.GetFileOperationAsync(get, cancellationToken: token);
            Assert.Equal("permission_denied", denied.Error.Code);
            Assert.True(NodeShapes.IsValid(denied));
            Assert.Equal(get.Meta.CorrelationId, denied.Error.CorrelationId);
        }

        var shown = await human.Files.GetFileOperationAsync(get, cancellationToken: token);
        Assert.True(NodeShapes.IsValid(shown));
        Assert.Equal(FileOperationState.Unknown, shown.Value.Operation.State);
        Assert.True(shown.Value.Operation.Held);
        Assert.Equal(SHA256.HashData(raw), shown.Value.Operation.RequestSha256.ToByteArray());
        Assert.Equal(intent.CorrelationId, shown.Value.Operation.Error.CorrelationId.Value.ToByteArray());

        var deniedAck = new FileServiceAcknowledgeFileOperationRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            OperationCommandId = operationId,
            OperationDigest = shown.Value.Operation.RequestSha256,
        };
        var deniedReply = await agent.Files.AcknowledgeFileOperationAsync(deniedAck, cancellationToken: token);
        Assert.Equal("permission_denied", deniedReply.Error.Code);
        Assert.True(node.Runtime.Store.Read(r => FileMutationJournal.HasWorkspaceHold(r, intent.WorkspaceId)));

        var wrong = deniedAck.Clone();
        wrong.Meta.CommandId = CommandIds.New();
        wrong.OperationDigest = ByteString.CopyFrom(new byte[32]);
        var mismatch = await human.Files.AcknowledgeFileOperationAsync(wrong, cancellationToken: token);
        Assert.True(NodeShapes.IsValid(mismatch));
        Assert.Equal("digest_mismatch", mismatch.Error.Code);
        Assert.Equal("file_operation", mismatch.Error.Details.State.State);
        Assert.Equal("operation_digest_mismatch", mismatch.Error.Details.State.Reason);
        Assert.Equal(wrong.Meta.CorrelationId, mismatch.Error.CorrelationId);
        Assert.True(node.Runtime.Store.Read(r => FileMutationJournal.HasWorkspaceHold(r, intent.WorkspaceId)));

        var ack = deniedAck.Clone();
        ack.Meta.CommandId = CommandIds.New();
        var accepted = await human.Files.AcknowledgeFileOperationAsync(ack, cancellationToken: token);
        Assert.True(NodeShapes.IsValid(accepted));
        Assert.Equal(ack.Meta.CommandId, accepted.Value.Receipt.CommandId);
        Assert.Equal(EffectCertainty.Happened, accepted.Value.Receipt.Effect); // acknowledgment only
        Assert.Equal(FileOperationState.Unknown, accepted.Value.Operation.State);
        Assert.True(accepted.Value.Operation.Acknowledged);
        Assert.False(accepted.Value.Operation.Held);
        var replay = await human.Files.AcknowledgeFileOperationAsync(ack, cancellationToken: token);
        Assert.Equal(accepted.ToByteArray(), replay.ToByteArray());
        var reused = ack.Clone();
        reused.OperationDigest = ByteString.CopyFrom(new byte[32]);
        var conflict = await human.Files.AcknowledgeFileOperationAsync(reused, cancellationToken: token);
        Assert.True(NodeShapes.IsValid(conflict));
        Assert.Equal("command_id_reused", conflict.Error.Code);
        Assert.Equal(ack.Meta.CorrelationId, conflict.Error.CorrelationId);

        // Mapping this service must not expose the ordinary file mutation entry point on local IPC.
        var direct = FileServiceWriteFileRequest.Parser.ParseFrom(raw);
        var rpc = await Assert.ThrowsAsync<Grpc.Core.RpcException>(async () =>
            await human.Files.WriteFileAsync(direct, cancellationToken: token));
        Assert.Equal(Grpc.Core.StatusCode.Unimplemented, rpc.StatusCode);
        Assert.Equal("original test bytes", File.ReadAllText(fixture.Target));
        AssertNoContent(node.Runtime.Store.DatabasePath, marker);
    }

    [Fact(Timeout = 45_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task CanceledQueuedAcknowledgmentCannotReleaseTheHoldAfterTheWriterResumes()
    {
        using var fixture = new Fixture();
        await using var node = await InProcessNode.Create().StartAsync();
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(fixture.Workspace, "journal-test",
            cancellationToken: TestContext.Current.CancellationToken);
        var (intent, raw) = fixture.WriteIntent(registered.Id, Encoding.UTF8.GetBytes("queued-ack-test"));
        Assert.Equal(FileJournalPreparation.Prepared, node.Runtime.Store.Write(
            t => FileMutationJournal.Prepare(t, intent, raw), CommitDurability.Full));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var testToken = TestContext.Current.CancellationToken;
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocker = node.Runtime.Processor.ExecuteAsync(_ =>
        {
            entered.TrySetResult();
            if (!release.Wait(TimeSpan.FromSeconds(20), testToken))
                throw new TimeoutException("The owned writer stall was not released.");
            return 0;
        });
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            var commandId = CommandIds.New();
            var enqueued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            node.Runtime.Processor.EnqueuedForTests = new Dictionary<string, TaskCompletionSource>
            {
                [Convert.ToHexString(commandId.Value.Span)] = enqueued,
            };
            var request = new FileServiceAcknowledgeFileOperationRequest
            {
                Meta = new RequestMeta { CommandId = commandId, CorrelationId = CommandIds.New() },
                OperationCommandId = new Id { Value = ByteString.CopyFrom(intent.CommandId) },
                OperationDigest = ByteString.CopyFrom(SHA256.HashData(raw)),
            };
            using var cancel = new CancellationTokenSource();
            var response = human.Files.AcknowledgeFileOperationAsync(request, cancellationToken: cancel.Token).ResponseAsync;
            await enqueued.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            await cancel.CancelAsync();
            var failure = await Record.ExceptionAsync(async () => await response.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken));
            Assert.True(failure is OperationCanceledException or Grpc.Core.RpcException { StatusCode: Grpc.Core.StatusCode.Cancelled });
            release.Set();
            await blocker.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            await node.Runtime.Processor.ExecuteAsync(_ => 0).WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            Assert.True(node.Runtime.Store.Read(r => FileMutationJournal.HasWorkspaceHold(r, intent.WorkspaceId)));
            Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;",
                ("$id", commandId.Value.ToByteArray()))));
            Assert.Equal("original test bytes", File.ReadAllText(fixture.Target));
        }
        finally
        {
            release.Set();
            node.Runtime.Processor.EnqueuedForTests = null;
            await blocker;
        }
    }

    private static void AssertNoContent(string database, byte[] marker)
    {
        foreach (var file in new[] { database, database + "-wal" })
        {
            if (File.Exists(file)) Assert.True(File.ReadAllBytes(file).AsSpan().IndexOf(marker) < 0);
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("arcforges-file-journal-");
        internal Fixture()
        {
            Workspace = Directory.CreateDirectory(Path.Combine(_root.FullName, "workspace")).FullName;
            Target = Path.Combine(Workspace, "target.txt");
            File.WriteAllText(Target, "original test bytes");
        }

        internal string Workspace { get; }
        internal string Target { get; }
        internal NodeStore Open() => NodeStore.Open(new NodeStoreOptions
        {
            DataRoot = Path.Combine(_root.FullName, "node-data"),
            BootIdentity = "journal-test",
        });

        internal (FileJournalIntent Intent, byte[] Raw) WriteIntent(byte[] workspaceId, byte[] data)
        {
            // Test-owned named fixture files supply real object identities and hashes to the isolated DB component.
            // They are not the production stage implementation and are never claimed to survive an actual crash safely.
            var original = File.ReadAllBytes(Target);
            var originalStage = Path.Combine(_root.FullName, "original-stage");
            var intendedStage = Path.Combine(_root.FullName, "intended-stage");
            WriteFlushed(originalStage, original);
            WriteFlushed(intendedStage, data);
            using var root = WorkspacePath.OpenRoot(Workspace);
            var rootId = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            using var target = File.OpenHandle(Target, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var oldStage = File.OpenHandle(originalStage, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var newStage = File.OpenHandle(intendedStage, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var targetId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(target), directory: false);
            var oldId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(oldStage), directory: false);
            var newId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(newStage), directory: false);
            var meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
            var request = new FileServiceWriteFileRequest
            {
                Meta = meta,
                Path = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspaceId) }, Path = "target.txt" },
                Data = ByteString.CopyFrom(data),
                ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original)),
            };
            var caller = new CenterCaller
            {
                Kind = CenterCallerKind.AccountSession,
                AccountId = CommandIds.New(),
                UserId = CommandIds.New(),
                SessionId = CommandIds.New(),
            };
            var intent = new FileJournalIntent(FileOperationKind.Write, meta.CommandId.Value.ToByteArray(),
                meta.CorrelationId.Value.ToByteArray(), caller, workspaceId, "target.txt", rootId.Platform, rootId.Bytes,
                rootId.Bytes, targetId.Bytes, original.LongLength, SHA256.HashData(original), oldId.Bytes,
                data.LongLength, SHA256.HashData(data), newId.Bytes);
            return (intent, request.ToByteArray());
        }

        private static void WriteFlushed(string path, byte[] bytes)
        {
            using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            file.Write(bytes);
            file.Flush(flushToDisk: true);
        }

        public void Dispose() => _root.Delete(recursive: true);
    }
}
