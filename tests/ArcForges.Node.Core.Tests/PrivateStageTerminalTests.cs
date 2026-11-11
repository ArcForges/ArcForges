// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual SQLite writer ordering and native stage identities; no target mutation or real center.</summary>
public sealed class PrivateStageTerminalTests
{
    [Fact(Timeout = 120_000)]
    public async Task StartupFenceWinsBeforeAnAlreadyWaitingProducerAndCannotBeReactivated()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var caller = new RoutedCalls(node).Relay(Origin.Script);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "fence-first")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        var body = Encoding.UTF8.GetBytes("fence-first-private");
        var request = Request(workspace.Id, body);
        var raw = request.ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        var stagePath = Path.Combine(directory, "stage");
        Reserve(node, caller, workspace.Id, request, stagePath);
        using var root = WorkspacePath.OpenRoot(directory);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var oldProducer = Task.Run(async () =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(ct);
            return await PrivateStageProducer.CreateBoundAsync(node.Runtime.Processor, id, 2, root, root, "stage", ct);
        }, ct);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), ct);
        Assert.Equal(1, node.Runtime.Store.Write(PrivateStageTerminal.RecoverUnraised, CommitDurability.Full));
        release.SetResult();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await oldProducer);
        Assert.False(File.Exists(stagePath));
        Assert.False(File.Exists(Path.Combine(directory, "target")));
        Assert.Equal((0, (long)body.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Throws<SqliteException>(() => node.Runtime.Store.Write(t => t.Execute(
            "UPDATE file_private_stage_reservation SET active = 1 WHERE command_id = $id;", ("$id", id)), CommitDurability.Full));
        var exact = node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, FileOperationKind.Write, id, caller, raw));
        Assert.NotNull(exact);
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(exact);
        Assert.Equal("invalid_state", response.Error.Code);
        Assert.Equal("file_preparation_abandoned", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(request.Meta.CorrelationId, response.Error.CorrelationId);
        var wrong = request.Clone();
        wrong.Data = ByteString.CopyFromUtf8("other");
        Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, FileOperationKind.Write, id, caller, wrong.ToByteArray())));
        Assert.Equal(FileOperationState.Completed, node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller))!.State);
    }

    [Fact(Timeout = 120_000)]
    public async Task WriterAlreadyCreatingFinishesBeforeFenceAndCannotWriteAfterward()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var caller = new RoutedCalls(node).Relay(Origin.Script);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "producer-first")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        var body = Encoding.UTF8.GetBytes("private-producer-first");
        var request = Request(workspace.Id, body);
        var id = request.Meta.CommandId.Value.ToByteArray();
        var raw = request.ToByteArray();
        var stagePath = Path.Combine(directory, "stage");
        Reserve(node, caller, workspace.Id, request, stagePath);
        using var root = WorkspacePath.OpenRoot(directory);
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var producer = PrivateStageProducer.CreateBoundAsync(node.Runtime.Processor, id, 2, root, root, "stage", ct,
            afterCreateForTests: () =>
            {
                entered.SetResult();
                if (!release.Wait(TimeSpan.FromSeconds(8))) throw new TimeoutException("Owned producer was not released.");
            });
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), ct);
            var recovery = Task.Run(() => node.Runtime.Store.Write(PrivateStageTerminal.RecoverUnraised, CommitDurability.Full), ct);
            Assert.NotSame(recovery, await Task.WhenAny(recovery, Task.Delay(100, ct)));
            release.Set();
            using var stage = await producer.WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Equal(1, await recovery.WaitAsync(TimeSpan.FromSeconds(10), ct));
            Assert.Throws<InvalidOperationException>(() => PrivateStageRegistry.WriteBoundStage(node.Runtime.Store,
                id, 2, caller, raw, stage, body, ct));
            Assert.Equal(0L, stage.Guard.ObserveLength(ct));
            Assert.Single(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
            Assert.Equal((0, (long)body.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
            Assert.False(File.Exists(Path.Combine(directory, "target")));
        }
        finally { release.Set(); }
    }

    [Fact(Timeout = 180_000)]
    public async Task SixtyFiveFinishedProducersReleaseSlotsWithoutDroppingRetainedBytesOrProtection()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "terminal-capacity")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        var body = Encoding.UTF8.GetBytes("retained-stage-65");
        var ids = new List<byte[]>();
        using (var root = WorkspacePath.OpenRoot(directory))
        {
            for (var index = 0; index < 65; index++)
            {
                var name = "stage-" + index.ToString("D3", System.Globalization.CultureInfo.InvariantCulture);
                var request = Request(workspace.Id, body);
                var id = request.Meta.CommandId.Value.ToByteArray();
                var raw = request.ToByteArray();
                Reserve(node, caller, workspace.Id, request, Path.Combine(directory, name));
                using (var stage = await PrivateStageProducer.CreateBoundAsync(node.Runtime.Processor, id, 2, root, root, name, ct))
                    PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2, caller, raw, stage, body, ct);
                Assert.True(node.Runtime.Store.Write(t => PrivateStageTerminal.RecoverFailedProducer(t, id), CommitDurability.Full));
                ids.Add(id);
            }
        }
        Assert.Equal((0, (long)body.Length * 65), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Equal(65, node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities).Count);
        var next = Request(workspace.Id, body);
        Reserve(node, caller, workspace.Id, next, Path.Combine(directory, "stage-next"));
        Assert.Equal((1, (long)body.Length * 66), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        // Startup also fences the last unraised reservation; every prior retained identity remains protected.
        Assert.Equal((0, (long)body.Length * 66), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Equal(65, node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities).Count);
        Assert.All(ids, id => Assert.Equal(FileOperationState.Completed,
            node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller))!.State));
        var read = new FileServiceReadFileRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "stage-000" },
            Offset = 0,
            Length = 128,
        };
        var reply = await new RoutedCalls(node).CallAsync(caller, RoutedMethod.ReadNodeFile, read.ToByteArray());
        var protectedResponse = FileServiceReadFileResponse.Parser.ParseFrom(reply.Answer!.Response);
        Assert.Equal("file_access_denied", protectedResponse.Error.Code);
        Assert.Equal(body, File.ReadAllBytes(Path.Combine(directory, "stage-000")));
    }

    private static FileServiceWriteFileRequest Request(byte[] workspace, byte[] body) => new()
    {
        Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
        Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = "target" },
        ExpectedAbsent = true,
        Data = ByteString.CopyFrom(body),
    };

    private static void Reserve(InProcessNode node, CenterCaller caller, byte[] workspace,
        FileServiceWriteFileRequest request, string stagePath)
    {
        var body = request.Data.ToByteArray();
        var spec = new PrivateStageSpec(2, stagePath, body.Length, SHA256.HashData(body));
        Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
            node.Runtime.FileStages, FileOperationKind.Write, request.Meta.CommandId.Value.Span, workspace,
            request.Meta.CorrelationId.Value.Span, caller, request.ToByteArray(), [spec]), CommitDurability.Full));
    }
}
