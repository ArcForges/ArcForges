// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Tests actual pre-effect authorization checks on native files; caller and transport are isolated substitutes.</summary>
public sealed class FileMutationEffectBoundaryTests
{
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task WindowsCreateAndExistingWriteRecheckLinkAndCancellationImmediatelyBeforeEffect()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native guarded-effect boundary."); return; }
        var testToken = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var handler = calls.Dispatcher.FileHandlerForTests!;
        var original = Encoding.UTF8.GetBytes("boundary-original-a134");
        var replacement = Encoding.UTF8.GetBytes("boundary-new-87ec");
        async Task<byte[]?> Invoke(FileServiceWriteFileRequest request, CancellationToken token)
        {
            var raw = request.ToByteArray();
            var now = node.Runtime.Clock.GetUtcNow();
            var routed = new RoutedContext(calls.Link, node.Runtime.Lifecycle, now.AddSeconds(30), TimeSpan.FromSeconds(15),
                node.Runtime.Clock, node.Runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
            var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: actor.Clone())
            {
                CellsOrigin = CenterRouting.CellsOrigin(actor, node.Runtime.NodeId.Span),
                RemoteCommandId = request.Meta.CommandId.Clone(),
                RawRequest = raw,
                Routed = routed,
            };
            return await handler.WriteExistingCandidateAsync(caller, token);
        }
        FileServiceWriteFileRequest Request(byte[] workspaceId, string name, bool absent) => new()
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspaceId) }, Path = name },
            Data = ByteString.CopyFrom(replacement),
            ExpectedAbsent = absent,
        };
        (string Root, byte[] Workspace) NewWorkspace(string name)
        {
            var root = Directory.CreateDirectory(Path.Combine(node.Root, name)).FullName;
            var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: testToken);
            return (root, workspace.Id);
        }

        var (createRoot, createWorkspace) = NewWorkspace("drop-before-create");
        var create = Request(createWorkspace, "new.txt", absent: true);
        handler.BeforeCreateForTests = () => calls.Link.Reset(usableFor: 0);
        var droppedCreate = await Record.ExceptionAsync(async () => await Invoke(create, testToken));
        handler.BeforeCreateForTests = null;
        Assert.IsType<RoutedAbortException>(droppedCreate);
        Assert.False(File.Exists(Path.Combine(createRoot, "new.txt")));
        var pendingCreate = node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, create.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Prepared, pendingCreate!.State);
        calls.Link.Reset();

        var (writeRoot, writeWorkspace) = NewWorkspace("drop-before-write");
        var existingPath = Path.Combine(writeRoot, "existing.txt");
        File.WriteAllBytes(existingPath, original);
        File.SetAttributes(existingPath, FileAttributes.Archive);
        var write = Request(writeWorkspace, "existing.txt", absent: false);
        write.ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(original));
        handler.BeforeMutationEffectForTests = () => calls.Link.Reset(usableFor: 0);
        var droppedWrite = await Record.ExceptionAsync(async () => await Invoke(write, testToken));
        handler.BeforeMutationEffectForTests = null;
        var guarded = Assert.IsType<WorkspaceGuardedMutationException>(droppedWrite);
        Assert.False(guarded.PossibleEffect);
        Assert.IsType<RoutedAbortException>(guarded.InnerException);
        Assert.Equal(original, File.ReadAllBytes(existingPath));
        var pendingWrite = node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, write.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Prepared, pendingWrite!.State);
        calls.Link.Reset();

        var (cancelRoot, cancelWorkspace) = NewWorkspace("cancel-before-create");
        var cancelled = Request(cancelWorkspace, "new.txt", absent: true);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(testToken);
        handler.BeforeCreateForTests = cancellation.Cancel;
        var cancelledReply = await Record.ExceptionAsync(async () => await Invoke(cancelled, cancellation.Token));
        handler.BeforeCreateForTests = null;
        Assert.IsAssignableFrom<OperationCanceledException>(cancelledReply);
        // Drain the actual writer before checking for a late target effect.
        await node.Runtime.Processor.ExecuteAsync(_ => 0).WaitAsync(TimeSpan.FromSeconds(5), testToken);
        Assert.False(File.Exists(Path.Combine(cancelRoot, "new.txt")));
        var pendingCancel = node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, cancelled.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Prepared, pendingCancel!.State);

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        foreach (var command in new[] { create.Meta.CommandId, write.Meta.CommandId, cancelled.Meta.CommandId })
        {
            var recovered = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, command.Value.Span, actor));
            Assert.Equal(FileOperationState.Unknown, recovered!.State);
            Assert.True(recovered.Held);
            Assert.Equal("file_outcome_unknown", recovered.Error.Details.State.Reason);
        }
        Assert.False(File.Exists(Path.Combine(createRoot, "new.txt")));
        Assert.Equal(original, File.ReadAllBytes(existingPath));
        Assert.False(File.Exists(Path.Combine(cancelRoot, "new.txt")));
    }
}
