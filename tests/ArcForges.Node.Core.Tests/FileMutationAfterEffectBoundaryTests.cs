// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>An actual held-handle partial write; the routed caller and link are isolated test substitutes.</summary>
public sealed class FileMutationAfterEffectBoundaryTests
{
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task LinkLossAfterFirstRealWriteStopsFurtherEffectsAndPersistsUnknown()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native guarded write boundary."); return; }
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "link-after-first-write")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        var path = Path.Combine(root, "target.bin");
        var before = Enumerable.Repeat((byte)0x41, 80_000).ToArray();
        var intended = Enumerable.Repeat((byte)0x42, 70_000).ToArray();
        File.WriteAllBytes(path, before);
        File.SetAttributes(path, FileAttributes.Archive);
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target.bin" },
            Data = ByteString.CopyFrom(intended),
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(before)),
        };
        var raw = request.ToByteArray();
        var now = node.Runtime.Clock.GetUtcNow();
        var context = new RoutedContext(calls.Link, node.Runtime.Lifecycle, now.AddSeconds(30), TimeSpan.FromSeconds(15),
            node.Runtime.Clock, node.Runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
        var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: actor.Clone())
        {
            CellsOrigin = CenterRouting.CellsOrigin(actor, node.Runtime.NodeId.Span),
            RemoteCommandId = request.Meta.CommandId.Clone(),
            RawRequest = raw,
            Routed = context,
        };
        var handler = calls.Dispatcher.FileHandlerForTests!;
        var checks = 0;
        handler.BeforeMutationEffectForTests = () =>
        {
            if (Interlocked.Increment(ref checks) == 2) calls.Link.Reset(usableFor: 0);
        };
        byte[]? outcome;
        try { outcome = await handler.WriteExistingCandidateAsync(caller, token); }
        finally { handler.BeforeMutationEffectForTests = null; calls.Link.Reset(); }

        var response = FileServiceWriteFileResponse.Parser.ParseFrom(outcome);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Equal("file_outcome_unknown", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, response.Error.Effect);
        Assert.Equal(RetryMode.Never, response.Error.Retry.Mode);
        Assert.Equal(request.Meta.CorrelationId, response.Error.CorrelationId);
        Assert.Equal(2, checks);
        var expected = before.ToArray();
        intended.AsSpan(0, 65_536).CopyTo(expected);
        Assert.Equal(expected, File.ReadAllBytes(path)); // exactly one chunk, no second write and no truncation
        var operation = node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, request.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Unknown, operation!.State);
        Assert.True(operation.Held);
        Assert.Equal(SHA256.HashData(raw), operation.RequestSha256.ToByteArray());
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var restarted = node.Runtime.Store.Read(reader =>
            FileMutationJournal.GetForCaller(reader, request.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Unknown, restarted!.State);
        Assert.True(restarted.Held);
        Assert.Equal(expected, File.ReadAllBytes(path));
    }
}
