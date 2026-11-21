// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

public sealed class FileMutationAfterEffectBoundaryTests
{
    // The native first-chunk link-loss test remains executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task AnInterruptedHistoricalWriteKeepsPartialBytesAndRecoversItsExactUnknownReceipt()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The historical partial write fixture uses Windows file identities.");
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "historical-partial-write")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        var path = Path.Combine(root, "target.bin");
        var before = Enumerable.Repeat((byte)0x41, 80_000).ToArray();
        var intended = Enumerable.Repeat((byte)0x42, 70_000).ToArray();
        var partial = before.ToArray();
        intended.AsSpan(0, 65_536).CopyTo(partial);
        File.WriteAllBytes(path, partial);
        var request = RetainedExistingFileFixture.Write(workspace, "target.bin", before, intended);
        var raw = request.ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        var digest = SHA256.HashData(raw);
        node.Runtime.Store.Write(tx => RetainedExistingFileFixture.Prepare(tx, workspace, actor, FileOperationKind.Write,
            request.Meta, request.Path.Path, raw, before, intended), CommitDurability.Full);

        calls.Link.Reset(usableFor: 0);
        Assert.Null((await calls.CallAsync(actor, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId, cancellationToken: token)).Answer);
        calls.Link.Reset();
        Assert.Null((await calls.CallAsync(actor, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId, cancellationToken: token)).Answer);
        var pending = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, id, actor));
        Assert.NotNull(pending);
        Assert.Equal(FileOperationState.Prepared, pending.State);
        Assert.True(pending.Held);
        Assert.Null(node.Runtime.Store.Read(reader => reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", id))) as byte[]);
        Assert.Equal(partial, File.ReadAllBytes(path));

        Assert.Equal(0, await node.StopAsync().WaitAsync(token));
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var retained = Assert.IsType<byte[]>(node.Runtime.Store.Read(reader =>
            reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", id))));
        var recovered = await RetainedExistingFileFixture.ReplyAsync(calls, actor, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId, token);
        Assert.Equal(retained, recovered);
        var replay = FileServiceWriteFileResponse.Parser.ParseFrom(recovered);
        Assert.True(NodeShapes.IsValid(replay));
        RetainedExistingFileFixture.AssertUnknown(replay.Error);
        Assert.Equal(request.Meta.CorrelationId, replay.Meta.CorrelationId);
        Assert.Equal(request.Meta.CorrelationId, replay.Error.CorrelationId);

        var get = new FileServiceGetFileOperationRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            OperationCommandId = request.Meta.CommandId.Clone(),
        };
        var outcome = await RetainedExistingFileFixture.ReplyAsync(calls, actor, RoutedMethod.GetNodeFileOperation, get.ToByteArray(), null, token);
        var status = FileServiceGetFileOperationResponse.Parser.ParseFrom(outcome);
        Assert.True(NodeShapes.IsValid(status));
        var operation = status.Value.Operation;
        Assert.Equal(FileOperationState.Unknown, operation.State);
        Assert.True(operation.Held);
        Assert.False(operation.Acknowledged);
        Assert.Equal(digest, operation.RequestSha256.ToByteArray());
        Assert.Equal(request.Path, operation.WorkspacePath);
        RetainedExistingFileFixture.AssertUnknown(operation.Error);

        var other = actor.Clone();
        other.LocalSessionId = CommandIds.New();
        var withheld = await RetainedExistingFileFixture.ReplyAsync(calls, other, RoutedMethod.GetNodeFileOperation, get.ToByteArray(), null, token);
        var denied = FileServiceGetFileOperationResponse.Parser.ParseFrom(withheld);
        Assert.Null(denied.Value);
        Assert.Equal("not_found", denied.Error.Code);
        Assert.Equal(partial, File.ReadAllBytes(path));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_effect_worker;")));
    }
}
