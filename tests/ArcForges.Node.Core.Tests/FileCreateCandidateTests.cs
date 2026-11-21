// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Retained expected-absent receipts and holds through the routed component seam. The original native producer
/// and competing create remain exercised at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
/// </summary>
public sealed class FileCreateCandidateTests
{
    [Fact(Timeout = 30_000)]
    public async Task RetainedCreateAndCollisionReplayWithoutMotionAndHeldCreationCanBeAcknowledged()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var owner = calls.Relay(Origin.Human);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "retained-creation")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        using var root = WorkspacePath.OpenRoot(rootPath);
        var body = "historical-private-create-body-7a239b"u8.ToArray();
        var hash = SHA256.HashData(body);

        var created = Request(workspace.Id, "created.txt", body);
        var collision = Request(workspace.Id, "occupied.txt", body);
        var interrupted = Request(workspace.Id, "interrupted.txt", body);
        var createdPath = Path.Combine(rootPath, created.Path.Path);
        var collisionPath = Path.Combine(rootPath, collision.Path.Path);
        var interruptedPath = Path.Combine(rootPath, interrupted.Path.Path);
        File.WriteAllText(createdPath, "current data must not be overwritten");
        File.WriteAllText(collisionPath, "competitor must be left alone");
        File.WriteAllBytes(interruptedPath, []);

        var (success, conflict) = node.Runtime.Store.Write(transaction =>
        {
            SeedPrepared(transaction, owner, root, created);
            var success = FileMutationJournal.CompleteVerifiedEffect(transaction, created.Meta.CommandId.Value.Span,
                created.ToByteArray(), body.Length, hash, replacements: null);
            var stage = SeedPrepared(transaction, owner, root, collision);
            var conflict = FileMutationJournal.CompleteKnownExpectedAbsentConflict(transaction, collision.Meta.CommandId.Value.Span,
                owner, collision.ToByteArray(), new WorkspaceCreateCollisionException(root.RootIdentity, collision.Path.Path, stage));
            SeedPrepared(transaction, owner, root, interrupted);
            return (success, conflict);
        }, CommitDurability.Full);

        var replay = await ReplayAsync(calls, owner, created, ct);
        Assert.Equal(success, replay);
        var recorded = FileServiceWriteFileResponse.Parser.ParseFrom(replay);
        Assert.Equal(created.Meta.CommandId, recorded.Value.Result.CommandId);
        Assert.Equal(created.Meta.CorrelationId, recorded.Meta.CorrelationId);
        Assert.Equal((ulong)body.Length, recorded.Value.Result.SizeBytes);
        Assert.Equal(hash, recorded.Value.Result.Sha256.ToByteArray());
        Assert.Equal("current data must not be overwritten", File.ReadAllText(createdPath));

        var rejected = await ReplayAsync(calls, owner, collision, ct);
        Assert.Equal(conflict, rejected);
        var refused = FileServiceWriteFileResponse.Parser.ParseFrom(rejected).Error;
        Assert.Equal(("expected_absent_conflict", EffectCertainty.DidNotHappen, RetryMode.Never),
            (refused.Details.State.Reason, refused.Effect, refused.Retry.Mode));
        Assert.Equal(collision.Meta.CorrelationId, refused.CorrelationId);
        Assert.Equal("competitor must be left alone", File.ReadAllText(collisionPath));

        var foreign = calls.Relay(Origin.Human);
        Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(await ReplayAsync(calls, foreign, created, ct)).Error.Code);
        var changed = created.Clone();
        changed.Meta.CorrelationId = CommandIds.New();
        Assert.Equal("command_id_reused", FileServiceWriteFileResponse.Parser.ParseFrom(await ReplayAsync(calls, owner, changed, ct)).Error.Code);
        var interruptedCall = await calls.CallAsync(owner, RoutedMethod.WriteNodeFile, interrupted.ToByteArray(), interrupted.Meta.CommandId,
            cancellationToken: ct);
        Assert.Null(interruptedCall.Answer);
        Assert.Equal(FileOperationState.Prepared, Status(node, interrupted, owner).State);

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        Assert.Equal(success, await ReplayAsync(calls, owner, created, ct));
        Assert.Equal(conflict, await ReplayAsync(calls, owner, collision, ct));
        var recovered = Status(node, interrupted, owner);
        Assert.Equal(FileOperationState.Unknown, recovered.State);
        Assert.True(recovered.Held);
        var rawUnknown = await ReplayAsync(calls, owner, interrupted, ct);
        Assert.Equal(recovered.Error, FileServiceWriteFileResponse.Parser.ParseFrom(rawUnknown).Error);
        Assert.Equal((EffectCertainty.Unknown, RetryMode.Never), (recovered.Error.Effect, recovered.Error.Retry.Mode));

        var fresh = Request(workspace.Id, "fresh.txt", body);
        var unknown = FileServiceWriteFileResponse.Parser.ParseFrom(await ReplayAsync(calls, owner, fresh, ct)).Error;
        Assert.Equal((EffectCertainty.Unknown, RetryMode.Never), (unknown.Effect, unknown.Retry.Mode));
        Assert.False(File.Exists(Path.Combine(rootPath, fresh.Path.Path)));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_private_stage_reservation;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_effect_worker;")));
        Assert.Equal(3L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));

        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var ack = await human.Files.AcknowledgeFileOperationAsync(new FileServiceAcknowledgeFileOperationRequest
        {
            Meta = Tasks.Meta(),
            OperationCommandId = interrupted.Meta.CommandId.Clone(),
            OperationDigest = ByteString.CopyFrom(SHA256.HashData(interrupted.ToByteArray())),
        }, cancellationToken: ct);
        Assert.Null(ack.Error);
        Assert.True(ack.Value.Operation.Acknowledged);
        Assert.False(ack.Value.Operation.Held);
        Assert.Equal(FileOperationState.Unknown, ack.Value.Operation.State);
        Assert.Equal(rawUnknown, await ReplayAsync(calls, owner, interrupted, ct));
        Assert.Empty(File.ReadAllBytes(interruptedPath));
        foreach (var database in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var file = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            file.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(body));
        }
    }

    internal static FileServiceWriteFileRequest Request(byte[] workspace, string path, byte[] body) => new()
    {
        Meta = Tasks.Meta(),
        Path = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = path },
        Data = ByteString.CopyFrom(body),
        ExpectedAbsent = true,
    };

    internal static RegisteredWorkspaces.RootIdentity SeedPrepared(StoreTransaction transaction, CenterCaller owner,
        WorkspacePath root, FileServiceWriteFileRequest request)
    {
        var identity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        // These retained records need a stage identity of the same format. No native stage is opened by the fixture or replay.
        var seed = new FileJournalIntent(FileOperationKind.Write,
            request.Meta.CommandId.Value.ToByteArray(), request.Meta.CorrelationId.Value.ToByteArray(), owner,
            request.Path.WorkspaceId.Value.ToByteArray(), request.Path.Path, identity.Platform, identity.Bytes, identity.Bytes,
            null, null, null, null, request.Data.Length, SHA256.HashData(request.Data.Span), identity.Bytes);
        Assert.Equal(FileJournalPreparation.Prepared, FileMutationJournal.Prepare(transaction, seed, request.ToByteArray()));
        return identity;
    }

    internal static async Task<byte[]> ReplayAsync(RoutedCalls calls, CenterCaller caller, FileServiceWriteFileRequest request, CancellationToken ct)
    {
        var answer = (await calls.CallAsync(caller, RoutedMethod.WriteNodeFile, request.ToByteArray(), request.Meta.CommandId,
            cancellationToken: ct)).Answer;
        Assert.NotNull(answer);
        Assert.Equal(RoutedOutcome.Executed, answer.Outcome);
        Assert.NotNull(answer.Response);
        return answer.Response.ToByteArray();
    }

    private static FileOperation Status(InProcessNode node, FileServiceWriteFileRequest request, CenterCaller owner) =>
        Assert.IsType<FileOperation>(node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, request.Meta.CommandId.Value.Span, owner)));
}
