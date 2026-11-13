// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual SQLite and native retained stages; approval decisions here are synthetic, not local RPC.</summary>
public sealed class FileApprovedRefusalTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(0, "permission_denied")]
    [InlineData(1, "invalid_state")]
    [InlineData(2, "enforcement_unavailable")]
    [InlineData(3, "file_changed")]
    public async Task KnownPreEffectRefusalIsBoundAuditedAndReplayable(int reasonCode, string code)
    {
        var reason = (ApprovedFileRefusal)reasonCode;
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var foreign = calls.Relay(Origin.Agent);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "approved-refusal")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        var body = Encoding.UTF8.GetBytes("private-approved-refusal-b108");
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
        };
        var raw = request.ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        var hash = SHA256.HashData(body);
        var spec = new PrivateStageSpec(2, Path.Combine(directory, "stage"), body.Length, hash);
        Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
            node.Runtime.FileStages, FileOperationKind.Write, id, workspace.Id, request.Meta.CorrelationId.Value.Span, caller, raw, [spec]),
            CommitDurability.Full));
        using var root = WorkspacePath.OpenRoot(directory);
        RegisteredWorkspaces.RootIdentity stageIdentity;
        using (var stage = await PrivateStageProducer.CreateBoundAsync(node.Runtime.Processor, id, 2, root, root, "stage", ct))
        {
            stageIdentity = stage.Identity;
            PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2, caller, raw, stage, body, ct);
        }
        var rootIdentity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var intent = new FileJournalIntent(FileOperationKind.Write, id, request.Meta.CorrelationId.Value.ToByteArray(),
            caller, workspace.Id, "target", rootIdentity.Platform, rootIdentity.Bytes, rootIdentity.Bytes,
            null, null, null, null, body.Length, hash, stageIdentity.Bytes);
        var requester = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId.Clone() };
        var approval = await node.Runtime.Processor.ExecuteAsync(command => PrivateStageApproval.Raise(command, intent, raw,
            requester, root, target: null, TimeSpan.FromHours(1), ct), CommitDurability.Full);
        var approvalId = approval.Approval!.Id;
        await node.Runtime.Processor.ExecuteAsync(command => Approvals.Decide(command, approvalId, approve: true,
            new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli }, comment: null), CommitDurability.Full);

        Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(t =>
            FileMutationJournal.RecordApprovedPreEffectRefusal(t, CommandIds.New().Value.Span, reason), CommitDurability.Full));
        var outcome = node.Runtime.Store.Write(t => FileMutationJournal.RecordApprovedPreEffectRefusal(t, approvalId, reason),
            CommitDurability.Full);
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(outcome);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Equal(code, response.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(request.Meta.CorrelationId, response.Meta.CorrelationId);
        Assert.Equal(request.Meta.CorrelationId, response.Error.CorrelationId);
        Assert.Equal(outcome, node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, FileOperationKind.Write, id, caller, raw)));
        Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, FileOperationKind.Write, id, foreign, raw)));
        var changed = request.Clone();
        changed.Meta.CorrelationId = CommandIds.New();
        Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, FileOperationKind.Write, id, caller, changed.ToByteArray())));
        var recorded = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller))!;
        Assert.Equal(FileOperationState.Completed, recorded.State);
        Assert.False(recorded.Held);
        Assert.Equal(SHA256.HashData(raw), recorded.RequestSha256.ToByteArray());
        Assert.Equal((0, (long)body.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Single(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
        Assert.False(File.Exists(Path.Combine(directory, "target")));
        Assert.Equal(body, File.ReadAllBytes(Path.Combine(directory, "stage")));
        Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write(t =>
            FileMutationJournal.RecordApprovedPreEffectRefusal(t, approvalId, reason), CommitDurability.Full));

        foreach (var path in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(path)) continue;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(body));
        }
    }
}
