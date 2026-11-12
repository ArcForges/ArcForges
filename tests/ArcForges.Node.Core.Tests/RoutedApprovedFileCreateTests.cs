// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Files;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Native create through a synthetic routed seam and authenticated local HUMAN approval.</summary>
public sealed class RoutedApprovedFileCreateTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ApprovedAbsentCreateIsExclusiveAndUncertainEffectsStayHeld(int scenario)
    {
        if (!OperatingSystem.IsWindows() && scenario != 0)
        {
            Assert.Skip("Windows exclusive-create collision and interruption.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "approved-create")).FullName;
        var target = Path.Combine(root, "new.txt");
        var body = Encoding.UTF8.GetBytes("approved-created-file-49ca");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "new.txt" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
        };
        var raw = request.ToByteArray();
        var dispatched = await calls.CallAsync(actor, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId);
        Assert.NotNull(dispatched.Answer);
        if (!OperatingSystem.IsWindows())
        {
            var failure = FileServiceWriteFileResponse.Parser.ParseFrom(dispatched.Answer.Response);
            Assert.Equal("enforcement_unavailable", failure.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, failure.Error.Effect);
            Assert.False(File.Exists(target));
            return;
        }

        Assert.Equal(RoutedOutcome.RefusedByPolicy, dispatched.Answer.Outcome);
        var refusal = Assert.IsType<ArcError>(dispatched.Answer.Error);
        Assert.Equal("approval_required", refusal.Code);
        var approval = refusal.Details.State.Resource.Id.Clone();
        var handler = calls.Dispatcher.FileHandlerForTests!;
        var rival = Encoding.UTF8.GetBytes("owned-competing-target-2ccd");
        if (scenario == 1) handler.BeforeCreateForTests = () => File.WriteAllBytes(target, rival);
        if (scenario == 2) handler.AfterCreateForTests = () => throw new IOException("owned post-create interruption");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var decided = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
        {
            Meta = InProcessNode.Command(),
            ApprovalId = approval,
            Decision = ApprovalDecisionKind.Approve,
        }, cancellationToken: ct);
        Assert.Null(decided.Error);
        handler.BeforeCreateForTests = null;
        handler.AfterCreateForTests = null;
        var op = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, request.Meta.CommandId.Value.Span, actor))!;
        var replay = await calls.CallAsync(actor, RoutedMethod.WriteNodeFile, raw, request.Meta.CommandId);
        var response = FileServiceWriteFileResponse.Parser.ParseFrom(replay.Answer!.Response);
        if (scenario == 0)
        {
            Assert.Equal(ApprovalState.Executed, decided.Value.Approval.State);
            Assert.Equal(FileOperationState.Completed, op.State);
            Assert.False(op.Held);
            Assert.Null(response.Error);
            Assert.Equal(body, File.ReadAllBytes(target));
            Assert.Equal(SHA256.HashData(body), response.Value.Result.Sha256.ToByteArray());
        }
        else if (scenario == 1)
        {
            Assert.Equal(ApprovalState.Failed, decided.Value.Approval.State);
            Assert.Equal(FileOperationState.Completed, op.State);
            Assert.False(op.Held);
            Assert.Equal("file_changed", response.Error.Code);
            Assert.Equal("expected_absent_conflict", response.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
            Assert.Equal(rival, File.ReadAllBytes(target));
        }
        else
        {
            Assert.Equal(ApprovalState.Failed, decided.Value.Approval.State);
            Assert.Equal(FileOperationState.Unknown, op.State);
            Assert.True(op.Held);
            Assert.Equal("operation_failed", response.Error.Code);
            Assert.Equal(EffectCertainty.Unknown, response.Error.Effect);
            Assert.True(File.Exists(target));
            Assert.Empty(File.ReadAllBytes(target));
            var ack = await human.Files.AcknowledgeFileOperationAsync(new FileServiceAcknowledgeFileOperationRequest
            {
                Meta = InProcessNode.Command(),
                OperationCommandId = request.Meta.CommandId.Clone(),
                OperationDigest = ByteString.CopyFrom(SHA256.HashData(raw)),
            }, cancellationToken: ct);
            Assert.Null(ack.Error);
            Assert.Equal(FileOperationState.Unknown, ack.Value.Operation.State);
            Assert.False(ack.Value.Operation.Held);
            Assert.True(ack.Value.Operation.Acknowledged);
            Assert.Empty(File.ReadAllBytes(target));
        }
        Assert.Equal(request.Meta.CorrelationId, response.Meta.CorrelationId);
        Assert.Equal(SHA256.HashData(raw), op.RequestSha256.ToByteArray());
        var ownershipRows = node.Runtime.Store.Read(r => r.Scalar(
            "SELECT count(*) FROM file_creation_ownership WHERE creation_command_id = $id;",
            ("$id", request.Meta.CommandId.Value.ToByteArray())));
        Assert.Equal(scenario == 0 ? 1L : 0L, ownershipRows);
        if (scenario == 0)
        {
            var recordedCaller = node.Runtime.Store.Read(r => (byte[])r.Scalar(
                "SELECT caller FROM file_creation_ownership WHERE creation_command_id = $id;",
                ("$id", request.Meta.CommandId.Value.ToByteArray()))!);
            Assert.True(ArcForges.Node.Core.Security.CenterRouting.SameFileCaller(actor, CenterCaller.Parser.ParseFrom(recordedCaller)));
        }
    }
}
