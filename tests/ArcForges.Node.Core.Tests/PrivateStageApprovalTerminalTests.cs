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

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual local HUMAN approval service with a synthetic routed requester and native private stage.</summary>
public sealed class PrivateStageApprovalTerminalTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task TerminalDecisionsReleaseOnlyTheActiveSlotAndLiveApprovalsRemain(int scenario)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var caller = new RoutedCalls(node).Relay(Origin.Script);
        var directory = Directory.CreateDirectory(Path.Combine(node.Root, "approval-terminal")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(directory, cancellationToken: ct);
        var body = Encoding.UTF8.GetBytes("terminal-approval-body-63ac");
        var request = new FileServiceWriteFileRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
        };
        var raw = request.ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        var digest = SHA256.HashData(body);
        var spec = new PrivateStageSpec(2, Path.Combine(directory, "stage"), body.Length, digest);
        Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t,
            node.Runtime.FileStages, FileOperationKind.Write, id, workspace.Id, request.Meta.CorrelationId.Value.Span, caller, raw, [spec]),
            CommitDurability.Full));
        byte[] approvalId;
        using (var root = WorkspacePath.OpenRoot(directory))
        {
            RegisteredWorkspaces.RootIdentity stageId;
            using (var stage = await PrivateStageProducer.CreateBoundAsync(node.Runtime.Processor, id, 2, root, root, "stage", ct))
            {
                stageId = stage.Identity;
                PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2, caller, raw, stage, body, ct);
            }
            var identity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            var intent = new FileJournalIntent(FileOperationKind.Write, id, request.Meta.CorrelationId.Value.ToByteArray(),
                caller, workspace.Id, "target", identity.Platform, identity.Bytes, identity.Bytes, null, null, null, null,
                body.Length, digest, stageId.Bytes);
            var requester = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId.Clone() };
            var raised = await node.Runtime.Processor.ExecuteAsync(command => PrivateStageApproval.Raise(command, intent, raw,
                requester, root, target: null, TimeSpan.FromHours(1), ct), CommitDurability.Full);
            approvalId = raised.Approval!.Id;
        }

        Assert.Equal(0, node.Runtime.Store.Write(PrivateStageTerminal.RecoverUnraised, CommitDurability.Full));
        Assert.Equal(0, node.Runtime.Store.Write(PrivateStageTerminal.RecoverTerminalApprovals, CommitDurability.Full));
        if (scenario == 3)
        {
            Assert.Equal(0, await node.StopAsync());
            await node.StartAsync();
            Assert.Equal(ApprovalState.Pending, node.Runtime.Store.Read(r => Approvals.Get(r, approvalId))!.State);
            Assert.Equal((1, (long)body.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
            Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller)));
            Assert.False(File.Exists(Path.Combine(directory, "target")));
            return;
        }
        if (scenario == 4)
        {
            // Synthetic decision holds APPROVED without invoking its worker, to test its recovery exclusion.
            await node.Runtime.Processor.ExecuteAsync(command => Approvals.Decide(command, approvalId, approve: true,
                new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli }, comment: null), CommitDurability.Full);
            Assert.Equal(0, node.Runtime.Store.Write(PrivateStageTerminal.RecoverUnraised, CommitDurability.Full));
            Assert.Equal(0, node.Runtime.Store.Write(PrivateStageTerminal.RecoverTerminalApprovals, CommitDurability.Full));
            Assert.Equal((1, (long)body.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
            Assert.Null(node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller)));
            Assert.False(File.Exists(Path.Combine(directory, "target")));
            return;
        }

        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var approval = new Id { Value = ByteString.CopyFrom(approvalId) };
        if (scenario == 0)
        {
            var decision = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
            {
                Meta = InProcessNode.Command(),
                ApprovalId = approval,
                Decision = ApprovalDecisionKind.Deny,
            }, cancellationToken: ct);
            Assert.Null(decision.Error);
            Assert.Equal(ApprovalState.Denied, decision.Value.Approval.State);
        }
        else if (scenario == 1)
        {
            var cancel = await human.Approvals.CancelApprovalAsync(new ApprovalServiceCancelApprovalRequest
            {
                Meta = InProcessNode.Command(),
                ApprovalId = approval,
            }, cancellationToken: ct);
            Assert.Null(cancel.Error);
            Assert.Equal(ApprovalState.Cancelled, cancel.Value.Approval.State);
        }
        else
        {
            // Test-owned expired approval metadata exercises the actual expiration path, not an elapsed-time claim.
            node.Runtime.Store.Write(t => t.Execute("UPDATE approval SET expires_at = $past WHERE approval_id = $id;",
                ("$past", t.NowMicroseconds - 1), ("$id", approvalId)), CommitDurability.Full);
            var expired = await human.Approvals.GetApprovalAsync(new ApprovalServiceGetApprovalRequest { ApprovalId = approval }, cancellationToken: ct);
            Assert.Null(expired.Error);
            Assert.Equal(ApprovalState.Expired, expired.Value.Approval.State);
        }

        var operation = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, id, caller))!;
        Assert.Equal(FileOperationState.Completed, operation.State);
        Assert.False(operation.Held);
        Assert.False(operation.Acknowledged);
        Assert.Equal(scenario == 2 ? "invalid_state" : "permission_denied", operation.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, operation.Error.Effect);
        Assert.Equal(SHA256.HashData(raw), operation.RequestSha256.ToByteArray());
        Assert.Equal((0, (long)body.Length), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Single(node.Runtime.Store.Read(PrivateStageRegistry.LoadIdentities));
        Assert.Equal(body, File.ReadAllBytes(Path.Combine(directory, "stage")));
        Assert.False(File.Exists(Path.Combine(directory, "target")));
        Assert.NotNull(node.Runtime.Store.Read(r => FileMutationJournal.Replay(r, FileOperationKind.Write, id, caller, raw)));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }
}
