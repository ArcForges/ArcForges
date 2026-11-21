// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Retained removal history, routed replay and owner-local decisions through the real Node and FULL SQLite.</summary>
public sealed class FileRemovalQuarantineRoutedTests
{
    // Native changed-tree refusal, managed maintenance lease and managed launch cases remain in this file at
    // executable historical commit eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    private const long CustodyMicroseconds = 24L * 60 * 60 * 1_000_000;

    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ARetainedQuarantinedFileOrTreeReplaysAcrossRestart(bool tree)
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "quarantine-workspace")).FullName;
        var source = Path.Combine(root, "selected");
        var custodyRoot = Directory.CreateDirectory(Path.Combine(node.Root, "completed-quarantine")).FullName;
        var location = Path.Combine(custodyRoot, "selected");
        if (tree) Directory.CreateDirectory(Path.Combine(location, "nested"));
        var file = tree ? Path.Combine(location, "nested", "body") : location;
        File.WriteAllText(file, "retained completed quarantine bytes");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        WorkspaceRemovalSnapshot snapshot;
        using (var workspaceRoot = WorkspacePath.OpenRoot(root))
        using (var retainedRoot = WorkspacePath.OpenRoot(custodyRoot))
        {
            snapshot = WorkspaceRemovalPlan.Capture(retainedRoot, "selected", token) with
            {
                RootIdentity = RegisteredWorkspaces.RootIdentity.Encode(workspaceRoot.RootIdentity),
            };
        }
        var (request, raw, approvalId, receipt) = await SeedRemovalHistory(node, actor, workspace.Id, root, snapshot,
            RemovalHistory.Completed, location, token);
        Assert.NotNull(receipt);
        var replayed = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        Assert.NotNull(replayed.Answer);
        Assert.Equal(RoutedOutcome.Executed, replayed.Answer.Outcome);
        Assert.Equal(receipt, replayed.Answer.Response?.ToByteArray());
        var response = FileServiceExecuteRemovalResponse.Parser.ParseFrom(replayed.Answer.Response);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Null(response.Error);
        Assert.Equal(request.Meta.CorrelationId, response.Meta.CorrelationId);
        Assert.True(response.Value.Result.Quarantined);
        Assert.Equal(tree ? 3u : 1u, response.Value.Result.ItemsRemoved);
        Assert.Equal(snapshot.TotalBytes, response.Value.Result.TotalBytes);
        Assert.False(File.Exists(source));
        Assert.False(Directory.Exists(source));
        Assert.Equal("retained completed quarantine bytes", File.ReadAllText(file));
        void AssertRetainedCustody() => node.Runtime.Store.Read(reader =>
        {
            var planId = request.PlanId.Value.ToByteArray();
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM quarantine_entry;"));
            Assert.Equal(source, reader.Scalar("SELECT original_path FROM quarantine_entry WHERE plan_id = $id;", ("$id", planId)));
            Assert.Equal(location, reader.Scalar("SELECT quarantine_path FROM quarantine_entry WHERE plan_id = $id;", ("$id", planId)));
            Assert.Equal(response.Value.Result.QuarantineId.Value.ToByteArray(), reader.Scalar(
                "SELECT item_id FROM quarantine_entry WHERE plan_id = $id;", ("$id", planId)) as byte[]);
            Assert.Equal(CustodyMicroseconds, reader.Scalar("SELECT purge_at - quarantined_at FROM quarantine_entry WHERE plan_id = $id;", ("$id", planId)));
            Assert.Equal((long)CleanupPlanState.Completed, reader.Scalar("SELECT state FROM cleanup_plan WHERE plan_id = $id;", ("$id", planId)));
            var operation = FileMutationJournal.GetForCaller(reader, request.Meta.CommandId.Value.Span, actor);
            Assert.NotNull(operation);
            Assert.Equal(FileOperationState.Completed, operation.State);
            Assert.Equal(FileOperationKind.Removal, operation.Kind);
            Assert.Equal(response.Value.Result, operation.Removal);
            Assert.False(operation.Held);
            var approval = Approvals.Get(reader, approvalId);
            Assert.Equal(ApprovalState.Executed, approval?.State);
            Assert.Equal(receipt, approval?.Outcome);
            return 0;
        });
        AssertRetainedCustody();

        var changed = request.Clone();
        changed.Meta.CorrelationId = CommandIds.New();
        Assert.Equal("command_id_reused", (await Invoke(calls, actor, changed)).Error.Code);
        var foreign = actor.Clone();
        foreign.LocalSessionId = CommandIds.New();
        Assert.Equal("command_id_reused", (await Invoke(calls, foreign, request)).Error.Code);
        File.WriteAllText(source, "later different object");
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var restarted = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(receipt, restarted.Answer?.Response?.ToByteArray());
        AssertRetainedCustody();
        Assert.Equal("later different object", File.ReadAllText(source));
        Assert.Equal("retained completed quarantine bytes", File.ReadAllText(file));
    }


    [Fact(Timeout = 120_000)]
    public async Task ARecoveredRemovalIntentHoldsUntilItsExactLocalAcknowledgment()
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "unknown-quarantine-workspace")).FullName;
        var source = Path.Combine(root, "selected");
        var custodyRoot = Directory.CreateDirectory(Path.Combine(node.Root, "retained-quarantine")).FullName;
        var location = Path.Combine(custodyRoot, "selected");
        File.WriteAllText(location, "retained quarantine fixture bytes");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        WorkspaceRemovalSnapshot snapshot;
        using (var workspaceRoot = WorkspacePath.OpenRoot(root))
        using (var retainedRoot = WorkspacePath.OpenRoot(custodyRoot))
        {
            // The retained object is placed directly at the recorded destination. No removal is invoked.
            snapshot = WorkspaceRemovalPlan.Capture(retainedRoot, "selected", token) with
            {
                RootIdentity = RegisteredWorkspaces.RootIdentity.Encode(workspaceRoot.RootIdentity),
            };
        }
        var (request, raw, approvalId, _) = await SeedRemovalHistory(node, actor, workspace.Id, root, snapshot,
            RemovalHistory.Interrupted, location, token);
        var id = request.Meta.CommandId.Value.ToByteArray();
        var planId = request.PlanId.Value.ToByteArray();
        Assert.False(File.Exists(source));
        Assert.Equal("retained quarantine fixture bytes", File.ReadAllText(location));
        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(FileOperationState.Prepared, FileMutationJournal.GetForCaller(reader, id, actor)?.State);
            Assert.Equal(3L, reader.Scalar("SELECT state FROM cleanup_plan WHERE plan_id = $id;", ("$id", planId)));
            Assert.Equal(location, FileMutationJournal.RemovalRecoveryLocation(reader, id));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM quarantine_entry;"));
            return 0;
        });
        File.WriteAllText(source, "later object remains");
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var recoveredAnswer = (await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId)).Answer;
        Assert.NotNull(recoveredAnswer);
        Assert.Equal(RoutedOutcome.Executed, recoveredAnswer.Outcome);
        var recoveredBytes = Assert.IsType<ByteString>(recoveredAnswer.Response);
        Assert.Equal(recoveredBytes.ToByteArray(), node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", id))) as byte[]);
        var replay = FileServiceExecuteRemovalResponse.Parser.ParseFrom(recoveredBytes);
        Assert.Equal(EffectCertainty.Unknown, replay.Error.Effect);
        Assert.Equal(RetryMode.Never, replay.Error.Retry.Mode);
        Assert.Equal("file_outcome_unknown", replay.Error.Details.State.Reason);
        Assert.Equal(request.Meta.CorrelationId, replay.Meta.CorrelationId);
        await using var local = await node.ChannelAsync(helloAsHuman: true);
        var get = new FileServiceGetFileOperationRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            OperationCommandId = request.Meta.CommandId.Clone(),
        };
        var shown = await local.Files.GetFileOperationAsync(get, cancellationToken: token);
        Assert.Null(shown.Error);
        Assert.Equal(FileOperationKind.Removal, shown.Value.Operation.Kind);
        Assert.Equal(FileOperationState.Unknown, shown.Value.Operation.State);
        Assert.True(shown.Value.Operation.Held);
        Assert.Contains("arcforges.file-removal.v1:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(location)), shown.Meta.Warnings);
        var ack = new FileServiceAcknowledgeFileOperationRequest
        {
            Meta = InProcessNode.Command(),
            OperationCommandId = request.Meta.CommandId.Clone(),
            OperationDigest = ByteString.CopyFrom(new byte[32]),
        };
        Assert.Equal("digest_mismatch", (await local.Files.AcknowledgeFileOperationAsync(ack, cancellationToken: token)).Error.Code);
        Assert.True(node.Runtime.Store.Read(reader => FileMutationJournal.HasWorkspaceHold(reader, workspace.Id)));
        ack.Meta = InProcessNode.Command();
        ack.OperationDigest = ByteString.CopyFrom(SHA256.HashData(raw));
        var accepted = await local.Files.AcknowledgeFileOperationAsync(ack, cancellationToken: token);
        Assert.Null(accepted.Error);
        Assert.True(accepted.Value.Operation.Acknowledged);
        Assert.False(accepted.Value.Operation.Held);
        Assert.Equal(FileOperationState.Unknown, accepted.Value.Operation.State);
        Assert.Equal(accepted.ToByteArray(), (await local.Files.AcknowledgeFileOperationAsync(ack, cancellationToken: token)).ToByteArray());
        node.Runtime.Store.Read(reader =>
        {
            Assert.False(FileMutationJournal.HasWorkspaceHold(reader, workspace.Id));
            Assert.Equal(5L, reader.Scalar("SELECT state FROM cleanup_plan WHERE plan_id = $id;", ("$id", planId)));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM quarantine_entry;"));
            var approval = Approvals.Get(reader, approvalId);
            Assert.Equal(ApprovalState.Approved, approval?.State);
            Assert.Null(approval?.Outcome);
            return 0;
        });
        var retried = (await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId)).Answer;
        Assert.Equal(recoveredBytes, retried?.Response);
        Assert.Equal("later object remains", File.ReadAllText(source));
        Assert.Equal("retained quarantine fixture bytes", File.ReadAllText(location));
    }

    private enum RemovalHistory { PendingApproval, Interrupted, Completed }

    private static Task<(FileServiceExecuteRemovalRequest Request, byte[] Raw, byte[] ApprovalId, byte[]? Receipt)> SeedRemovalHistory(
        InProcessNode node, CenterCaller caller, byte[] workspace, string root, WorkspaceRemovalSnapshot snapshot, RemovalHistory history,
        string? destination, CancellationToken token) => node.Runtime.Processor.ExecuteAsync(command =>
        {
            var transaction = command.Transaction;
            void Reserve(RequestMeta meta, string method, byte[] digest, string? policyReason = null)
            {
                var id = meta.CommandId.Value.ToByteArray();
                Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id,
                    "arcforges.node.v1.FileService/" + method, digest, Origin.Remote).Status);
                transaction.Execute("INSERT INTO file_removal_command_owner (command_id, caller, policy_reason) VALUES ($id, $caller, $reason);",
                    ("$id", id), ("$caller", caller.ToByteArray()), ("$reason", policyReason));
            }

            var path = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = "selected" };
            var planRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), WorkspacePath = path };
            var planDigest = SHA256.HashData(planRequest.ToByteArray());
            var requester = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = planRequest.Meta.CommandId };
            var plan = FileRemovalPlans.PrepareWorkspace(transaction, planRequest.Meta.CommandId.Value.Span, planDigest,
                caller, requester, path, root, snapshot, transaction.NowMicroseconds, quarantineAvailable: true);
            Reserve(planRequest.Meta, "PlanRemoval", planDigest);
            FileRemovalPlans.RecordWorkspace(transaction, plan);
            var planReceipt = new FileServicePlanRemovalResponse
            {
                Meta = new ResponseMeta { CorrelationId = planRequest.Meta.CorrelationId },
                Value = new FileServicePlanRemovalValue { Plan = plan.Plan },
            };
            Assert.True(NodeShapes.IsValid(planReceipt));
            CommandDeduplication.Complete(transaction, planRequest.Meta.CommandId.Value.Span, planReceipt.ToByteArray());

            var request = Execute(plan.Plan);
            request.DeleteWithoutQuarantine = false;
            var id = request.Meta.CommandId.Value.ToByteArray();
            var planId = request.PlanId.Value.ToByteArray();
            var raw = request.ToByteArray();
            var digest = SHA256.HashData(raw);
            requester.RemoteCommandId = request.Meta.CommandId;
            var (approval, created, error) = Approvals.Raise(command, new ApprovalCapture
            {
                Operation = "FileService.ExecuteRemoval",
                MatrixOperation = PermissionMatrix.FileRemove,
                Summary = "Quarantine the exact selected removal plan",
                Risk = RiskClass.High,
                Requester = requester,
                CommandId = id,
                Request = [2, .. id],
                RequestDigest = digest,
                TargetKind = "cleanup_plan",
                TargetId = planId,
                Details =
                [
                    new KeyValue { Name = "plan_id", Value = Convert.ToHexStringLower(request.PlanId.Value.Span) },
                    new KeyValue { Name = "plan_digest", Value = Convert.ToHexStringLower(request.PlanDigest.Span) },
                    new KeyValue { Name = "correlation_id", Value = Convert.ToHexStringLower(request.Meta.CorrelationId.Value.Span) },
                    new KeyValue { Name = "delete_without_quarantine", Value = "false" },
                ],
            }, Approvals.DefaultTtl);
            Assert.True(created);
            Assert.Null(error);
            Assert.NotNull(approval);
            Assert.Equal(1, transaction.Execute("UPDATE cleanup_plan SET state = 2, approval_id = $approval, rev = rev + 1 WHERE plan_id = $plan AND state = 1;",
                ("$approval", approval.Id), ("$plan", planId)));
            var pending = history == RemovalHistory.PendingApproval;
            Reserve(request.Meta, "ExecuteRemoval", digest, pending ? "approval_required" : null);
            if (pending)
                return (request, raw, approval.Id, (byte[]?)null);

            Assert.NotNull(destination);
            Approvals.Decide(command, approval.Id, approve: true, new ActorRef { Origin = Origin.Human }, null);
            var selected = snapshot.Entries[0];
            Assert.Equal(path.Path, selected.Path);
            FileMutationJournal.PrepareRemoval(transaction, id, request.Meta.CorrelationId.Value.ToByteArray(), digest, caller,
                workspace, null, path.Path, snapshot.RootIdentity, snapshot.RootIdentity, selected.NativeIdentity, planId, destination);
            if (history == RemovalHistory.Interrupted)
                return (request, raw, approval.Id, (byte[]?)null);

            var item = Assert.IsType<byte[]>(transaction.Scalar(
                "SELECT item_id FROM file_removal_plan_item WHERE plan_id = $id AND ordinal = 0;", ("$id", planId)));
            var moved = transaction.NowMicroseconds;
            var purge = checked(moved + CustodyMicroseconds);
            var response = new FileServiceExecuteRemovalResponse
            {
                Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
                Value = new FileServiceExecuteRemovalValue
                {
                    Result = new FileRemovalResult
                    {
                        PlanId = request.PlanId,
                        Quarantined = true,
                        QuarantineId = new Id { Value = ByteString.CopyFrom(item) },
                        ItemsRemoved = checked((uint)snapshot.Entries.Count),
                        TotalBytes = snapshot.TotalBytes,
                        PurgeAfter = ProtoTime.ToInstant(StoreTime.FromMicroseconds(purge)),
                    },
                },
            };
            var receipt = FileMutationJournal.CompleteRemoval(transaction, id, planId, response,
                Path.Combine(root, path.Path), destination, item, purge, moved);
            Assert.Equal(ApprovalState.Executed, Approvals.Executed(command, approval.Id, receipt, error: null, PermissionMatrix.FileRemove)?.State);
            return (request, raw, approval.Id, receipt);
        }, CommitDurability.Full).WaitAsync(token);

    [Fact(Timeout = 120_000)]
    public async Task DenyingAnExactPlanReleasesItsPendingHoldWithoutCreatingAnEffectIntent()
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "denied-quarantine-workspace")).FullName;
        File.WriteAllText(Path.Combine(root, "selected"), "denied body remains");
        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var workspace = manager.RegisterFromVerifiedHuman(root, cancellationToken: token);
        WorkspaceRemovalSnapshot snapshot;
        using (var nativeRoot = WorkspacePath.OpenRoot(root))
            snapshot = WorkspaceRemovalPlan.Capture(nativeRoot, "selected", token);
        var (request, _, approvalId, receipt) = await SeedRemovalHistory(node, actor, workspace.Id, root, snapshot,
            RemovalHistory.PendingApproval, null, token);
        Assert.Null(receipt);
        var command = request.Meta.CommandId.Value.ToByteArray();
        var plan = request.PlanId.Value.ToByteArray();

        void AssertHistory(ApprovalState approvalState, CleanupPlanState planState) => node.Runtime.Store.Read(reader =>
        {
            var approval = Approvals.Get(reader, approvalId);
            Assert.NotNull(approval);
            Assert.Equal(approvalState, approval.State);
            Assert.Null(approval.Outcome);
            Assert.Equal((long)planState, reader.Scalar("SELECT state FROM cleanup_plan WHERE plan_id = $id;", ("$id", plan)));
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM approval;"));
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id AND outcome IS NULL;", ("$id", command)));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM file_operation_journal;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM quarantine_entry;"));
            return 0;
        });

        AssertHistory(ApprovalState.Pending, CleanupPlanState.AwaitingApproval);
        Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.UnregisterFromVerifiedHuman(workspace.Id, token)).Reason);
        var first = await Invoke(calls, actor, request);
        Assert.Equal(("operation_failed", EffectCertainty.Unknown, RetryMode.Never, "file_outcome_unknown"),
            (first.Error.Code, first.Error.Effect, first.Error.Retry.Mode, first.Error.Details.State.Reason));
        AssertHistory(ApprovalState.Pending, CleanupPlanState.AwaitingApproval);

        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var decided = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
        {
            Meta = InProcessNode.Command(),
            ApprovalId = new Id { Value = ByteString.CopyFrom(approvalId) },
            Decision = ApprovalDecisionKind.Deny,
        }, cancellationToken: token);
        Assert.Null(decided.Error);
        Assert.Equal(ApprovalState.Denied, decided.Value.Approval.State);
        AssertHistory(ApprovalState.Denied, CleanupPlanState.Cancelled);
        manager.UnregisterFromVerifiedHuman(workspace.Id, token);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM workspace WHERE workspace_id = $id AND removed_at IS NOT NULL;", ("$id", workspace.Id))));
        var retry = await Invoke(calls, actor, request);
        Assert.Equal(first.ToByteArray(), retry.ToByteArray());
        AssertHistory(ApprovalState.Denied, CleanupPlanState.Cancelled);
        Assert.Equal("denied body remains", File.ReadAllText(Path.Combine(root, "selected")));
    }

    private static FileServiceExecuteRemovalRequest Execute(FileRemovalPlan plan) => new()
    { Meta = Tasks.Meta(), PlanId = plan.PlanId.Clone(), PlanDigest = plan.Digest };

    private static async Task<FileServiceExecuteRemovalResponse> Invoke(RoutedCalls calls, CenterCaller actor, FileServiceExecuteRemovalRequest request)
    {
        var response = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.NotNull(response.Answer);
        return FileServiceExecuteRemovalResponse.Parser.ParseFrom(response.Answer.Response);
    }
}
