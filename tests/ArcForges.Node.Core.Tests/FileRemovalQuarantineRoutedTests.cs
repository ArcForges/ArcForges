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

/// <summary>Actual Node, native rename and FULL SQLite. Actors/secret custody are isolated test substitutes.</summary>
public sealed class FileRemovalQuarantineRoutedTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AFileOrTreeIsQuarantinedAfterRealLocalApprovalAndReplaysAcrossRestart(bool tree)
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "quarantine-workspace")).FullName;
        var source = Path.Combine(root, "selected");
        if (tree) Directory.CreateDirectory(Path.Combine(source, "nested"));
        var file = tree ? Path.Combine(source, "nested", "body") : source;
        File.WriteAllText(file, "actual-owned-quarantine-bytes");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        var plan = await Plan(calls, actor, workspace.Id);
        Assert.True(plan.QuarantineAvailable);
        Assert.True(plan.RequiresApproval);
        var request = Execute(plan);
        var raw = request.ToByteArray();
        var initial = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.NotNull(initial.Answer);
        Assert.Null(initial.Answer.Response);
        var approvalError = Assert.IsType<ArcError>(initial.Answer.Error);
        Assert.Equal("approval_required", approvalError.Code);
        Assert.True(File.Exists(file));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        var approvalId = approvalError.Details.State.Resource.Id.Clone();
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            var decided = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
            {
                Meta = InProcessNode.Command(),
                ApprovalId = approvalId,
                Decision = ApprovalDecisionKind.Approve,
            }, cancellationToken: token);
            Assert.Null(decided.Error);
            Assert.Null(decided.Value.Approval.OutcomeError);
            Assert.Equal(ApprovalState.Executed, decided.Value.Approval.State);
        }
        var replayed = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        var response = FileServiceExecuteRemovalResponse.Parser.ParseFrom(replayed.Answer!.Response);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Null(response.Error);
        Assert.True(response.Value.Result.Quarantined);
        Assert.Equal(tree ? 3u : 1u, response.Value.Result.ItemsRemoved);
        Assert.False(File.Exists(source));
        Assert.False(Directory.Exists(source));
        var location = node.Runtime.Store.Read(r => (string)r.Scalar("SELECT quarantine_path FROM quarantine_entry;")!);
        Assert.Equal("actual-owned-quarantine-bytes", File.ReadAllText(tree ? Path.Combine(location, "nested", "body") : location));
        Assert.Equal(24L * 60 * 60 * 1_000_000, node.Runtime.Store.Read(r => r.Scalar("SELECT purge_at - quarantined_at FROM quarantine_entry;")));
        Assert.Equal(4L, node.Runtime.Store.Read(r => r.Scalar("SELECT state FROM cleanup_plan;")));
        var operation = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, request.Meta.CommandId.Value.Span, actor));
        Assert.NotNull(operation);
        Assert.Equal(FileOperationState.Completed, operation.State);
        Assert.Equal(FileOperationKind.Removal, operation.Kind);
        Assert.Equal(response.Value.Result, operation.Removal);
        Assert.False(operation.Held);
        var receipt = replayed.Answer.Response;
        File.WriteAllText(source, "later different object");
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var restarted = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(receipt, restarted.Answer!.Response);
        Assert.Equal("later different object", File.ReadAllText(source));
        Assert.Equal("actual-owned-quarantine-bytes", File.ReadAllText(tree ? Path.Combine(location, "nested", "body") : location));
    }

    [Fact(Timeout = 120_000)]
    public async Task ChangedTreeAfterApprovalRequestIsRefusedBeforeAnyMove()
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "changed-quarantine-workspace")).FullName;
        var source = Directory.CreateDirectory(Path.Combine(root, "selected")).FullName;
        File.WriteAllText(Path.Combine(source, "body"), "original unchanged");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        var plan = await Plan(calls, actor, workspace.Id);
        var request = Execute(plan);
        var initial = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.NotNull(initial.Answer);
        Assert.Null(initial.Answer.Response);
        var approvalError = Assert.IsType<ArcError>(initial.Answer.Error);
        Assert.Equal("approval_required", approvalError.Code);
        File.WriteAllText(Path.Combine(source, "new-child"), "new child unchanged");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var decided = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
        {
            Meta = InProcessNode.Command(),
            ApprovalId = approvalError.Details.State.Resource.Id.Clone(),
            Decision = ApprovalDecisionKind.Approve,
        }, cancellationToken: token);
        Assert.Null(decided.Error);
        Assert.Equal(ApprovalState.Failed, decided.Value.Approval.State);
        var response = await Invoke(calls, actor, request);
        Assert.Equal("file_changed", response.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal("original unchanged", File.ReadAllText(Path.Combine(source, "body")));
        Assert.Equal("new child unchanged", File.ReadAllText(Path.Combine(source, "new-child")));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM quarantine_entry;")));
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
        var (request, raw, approvalId) = await SeedInterruptedRemoval(node, actor, workspace.Id, root, location, snapshot, token);
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

    private static Task<(FileServiceExecuteRemovalRequest Request, byte[] Raw, byte[] ApprovalId)> SeedInterruptedRemoval(
        InProcessNode node, CenterCaller caller, byte[] workspace, string root, string destination, WorkspaceRemovalSnapshot snapshot,
        CancellationToken token) => node.Runtime.Processor.ExecuteAsync(command =>
        {
            var transaction = command.Transaction;
            void Reserve(RequestMeta meta, string method, byte[] digest)
            {
                var id = meta.CommandId.Value.ToByteArray();
                Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id,
                    "arcforges.node.v1.FileService/" + method, digest, Origin.Remote).Status);
                transaction.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);",
                    ("$id", id), ("$caller", caller.ToByteArray()));
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
            Approvals.Decide(command, approval.Id, approve: true, new ActorRef { Origin = Origin.Human }, null);
            Reserve(request.Meta, "ExecuteRemoval", digest);
            FileMutationJournal.PrepareRemoval(transaction, id, request.Meta.CorrelationId.Value.ToByteArray(), digest, caller,
                workspace, null, path.Path, snapshot.RootIdentity, snapshot.RootIdentity, Assert.Single(snapshot.Entries).NativeIdentity, planId, destination);
            return (request, raw, approval.Id);
        }, CommitDurability.Full).WaitAsync(token);

    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OnlyANativelyRelatedManagedMaintenanceLeaseBlocksTheApprovedTree(bool related)
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "lease-quarantine-workspace")).FullName;
        var source = Directory.CreateDirectory(Path.Combine(root, "selected")).FullName;
        var child = Directory.CreateDirectory(Path.Combine(source, "cache")).FullName;
        File.WriteAllText(Path.Combine(child, "body"), "managed use bytes");
        var unrelated = Directory.CreateDirectory(Path.Combine(node.Root, "unrelated-cache")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        // Isolated persistent managed-reference metadata, not a fabricated creation ownership record or external holder.
        node.Runtime.Store.Write(tx => tx.Execute("""
            INSERT INTO cache_instance (cache_id, kind, path, compat_key, maintenance_lease_holder, rev)
            VALUES ($id, 'cleanup-fixture', $path, 'one', $holder, 0);
            """, ("$id", CommandIds.New().Value.ToByteArray()), ("$path", related ? child : unrelated),
            ("$holder", CommandIds.New().Value.ToByteArray())), CommitDurability.Full);
        var plan = await Plan(calls, actor, workspace.Id);
        var request = Execute(plan);
        var pending = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.Equal("approval_required", pending.Answer!.Error!.Code);
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var decision = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
        {
            Meta = InProcessNode.Command(),
            ApprovalId = pending.Answer!.Error!.Details.State.Resource.Id.Clone(),
            Decision = ApprovalDecisionKind.Approve,
        }, cancellationToken: token);
        Assert.Null(decision.Error);
        TestContext.Current.TestOutputHelper?.WriteLine($"managed-maintenance related={related}; approval={decision.Value.Approval.State}; outcome={decision.Value.Approval.OutcomeError}");
        var result = await Invoke(calls, actor, request);
        if (related)
        {
            Assert.Equal(ApprovalState.Failed, decision.Value.Approval.State);
            Assert.Equal("in_use", result.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, result.Error.Effect);
            Assert.Equal("managed use bytes", File.ReadAllText(Path.Combine(child, "body")));
            Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
            Assert.Equal(7L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan;")));
        }
        else
        {
            Assert.Null(decision.Value.Approval.OutcomeError);
            Assert.Equal(ApprovalState.Executed, decision.Value.Approval.State);
            Assert.Null(result.Error);
            Assert.True(result.Value.Result.Quarantined);
            Assert.False(Directory.Exists(source));
            Assert.True(Directory.Exists(unrelated));
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task DenyingAnExactPlanReleasesItsPendingHoldWithoutCreatingAnEffectIntent()
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "denied-quarantine-workspace")).FullName;
        File.WriteAllText(Path.Combine(root, "selected"), "denied body remains");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        var request = Execute(await Plan(calls, actor, workspace.Id));
        var first = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        var repeated = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, repeated.Answer!.Outcome);
        Assert.Equal(first.Answer!.Error!.Details.State.Resource.Id, repeated.Answer!.Error!.Details.State.Resource.Id);
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var decided = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
        {
            Meta = InProcessNode.Command(),
            ApprovalId = first.Answer.Error.Details.State.Resource.Id.Clone(),
            Decision = ApprovalDecisionKind.Deny,
        }, cancellationToken: token);
        Assert.Null(decided.Error);
        Assert.Equal(ApprovalState.Denied, decided.Value.Approval.State);
        Assert.Equal(7L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan;")));
        var retry = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, retry.Answer!.Outcome);
        Assert.Equal("permission_denied", retry.Answer!.Error!.Code);
        Assert.Equal("denied body remains", File.ReadAllText(Path.Combine(root, "selected")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }


    [Fact(Timeout = 120_000)]
    public async Task ManagedLaunchWaitsForCleanupCoordinationAndItsLiveWorkspaceUseThenRefusesRemoval()
    {
        Sched.RequirePlatform();
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Script);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "live-use-workspace")).FullName;
        File.WriteAllText(Path.Combine(root, "selected"), "owned child workspace bytes");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var marker = Path.Combine(node.Root, "cleanup-admission-marker");
        Id task;
        // Exercise the exact same gate held by ExecuteRemoval, with a real accepted task and native child.
        using (await node.Runtime.Execution!.CoordinateFileCleanupAsync(token))
        {
            task = await Tasks.SubmitAsync(human, Sched.Hold(root, marker, 30_000));
            Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt WHERE task_id = $task;",
                ("$task", task.Value.ToByteArray()))));
        }
        await Tasks.RunningAsync(human, task);
        try
        {
            await Tasks.WaitForAsync(() => Sched.ReadyAt(marker) > 0, Tasks.Bound, "the managed native child to enter its hold");
            var request = Execute(await Plan(calls, actor, workspace.Id));
            var pending = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
            Assert.Equal("approval_required", pending.Answer!.Error?.Code);
            var decision = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
            {
                Meta = InProcessNode.Command(),
                ApprovalId = pending.Answer!.Error!.Details.State.Resource.Id.Clone(),
                Decision = ApprovalDecisionKind.Approve,
            }, cancellationToken: token);
            Assert.Null(decision.Error);
            Assert.Equal(ApprovalState.Failed, decision.Value.Approval.State);
            var refused = await Invoke(calls, actor, request);
            Assert.Equal("in_use", refused.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, refused.Error.Effect);
            Assert.Equal("owned child workspace bytes", File.ReadAllText(Path.Combine(root, "selected")));
            Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        }
        finally
        {
            await Sched.CancelAsync(human, task);
        }
    }

    private static async Task<FileRemovalPlan> Plan(RoutedCalls calls, CenterCaller actor, byte[] workspace)
    {
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = "selected" },
        };
        var answer = await calls.CallAsync(actor, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(answer.Answer!.Response);
        Assert.Null(response.Error);
        return response.Value.Plan;
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
