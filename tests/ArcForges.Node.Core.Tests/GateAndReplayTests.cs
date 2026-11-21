// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Verifies command replay, approval ownership and current policy gates through the real local handlers and a synthetic routed link.
/// Legacy Task submission and retry use retained SQLite history while Queue and Cancel still exercise their live decisions.
/// </summary>
public sealed class GateAndReplayTests
{
    private const PermissionDecision P = PermissionDecision.Approval;
    private const PermissionDecision D = PermissionDecision.Deny;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// A completed historical Retry approval retains its exact reply after the command window without creating another attempt.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task AnExecutedRetryApprovalReplaysAfterItsCommandWindowWithoutRequeuing()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        var (request, stored, approvalId) = await node.Runtime.Processor.ExecuteAsync(command =>
        {
            var transaction = command.Transaction;
            var requester = new ActorRef { Origin = Origin.Agent, ClientKind = ClientKind.McpAdapter };
            var task = LegacyTaskHistoryFixture.SeedQueued(transaction, requester);
            transaction.Execute("UPDATE task SET state = $state, finished_at = $now WHERE task_id = $task;",
                ("$state", (int)TaskState.Cancelled), ("$now", transaction.NowMicroseconds), ("$task", task.Value.ToByteArray()));
            var retry = new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = task };
            var response = new TaskServiceRetryTaskResponse
            {
                Meta = new() { CorrelationId = retry.Meta.CorrelationId },
                Value = new()
                {
                    Receipt = new Receipt { CommandId = retry.Meta.CommandId, Effect = EffectCertainty.Happened },
                    State = TaskState.Queued,
                    Warnings = { "The task's side effects are unknown: running it again may repeat external effects." },
                },
            };
            var (approval, created, error) = Approvals.Raise(command, new ApprovalCapture
            {
                Operation = "TaskService.RetryTask",
                MatrixOperation = PermissionMatrix.TaskRetry,
                Summary = "retry task " + IdText.Format(task) + " (UNKNOWN)",
                Risk = PermissionMatrix.Find(PermissionMatrix.TaskRetry)!.Risk,
                Requester = requester,
                CommandId = retry.Meta.CommandId.Value.ToByteArray(),
                Request = retry.ToByteArray(),
                RequestDigest = PayloadDigest.Compute(retry),
                TargetKind = "task",
                TargetId = task.Value.ToByteArray(),
            }, Approvals.DefaultTtl);
            Assert.True(created);
            Assert.Null(error);
            Assert.NotNull(approval);
            Approvals.Decide(command, approval.Id, approve: true, new ActorRef { Origin = Origin.Human }, null);
            Assert.Equal(ApprovalState.Executed, Approvals.Executed(command, approval.Id, response.ToByteArray(), null, PermissionMatrix.TaskRetry)?.State);
            RetainCommand(transaction, "RetryTask", retry.Meta.CommandId, retry, response, Origin.Agent);
            return (retry, response, approval.Id);
        }, CommitDurability.Full).WaitAsync(Ct);

        Assert.Equal(stored, await agent.Tasks.RetryTaskAsync(request, cancellationToken: Ct));
        var expiry = ExpireCommand(node, request.Meta.CommandId);
        var retried = request.Clone();
        retried.Meta.CorrelationId = CommandIds.New();
        Assert.Equal(stored, await agent.Tasks.RetryTaskAsync(retried, cancellationToken: Ct));
        retried.TaskId = CommandIds.New();
        Assert.Equal("command_id_reused", (await agent.Tasks.RetryTaskAsync(retried, cancellationToken: Ct)).Error.Code);
        var fresh = new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = request.TaskId };
        AssertLegacyTaskUnknown((await agent.Tasks.RetryTaskAsync(fresh, cancellationToken: Ct)).Error);
        Assert.Equal(TaskState.Cancelled, (await Tasks.GetAsync(human, request.TaskId)).State);
        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM attempt;"));
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM approval;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", fresh.Meta.CommandId.Value.ToByteArray())));
            Assert.Equal(expiry, reader.Scalar("SELECT expires_at FROM command_dedup WHERE command_id = $id;",
                ("$id", request.Meta.CommandId.Value.ToByteArray())));
            var approval = Approvals.Get(reader, approvalId)!;
            Assert.Equal(ApprovalState.Executed, approval.State);
            Assert.Equal(Origin.Agent, approval.View.Requester.Origin);
            Assert.Equal(stored.ToByteArray(), approval.Outcome);
            var audit = AuditLog.Recent(reader);
            const string retryOperation = PermissionMatrix.TaskRetry + " TaskService.RetryTask";
            var raised = Assert.Single(audit, entry => entry.Operation == retryOperation && entry.Decision == P);
            Assert.Equal(("task", Origin.Agent, "approval requested: retry task " + IdText.Format(request.TaskId) + " (UNKNOWN)"),
                (raised.TargetKind, raised.Actor.Origin, raised.Outcome));
            Assert.Equal(request.TaskId.Value.ToByteArray(), raised.TargetId);
            Assert.Equal(approvalId, raised.ApprovalId);
            var executed = Assert.Single(audit, entry => entry.Operation == retryOperation && entry.Outcome == "executed after approval");
            Assert.Equal(("approval", Origin.Agent), (executed.TargetKind, executed.Actor.Origin));
            Assert.Equal(approvalId, executed.TargetId);
            return 0;
        });
    }

    /// <summary>
    /// The gate runs after dedup: a command that already ran answers with its recorded outcome after the matrix changed (no new approval),
    /// while a new command meets the changed matrix; a cancel of a task that already ended answers with its state and raises no approval.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task ARecordedCommandReplaysWithoutTheGateAndANoOpRaisesNoApproval()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        var pause = new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true };
        var first = await script.Queue.PausePoolAsync(pause, cancellationToken: Ct);
        Assert.Null(first.Error);

        // pool.pause becomes an approval for SCRIPT callers.
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.PoolPause,
            Origin = Origin.Script,
            Decision = P,
        }))).Error);
        var replayed = await script.Queue.PausePoolAsync(pause, cancellationToken: Ct);
        Assert.Null(replayed.Error);
        Assert.Equal(first.Value, replayed.Value);
        Assert.Empty((await human.Approvals.ListApprovalsAsync(new ApprovalServiceListApprovalsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Approvals);
        Assert.Equal("approval_required", (await script.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error?.Code);

        // A recovered task owned by a different session can still be cancelled; its subsequent cancel is a no-op.
        var others = node.Runtime.Store.Write(transaction => LegacyTaskHistoryFixture.SeedQueued(transaction,
            new ActorRef { Origin = Origin.Agent, ClientKind = ClientKind.McpAdapter, SessionId = new Id { Value = ByteString.CopyFrom(Sched.SeedSession(transaction)) } }),
            CommitDurability.Full);
        Assert.Equal(TaskState.Cancelled, (await human.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = others }, cancellationToken: Ct)).Value.State);
        var before = (await human.Approvals.ListApprovalsAsync(new ApprovalServiceListApprovalsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Approvals.Count;
        var noOp = await script.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = others }, cancellationToken: Ct);
        Assert.Null(noOp.Error);
        Assert.Equal(TaskState.Cancelled, noOp.Value.State);
        Assert.NotEqual("approval_required", (await script.Tasks.PauseTaskAsync(new TaskServicePauseTaskRequest { Meta = Tasks.Meta(), TaskId = others }, cancellationToken: Ct)).Error?.Code);
        Assert.Equal(before, (await human.Approvals.ListApprovalsAsync(new ApprovalServiceListApprovalsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Approvals.Count);
    }

    /// <summary>
    /// After the 24-hour command window (its record removed here), the approval's stored outcome answers the same method and request under
    /// its command ID, while another request reusing that ID is <c>CONFLICT/command_id_reused</c>.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task TheLongWindowReplayAnswersOnlyTheSameMethodAndRequest()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        var request = new QueueServiceSetParallelismRequest { Meta = Tasks.Meta(), Scope = ParallelismScope.Global, Mode = ParallelismMode.Fixed, Fixed = 4 };
        var id = (await script.Queue.SetParallelismAsync(request, cancellationToken: Ct)).Error!.Details.State.Resource.Id;
        Assert.Equal(ApprovalState.Executed, (await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
        {
            Meta = Tasks.Meta(),
            ApprovalId = id,
            Decision = ApprovalDecisionKind.Approve,
        }, cancellationToken: Ct)).Value.Approval.State);
        await node.Runtime.Processor.ExecuteAsync(context =>
        {
            context.Transaction.Execute("DELETE FROM command_dedup WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()));
            return 0;
        }, CommitDurability.Full);

        var same = await script.Queue.SetParallelismAsync(request, cancellationToken: Ct);
        Assert.Null(same.Error);
        var other = request.Clone();
        other.Fixed = 5;
        Assert.Equal("command_id_reused", (await script.Queue.SetParallelismAsync(other, cancellationToken: Ct)).Error?.Code);
        var otherMethod = new QueueServicePausePoolRequest { Meta = request.Meta.Clone(), All = true };
        Assert.Equal("command_id_reused", (await script.Queue.PausePoolAsync(otherMethod, cancellationToken: Ct)).Error?.Code);
        var policy = (await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Document;
        Assert.Contains(policy.Parallelism, rule => rule.Scope == ParallelismScope.Global && rule.Fixed == 4);
        Assert.DoesNotContain(policy.Parallelism, rule => rule.Fixed == 5);
    }

    /// <summary>
    /// An approval approved while the node stopped before executing it (APPROVED, never EXECUTED) executes once when the node starts again,
    /// under its original command ID, and the requester's retry receives that outcome.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task AnApprovalApprovedBeforeARestartExecutesOnceAfterIt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var request = new QueueServiceSetParallelismRequest { Meta = Tasks.Meta(), Scope = ParallelismScope.Global, Mode = ParallelismMode.Fixed, Fixed = 6 };
        Id id;
        await using (var script = await node.ChannelAsync())
        {
            id = (await script.Queue.SetParallelismAsync(request, cancellationToken: Ct)).Error!.Details.State.Resource.Id;
        }

        // A HUMAN's decision recorded, then the node stops before the request ran.
        await node.Runtime.Processor.ExecuteAsync(context => Approvals.Decide(context, id.Value.Span, approve: true, new ActorRef { Origin = Origin.Human }, "before a restart"),
            CommitDurability.Full);
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();

        await using var human = await node.ChannelAsync(helloAsHuman: true);

        // AF-CTR-05 N2b (the routed GateAndReplay investigation): a timeout names what the approval became and the node's approval events
        // (resume_failed, record_deferred, execute_failed, command.failed), the three paths that leave it APPROVED or FAILED.
        var watch = Stopwatch.StartNew();
        while (node.Runtime.Store.Read(reader => Approvals.Get(reader, id.Value.Span)) is not { State: ApprovalState.Executed })
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(30))
            {
                var now = node.Runtime.Store.Read(reader => Approvals.Get(reader, id.Value.Span));
                var events = Directory.EnumerateFiles(Path.Combine(node.DataRoot, "logs", "node"))
                    .SelectMany(file => File.ReadLines(file))
                    .Where(line => line.Contains("approval", StringComparison.Ordinal) || line.Contains("api.command.failed", StringComparison.Ordinal))
                    .TakeLast(20);
                Assert.Fail($"The approval did not execute after the restart: {now?.View.State} outcome error {Approvals.OutcomeError(now?.Outcome ?? [])?.Code}; "
                    + string.Join(" | ", events));
            }

            await Task.Delay(25, Ct);
        }

        await using (var script = await node.ChannelAsync())
        {
            var retried = await script.Queue.SetParallelismAsync(request, cancellationToken: Ct);
            Assert.Null(retried.Error);
        }

        var policy = (await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value;
        Assert.Single(policy.Document.Parallelism, rule => rule.Scope == ParallelismScope.Global && rule.Fixed == 6);
        var audit = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Where(entry => entry.ApprovalId is { } approval && approval.AsSpan().SequenceEqual(id.Value.Span)).ToList();
        Assert.Single(audit, entry => entry.Outcome == "executed after approval");
        Assert.Single(audit, entry => entry.Outcome.StartsWith("done: set parallelism", StringComparison.Ordinal));
        var revisions = (await human.Policy.ListPolicyRevisionsAsync(new PolicyServiceListPolicyRevisionsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Revisions;
        Assert.Single(revisions, revision => revision.Actor.Origin == Origin.Script);
    }

    /// <summary>
    /// An approved cancel of an ADOPTED task (a recorded adoption, its container gone) is gated and audited as <c>process.terminate</c>: the
    /// request, the decision's execution and the action itself.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task AnApprovedCancelOfAnAdoptedTaskIsAuditedAsProcessTerminate()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var task = await node.Runtime.Processor.ExecuteAsync(context => SeedAdopted(context, nodeId));
        var raised = (await script.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = new Id { Value = ByteString.CopyFrom(task) } },
            cancellationToken: Ct)).Error;
        Assert.Equal("approval_required", raised?.Code);
        var id = raised!.Details.State.Resource.Id;
        Assert.Equal(ApprovalState.Executed, (await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
        {
            Meta = Tasks.Meta(),
            ApprovalId = id,
            Decision = ApprovalDecisionKind.Approve,
        }, cancellationToken: Ct)).Value.Approval.State);
        var audit = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Where(entry => entry.ApprovalId is { } approval && approval.AsSpan().SequenceEqual(id.Value.Span)).ToList();
        const string Terminate = PermissionMatrix.ProcessTerminate + " TaskService.CancelTask";
        Assert.Contains(audit, entry => entry.Operation == Terminate && entry.Decision == P);
        Assert.Contains(audit, entry => entry.Operation == Terminate && entry.Outcome == "executed after approval");
        Assert.Contains(audit, entry => entry.Operation == Terminate && entry.Outcome.StartsWith("done: cancel task", StringComparison.Ordinal));
        Assert.DoesNotContain(audit, entry => entry.Operation.StartsWith(PermissionMatrix.TaskCancelOthers, StringComparison.Ordinal));
    }

    /// <summary>
    /// A historical routed Submit receipt is bound to its requester class and digest. Expiry does not admit another Task or replace that receipt.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task ARoutedSubmitReceiptRequiresOwnershipAndExpiryDoesNotAdmitWork()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        const string program = "historical-fixture-never-starts";
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Title = "historical routed submit",
            WorkingDirectory = node.Root,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { program } } },
        };
        Assert.Equal("local_submission_human_only", (await Tasks.SubmitRawAsync(agent, spec)).Error?.Details.State.Reason);
        AssertLegacyTaskUnknown((await Tasks.SubmitRawAsync(script, spec)).Error);
        AssertLegacyTaskUnknown((await Tasks.SubmitRawAsync(human, spec)).Error);

        var routed = new RoutedCalls(node);
        var owner = RoutedCalls.Session();
        var relayedAgent = routed.Relay(Origin.Agent);
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec };
        var commandId = request.Meta.CommandId.Value.ToByteArray();
        var stored = node.Runtime.Store.Write(transaction =>
        {
            var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = owner, RemoteCommandId = request.Meta.CommandId };
            var taskId = LegacyTaskHistoryFixture.SeedQueued(transaction, actor);
            var storedSpec = spec.ToByteArray();
            transaction.Execute("""
                UPDATE task SET remote_command_id = $command, spec = $spec, spec_digest = $specDigest, title = $title,
                                command_summary = $summary, command_fingerprint = $fingerprint, command_digest = $commandDigest
                WHERE task_id = $task;
                """, ("$command", commandId), ("$spec", storedSpec), ("$specDigest", SHA256.HashData(storedSpec)),
                ("$title", spec.Title), ("$summary", program), ("$fingerprint", CommandText.Fingerprint(spec.Command)),
                ("$commandDigest", CommandText.Digest(spec, [])), ("$task", taskId.Value.ToByteArray()));
            var task = TaskRecords.GetTask(transaction, taskId.Value.Span, full: true);
            Assert.NotNull(task);
            Assert.Equal(spec, task.Spec);
            Assert.NotNull(task.Queue);
            var response = new TaskServiceSubmitTaskResponse
            {
                Meta = new() { CorrelationId = request.Meta.CorrelationId },
                Value = new()
                {
                    Receipt = new Receipt { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened },
                    State = task.State,
                    TaskId = task.TaskId,
                    Queue = task.Queue,
                },
            };
            RetainCommand(transaction, "SubmitTask", request.Meta.CommandId, request, response, Origin.Remote);
            RoutedCommandOwnership.Record(transaction, commandId, actor);
            return response;
        }, CommitDurability.Full);

        var sameOwner = (await routed.SubmitAsync(RoutedCalls.Session(), request)).Answer;
        Assert.NotNull(sameOwner);
        Assert.Equal(RoutedOutcome.Executed, sameOwner.Outcome);
        Assert.Equal(ByteString.CopyFrom(stored.ToByteArray()), sameOwner.Response);
        var changed = request.Clone();
        changed.Spec.Title = "different request";
        Assert.Equal("command_id_reused", (await routed.SubmitAsync(owner, changed)).Response?.Error?.Code);
        Assert.Equal("command_id_reused", (await routed.SubmitAsync(relayedAgent, request)).Response?.Error?.Code);

        var expiry = ExpireCommand(node, request.Meta.CommandId);
        AssertLegacyTaskUnknown((await routed.SubmitAsync(owner, request)).Response?.Error);
        AssertLegacyTaskUnknown((await routed.SubmitAsync(relayedAgent, request)).Response?.Error);
        var fresh = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec };
        AssertLegacyTaskUnknown((await routed.SubmitAsync(relayedAgent, fresh)).Response?.Error);

        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.TaskSubmit,
            Origin = Origin.Remote,
            Decision = D,
        }))).Error);
        var denial = (await routed.SubmitAsync(relayedAgent, fresh)).Answer;
        Assert.NotNull(denial);
        Assert.NotNull(denial.Error);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, denial.Outcome);
        Assert.Equal(("permission_denied", ErrorCategory.Authorization, "permission_override", PermissionMatrix.TaskSubmit),
            (denial.Error.Code, denial.Error.Category, denial.Error.Details.State.Reason, denial.Error.Details.State.State));
        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;", ("$id", commandId)));
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM task;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM attempt;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM approval;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", fresh.Meta.CommandId.Value.ToByteArray())));
            Assert.Equal(stored.ToByteArray(), reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", commandId)) as byte[]);
            Assert.Equal(expiry, reader.Scalar("SELECT expires_at FROM command_dedup WHERE command_id = $id;", ("$id", commandId)));
            var audit = AuditLog.Recent(reader);
            var marker = Assert.Single(audit, entry => entry.TargetKind == RoutedCommandOwnership.TargetKind
                && entry.Actor.RemoteCommandId?.Equals(request.Meta.CommandId) == true);
            Assert.Equal(("routed.command.outcome", "routed command outcome recorded", Origin.Remote),
                (marker.Operation, marker.Outcome, marker.Actor.Origin));
            Assert.Equal(owner, marker.Actor.CenterCaller);
            Assert.Null(marker.TargetId);
            var refused = Assert.Single(audit, entry => entry.Operation == PermissionMatrix.TaskSubmit + " TaskService.SubmitTask"
                && entry.Decision == D && entry.Actor.RemoteCommandId?.Equals(fresh.Meta.CommandId) == true);
            Assert.Equal(("denied: permission_override", Origin.Remote, ClientKind.Unspecified),
                (refused.Outcome, refused.Actor.Origin, refused.Actor.ClientKind));
            Assert.Equal(relayedAgent, refused.Actor.CenterCaller);
            Assert.Null(refused.TargetId);
            return 0;
        });
    }

    private static void RetainCommand(StoreTransaction transaction, string method, Id id, IMessage request, IMessage outcome, Origin origin)
    {
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id.Value.Span,
            "arcforges.node.v1.TaskService/" + method, PayloadDigest.Compute(request), origin).Status);
        CommandDeduplication.Complete(transaction, id.Value.Span, outcome.ToByteArray());
    }

    private static long ExpireCommand(InProcessNode node, Id commandId) => node.Runtime.Store.Write(transaction =>
    {
        var expiry = transaction.NowMicroseconds - 1;
        Assert.Equal(1, transaction.Execute("UPDATE command_dedup SET expires_at = $expires WHERE command_id = $id;",
            ("$expires", expiry), ("$id", commandId.Value.ToByteArray())));
        return expiry;
    }, CommitDurability.Full);

    private static void AssertLegacyTaskUnknown(ArcError? error)
    {
        Assert.NotNull(error);
        Assert.Equal((ErrorCategory.Execution, "operation_failed", "LEGACY_DRAIN", "legacy_task_outcome_unavailable",
                EffectCertainty.Unknown, RetryMode.Never),
            (error.Category, error.Code, error.Details.State.State, error.Details.State.Reason, error.Effect, error.Retry.Mode));
    }

    /// <summary>
    /// 11 section 1 (review round 1): the client-image test hook applies only in test mode on an isolated test node, where the endpoint, the
    /// configuration file and the data root are all overridden; on the user's real endpoint, configuration or data root it is ignored.
    /// </summary>
    [Fact]
    public void TheClientImageTestHookAppliesOnlyToAnIsolatedTestNode()
    {
        var root = Path.Combine(Path.GetTempPath(), "arcforges-isolated");
        var endpoint = OperatingSystem.IsWindows() ? "af-test-pipe" : Path.Combine(root, "node.sock");
        var config = Path.Combine(root, "config", "node.json");
        var data = Path.Combine(root, "data");
        var realRoot = NodeLocations.DefaultDataRoot();
        var realEndpoint = NodeLocations.Endpoint(testMode: false, realRoot).Address;
        var realConfig = NodeLocations.ConfigFile(testMode: false);
        Assert.True(ClientImages.TestHookApplies(testMode: true, endpoint, config, data));
        Assert.False(ClientImages.TestHookApplies(testMode: false, endpoint, config, data));
        Assert.False(ClientImages.TestHookApplies(testMode: true, realEndpoint, config, data));
        Assert.False(ClientImages.TestHookApplies(testMode: true, endpoint, realConfig, data));
        Assert.False(ClientImages.TestHookApplies(testMode: true, endpoint, config, realRoot));
    }

    /// <summary>A recorded ADOPTED task and attempt (the rows <c>Adoptions.Record</c> writes) whose container no longer exists.</summary>
    internal static byte[] SeedAdopted(CommandContext context, byte[] nodeId)
    {
        var transaction = context.Transaction;
        var taskId = StoreIds.NewUuid7(transaction.Clock);
        var attemptId = StoreIds.NewUuid7(transaction.Clock);
        var spec = new TaskSpec { Kind = TaskKind.Adopted, Title = "adopted (test)", Pool = "default", Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "sleep" } } } };
        var specBytes = spec.ToByteArray();
        var now = transaction.NowMicroseconds;
        transaction.Execute(
            """
            INSERT INTO task (task_id, state, state_reason, kind, title, command_summary, spec, env_digest, spec_digest, owner, owner_origin, owner_session_id,
                              workspace_id, pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint, command_digest, created_at,
                              queued_at, started_at, current_attempt_id, attempt_count, pinned, labels_json, rev)
            VALUES ($id, 4, 'adopted', 3, 'adopted (test)', 'sleep', $spec, NULL, $specDigest, $owner, 1, NULL, NULL, 'default', 3, 3, 4, 1, 'adopted:sleep', $digest,
                    $now, NULL, $now, $attempt, 1, 0, '{}', 0);
            """,
            ("$id", taskId), ("$spec", specBytes), ("$specDigest", System.Security.Cryptography.SHA256.HashData(specBytes)),
            ("$owner", new ActorRef { Origin = Origin.Human }.ToByteArray()), ("$digest", System.Security.Cryptography.SHA256.HashData(taskId)), ("$now", now), ("$attempt", attemptId));
        transaction.Execute(
            """
            INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, container_name, root_pid, root_start, boot_identity,
                                 request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source, accounted_mem_bytes,
                                 unenforced, created_at, started_at, detail, rev)
            VALUES ($id, $task, 1, 4, 4, $node, 'arcforges-x-gone.scope', 1, $now, 'test', 1, 1, 0, 4, 1, 0, $now, $now, 'adopted (test)', 0);
            """,
            ("$id", attemptId), ("$task", taskId), ("$node", nodeId), ("$now", now));
        return taskId;
    }
}
