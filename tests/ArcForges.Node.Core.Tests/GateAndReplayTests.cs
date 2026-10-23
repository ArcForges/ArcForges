// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// AF-SEC-01 review round 1: the permission gate against the command record and the matrix's per-target rules, on real nodes in the test
/// process through the real client. <c>task.retry</c> (an AGENT's retry of a SIDE_EFFECTING or UNKNOWN task needs approval); the gate runs
/// after dedup (a command that ran answers with its outcome whatever the matrix says now; a no-op raises no approval); the long-window
/// replay of an approval's outcome answers only the same method and request; an approval approved before a restart executes once after it;
/// an approved cancel of an ADOPTED task is audited as <c>process.terminate</c>; AGENT submissions follow
/// <c>agents.allowed_command_patterns</c>; the client-image test hook applies only to an isolated test node.
/// </summary>
public sealed class GateAndReplayTests
{
    private const PermissionDecision A = PermissionDecision.Allow;
    private const PermissionDecision P = PermissionDecision.Approval;
    private const PermissionDecision D = PermissionDecision.Deny;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// <c>task.retry</c> (tasks.proto <c>RetryTask</c>): HUMAN and SCRIPT retry any task; an AGENT retries an IDEMPOTENT task at once, while its
    /// retry of an UNKNOWN (or SIDE_EFFECTING) task raises an approval; each retry is audited under <c>task.retry</c>.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task RetryNeedsApprovalOnlyForAnAgentOnASideEffectingOrUnknownTask()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        async Task<Id> CancelledAsync(SideEffectClass sideEffect)
        {
            var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
            spec.SideEffect = sideEffect;
            var id = await Tasks.SubmitAsync(script, spec);
            Assert.Equal(TaskState.Cancelled, (await script.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id }, cancellationToken: Ct)).Value.State);
            return id;
        }

        static TaskServiceRetryTaskRequest Retry(Id id) => new() { Meta = Tasks.Meta(), TaskId = id };
        var unknown = await CancelledAsync(SideEffectClass.Unknown);
        var sideEffecting = await CancelledAsync(SideEffectClass.SideEffecting);
        var idempotent = await CancelledAsync(SideEffectClass.Idempotent);

        var raised = (await agent.Tasks.RetryTaskAsync(Retry(unknown), cancellationToken: Ct)).Error;
        Assert.Equal("approval_required", raised?.Code);
        Assert.Equal("approval_required", (await agent.Tasks.RetryTaskAsync(Retry(sideEffecting), cancellationToken: Ct)).Error?.Code);
        Assert.Null((await agent.Tasks.RetryTaskAsync(Retry(idempotent), cancellationToken: Ct)).Error);
        Assert.Null((await script.Tasks.RetryTaskAsync(Retry(unknown), cancellationToken: Ct)).Error);
        Assert.Null((await human.Tasks.RetryTaskAsync(Retry(sideEffecting), cancellationToken: Ct)).Error);
        Assert.Equal((A, A, A), (PermissionMatrix.Decide(Origin.Human, PermissionMatrix.TaskRetry, []).Decision,
            PermissionMatrix.Decide(Origin.Script, PermissionMatrix.TaskRetry, []).Decision, PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.TaskRetry, []).Decision));

        var audit = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Where(entry => entry.Operation == PermissionMatrix.TaskRetry + " TaskService.RetryTask").ToList();
        Assert.Equal(2, audit.Count(entry => entry.Decision == P && entry.Actor.Origin == Origin.Agent));
        Assert.Contains(audit, entry => entry.Decision == A && entry.Actor.Origin == Origin.Agent && entry.Outcome.StartsWith("done: retry task", StringComparison.Ordinal));
        Assert.Contains(audit, entry => entry.Decision == A && entry.Actor.Origin == Origin.Script);
        Assert.Contains(audit, entry => entry.Decision == A && entry.Actor.Origin == Origin.Human);
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

        // A task another owner's session owns, cancelled by a HUMAN; a SCRIPT cancel of it now changes nothing and raises no approval.
        byte[] session = [];
        node.Runtime.Store.Write(transaction => session = Sched.SeedSession(transaction));
        var others = await Sched.SubmitAsSessionAsync(node, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100"), session);
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
        await Tasks.WaitForAsync(() => node.Runtime.Store.Read(reader => Approvals.Get(reader, id.Value.Span))?.View.State == ApprovalState.Executed,
            TimeSpan.FromSeconds(30), "the approval to execute after the restart");
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
    /// 11 section 1, "Submit task (own)": an AGENT submission whose command line matches none of <c>agents.allowed_command_patterns</c> is
    /// <c>AUTHORIZATION/command_pattern_denied</c> (audited); a matching one is accepted; SCRIPT and HUMAN callers are not filtered; the
    /// default (<c>[".*"]</c>) allows every command.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task AgentSubmissionsFollowTheAllowedCommandPatterns()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        Assert.True(node.Runtime.Execution!.Settings.AgentCommandAllowed("anything at all\nover two lines"), "The default allows every command.");
        var hold = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
        var other = Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "100");
        Assert.Null((await Tasks.SubmitRawAsync(agent, other)).Error);

        Assert.Null((await Sched.ChangePolicyAsync(human, policy =>
        {
            policy.Agents.AllowedCommandPatterns.Clear();
            policy.Agents.AllowedCommandPatterns.Add(".*arcforges-testload(\\.exe)? hold .*");
        })).Error);
        await Tasks.WaitForAsync(() => node.Runtime.Execution.Settings.AgentCommandPatterns is not null, TimeSpan.FromSeconds(30), "the policy to take effect");
        var denied = await Tasks.SubmitRawAsync(agent, other);
        Assert.Equal(("command_pattern_denied", ErrorCategory.Authorization, "agents.allowed_command_patterns"),
            (denied.Error?.Code, denied.Error?.Category ?? ErrorCategory.Unspecified, denied.Error?.Details.State.Reason));
        Assert.Null((await Tasks.SubmitRawAsync(agent, hold)).Error);
        Assert.Null((await Tasks.SubmitRawAsync(script, other)).Error);
        Assert.Null((await Tasks.SubmitRawAsync(human, other)).Error);
        Assert.Contains(node.Runtime.Store.Read(reader => AuditLog.Recent(reader)), entry => entry.Operation == PermissionMatrix.TaskSubmit + " TaskService.SubmitTask"
            && entry.Decision == D && entry.Actor.Origin == Origin.Agent);
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
    private static byte[] SeedAdopted(CommandContext context, byte[] nodeId)
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
