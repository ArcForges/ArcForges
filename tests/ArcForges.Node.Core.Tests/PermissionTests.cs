// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Security;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The permission matrix, approvals and the local audit log of 11 section 1 (AF-SEC-01; R-AI-009, R-SEC-002, R-EXE-010): the default matrix
/// per origin for the supported clients, policy overrides (HUMAN-edited), <c>ExplainPermission</c>, the approval lifecycle (SM-APPROVAL:
/// raised, denied, withdrawn, expired; a command ID reused for another request), the HUMAN-only <c>retry_safety</c> and <c>permissions</c>
/// sections, agent assertions under <c>accept_agent_assertions</c>, the client kind verified against the peer, and an audit entry for every
/// privileged action. Real nodes in the test process, reached through the real client.
/// </summary>
public sealed class PermissionTests
{
    private const PermissionDecision A = PermissionDecision.Allow;
    private const PermissionDecision P = PermissionDecision.Approval;
    private const PermissionDecision D = PermissionDecision.Deny;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>11 section 1's default matrix, written out from the Design table (HUMAN, SCRIPT, AGENT) and its REMOTE command kinds.</summary>
    public static TheoryData<string, PermissionDecision, PermissionDecision, PermissionDecision, string?> Defaults => new()
    {
        { PermissionMatrix.TaskSubmit, A, A, A, "run_task" },
        { PermissionMatrix.TaskRead, A, A, A, "refresh" },
        { PermissionMatrix.TaskReadOutput, A, A, A, "read_output_tail" },
        { PermissionMatrix.TaskCancelOwn, A, A, A, "cancel_task" },
        { PermissionMatrix.TaskCancelOthers, A, P, P, "cancel_task" },
        { PermissionMatrix.TaskSetPriority, A, A, P, "set_priority" },
        { PermissionMatrix.PoolPause, A, A, P, "pause_queue" },
        { PermissionMatrix.ParallelismChange, A, P, P, "set_parallelism" },
        { PermissionMatrix.ParallelismLowerOwnSession, A, P, A, "set_parallelism" },
        { PermissionMatrix.PolicyChange, A, P, P, null },
        { PermissionMatrix.ApprovalDecide, A, D, D, "decide_approval" },
        { PermissionMatrix.CleanupPlan, A, A, A, null },
        { PermissionMatrix.CleanupExecute, A, P, P, null },
        { PermissionMatrix.ProcessAdopt, A, D, D, null },
        { PermissionMatrix.ProcessTerminate, A, P, P, null },
        { PermissionMatrix.Integrations, A, D, D, null },
        { PermissionMatrix.NodeStop, A, A, D, "stop_node" },
        { PermissionMatrix.NodeUpdate, A, A, D, "apply_update" },
        { PermissionMatrix.NodeRollback, A, D, D, null },
        { PermissionMatrix.TaskPause, A, A, P, null },
        { PermissionMatrix.TaskPurge, A, D, D, null },
        { PermissionMatrix.NodeSettings, A, P, D, null },
        { PermissionMatrix.NodeRename, A, A, D, null },
        { PermissionMatrix.NotificationsMarkRead, A, D, D, null },
        { PermissionMatrix.PolicyRetrySafety, A, D, D, null },
        { PermissionMatrix.PolicyPermissions, A, D, D, null },
    };

    [Theory]
    [MemberData(nameof(Defaults))]
    public void TheDefaultMatrixDecidesPerOrigin(string operation, PermissionDecision human, PermissionDecision script, PermissionDecision agent, string? remoteKind)
    {
        Assert.Equal(human, PermissionMatrix.Decide(Origin.Human, operation, []).Decision);
        Assert.Equal(script, PermissionMatrix.Decide(Origin.Script, operation, []).Decision);
        Assert.Equal(agent, PermissionMatrix.Decide(Origin.Agent, operation, []).Decision);
        var remote = PermissionMatrix.Decide(Origin.Remote, operation, []);
        Assert.Equal(remoteKind is null ? D : PermissionDecision.RemotePolicy, remote.Decision);
        Assert.Equal(remoteKind, PermissionMatrix.Find(operation)!.RemoteKind);

        // Origins the matrix does not grant fail closed.
        Assert.Equal(D, PermissionMatrix.Decide(Origin.Unspecified, operation, []).Decision);
        Assert.Equal(D, PermissionMatrix.Decide(Origin.Guest, operation, []).Decision);
        Assert.Equal(PermissionMatrix.DefaultSource, PermissionMatrix.Decide(Origin.Script, operation, []).Source);
    }

    [Fact]
    public void OverridesChangeOnlyTheirOriginAndNeverAHumanOrFixedRow()
    {
        Assert.Equal(PermissionMatrix.Rows.Count, Defaults.Count);
        List<PermissionOverride> overrides =
        [
            new() { Operation = PermissionMatrix.ParallelismChange, Origin = Origin.Script, Decision = A },
            new() { Operation = PermissionMatrix.TaskSetPriority, Origin = Origin.Agent, Decision = D },
            new() { Operation = PermissionMatrix.TaskSetPriority, Origin = Origin.Agent, Decision = A },
            new() { Operation = PermissionMatrix.ApprovalDecide, Origin = Origin.Agent, Decision = A },
            new() { Operation = PermissionMatrix.TaskSubmit, Origin = Origin.Remote, Decision = D },
        ];
        var verdict = PermissionMatrix.Decide(Origin.Script, PermissionMatrix.ParallelismChange, overrides);
        Assert.Equal((A, "policy permissions[0]"), (verdict.Decision, verdict.Source));
        Assert.Equal(P, PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.ParallelismChange, overrides).Decision);
        Assert.Equal((A, "policy permissions[2]"), (PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.TaskSetPriority, overrides).Decision,
            PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.TaskSetPriority, overrides).Source));

        // The approver must be HUMAN (fixed row); a REMOTE override can only deny.
        Assert.Equal(D, PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.ApprovalDecide, overrides).Decision);
        Assert.Equal(D, PermissionMatrix.Decide(Origin.Remote, PermissionMatrix.TaskSubmit, overrides).Decision);
        Assert.Equal(PermissionDecision.RemotePolicy, PermissionMatrix.Decide(Origin.Remote, PermissionMatrix.TaskSubmit, []).Decision);
        Assert.Equal(RiskClass.High, PermissionMatrix.Decide(Origin.Remote, PermissionMatrix.TaskSubmit, []).RemoteRisk);

        // Validation (policy.proto: a matrix operation; SCRIPT, AGENT or REMOTE; HUMAN rows are fixed).
        Assert.Null(PermissionMatrix.Valid(overrides[0]));
        Assert.Contains("fixed", PermissionMatrix.Valid(overrides[3]), StringComparison.Ordinal);
        Assert.Contains("operation", PermissionMatrix.Valid(new PermissionOverride { Operation = "task.fly", Origin = Origin.Agent, Decision = A }), StringComparison.Ordinal);
        Assert.Contains("HUMAN rows are fixed", PermissionMatrix.Valid(new PermissionOverride { Operation = PermissionMatrix.TaskSubmit, Origin = Origin.Human, Decision = D }),
            StringComparison.Ordinal);
        Assert.NotNull(PermissionMatrix.Valid(new PermissionOverride { Operation = PermissionMatrix.TaskSubmit, Origin = Origin.Remote, Decision = A }));
    }

    [Fact(Timeout = 120_000)]
    public async Task ExplainPermissionAnswersTheDecisionAndItsSource()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        async Task<PolicyServiceExplainPermissionResponse> ExplainAsync(NodeChannel channel, string operation, Origin origin) =>
            await channel.Policy.ExplainPermissionAsync(new PolicyServiceExplainPermissionRequest { Meta = Tasks.Meta(), Operation = operation, Origin = origin },
                cancellationToken: Ct);

        var explained = (await ExplainAsync(agent, PermissionMatrix.TaskCancelOthers, Origin.Agent)).Value;
        Assert.Equal((P, PermissionMatrix.DefaultSource), (explained.Decision, explained.Source));
        var remote = (await ExplainAsync(agent, PermissionMatrix.TaskCancelOthers, Origin.Remote)).Value;
        Assert.Equal((PermissionDecision.RemotePolicy, RiskClass.Medium), (remote.Decision, remote.RemoteRisk));
        Assert.Equal("invalid_argument", (await ExplainAsync(agent, "task.fly", Origin.Agent)).Error?.Code);
        Assert.Equal("invalid_argument", (await ExplainAsync(agent, PermissionMatrix.TaskSubmit, Origin.Unspecified)).Error?.Code);

        // A HUMAN override shows as its source.
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.TaskCancelOthers,
            Origin = Origin.Agent,
            Decision = D,
        }))).Error);
        var overridden = (await ExplainAsync(agent, PermissionMatrix.TaskCancelOthers, Origin.Agent)).Value;
        Assert.Equal((D, "policy permissions[0]"), (overridden.Decision, overridden.Source));

        // An override of a fixed row or a HUMAN row is an invalid policy.
        var invalid = await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.ApprovalDecide,
            Origin = Origin.Agent,
            Decision = A,
        }));
        Assert.Equal("invalid_policy", invalid.Error?.Code);
    }

    /// <summary>
    /// SM-APPROVAL apart from approval: a denied request is refused to its retry, a withdrawn one too, an expired one is
    /// <c>STATE/expired</c>; a command ID raised for one request and reused for another is <c>CONFLICT/command_id_reused</c>; only the
    /// requester or a HUMAN withdraws, only a HUMAN decides; every step is audited, and nothing executed.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task DeniedWithdrawnAndExpiredApprovalsNeverExecute()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // A 1 s approval TTL (policy approvals.default_ttl_ms; default 24 h) lets one approval expire within the test.
        await using var node = await InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy => policy.Approvals.DefaultTtlMs = 1_500)).StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        static QueueServiceCreatePoolRequest Pool(string name) => new() { Meta = Tasks.Meta(), Name = name };
        async Task<Approval> GetAsync(Id id) => (await human.Approvals.GetApprovalAsync(new ApprovalServiceGetApprovalRequest { Meta = Tasks.Meta(), ApprovalId = id },
            cancellationToken: Ct)).Value.Approval;
        async Task<ApprovalServiceDecideApprovalResponse> DecideAsync(NodeChannel channel, Id id, ApprovalDecisionKind decision) =>
            await channel.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest { Meta = Tasks.Meta(), ApprovalId = id, Decision = decision },
                cancellationToken: Ct);

        // Expired: raised, then not decided within the TTL.
        var late = Pool("late");
        var expiring = (await agent.Queue.CreatePoolAsync(late, cancellationToken: Ct)).Error!.Details.State.Resource.Id;
        await Tasks.WaitForAsync(() => GetAsync(expiring).GetAwaiter().GetResult().State == ApprovalState.Expired, TimeSpan.FromSeconds(20), "the approval to expire");
        Assert.Equal("expired", (await agent.Queue.CreatePoolAsync(late, cancellationToken: Ct)).Error?.Code);
        Assert.Equal("expired", (await DecideAsync(human, expiring, ApprovalDecisionKind.Approve)).Error?.Code);

        // Denied: the AGENT's retry is refused; the pool does not exist.
        var denied = Pool("denied");
        var deniedId = (await agent.Queue.CreatePoolAsync(denied, cancellationToken: Ct)).Error!.Details.State.Resource.Id;
        Assert.Equal("permission_denied", (await DecideAsync(agent, deniedId, ApprovalDecisionKind.Approve)).Error?.Code);
        Assert.Equal("permission_denied", (await DecideAsync(script, deniedId, ApprovalDecisionKind.Approve)).Error?.Code);
        var decision = await DecideAsync(human, deniedId, ApprovalDecisionKind.Deny);
        Assert.Equal(ApprovalState.Denied, decision.Value.Approval.State);

        // approvals.proto: a second decision returns the first.
        Assert.Equal(ApprovalState.Denied, (await DecideAsync(human, deniedId, ApprovalDecisionKind.Approve)).Value.Approval.State);
        var retried = (await agent.Queue.CreatePoolAsync(denied, cancellationToken: Ct)).Error;
        Assert.Equal("permission_denied", retried?.Code);
        Assert.Contains("denied", retried!.Details.State.Reason, StringComparison.Ordinal);

        // Withdrawn by its requester (a SCRIPT caller cannot withdraw the AGENT's request; a HUMAN could).
        var withdrawn = Pool("withdrawn");
        var withdrawnId = (await agent.Queue.CreatePoolAsync(withdrawn, cancellationToken: Ct)).Error!.Details.State.Resource.Id;
        Assert.Equal("permission_denied", (await script.Approvals.CancelApprovalAsync(new ApprovalServiceCancelApprovalRequest { Meta = Tasks.Meta(), ApprovalId = withdrawnId },
            cancellationToken: Ct)).Error?.Code);
        var cancelled = await agent.Approvals.CancelApprovalAsync(new ApprovalServiceCancelApprovalRequest { Meta = Tasks.Meta(), ApprovalId = withdrawnId }, cancellationToken: Ct);
        Assert.Equal(ApprovalState.Cancelled, cancelled.Value.Approval.State);
        Assert.Equal("invalid_state", (await DecideAsync(human, withdrawnId, ApprovalDecisionKind.Approve)).Error?.Code);
        Assert.Equal("permission_denied", (await agent.Queue.CreatePoolAsync(withdrawn, cancellationToken: Ct)).Error?.Code);

        // A command ID raised for one request and reused with another payload.
        var reused = new QueueServiceCreatePoolRequest { Meta = withdrawn.Meta, Name = "another" };
        Assert.Equal("command_id_reused", (await agent.Queue.CreatePoolAsync(reused, cancellationToken: Ct)).Error?.Code);

        // An AGENT sees its own requests; nothing was created.
        var listed = (await agent.Approvals.ListApprovalsAsync(new ApprovalServiceListApprovalsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Approvals;
        Assert.Equal(3, listed.Count);
        Assert.All(listed, approval => Assert.Equal(Origin.Agent, approval.Requester.Origin));
        Assert.Empty((await script.Approvals.ListApprovalsAsync(new ApprovalServiceListApprovalsRequest { Meta = Tasks.Meta(), States = { ApprovalState.Executed } },
            cancellationToken: Ct)).Value.Approvals);
        var pools = (await human.Queue.ListPoolsAsync(new QueueServiceListPoolsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Pools;
        Assert.DoesNotContain(pools, pool => pool.Name is "late" or "denied" or "withdrawn" or "another");

        // R-SEC-002: each request, decision, withdrawal, expiry and refused decision is in the audit log.
        var audit = node.Runtime.Store.Read(reader => AuditLog.Recent(reader));
        Assert.Equal(3, audit.Count(entry => entry.Outcome.StartsWith("approval requested", StringComparison.Ordinal)));
        Assert.Contains(audit, entry => entry.Outcome.StartsWith("denied: create pool 'denied'", StringComparison.Ordinal) && entry.Actor.Origin == Origin.Human);
        Assert.Contains(audit, entry => entry.Outcome.StartsWith("approval withdrawn", StringComparison.Ordinal) && entry.Actor.Origin == Origin.Agent);
        Assert.Contains(audit, entry => entry.Outcome.StartsWith("approval expired", StringComparison.Ordinal));
        Assert.Contains(audit, entry => entry.Operation.StartsWith(PermissionMatrix.ApprovalDecide, StringComparison.Ordinal) && entry.Decision == D
            && entry.Actor.Origin == Origin.Agent);
        Assert.DoesNotContain(audit, entry => entry.Outcome.StartsWith("executed", StringComparison.Ordinal));
    }

    /// <summary>
    /// The approval round trip of policy changes (11 section 1; contracts README section 6): a SCRIPT <c>SetParallelism</c> is captured with its
    /// command ID; once a HUMAN approves it runs under that ID as the requester, and the retry receives the executed outcome (the revision it
    /// wrote) without a second revision. Audit: requested, approved, executed.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task AnApprovedPolicyChangeRunsOnceAndItsRetryReceivesTheOutcome()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        var request = new QueueServiceSetParallelismRequest { Meta = Tasks.Meta(), Scope = ParallelismScope.Global, Mode = ParallelismMode.Fixed, Fixed = 3 };
        var raised = (await script.Queue.SetParallelismAsync(request, cancellationToken: Ct)).Error;
        Assert.Equal("approval_required", raised?.Code);
        var id = raised!.Details.State.Resource.Id;
        var pending = (await human.Approvals.GetApprovalAsync(new ApprovalServiceGetApprovalRequest { Meta = Tasks.Meta(), ApprovalId = id }, cancellationToken: Ct)).Value.Approval;
        Assert.Equal((ApprovalState.Pending, "QueueService.SetParallelism", Origin.Script, RiskClass.Medium), (pending.State, pending.Operation, pending.Requester.Origin, pending.Risk));
        Assert.Equal("set parallelism global fixed 3", pending.Summary);
        Assert.Equal(Convert.ToHexStringLower(ArcForges.Node.Store.PayloadDigest.Compute(request)), pending.RequestDigest);

        var decided = (await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
        {
            Meta = Tasks.Meta(),
            ApprovalId = id,
            Decision = ApprovalDecisionKind.Approve,
        }, cancellationToken: Ct)).Value.Approval;
        Assert.Equal(ApprovalState.Executed, decided.State);
        Assert.Equal(EffectCertainty.Happened, decided.Outcome.Effect);
        var policy = (await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value;
        Assert.Contains(policy.Document.Parallelism, rule => rule.Scope == ParallelismScope.Global && rule.Fixed == 3);
        var revision = policy.Revision.Revision.Value;

        var retried = await script.Queue.SetParallelismAsync(request, cancellationToken: Ct);
        Assert.Null(retried.Error);
        Assert.Equal(revision, retried.Value.PolicyRevision.Value);
        Assert.Equal(revision, (await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Revision.Revision.Value);
        var actor = (await human.Policy.ListPolicyRevisionsAsync(new PolicyServiceListPolicyRevisionsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Revisions[0].Actor;
        Assert.Equal(Origin.Script, actor.Origin);

        var audit = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Where(entry => entry.ApprovalId is { } approval
            && approval.AsSpan().SequenceEqual(id.Value.Span)).ToList();
        Assert.Contains(audit, entry => entry.Decision == P && entry.Actor.Origin == Origin.Script);
        Assert.Contains(audit, entry => entry.Outcome.StartsWith("approved", StringComparison.Ordinal) && entry.Actor.Origin == Origin.Human);
        Assert.Contains(audit, entry => entry.Outcome.StartsWith("done: set parallelism", StringComparison.Ordinal) && entry.Actor.Origin == Origin.Script);
        Assert.Contains(audit, entry => entry.Outcome == "executed after approval");
    }

    /// <summary>
    /// AD-0006 section 4 and 11 section 1: <c>retry_safety</c> and <c>permissions</c> are edited only by HUMAN callers (a change from SCRIPT or
    /// AGENT is refused outright, never turned into an approval); an AGENT's PURE or IDEMPOTENT assertion is accepted only when
    /// <c>accept_agent_assertions</c> is true, otherwise the task is UNKNOWN with a warning; the source is recorded (R-EXE-010).
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task RetrySafetyIsHumanEditedAndAgentAssertionsFollowThePolicy()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        foreach (var caller in (NodeChannel[])[script, agent])
        {
            var rule = await Sched.ChangePolicyAsync(caller, policy => (policy.RetrySafety ??= new RetrySafetyPolicy()).Rules.Add(new RetrySafetyRule
            {
                Pattern = "^dotnet build",
                SideEffect = SideEffectClass.Idempotent,
            }));
            Assert.Equal("permission_denied", rule.Error?.Code);
            Assert.Contains("retry_safety", rule.Error!.Details.State.Reason, StringComparison.Ordinal);
            Assert.Equal("permission_denied", (await Sched.ChangePolicyAsync(caller, policy => policy.RetrySafety.AcceptAgentAssertions = true)).Error?.Code);
            var permissions = await Sched.ChangePolicyAsync(caller, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.ParallelismChange,
                Origin = Origin.Agent,
                Decision = A,
            }));
            Assert.Equal("permission_denied", permissions.Error?.Code);
        }

        Assert.Empty((await human.Approvals.ListApprovalsAsync(new ApprovalServiceListApprovalsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Approvals);

        // Tasks wait in paused pools; nothing runs.
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        TaskSpec Pure()
        {
            var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
            spec.SideEffect = SideEffectClass.Pure;
            return spec;
        }

        var refused = await Tasks.SubmitRawAsync(agent, Pure());
        Assert.Contains(refused.Value.Warnings, warning => warning.Contains("accept_agent_assertions", StringComparison.Ordinal));
        var unknown = await Tasks.GetAsync(human, refused.Value.TaskId);
        Assert.Equal((SideEffectClass.Unknown, SideEffectSource.Default), (unknown.SideEffect, unknown.SideEffectSource));
        var fromScript = await Tasks.GetAsync(human, (await Tasks.SubmitRawAsync(script, Pure())).Value.TaskId);
        Assert.Equal((SideEffectClass.Pure, SideEffectSource.Caller), (fromScript.SideEffect, fromScript.SideEffectSource));

        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.RetrySafety.AcceptAgentAssertions = true)).Error);
        await Tasks.WaitForAsync(() => node.Runtime.Execution!.Settings.AcceptAgentAssertions, TimeSpan.FromSeconds(30), "the policy to take effect");
        var accepted = await Tasks.GetAsync(human, (await Tasks.SubmitRawAsync(agent, Pure())).Value.TaskId);
        Assert.Equal((SideEffectClass.Pure, SideEffectSource.Caller), (accepted.SideEffect, accepted.SideEffectSource));

        // The refusals of the HUMAN-only sections are audited.
        var audit = node.Runtime.Store.Read(reader => AuditLog.Recent(reader));
        Assert.Equal(4, audit.Count(entry => entry.Operation.StartsWith(PermissionMatrix.PolicyRetrySafety, StringComparison.Ordinal) && entry.Decision == D));
        Assert.Equal(2, audit.Count(entry => entry.Operation.StartsWith(PermissionMatrix.PolicyPermissions, StringComparison.Ordinal) && entry.Decision == D));
    }

    /// <summary>
    /// The node's own operations per origin (11 section 1 and node.proto): stopping the node and renaming it are denied to AGENT callers,
    /// marking notifications read and purging a record are HUMAN-only; each refusal and each privileged action that ran is audited.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task NodeOperationsFollowTheMatrixAndAreAudited()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        Assert.Equal("permission_denied", (await agent.Node.StopNodeAsync(new NodeServiceStopNodeRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Error?.Code);
        Assert.Equal("permission_denied", (await agent.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Meta = Tasks.Meta(), Name = "agent's" }, cancellationToken: Ct)).Error?.Code);
        Assert.Null((await script.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Meta = Tasks.Meta(), Name = "script's" }, cancellationToken: Ct)).Error);
        var mark = new NodeServiceMarkNotificationsReadRequest { UpTo = ProtoTime.ToInstant(DateTimeOffset.UtcNow) };
        Assert.Equal("permission_denied", (await script.Node.MarkNotificationsReadAsync(mark, cancellationToken: Ct)).Error?.Code);
        Assert.Null((await human.Node.MarkNotificationsReadAsync(mark, cancellationToken: Ct)).Error);
        var purge = new TaskServicePurgeTaskRecordRequest { Meta = Tasks.Meta(), TaskId = new Id { Value = ByteString.CopyFrom(new byte[16]) } };
        Assert.Equal("permission_denied", (await script.Tasks.PurgeTaskRecordAsync(purge, cancellationToken: Ct)).Error?.Code);
        Assert.Equal("not_found", (await human.Tasks.PurgeTaskRecordAsync(purge, cancellationToken: Ct)).Error?.Code);
        Assert.Equal("permission_denied", (await script.Resources.AdoptProcessAsync(new ResourceServiceAdoptProcessRequest
        {
            Meta = Tasks.Meta(),
            Process = ClientProcess.Current(),
        }, cancellationToken: Ct)).Error?.Code);

        var audit = node.Runtime.Store.Read(reader => AuditLog.Recent(reader));
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.NodeStop + " NodeService.StopNode" && entry.Decision == D && entry.Actor.Origin == Origin.Agent);
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.NodeRename + " NodeService.RenameNode" && entry.Decision == D);
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.NotificationsMarkRead + " NodeService.MarkNotificationsRead" && entry.Decision == D);
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.TaskPurge + " TaskService.PurgeTaskRecord" && entry.Decision == D);
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.TaskPurge + " TaskService.PurgeTaskRecord" && entry.Decision == A
            && entry.Outcome.StartsWith("failed (State/not_found)", StringComparison.Ordinal));
        Assert.Contains(audit, entry => entry.Operation == PermissionMatrix.ProcessAdopt + " ResourceService.AdoptProcess" && entry.Decision == D);

        // StopNode by a HUMAN runs, audited in its own transaction.
        Assert.Null((await human.Node.StopNodeAsync(new NodeServiceStopNodeRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Error);
        Assert.Equal(0, await node.Exit.WaitAsync(TimeSpan.FromSeconds(30), Ct));
        using var store = ArcForges.Node.Store.NodeStore.Open(new ArcForges.Node.Store.NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "audit" });
        Assert.Contains(store.Read(reader => AuditLog.Recent(reader)), entry => entry.Operation == PermissionMatrix.NodeStop + " NodeService.StopNode" && entry.Decision == A
            && entry.Actor.Origin == Origin.Human && entry.Outcome == "done: stop the node");
    }

    /// <summary>
    /// The client kind is verified against the peer (11 section 1): an executable verifies a kind by path or by its content (a version
    /// directory reached through a link), the Desktop kind only by the Desktop executable; a CLI under a registered agent root is AGENT.
    /// </summary>
    [Fact(Timeout = 60_000)]
    public async Task TheClientKindIsVerifiedAgainstThePeerExecutableAndAgentRoots()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var root = Directory.CreateTempSubdirectory("arcforges-images-").FullName;
        try
        {
            var node = Path.Combine(root, "arcforges");
            var desktop = Path.Combine(root, "arcforges-desktop");
            var copy = Path.Combine(root, "other", "arcforges");
            Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
            await File.WriteAllTextAsync(node, "node binary", Ct);
            await File.WriteAllTextAsync(desktop, "desktop binary", Ct);
            await File.WriteAllTextAsync(copy, "node binary", Ct);
            var images = new ClientImages([node], [desktop]);
            Assert.True(images.Verifies(ClientKind.Cli, node));
            Assert.True(images.Verifies(ClientKind.Cli, copy), "the same executable reached through another path (content)");
            Assert.True(images.Verifies(ClientKind.McpAdapter, node));
            Assert.False(images.Verifies(ClientKind.Desktop, node), "the node's executable is not the Desktop");
            Assert.True(images.Verifies(ClientKind.Desktop, desktop));
            Assert.False(images.Verifies(ClientKind.Cli, desktop));
            Assert.False(images.Verifies(ClientKind.Desktop, null));
            Assert.False(images.Verifies(ClientKind.Supervisor, node));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        // A CLI under a registered agent root is AGENT (AF-AI-01 registers roots): this process as a root covers its real child, and a root
        // whose recorded start differs (a reused ID) covers nothing.
        var roots = new AgentRoots();
        var started = ProtoTime.ToDateTimeOffset(ClientProcess.Identity(Environment.ProcessId)!.StartTime)!.Value;
        using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Tasks.TestLoad, ["hold", "--hold-ms", "30000"])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        try
        {
            Assert.False(roots.Contains(child.Id));
            roots.Register(Environment.ProcessId, started.AddMinutes(-5));
            Assert.False(roots.Contains(child.Id), "a root whose start does not match is another process");
            roots.Register(Environment.ProcessId, started);
            Assert.True(roots.Contains(Environment.ProcessId));
            Assert.True(roots.Contains(child.Id), "the child descends from the registered root");
            roots.Remove(Environment.ProcessId);
            Assert.False(roots.Contains(child.Id));
        }
        finally
        {
            child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync(Ct);
        }
    }
}
