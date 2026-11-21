// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using OutputIndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// AF-CTR-05 part N2b on real nodes, through the routed test seam (<see cref="RoutedCalls"/>): the center-routed policy and the routed column
/// (N2-1, PB-2), caller narrowing, approvals (N2-5), MR-08 (N2-2, N2-3), the owner and what a routed read shows
/// (N2-6, PN-8), command deduplication over the exact bytes with Q-5 replay fidelity (N2-7, N2-8), the in-progress duplicate (decisions
/// B-2), the cross-part rule for handler errors (decisions B-1), the link and stop re-checks (B-3), the expiry re-check (PN-15),
/// <c>routed_call_log</c> (N2-10) and retained local and routed submission records.
/// </summary>
public sealed class RoutedDispatchTests
{
    private const PermissionDecision A = PermissionDecision.Allow;
    private const PermissionDecision P = PermissionDecision.Approval;
    private const PermissionDecision D = PermissionDecision.Deny;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>The routed column narrowed by the cells (11 section 1, "Center-routed operations"): REMOTE = an account session, the routed column alone.</summary>
    public static TheoryData<string, Origin, PermissionDecision> Column => new()
    {
        { PermissionMatrix.TaskSubmit, Origin.Remote, A }, { PermissionMatrix.TaskSubmit, Origin.Human, A }, { PermissionMatrix.TaskSubmit, Origin.Script, A },
        { PermissionMatrix.TaskSubmit, Origin.Agent, A },
        { PermissionMatrix.TaskRead, Origin.Remote, A }, { PermissionMatrix.TaskRead, Origin.Human, A }, { PermissionMatrix.TaskRead, Origin.Script, A },
        { PermissionMatrix.TaskRead, Origin.Agent, A },
        { PermissionMatrix.TaskReadOutput, Origin.Remote, A }, { PermissionMatrix.TaskReadOutput, Origin.Human, A }, { PermissionMatrix.TaskReadOutput, Origin.Script, A },
        { PermissionMatrix.TaskReadOutput, Origin.Agent, A },
        { PermissionMatrix.TaskCancelOwn, Origin.Remote, A }, { PermissionMatrix.TaskCancelOwn, Origin.Human, A }, { PermissionMatrix.TaskCancelOwn, Origin.Script, A },
        { PermissionMatrix.TaskCancelOwn, Origin.Agent, A },
        { PermissionMatrix.TaskCancelOthers, Origin.Remote, P }, { PermissionMatrix.TaskCancelOthers, Origin.Human, P },
        { PermissionMatrix.TaskCancelOthers, Origin.Script, P }, { PermissionMatrix.TaskCancelOthers, Origin.Agent, P },
        { PermissionMatrix.ProcessTerminate, Origin.Remote, D }, { PermissionMatrix.ProcessTerminate, Origin.Human, D },
        { PermissionMatrix.ProcessTerminate, Origin.Script, D }, { PermissionMatrix.ProcessTerminate, Origin.Agent, D },
        { PermissionMatrix.PolicyCenterRouted, Origin.Human, D }, { PermissionMatrix.ApprovalDecide, Origin.Human, D },
        { PermissionMatrix.NodeStop, Origin.Human, D },
    };

    [Theory]
    [MemberData(nameof(Column))]
    public void TheRoutedColumnNarrowedByTheCellsDecidesARoutedCaller(string operation, Origin cells, PermissionDecision expected) =>
        Assert.Equal(expected, PermissionMatrix.DecideRouted(operation, cells, []).Decision);

    [Fact]
    public void OverridesOnlyNarrowARoutedCallerAndNothingReachesProcessTerminate()
    {
        List<PermissionOverride> overrides =
        [
            new() { Operation = PermissionMatrix.TaskCancelOthers, Origin = Origin.Script, Decision = A },
            new() { Operation = PermissionMatrix.ProcessTerminate, Origin = Origin.Script, Decision = A },
            new() { Operation = PermissionMatrix.ProcessTerminate, Origin = Origin.Agent, Decision = A },
            new() { Operation = PermissionMatrix.TaskSubmit, Origin = Origin.Agent, Decision = D },
            new() { Operation = PermissionMatrix.TaskRead, Origin = Origin.Remote, Decision = D },
            new() { Operation = PermissionMatrix.ProcessTerminate, Origin = Origin.Remote, Decision = A },
        ];

        // A wider SCRIPT cell never widens the routed column; an AGENT deny narrows it; a REMOTE deny narrows every routed caller.
        Assert.Equal(P, PermissionMatrix.DecideRouted(PermissionMatrix.TaskCancelOthers, Origin.Script, overrides).Decision);
        Assert.Equal(D, PermissionMatrix.DecideRouted(PermissionMatrix.TaskSubmit, Origin.Agent, overrides).Decision);
        Assert.Equal(A, PermissionMatrix.DecideRouted(PermissionMatrix.TaskSubmit, Origin.Script, overrides).Decision);
        Assert.Equal(D, PermissionMatrix.DecideRouted(PermissionMatrix.TaskRead, Origin.Remote, overrides).Decision);
        Assert.Equal(D, PermissionMatrix.DecideRouted(PermissionMatrix.TaskRead, Origin.Human, overrides).Decision);
        foreach (var cells in (Origin[])[Origin.Remote, Origin.Human, Origin.Script, Origin.Agent])
        {
            Assert.Equal(D, PermissionMatrix.DecideRouted(PermissionMatrix.ProcessTerminate, cells, overrides).Decision);
        }

        // A REMOTE override may only deny, and the center-routed policy is a fixed, HUMAN-edited row.
        Assert.NotNull(PermissionMatrix.Valid(overrides[^1]));
        Assert.NotNull(PermissionMatrix.Valid(new PermissionOverride { Operation = PermissionMatrix.PolicyCenterRouted, Origin = Origin.Script, Decision = A }));
        Assert.True(PermissionMatrix.Find(PermissionMatrix.PolicyCenterRouted)!.Fixed);
    }

    [Fact]
    public void TheCallerLevelPolicyConfinesRelayedCallersToTheirOwnNode()
    {
        var self = CommandIds.New().Value.ToByteArray();
        CenterCaller Relay(Origin origin, bool own) => new()
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = CommandIds.New(),
            RelayingNodeId = own ? new Id { Value = ByteString.CopyFrom(self) } : CommandIds.New(),
            LocalOrigin = origin,
            LocalSessionId = CommandIds.New(),
        };

        var account = RoutedCalls.Session();
        var optIn = new CenterRoutedPolicy { RelayedFrom = RelayedFrom.Account };
        Assert.Null(CenterRouting.Refusal(account, self, null));
        Assert.Null(CenterRouting.Refusal(Relay(Origin.Agent, own: true), self, null));
        foreach (var origin in (Origin[])[Origin.Human, Origin.Script, Origin.Agent])
        {
            // PB-2: OWN_NODE by default (UNSPECIFIED reads as OWN_NODE).
            Assert.Equal(CenterRouting.OwnNodeOnly, CenterRouting.Refusal(Relay(origin, own: false), self, null));
            Assert.Equal(CenterRouting.OwnNodeOnly, CenterRouting.Refusal(Relay(origin, own: false), self, new CenterRoutedPolicy { RelayedFrom = RelayedFrom.Unspecified }));
            Assert.Equal(CenterRouting.OwnNodeOnly, CenterRouting.Refusal(Relay(origin, own: false), self, new CenterRoutedPolicy { RelayedFrom = RelayedFrom.OwnNode }));
        }

        // The opt-in: a claimed HUMAN or SCRIPT origin gets the SCRIPT cells, a claimed AGENT is refused (N-9, the target's side).
        Assert.Null(CenterRouting.Refusal(Relay(Origin.Human, own: false), self, optIn));
        Assert.Equal(Origin.Script, CenterRouting.CellsOrigin(Relay(Origin.Human, own: false), self));
        Assert.Equal(Origin.Human, CenterRouting.CellsOrigin(Relay(Origin.Human, own: true), self));
        Assert.Equal(Origin.Remote, CenterRouting.CellsOrigin(account, self));
        Assert.Equal(CenterRouting.AgentOwnNodeOnly, CenterRouting.Refusal(Relay(Origin.Agent, own: false), self, optIn));

        // Off: every routed caller is refused.
        Assert.Equal(CenterRouting.Disabled, CenterRouting.Refusal(account, self, new CenterRoutedPolicy { Enabled = false }));

        // Verifier N-4: a caller missing its kind's fields, or carrying another kind's, fails closed before policy.
        var noRelaying = Relay(Origin.Script, own: false);
        noRelaying.RelayingNodeId = null;
        var noOrigin = Relay(Origin.Script, own: true);
        noOrigin.ClearLocalOrigin();
        var remoteOrigin = Relay(Origin.Remote, own: true);
        var mixed = Relay(Origin.Script, own: true);
        mixed.UserId = CommandIds.New();
        var noSession = RoutedCalls.Session();
        noSession.SessionId = null;
        var grant = RoutedCalls.Session();
        grant.Kind = CenterCallerKind.AgentGrant;
        foreach (var incomplete in (CenterCaller[])[noRelaying, noOrigin, remoteOrigin, mixed, noSession])
        {
            Assert.Equal(CenterRouting.Incomplete, CenterRouting.Refusal(incomplete, self, optIn));
        }

        Assert.Equal(CenterRouting.Unsupported, CenterRouting.Refusal(grant, self, optIn));

        // The same caller: the same account session, or the same relaying node and local origin (not the local session).
        var relay = Relay(Origin.Script, own: true);
        var again = relay.Clone();
        again.LocalSessionId = CommandIds.New();
        Assert.True(CenterRouting.Same(relay, again));
        again.LocalOrigin = Origin.Human;
        Assert.False(CenterRouting.Same(relay, again));
        Assert.False(CenterRouting.Same(account, RoutedCalls.Session()));
        Assert.True(CenterRouting.Same(account, account.Clone()));

        // The caller class of replay and the in-progress answer (E2b review C2-N3): the user, not the session; the local session never.
        Assert.True(CenterRouting.SameClass(account, RoutedCalls.Session()));
        var otherUser = RoutedCalls.Session();
        otherUser.UserId = CommandIds.New();
        Assert.False(CenterRouting.SameClass(account, otherUser));
        var relayAgain = relay.Clone();
        relayAgain.LocalSessionId = CommandIds.New();
        Assert.True(CenterRouting.SameClass(relay, relayAgain));
        Assert.False(CenterRouting.SameClass(relay, Relay(Origin.Agent, own: true)));
        Assert.False(CenterRouting.SameClass(account, relay));
    }

    /// <summary>N2-6, N2-10: a retained routed submission's owner, original outcome and command privacy.</summary>
    [Fact(Timeout = 180_000)]
    public async Task ARetainedRoutedSubmissionPreservesOwnershipAndCommandPrivacy()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var owner = RoutedCalls.Session();
        var spec = Tasks.Argv(node.Root, "historical-fixture-no-launch");
        spec.Environment.Set["VISIBLE_NAME"] = "a value";
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec, CancelWhenCallerGone = true };
        var retained = await SeedHistoricalSubmitAsync(node, owner, request, retainQueued: true,
            historicalWarning: "cancel_when_caller_gone was ignored for this routed submission");
        var (answer, response) = await routed.SubmitAsync(owner, request);
        Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
        Assert.Equal(retained.ToByteArray(), answer.Response!.ToByteArray());
        Assert.Equal(3, answer.Risk);
        var taskId = response!.Value.TaskId;
        Assert.Null(node.Runtime.Execution!.BindingOf(taskId.Value.Span));
        Assert.Equal(taskId.Value.ToByteArray(), answer.TaskId);

        // CTR5-NODE-10: the owner is REMOTE with the center caller and the routed command ID; never a diagnostic local submission.
        var stored = await Tasks.GetAsync(human, taskId, full: true);
        Assert.Equal(new ActorRef { Origin = Origin.Remote, ClientKind = ClientKind.Unspecified, CenterCaller = owner, RemoteCommandId = request.Meta.CommandId }, stored.Owner);
        Assert.False(stored.HasLocalDiagnostic);
        Assert.Equal((long)Origin.Remote, node.Runtime.Store.Read(reader =>
            reader.Scalar("SELECT origin FROM command_dedup WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        Assert.Equal(request.Meta.CommandId.Value.ToByteArray(), node.Runtime.Store.Read(reader =>
            (byte[])reader.Scalar("SELECT remote_command_id FROM task WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray()))!));

        // PN-8: the owner reads its specification; another account session reads the task without its command, and with
        // remote_command_lines only argv, the working directory and environment names.
        var get = new TaskServiceGetTaskRequest { Meta = Tasks.Meta(), TaskId = taskId, Detail = TaskDetail.Full };
        var own = (await routed.ReadAsync(owner, RoutedMethod.GetNodeTask, get, TaskServiceGetTaskResponse.Parser)).Response!.Value.Task;
        Assert.Equal("a value", own.Spec.Environment.Set["VISIBLE_NAME"]);
        var other = RoutedCalls.Session();
        var seen = (await routed.ReadAsync(other, RoutedMethod.GetNodeTask, get, TaskServiceGetTaskResponse.Parser)).Response!.Value.Task;
        Assert.Null(seen.Spec);
        Assert.False(seen.HasCommandSummary);
        Assert.False(seen.HasTitle);
        var listed = (await routed.ReadAsync(other, RoutedMethod.ListNodeTasks, new TaskServiceListTasksRequest { Meta = Tasks.Meta() },
            TaskServiceListTasksResponse.Parser)).Response!.Value.Tasks.Single(task => task.TaskId.Equals(taskId));
        Assert.False(listed.HasCommandSummary);
        Assert.True((await routed.ReadAsync(owner, RoutedMethod.ListNodeTasks, new TaskServiceListTasksRequest { Meta = Tasks.Meta() },
            TaskServiceListTasksResponse.Parser)).Response!.Value.Tasks.Single(task => task.TaskId.Equals(taskId)).HasCommandSummary);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => (policy.Privacy ??= new PrivacyPolicy()).RemoteCommandLines = true)).Error);
        var lines = (await routed.ReadAsync(other, RoutedMethod.GetNodeTask, get, TaskServiceGetTaskResponse.Parser)).Response!.Value.Task;
        Assert.Equal(spec.Command, lines.Spec.Command);
        Assert.Equal(spec.WorkingDirectory, lines.Spec.WorkingDirectory);
        Assert.Equal(string.Empty, lines.Spec.Environment.Set["VISIBLE_NAME"]);

        // N2-10: one routed_call_log row per decision, completed with the risk, the task and the response's digest; no payload.
        var rows = node.Runtime.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("SELECT decision, method, risk, task_id IS NOT NULL, response_sha256 IS NOT NULL, refusal_code FROM routed_call_log ORDER BY log_id;");
            using var all = command.ExecuteReader();
            var found = new List<(long, long, long?, bool, bool, string?)>();
            while (all.Read())
            {
                found.Add((all.GetInt64(0), all.GetInt64(1), all.IsDBNull(2) ? null : all.GetInt64(2), all.GetBoolean(3), all.GetBoolean(4), all.IsDBNull(5) ? null : all.GetString(5)));
            }

            return found;
        });
        Assert.Equal((1L, 1L, (long?)3, true, true, (string?)null), rows[0]);
        Assert.All(rows, row => Assert.Equal(1L, row.Item1));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM remote_command_log;")));

        // Q-5 also covers an ordinary own-task Cancel, not only Submit and a Cancel executed by an approval.
        var cancelMeta = Tasks.Meta();
        var cancelled = (await routed.CancelAsync(owner, taskId, cancelMeta)).Answer!;
        var replayed = (await routed.CancelAsync(owner, taskId, cancelMeta)).Answer!;
        Assert.Equal(RoutedOutcome.Executed, cancelled.Outcome);
        Assert.Equal(cancelled.Response!.ToByteArray(), replayed.Response!.ToByteArray());
        Assert.Equal(TaskState.Cancelled, (await Tasks.GetAsync(human, taskId)).State);
    }

    /// <summary>N2-1 (PB-2): cross-node relay refused by default; the opt-in gives the SCRIPT cells; an AGENT never crosses; off refuses all.</summary>
    [Fact(Timeout = 180_000)]
    public async Task ACrossNodeRelayIsRefusedByDefaultAndAClaimedHumanFromAnotherNodeGetsNoMoreThanScript()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        TaskServiceSubmitTaskRequest Request() => new() { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, "historical-fixture-no-launch") };
        int TaskCount() => (int)(long)node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;"))!;

        foreach (var origin in (Origin[])[Origin.Human, Origin.Script, Origin.Agent])
        {
            var refused = (await routed.SubmitAsync(routed.Relay(origin, ownNode: false), Request())).Answer!;
            Assert.Equal((RoutedOutcome.RefusedByPolicy, "permission_denied", "task.submit", CenterRouting.OwnNodeOnly),
                (refused.Outcome, refused.Error?.Code, refused.Error?.Details.State.State, refused.Error?.Details.State.Reason));
            Assert.True(RoutedRefusals.Closed(refused.Error!));
            var read = (await routed.ReadAsync(routed.Relay(origin, ownNode: false), RoutedMethod.ListNodeTasks, new TaskServiceListTasksRequest { Meta = ArcForges.Node.Core.Tests.Tasks.Meta() },
                TaskServiceListTasksResponse.Parser)).Answer!;
            Assert.Equal(CenterRouting.OwnNodeOnly, read.Error?.Details.State.Reason);
        }

        Assert.Equal(0, TaskCount());
        Assert.Contains(node.Runtime.Store.Read(reader => AuditLog.Recent(reader)), entry => entry.Decision == D
            && entry.Operation == "task.submit FleetService.SubmitTask" && entry.Actor.Origin == Origin.Remote && entry.Actor.CenterCaller is not null);

        // Verifier N-6: neither an update nor a restored revision from a SCRIPT changes center_routed; a HUMAN opts in.
        Assert.Equal("permission_denied", (await Sched.ChangePolicyAsync(script, policy => (policy.CenterRouted ??= new CenterRoutedPolicy()).RelayedFrom = RelayedFrom.Account)).Error?.Code);
        var before = (await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = ArcForges.Node.Core.Tests.Tasks.Meta() }, cancellationToken: Ct)).Value.Revision.Revision.Value;
        Assert.Null((await Sched.ChangePolicyAsync(human, policy =>
        {
            (policy.CenterRouted ??= new CenterRoutedPolicy()).RelayedFrom = RelayedFrom.Account;
            policy.Permissions.Add(new PermissionOverride { Operation = PermissionMatrix.TaskSubmit, Origin = Origin.Script, Decision = D });
        })).Error);
        var opened = (await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = ArcForges.Node.Core.Tests.Tasks.Meta() }, cancellationToken: Ct)).Value.Revision.Revision.Value;
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.CenterRouted.RelayedFrom = RelayedFrom.OwnNode)).Error);
        async Task<PolicyServiceRestorePolicyRevisionResponse> RestoreAsync(NodeChannel channel, long revision)
        {
            var meta = ArcForges.Node.Core.Tests.Tasks.Meta();
            meta.ExpectedRev = (await channel.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = ArcForges.Node.Core.Tests.Tasks.Meta() }, cancellationToken: Ct))
                .Value.Revision.Revision;
            return await channel.Policy.RestorePolicyRevisionAsync(new PolicyServiceRestorePolicyRevisionRequest { Meta = meta, Revision = new Revision { Value = revision } },
                cancellationToken: Ct);
        }

        var restore = await RestoreAsync(script, opened);
        if (restore.Error?.Code == "approval_required")
        {
            // A HUMAN approval must never lend SCRIPT permission to restore center_routed. Exercise the potential
            // bypass if a regression offers one, then check the actual stored policy before checking the refusal.
            var decision = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
            {
                Meta = Tasks.Meta(),
                ApprovalId = restore.Error.Details.State.Resource.Id,
                Decision = ApprovalDecisionKind.Approve,
            }, cancellationToken: Ct);
            Assert.Null(decision.Error);
        }

        var afterDeniedRestore = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct);
        Assert.Null(afterDeniedRestore.Error);
        Assert.Equal(RelayedFrom.OwnNode, afterDeniedRestore.Value.Document.CenterRouted.RelayedFrom);
        Assert.Equal("permission_denied", restore.Error?.Code);
        Assert.True(before < opened);
        Assert.Null((await RestoreAsync(human, opened)).Error);

        // After the opt-in: a claimed HUMAN from another node gets the SCRIPT cells (here a SCRIPT deny), an own-node HUMAN its own; an AGENT
        // from another node is refused.
        var crossHuman = (await routed.SubmitAsync(routed.Relay(Origin.Human, ownNode: false), Request())).Answer!;
        Assert.Equal((RoutedOutcome.RefusedByPolicy, "permission_override"), (crossHuman.Outcome, crossHuman.Error?.Details.State.Reason));
        var ownHuman = routed.Relay(Origin.Human);
        AssertRetiredSubmit((await routed.SubmitAsync(ownHuman, Request())).Response!);
        var ownRead = await routed.ReadAsync(ownHuman, RoutedMethod.ListNodeTasks, new TaskServiceListTasksRequest { Meta = Tasks.Meta() },
            TaskServiceListTasksResponse.Parser);
        Assert.Equal(RoutedOutcome.Executed, ownRead.Answer!.Outcome);
        Assert.Null(ownRead.Response!.Error);
        Assert.Equal(CenterRouting.AgentOwnNodeOnly, (await routed.SubmitAsync(routed.Relay(Origin.Agent, ownNode: false), Request())).Answer!.Error?.Details.State.Reason);
        Assert.Equal(0, TaskCount());

        // Off: every routed call is refused before any effect.
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.CenterRouted.Enabled = false)).Error);
        Assert.Equal(CenterRouting.Disabled, (await routed.SubmitAsync(RoutedCalls.Session(), Request())).Answer!.Error?.Details.State.Reason);
        Assert.Equal(0, TaskCount());
    }

    /// <summary>Routed Submit retains its caller gate and accepts no fresh legacy work.</summary>
    [Fact(Timeout = 30_000)]
    public async Task FreshRoutedSubmitDoesNotAdmitLegacyWorkForAnyCallerKind()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var routed = new RoutedCalls(node);
        // The live caller matrix remains covered by TheRoutedColumnNarrowedByTheCellsDecidesARoutedCaller.
        // Queue placement and Submit-time spec narrowing belonged to the retired admission path.
        foreach (var caller in new[] { RoutedCalls.Session(), routed.Relay(Origin.Human), routed.Relay(Origin.Script), routed.Relay(Origin.Agent) })
        {
            foreach (var priority in new[] { Priority.Normal, Priority.Interactive })
            {
                var spec = Tasks.Argv(node.Root, "historical-fixture-no-launch");
                spec.Priority = priority;
                spec.SideEffect = SideEffectClass.Pure;
                var (answer, response) = await routed.SubmitAsync(caller, new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec });
                Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
                AssertRetiredSubmit(response!);
            }
        }

        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
    }

    /// <summary>N2-5, decisions B-2: a routed caller never approves; its approval is closed; an APPROVED one is in progress; the executed one replays.</summary>
    [Fact(Timeout = 180_000)]
    public async Task ARoutedCallerNeverApprovesAndItsApprovedCancelIsInProgressThenReplayed()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var caller = RoutedCalls.Session();
        var first = await SeedHumanQueueAsync(node);
        var second = await SeedHumanQueueAsync(node);

        // Another owner's task: P. The approval is raised and answered with closed fields: its ID, RECONCILE through GetApproval.
        var meta = Tasks.Meta();
        var raised = (await routed.CancelAsync(caller, first, meta)).Answer!;
        Assert.Equal((RoutedOutcome.RefusedByPolicy, "approval_required", PermissionMatrix.TaskCancelOthers, RetryMode.Reconcile, RoutedRefusals.ApprovalReconciliation),
            (raised.Outcome, raised.Error?.Code, raised.Error?.Details.State.State, raised.Error!.Retry.Mode, raised.Error.Retry.ReconciliationOperation));
        Assert.True(RoutedRefusals.Closed(raised.Error));
        var approval = raised.Error.Details.State.Resource.Id;
        Assert.Equal("approval_required", (await routed.CancelAsync(caller, first, meta)).Answer!.Error?.Code);
        var requester = node.Runtime.Store.Read(reader => Approvals.Get(reader, approval.Value.Span))!.View.Requester;
        Assert.Equal((Origin.Remote, caller), (requester.Origin, requester.CenterCaller));

        // A HUMAN approves: the cancel executes as the routed requester; the routed resend gets that outcome, byte for byte.
        Assert.Equal(ApprovalState.Executed, (await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
        {
            Meta = Tasks.Meta(),
            ApprovalId = approval,
            Decision = ApprovalDecisionKind.Approve,
        }, cancellationToken: Ct)).Value.Approval.State);
        var replayed = (await routed.CancelAsync(caller, first, meta)).Answer!;
        Assert.Equal(RoutedOutcome.Executed, replayed.Outcome);
        Assert.Equal(node.Runtime.Store.Read(reader => Approvals.Get(reader, approval.Value.Span))!.Outcome, replayed.Response!.ToByteArray());
        Assert.Equal(TaskState.Cancelled, (await Tasks.WaitAsync(human, first)).State);

        // An approval APPROVED but not yet executed: the same caller's duplicate is in progress (UNKNOWN), never a refusal; another caller is not
        // answered from it.
        var pending = Tasks.Meta();
        var other = (await routed.CancelAsync(caller, second, pending)).Answer!.Error!.Details.State.Resource.Id;
        await node.Runtime.Processor.ExecuteAsync(context => Approvals.Decide(context, other.Value.Span, approve: true, new ActorRef { Origin = Origin.Human }, "held"),
            CommitDurability.Full);
        var duplicate = (await routed.CancelAsync(caller, second, pending)).Answer!;
        var inProgress = TaskServiceCancelTaskResponse.Parser.ParseFrom(duplicate.Response).Error;
        Assert.Equal((RoutedOutcome.Executed, "operation_failed", EffectCertainty.Unknown, RetryMode.SameCommand, "command_in_progress", "EXECUTION/operation_failed"),
            (duplicate.Outcome, inProgress.Code, inProgress.Effect, inProgress.Retry.Mode, inProgress.Details.State.Reason, duplicate.HandlerCode));
        Assert.NotEqual(TaskState.Cancelled, (await Tasks.GetAsync(human, second)).State);
    }

    /// <summary>N2-2, N2-3 (MR-08), verifier N-7: the routed cancel of an ADOPTED task is denied whatever the policy, also after an approval.</summary>
    [Fact(Timeout = 180_000)]
    public async Task NoPolicyOrApprovalReachesTheRoutedCancelOfAnAdoptedTask()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var files = InProcessNode.Create();
        files.Clock = new RoutedWallClock();
        var human = new Caller(Origin.Human, ClientKind.Cli, null);
        var (queued, approval, requester) = await WithRoutedAdoptionAsync(files, seed: true, async fixture =>
        {
            var before = await fixture.ReadTaskAsync(human, fixture.AdoptedTaskId);
            Assert.Equal((TaskState.Running, TaskKind.Adopted, AttemptKind.Adopted), (before.State, before.Spec.Kind, before.CurrentAttempt.Kind));
            foreach (var caller in (CenterCaller[])[RoutedCalls.Session(), fixture.Relay(Origin.Human), fixture.Relay(Origin.Script), fixture.Relay(Origin.Agent)])
            {
                var denied = await fixture.CancelAsync(caller, fixture.AdoptedTaskId);
                Assert.Equal((RoutedOutcome.RefusedByPolicy, "permission_denied", PermissionMatrix.ProcessTerminate, EffectCertainty.DidNotHappen),
                    (denied.Outcome, denied.Error?.Code, denied.Error?.Details.State.State, denied.Error?.Effect));
                Assert.Contains(fixture.Runtime.Store.Read(reader => AuditLog.Recent(reader)), entry =>
                    entry.Operation == PermissionMatrix.ProcessTerminate + " TaskService.CancelTask" && entry.Decision == D
                    && entry.Actor.Origin == Origin.Remote && caller.Equals(entry.Actor.CenterCaller));
            }

            Assert.Equal(before, await fixture.ReadTaskAsync(human, fixture.AdoptedTaskId));
            Assert.Equal(0, fixture.Platform.Terminations);
            Assert.Equal(0L, fixture.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM approval;")));
            var task = await fixture.Runtime.Processor.ExecuteAsync(command => LegacyTaskHistoryFixture.SeedQueued(command.Transaction, human.Actor),
                CommitDurability.Full).WaitAsync(Ct);
            var session = RoutedCalls.Session();
            var pending = await fixture.CancelAsync(session, task);
            Assert.Equal((RoutedOutcome.RefusedByPolicy, "approval_required", PermissionMatrix.TaskCancelOthers),
                (pending.Outcome, pending.Error?.Code, pending.Error?.Details.State.State));
            var approvalId = pending.Error!.Details.State.Resource.Id;
            await fixture.Runtime.Processor.ExecuteAsync(command =>
            {
                var tx = command.Transaction;
                var spec = TaskRecords.GetRow(tx, task.Value.Span)!.Spec;
                spec.Kind = TaskKind.Adopted;
                var serialized = spec.ToByteArray();
                return tx.Execute("UPDATE task SET kind = $kind, spec = $spec, spec_digest = $digest WHERE task_id = $id;",
                    ("$kind", (int)TaskKind.Adopted), ("$spec", serialized), ("$digest", SHA256.HashData(serialized)), ("$id", task.Value.ToByteArray()));
            }, CommitDurability.Full).WaitAsync(Ct);
            return (task, approvalId, session);
        });

        // Verifier N-7: reopening the database preserves the pending approval and the target's new classification.
        await WithRoutedAdoptionAsync(files, seed: false, async fixture =>
        {
            var target = await fixture.ReadTaskAsync(human, queued);
            Assert.Equal((TaskKind.Adopted, TaskState.Queued), (target.Spec.Kind, target.State));
            var approvalId = approval.Value.ToByteArray();
            var pending = fixture.Runtime.Store.Read(reader => Approvals.Get(reader, approvalId));
            Assert.NotNull(pending);
            Assert.Equal(ApprovalState.Pending, pending.State);
            Assert.Equal(requester, pending.View.Requester.CenterCaller);
            var approved = await fixture.Runtime.Processor.ExecuteAsync(command =>
                Approvals.Decide(command, approvalId, approve: true, human.Actor, null), CommitDurability.Full).WaitAsync(Ct);
            Assert.Equal(ApprovalState.Approved, approved.State);
            await fixture.ApprovalHandler.ResumeAsync().WaitAsync(Ct);

            var completed = fixture.Runtime.Store.Read(reader => Approvals.Get(reader, approvalId));
            Assert.NotNull(completed);
            Assert.Equal(ApprovalState.Failed, completed.State);
            var refused = TaskServiceCancelTaskResponse.Parser.ParseFrom(completed.Outcome);
            Assert.Equal((ErrorCategory.Authorization, "permission_denied", EffectCertainty.DidNotHappen, RetryMode.Never),
                (refused.Error.Category, refused.Error.Code, refused.Error.Effect, refused.Error.Retry.Mode));
            Assert.Contains(PermissionMatrix.ProcessTerminate + " is denied for REMOTE callers", refused.Error.Details.State.Reason, StringComparison.Ordinal);
            Assert.Contains(fixture.Runtime.Store.Read(reader => AuditLog.Recent(reader)), entry =>
                entry.Operation == PermissionMatrix.ProcessTerminate + " TaskService.CancelTask" && entry.Decision == D
                && requester.Equals(entry.Actor.CenterCaller) && entry.TargetId.AsSpan().SequenceEqual(queued.Value.Span));
            Assert.Equal(target, await fixture.ReadTaskAsync(human, queued));
            Assert.Equal(0, fixture.Platform.Terminations);
            return true;
        });
    }

    /// <summary>
    /// N2-7, Q-5, decisions Q6: a historical task keeps its exact recorded bytes. Other bytes under the command ID,
    /// including a re-encoded equivalent, are <c>command_id_reused</c>.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task ARoutedSubmitDeduplicatesByTheExactBytesAndReplaysTheRecordedOutcome()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        var routed = new RoutedCalls(node);
        var caller = routed.Relay(Origin.Script);
        var spec = Tasks.Argv(node.Root, "historical-fixture-no-launch");
        spec.Labels["a"] = "1";
        spec.Labels["b"] = "2";
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec };
        var retained = await SeedHistoricalSubmitAsync(node, caller, request);
        var first = (await routed.SubmitAsync(caller, request)).Answer!;
        Assert.Equal(RoutedOutcome.Executed, first.Outcome);
        Assert.Equal(retained.ToByteArray(), first.Response!.ToByteArray());

        // The same bytes under a new call ID (and a new local session of the same origin): the recorded bytes, exactly.
        var again = (await routed.SubmitAsync(routed.Relay(Origin.Script), request)).Answer!;
        Assert.Equal(first.Response!.ToByteArray(), again.Response!.ToByteArray());

        // A new correlation ID: the same outcome outside the volatile fields (the center's OutcomeDigest).
        var correlated = request.Clone();
        correlated.Meta.CorrelationId = CommandIds.New();
        var other = (await routed.SubmitAsync(caller, correlated)).Answer!;
        Assert.Equal(RoutedCalls.OutcomeDigest(first.Response.Span), RoutedCalls.OutcomeDigest(other.Response!.Span));

        // A different caller class first takes its normal policy path, then receives a conflict instead of the other caller's outcome.
        var session = (await routed.SubmitAsync(RoutedCalls.Session(), request)).Response!;
        Assert.Equal("command_id_reused", session.Error?.Code);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));

        // Other bytes: another request, and the same message re-encoded with its spec's fields in another order.
        var changed = request.Clone();
        changed.Spec.Title = "another";
        Assert.Equal("command_id_reused", TaskServiceSubmitTaskResponse.Parser.ParseFrom((await routed.SubmitAsync(caller, changed)).Answer!.Response).Error?.Code);
        var reordered = Reorder(request);
        var parsed = TaskServiceSubmitTaskRequest.Parser.ParseFrom(reordered);
        Assert.Equal(request, parsed);
        Assert.NotEqual(request.ToByteArray(), reordered);
        Assert.Equal(request.ToByteArray(), parsed.ToByteArray()); // a re-encoder would erase exactly this wire-order difference
        var reencoded = (await routed.SubmitAsync(caller, request, raw: reordered)).Answer!;
        Assert.Equal("command_id_reused", TaskServiceSubmitTaskResponse.Parser.ParseFrom(reencoded.Response).Error?.Code);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));

        // N2-8: across a restart.
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var restarted = (await new RoutedCalls(node).SubmitAsync(caller, request)).Answer!;
        Assert.Equal(first.Response.ToByteArray(), restarted.Response!.ToByteArray());
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
    }

    /// <summary>Review B-2: earlier pending or no-effect calls never own a later committed outcome of another caller class.</summary>
    [Fact(Timeout = 180_000)]
    public async Task APreEffectFailureCannotClaimAnotherCallersLaterOutcome()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        var routed = new RoutedCalls(node);
        var earlier = routed.Relay(Origin.Script);
        var executing = RoutedCalls.Session();
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, "historical-fixture-no-launch") };

        routed.Link.Reset(notStoppingFor: 0);
        Assert.Equal("node_stopping", (await routed.SubmitAsync(earlier, request)).Response!.Error?.Code);
        routed.Link.Reset();
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;",
            ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        var retained = await SeedHistoricalSubmitAsync(node, executing, request);
        var first = (await routed.SubmitAsync(executing, request)).Response!;
        Assert.Equal(retained, first);
        var sameClass = (await routed.SubmitAsync(RoutedCalls.Session(), request)).Response!;
        Assert.Equal(first.Value.TaskId, sameClass.Value.TaskId);
        var wrongClass = (await routed.SubmitAsync(earlier, request)).Response!;
        Assert.Equal("command_id_reused", wrongClass.Error?.Code);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
    }

    /// <summary>Review B-2: none of the four approval states may expose a different caller class's approval or recorded outcome.</summary>
    [Theory(Timeout = 180_000)]
    [InlineData(true, ApprovalState.Pending)]
    [InlineData(true, ApprovalState.Approved)]
    [InlineData(true, ApprovalState.Executed)]
    [InlineData(true, ApprovalState.Failed)]
    [InlineData(false, ApprovalState.Pending)]
    [InlineData(false, ApprovalState.Approved)]
    [InlineData(false, ApprovalState.Executed)]
    [InlineData(false, ApprovalState.Failed)]
    public async Task AnotherCallerClassCannotReadAnApprovalsStateOrOutcome(bool ownerIsRelay, ApprovalState state)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var task = await SeedHumanQueueAsync(node);
        var routed = new RoutedCalls(node);
        var owner = ownerIsRelay ? routed.Relay(Origin.Script) : RoutedCalls.Session();
        var foreign = ownerIsRelay ? RoutedCalls.Session() : routed.Relay(Origin.Script);
        var meta = Tasks.Meta();
        var raised = (await routed.CancelAsync(owner, task, meta)).Answer!;
        Assert.Equal("approval_required", raised.Error?.Code);
        var approvalId = raised.Error!.Details.State.Resource.Id;

        if (state is not ApprovalState.Pending)
        {
            await node.Runtime.Processor.ExecuteAsync(context => Approvals.Decide(context, approvalId.Value.Span, approve: true, new ActorRef { Origin = Origin.Human }, "test"),
                CommitDurability.Full);
        }

        if (state is ApprovalState.Executed or ApprovalState.Failed)
        {
            var error = ArcForges.Node.Core.NodeErrors.InvalidArgument("synthetic recorded outcome");
            var bytes = new TaskServiceCancelTaskResponse { Error = error }.ToByteArray();
            await node.Runtime.Processor.ExecuteAsync(context => Approvals.Executed(context, approvalId.Value.Span, bytes,
                state == ApprovalState.Failed ? error : null, PermissionMatrix.TaskCancelOthers), CommitDurability.Full);
        }

        var foreignAnswer = await routed.CancelAsync(foreign, task, meta);
        Assert.Equal("command_id_reused", foreignAnswer.Response?.Error?.Code ?? foreignAnswer.Answer?.Error?.Code);
        var stored = node.Runtime.Store.Read(reader => Approvals.ByCommand(reader, meta.CommandId.Value.Span))!;
        Assert.Equal((state, approvalId), (stored.State, stored.View.ApprovalId));
        Assert.NotEqual(TaskState.Cancelled, (await Tasks.GetAsync(human, task)).State);
    }

    /// <summary>A stopped node refuses even a recorded replay before looking up the previous outcome (decisions B-2 and B-3).</summary>
    [Fact(Timeout = 180_000)]
    public async Task ARecordedRoutedCommandIsNotReplayedAfterStopping()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        var routed = new RoutedCalls(node);
        var caller = RoutedCalls.Session();
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, "historical-fixture-no-launch") };
        var retained = await SeedHistoricalSubmitAsync(node, caller, request);
        Assert.Equal(retained, (await routed.SubmitAsync(caller, request)).Response);

        routed.Link.Reset(notStoppingFor: 0);
        var stopped = (await routed.SubmitAsync(caller, request)).Response!.Error;
        Assert.Equal(("node_stopping", EffectCertainty.DidNotHappen, RetryMode.AfterTime), (stopped?.Code, stopped?.Effect, stopped?.Retry.Mode));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
    }

    /// <summary>A different caller cannot use another caller's recorded command to bypass the routed policy gate.</summary>
    [Theory(Timeout = 180_000)]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ARecordedRoutedCommandDoesNotBypassAnotherCallersPolicy(bool adopted)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        var routed = new RoutedCalls(node);
        var owner = RoutedCalls.Session();
        var other = RoutedCalls.Session();
        other.UserId = CommandIds.New();
        var task = new Id { Value = ByteString.CopyFrom(await node.Runtime.Processor.ExecuteAsync(context => GateAndReplayTests.SeedAdopted(context, node.Runtime.NodeId.ToArray()))) };
        if (!adopted)
        {
            // Exercise the approval cell as well as the fixed adopted-process deny; no effect is executed in this fixture.
            await node.Runtime.Processor.ExecuteAsync(context => context.Transaction.Execute("UPDATE task SET kind = $kind WHERE task_id = $id;",
                ("$kind", (int)TaskKind.Command), ("$id", task.Value.ToByteArray())));
        }

        var request = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = task };
        var bytes = request.ToByteArray();
        var digest = PayloadDigest.Compute(bytes);

        // Seed a recorded prior outcome and its verified caller. The adopted task remains active, so the other caller must reach process.terminate's fixed denial.
        var log = new RoutedCallLog(new ProcessorRoutedCallStore(node.Runtime.Processor), node.Runtime.Clock);
        var prior = await log.RecordVerifiedAsync(new VerifiedCallRow
        {
            FrameSha256 = System.Security.Cryptography.SHA256.HashData(bytes),
            CallId = CommandIds.New().Value.ToByteArray(),
            Kid = "routed-test-key",
            Method = (int)RoutedMethod.CancelNodeTask,
            Caller = owner.ToByteArray(),
            CommandId = request.Meta.CommandId.Value.ToByteArray(),
            RequestSha256 = System.Security.Cryptography.SHA256.HashData(bytes),
            RequestSize = bytes.Length,
        });
        Assert.NotNull(prior);
        var result = new TaskServiceCancelTaskResponse { Value = new TaskServiceCancelTaskValue { State = TaskState.Running } }.ToByteArray();
        await node.Runtime.Processor.ExecuteIdempotentAsync(request.Meta.CommandId.Value.Memory, "arcforges.node.v1.TaskService/CancelTask", digest,
            Origin.Remote, _ => result, afterComplete: context => RoutedCommandOwnership.Record(context.Transaction, request.Meta.CommandId.Value.Span,
                new ActorRef { Origin = Origin.Remote, CenterCaller = owner, RemoteCommandId = request.Meta.CommandId }));
        await log.CompleteAsync(prior.Value, RoutedCallDecision.Executed, null, task.Value.ToByteArray(), 2,
            System.Security.Cryptography.SHA256.HashData(result), result.Length);

        var (answer, _) = await routed.CallAsync(other, RoutedMethod.CancelNodeTask, bytes, request.Meta.CommandId);
        if (adopted)
        {
            Assert.Equal((RoutedOutcome.RefusedByPolicy, "permission_denied", PermissionMatrix.ProcessTerminate),
                (answer!.Outcome, answer.Error?.Code, answer.Error?.Details.State.State));
        }
        else
        {
            // The approval cell is evaluated, but another requester's recorded command cannot raise or reveal an approval.
            Assert.Equal("command_id_reused", TaskServiceCancelTaskResponse.Parser.ParseFrom(answer!.Response).Error?.Code);
        }
    }

    /// <summary>Decisions B-2: a duplicate while the retained Task's Cancel is admitted answers UNKNOWN before the original settles.</summary>
    [Fact(Timeout = 180_000)]
    public async Task ADuplicateCancelWhileTheFirstIsAdmittedAnswersEffectUnknownAndNeverFinal()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var caller = RoutedCalls.Session();
        var taskId = await SeedOwnedQueueAsync(node, caller);
        var request = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId };
        var bytes = request.ToByteArray();
        Task<(RoutedAnswer? Answer, long LogId)> Call(bool record = false) =>
            routed.CallAsync(caller, RoutedMethod.CancelNodeTask, bytes, request.Meta.CommandId, record: record, cancellationToken: ct);

        // The writer is held, so the first call waits in its admission.
        using var hold = new ManualResetEventSlim();
        var held = node.Runtime.Processor.ExecuteAsync(_ =>
        {
            hold.Wait(TimeSpan.FromSeconds(45), ct);
            return 0;
        });
        var first = Call();
        try
        {
            await Tasks.WaitForAsync(() => node.Runtime.Processor.Queued >= 1, TimeSpan.FromSeconds(30), "the first cancellation to wait for the writer");
            var duplicate = (await Call()).Answer!;
            var error = TaskServiceCancelTaskResponse.Parser.ParseFrom(duplicate.Response).Error;
            Assert.Equal((RoutedOutcome.Executed, "operation_failed", EffectCertainty.Unknown, RetryMode.SameCommand, "command_in_progress"),
                (duplicate.Outcome, error?.Code, error?.Effect ?? EffectCertainty.Unspecified, error?.Retry.Mode ?? RetryMode.Unspecified, error?.Details.State.Reason));

            // Once stopping begins, even a duplicate of an in-progress command is refused before replay/in-progress lookup.
            routed.Link.Reset(notStoppingFor: 0);
            var afterStop = TaskServiceCancelTaskResponse.Parser.ParseFrom((await Call()).Answer!.Response).Error;
            Assert.Equal(("node_stopping", EffectCertainty.DidNotHappen, RetryMode.AfterTime), (afterStop?.Code, afterStop?.Effect, afterStop?.Retry.Mode));
            routed.Link.Reset();
        }
        finally
        {
            hold.Set();
        }

        await held.WaitAsync(ct);
        var done = (await first.WaitAsync(ct)).Answer!;
        var completed = TaskServiceCancelTaskResponse.Parser.ParseFrom(done.Response);
        Assert.Null(completed.Error);
        Assert.Equal(TaskState.Cancelled, completed.Value.State);
        var resent = (await Call(record: true)).Answer!;
        Assert.Equal(RoutedCalls.OutcomeDigest(done.Response!.Span), RoutedCalls.OutcomeDigest(resent.Response!.Span));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
    }

    /// <summary>Retained Cancel keeps the B-1/B-3 effect, link, stopping and expiry boundaries.</summary>
    [Fact(Timeout = 180_000)]
    public async Task RoutedCancelChecksTheLinkAndExpiryBeforeChangingARetainedTask()
    {
        var ct = TestContext.Current.CancellationToken;
        var clock = new RoutedWallClock();
        await using var node = InProcessNode.Create();
        node.Clock = clock;
        await node.StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var caller = RoutedCalls.Session();
        var first = await SeedOwnedQueueAsync(node, caller);
        var second = await SeedOwnedQueueAsync(node, caller);
        var third = await SeedOwnedQueueAsync(node, caller);
        TaskServiceCancelTaskRequest Request(Id task) => new() { Meta = Tasks.Meta(), TaskId = task };
        long Receipts() => (long)node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE method = 'arcforges.node.v1.TaskService/CancelTask';"))!;
        (long Decision, string? Code) Row(long logId) => node.Runtime.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("SELECT decision, refusal_code FROM routed_call_log WHERE log_id = $id;");
            command.Parameters.AddWithValue("$id", logId);
            using var row = command.ExecuteReader();
            Assert.True(row.Read());
            return (row.GetInt64(0), row.IsDBNull(1) ? null : row.GetString(1));
        });
        Task<(RoutedAnswer? Answer, long LogId)> Call(TaskServiceCancelTaskRequest request, Id? headerId = null,
            DateTimeOffset? expires = null, bool record = true) =>
            routed.CallAsync(caller, RoutedMethod.CancelNodeTask, request.ToByteArray(), headerId ?? request.Meta.CommandId, expires, record, ct);

        async Task<RoutedAnswer?> CrossWriterExpiryAsync(TaskServiceCancelTaskRequest request, TimeSpan afterExpiry)
        {
            using var release = new ManualResetEventSlim();
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var processor = node.Runtime.Processor;
            var held = processor.ExecuteAsync(_ =>
            {
                entered.SetResult();
                Assert.True(release.Wait(TimeSpan.FromSeconds(45), ct));
                return 0;
            });
            Task<(RoutedAnswer? Answer, long LogId)> pending;
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(20), ct);
                var enqueued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                processor.EnqueuedForTests = new Dictionary<string, TaskCompletionSource>(StringComparer.Ordinal)
                {
                    [Convert.ToHexString(request.Meta.CommandId.Value.Span)] = enqueued,
                };
                var lifetime = TimeSpan.FromMinutes(1);
                var expires = clock.GetUtcNow() + lifetime;
                // This seam starts after verification. Skip its log write so Cancel can reach the held writer.
                pending = Call(request, expires: expires, record: false);
                await enqueued.Task.WaitAsync(TimeSpan.FromSeconds(20), ct);
                Assert.False(pending.IsCompleted);
                clock.Advance(lifetime + afterExpiry);
            }
            finally
            {
                release.Set();
                processor.EnqueuedForTests = null;
                await held;
            }

            return (await pending.WaitAsync(ct)).Answer;
        }

        static TaskServiceCancelTaskResponse Result(RoutedAnswer? answer)
        {
            Assert.NotNull(answer);
            Assert.Equal(RoutedOutcome.Executed, answer.Outcome);
            return TaskServiceCancelTaskResponse.Parser.ParseFrom(Assert.IsType<ByteString>(answer.Response));
        }

        var invalid = Request(first);
        invalid.GraceMs = 300_001;
        var refused = Result((await Call(invalid)).Answer).Error;
        Assert.Equal(("invalid_argument", EffectCertainty.DidNotHappen), (refused.Code, refused.Effect));
        Assert.Equal(0L, Receipts());

        var (wrong, wrongLog) = await Call(Request(first), headerId: CommandIds.New());
        var mismatch = Result(wrong).Error;
        Assert.Equal(("invalid_argument", EffectCertainty.DidNotHappen), (mismatch.Code, mismatch.Effect));
        Assert.Equal((1L, "VALIDATION/invalid_argument"), Row(wrongLog));

        var stopped = Request(first);
        routed.Link.Reset(notStoppingFor: 0);
        var stopping = Result((await Call(stopped)).Answer).Error;
        Assert.Equal(("node_stopping", EffectCertainty.DidNotHappen, RetryMode.AfterTime, true),
            (stopping.Code, stopping.Effect, stopping.Retry.Mode, stopping.Retry.RetryAt is not null));
        routed.Link.Reset(notStoppingFor: 1);
        Assert.Equal("node_stopping", Result((await Call(stopped)).Answer).Error.Code);
        Assert.Equal(0L, Receipts());
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(human, first)).State);
        routed.Link.Reset();
        var cancelled = Result((await Call(stopped)).Answer);
        Assert.Null(cancelled.Error);
        Assert.Equal(TaskState.Cancelled, cancelled.Value.State);
        Assert.Equal(1L, Receipts());

        // A link ending before the writer checks the call leaves its log pending and the Task unchanged.
        routed.Link.Reset(usableFor: 2);
        var (dropped, droppedLog) = await Call(Request(second));
        Assert.Null(dropped);
        Assert.Equal((5L, (string?)null), Row(droppedLog));
        Assert.Equal(1L, Receipts());
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(human, second)).State);
        routed.Link.Reset();

        var late = Result(await CrossWriterExpiryAsync(Request(second), CallVerifier.Skew / 2));
        Assert.Null(late.Error);
        Assert.Equal(TaskState.Cancelled, late.Value.State);
        var original = await Tasks.GetAsync(human, third);
        var request = Request(third);
        var expired = await CrossWriterExpiryAsync(request, CallVerifier.Skew + TimeSpan.FromSeconds(1));
        Assert.NotNull(expired);
        Assert.Equal(RoutedOutcome.Expired, expired.Outcome);
        Assert.Null(expired.Response);
        Assert.Equal(("expired", "expired_before_effect", EffectCertainty.DidNotHappen),
            (expired.Error?.Code, expired.Error?.Details.State.Reason, expired.Error?.Effect));
        var unchanged = await Tasks.GetAsync(human, third);
        Assert.Equal(third, unchanged.TaskId);
        Assert.Equal(TaskState.Queued, unchanged.State);
        Assert.Equal(original.Revision, unchanged.Revision);
        Assert.Equal(caller, unchanged.Owner.CenterCaller);
        Assert.Equal(original.Owner, unchanged.Owner);
        Assert.Equal(2L, Receipts());
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;",
            ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        Assert.Equal(3L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
    }

    /// <summary>N2-12 (CTR5-NODE-12): routed output by offset, other owners' output only by policy, the routed cap, and waits within the deadline.</summary>
    // This asserts a four-second observation bound on a three-second routed wait; run in the existing timing-sensitive tier.
    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RoutedOutputIsReadByOffsetWithinTheCapAndTheDeadline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished);
        var (waitingTaskId, waitingAttemptId) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished);
        var files = Tasks.Files(node, attemptId);
        var output = Enumerable.Range(0, 4096).Select(index => (byte)(index % 251)).ToArray();
        Directory.CreateDirectory(files.Directory);
        File.WriteAllBytes(files.StdoutPath, output);
        var index = new byte[OutputIndexRecord.Size];
        new OutputIndexRecord(OutputStreamKind.Stdout, 0, (uint)output.Length, 1_700_000_000_000_000_000, OutputChunkMarks.None).Write(index);
        File.WriteAllBytes(files.IndexPath, index);

        await node.StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var routed = new RoutedCalls(node);
        var owner = RoutedCalls.Session();
        await node.Runtime.Processor.ExecuteAsync(command => command.Transaction.Execute(
            "UPDATE task SET owner = $owner, owner_origin = $origin WHERE task_id = $id;",
            ("$owner", new ActorRef { Origin = Origin.Remote, CenterCaller = owner }.ToByteArray()),
            ("$origin", (int)Origin.Remote), ("$id", taskId.Value.ToByteArray())), CommitDurability.Full).WaitAsync(Ct);

        var task = await Tasks.GetAsync(human, taskId);
        Assert.Equal(TaskState.Succeeded, task.State);
        Assert.Equal(attemptId, task.CurrentAttempt.AttemptId);
        var read = new TaskServiceReadTaskOutputRequest { Meta = Tasks.Meta(), AttemptId = attemptId, FromOffset = 1000, MaxBytes = 100 };
        var own = (await routed.ReadAsync(owner, RoutedMethod.ReadNodeTaskOutput, read, TaskServiceReadTaskOutputResponse.Parser)).Response!.Value;
        Assert.Equal((100, 1100UL), (own.Data.Length, own.NextOffset));
        Assert.Equal(output[1000..1100], own.Data.ToByteArray());
        var others = (await routed.ReadAsync(RoutedCalls.Session(), RoutedMethod.ReadNodeTaskOutput, read, TaskServiceReadTaskOutputResponse.Parser)).Answer!;
        Assert.Equal((RoutedOutcome.RefusedByPolicy, PermissionMatrix.TaskReadOutput, "remote_output_tail_off"),
            (others.Outcome, others.Error?.Details.State.State, others.Error?.Details.State.Reason));
        var large = read.Clone();
        large.MaxBytes = 262_145;
        Assert.Equal("invalid_argument", (await routed.ReadAsync(owner, RoutedMethod.ReadNodeTaskOutput, large, TaskServiceReadTaskOutputResponse.Parser)).Response!.Error?.Code);
        Assert.Null((await human.Tasks.ReadTaskOutputAsync(large, cancellationToken: Ct)).Error);

        // The second synthetic attempt has no output. Expose its active metadata only during the two wait observations.
        Task SetFinishedAsync(bool finished) => node.Runtime.Processor.ExecuteAsync(command =>
        {
            var transaction = command.Transaction;
            var end = finished ? transaction.NowMicroseconds : (long?)null;
            transaction.Execute("UPDATE task SET state = $state, finished_at = $end WHERE task_id = $id;",
                ("$state", (int)(finished ? TaskState.Succeeded : TaskState.Running)), ("$end", end), ("$id", waitingTaskId.Value.ToByteArray()));
            transaction.Execute("""
                UPDATE attempt SET state = $state, finished_at = $end, exit_code = $exit, termination_reason = $reason, effect = $effect
                WHERE attempt_id = $id;
                """, ("$state", (int)(finished ? AttemptState.Finished : AttemptState.Running)), ("$end", end),
                ("$exit", finished ? 0 : (int?)null), ("$reason", finished ? (int)TerminationReason.Exited : (int?)null),
                ("$effect", finished ? (int)EffectCertainty.Happened : (int?)null), ("$id", waitingAttemptId.Value.ToByteArray()));
            return 0;
        }, CommitDurability.Full);

        try
        {
            await SetFinishedAsync(finished: false).WaitAsync(Ct);
            var wait = new TaskServiceReadTaskOutputRequest { Meta = Tasks.Meta(), AttemptId = waitingAttemptId, FromOffset = 1_000_000, WaitMs = 1_500 };
            var clock = Stopwatch.StartNew();
            var waiting = await human.Tasks.ReadTaskOutputAsync(wait, cancellationToken: Ct);
            Assert.Null(waiting.Error);
            Assert.Empty(waiting.Value.Data);
            Assert.False(waiting.Value.Eof);
            Assert.InRange(clock.Elapsed, TimeSpan.FromMilliseconds(1_200), TimeSpan.FromSeconds(10));
            var waitTask = new TaskServiceWaitTaskRequest { Meta = Tasks.Meta(), TaskId = waitingTaskId, WaitMs = 20_000 };
            clock.Restart();
            var (bounded, _) = await routed.CallAsync(RoutedCalls.Session(), RoutedMethod.WaitNodeTask, waitTask.ToByteArray(), null,
                node.Runtime.Clock.GetUtcNow().AddSeconds(3));
            Assert.Equal(RoutedOutcome.Executed, bounded!.Outcome);
            var value = TaskServiceWaitTaskResponse.Parser.ParseFrom(bounded.Response).Value;
            Assert.False(value.Reached);
            Assert.Equal(waitingTaskId, value.Task.TaskId);
            Assert.Equal(waitingAttemptId, value.Task.CurrentAttempt.AttemptId);
            TestContext.Current.TestOutputHelper?.WriteLine($"routed-wait elapsed-ms={clock.Elapsed.TotalMilliseconds:F3}; original bound=4000ms");
            Assert.InRange(clock.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(4));
            Assert.Empty(node.Runtime.Execution!.RunningAttempts);
        }
        finally
        {
            await SetFinishedAsync(finished: true);
        }
    }

    /// <summary>Legacy local Submit retains its origin gate, and diagnostic labels remain readable on historical Tasks.</summary>
    [Fact(Timeout = 180_000)]
    public async Task LegacyLocalSubmissionRetainsItsOriginGateAndHistoricalDiagnosticLabels()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var created = InProcessNode.Create();
        created.AllowLocalScriptSubmit = false;
        await using var node = await created.StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        await using var bare = NodeChannel.Create(node.Endpoint);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var spec = Tasks.Argv(node.Root, "historical-fixture-no-launch");
        foreach (var channel in (NodeChannel[])[script, agent, bare])
        {
            var refused = (await Tasks.SubmitRawAsync(channel, spec)).Error;
            Assert.Equal(("permission_denied", "task.submit", "local_submission_human_only", EffectCertainty.DidNotHappen),
                (refused?.Code, refused?.Details.State.State, refused?.Details.State.Reason, refused?.Effect ?? EffectCertainty.Unspecified));
        }

        AssertRetiredSubmit(await Tasks.SubmitRawAsync(human, spec));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        var local = await node.Runtime.Processor.ExecuteAsync(command =>
        {
            var task = LegacyTaskHistoryFixture.SeedQueued(command.Transaction, new ActorRef { Origin = Origin.Human });
            command.Transaction.Execute("UPDATE task SET local_diagnostic = 1, state = $done, finished_at = $now WHERE task_id = $id;",
                ("$done", (int)TaskState.Succeeded), ("$now", command.Transaction.NowMicroseconds), ("$id", task.Value.ToByteArray()));
            return task;
        }, CommitDurability.Full).WaitAsync(Ct);
        Assert.True((await Tasks.GetAsync(human, local)).LocalDiagnostic);
        var retained = await SeedHistoricalSubmitAsync(node, RoutedCalls.Session(), new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec });
        Assert.False((await Tasks.GetAsync(human, retained.Value.TaskId)).HasLocalDiagnostic);

        // CTR5-NODE-14: the allowance holds only in test mode and only for exactly "1".
        Assert.True(LocalSubmission.ScriptAllowed(testMode: true, "1"));
        Assert.False(LocalSubmission.ScriptAllowed(testMode: false, "1"));
        Assert.False(LocalSubmission.ScriptAllowed(testMode: true, "true"));
        Assert.False(LocalSubmission.ScriptAllowed(testMode: true, null));
    }

    private static Task<Id> SeedHumanQueueAsync(InProcessNode node) => node.Runtime.Processor.ExecuteAsync(command =>
        LegacyTaskHistoryFixture.SeedQueued(command.Transaction, new ActorRef { Origin = Origin.Human }), CommitDurability.Full).WaitAsync(Ct);

    private static Task<Id> SeedOwnedQueueAsync(InProcessNode node, CenterCaller owner) => node.Runtime.Processor.ExecuteAsync(command =>
        LegacyTaskHistoryFixture.SeedQueued(command.Transaction, new ActorRef { Origin = Origin.Remote, CenterCaller = owner }), CommitDurability.Full).WaitAsync(Ct);

    private static async Task<T> WithRoutedAdoptionAsync<T>(InProcessNode files, bool seed, Func<RoutedAdoptionFixture, Task<T>> verify)
    {
        const string fixtureBoot = "linux:532cb2f3-6b2a-48af-a8ca-3b72ac02ecb1";
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = files.DataRoot, BootIdentity = fixtureBoot, Clock = files.Clock });
        using var log = new NodeLog(Path.Combine(files.DataRoot, "logs", "node"), LogLevel.Info, files.Clock);
        using var heartbeat = new NodeHeartbeatWriter(files.DataRoot, log, files.Clock);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        if (seed)
        {
            await processor.ExecuteAsync(command =>
            {
                Tasks.SeedPolicy(command.Transaction, policy =>
                {
                    policy.Permissions.Add(new PermissionOverride { Operation = PermissionMatrix.ProcessTerminate, Origin = Origin.Script, Decision = A });
                    policy.Permissions.Add(new PermissionOverride { Operation = PermissionMatrix.ProcessTerminate, Origin = Origin.Agent, Decision = A });
                });
                var adopted = GateAndReplayTests.SeedAdopted(command, store.Metadata.NodeId.ToArray());
                return command.Transaction.Execute("UPDATE attempt SET container_name = $name, boot_identity = $boot, root_pid = $pid WHERE task_id = $id;",
                    ("$name", RoutedAdoptionPlatform.RecordedName), ("$boot", store.Metadata.BootIdentity), ("$pid", RoutedAdoptionPlatform.RecordedPid), ("$id", adopted));
            }, CommitDurability.Full).WaitAsync(Ct);
        }

        using var platform = new RoutedAdoptionPlatform();
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = files.Clock,
            DataRoot = files.DataRoot,
            Platform = platform,
            Heartbeat = heartbeat,
        });
        var recovery = new RecoveryReport(!seed, false, null, store.Opening);
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(files.ConfigPath, files.DataRoot, log), files.DataRoot, "routed-adoption-fixture", files.Clock,
            recovery, new CapabilityReport())
        { Execution = execution };
        await runtime.TransitionAsync(NodeLifecycleState.Recovering, "fixture").WaitAsync(Ct);
        await execution.RecoverAsync(recovery, processor, Ct);
        await runtime.TransitionAsync(NodeLifecycleState.Ready, "fixture").WaitAsync(Ct);
        Assert.Equal(1, platform.Reopens);
        Assert.Single(execution.Adoptions.Tracked);
        var sessions = new ClientSessions();
        var executors = new ApprovalExecutors();
        var tasks = new TaskServiceHandler(runtime, sessions, executors);
        var approvals = new ApprovalServiceHandler(runtime, sessions, executors);
        using var dispatcher = new RoutedDispatcher(runtime);
        dispatcher.Bind(tasks, new WorkspaceServiceHandler(runtime), new FileServiceHandler(runtime));
        var taskId = store.Read(reader => new Id
        {
            Value = ByteString.CopyFrom((byte[])reader.Scalar("SELECT task_id FROM attempt WHERE container_name = $name;",
                ("$name", RoutedAdoptionPlatform.RecordedName))!),
        });
        return await verify(new RoutedAdoptionFixture(runtime, tasks, approvals, dispatcher, platform, taskId));
    }

    private sealed record RoutedAdoptionFixture(NodeRuntime Runtime, TaskServiceHandler TaskHandler, ApprovalServiceHandler ApprovalHandler,
        RoutedDispatcher Dispatcher, RoutedAdoptionPlatform Platform, Id AdoptedTaskId)
    {
        public CenterCaller Relay(Origin origin) => new()
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = RoutedCalls.Account.Clone(),
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(Runtime.NodeId.Span) },
            LocalOrigin = origin,
            LocalSessionId = CommandIds.New(),
        };

        public async Task<ManagedTask> ReadTaskAsync(Caller caller, Id taskId)
        {
            var response = await TaskHandler.GetTask(caller, new TaskServiceGetTaskRequest { TaskId = taskId, Detail = TaskDetail.Full }, Ct);
            Assert.Null(response.Error);
            return response.Value.Task;
        }

        public async Task<RoutedAnswer> CancelAsync(CenterCaller caller, Id taskId)
        {
            var request = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId };
            var payload = request.ToByteString();
            var now = Runtime.Clock.GetUtcNow();
            var header = new CallHeader
            {
                CallId = CommandIds.New(),
                Caller = caller,
                AccountId = caller.AccountId,
                TargetNodeId = new Id { Value = ByteString.CopyFrom(Runtime.NodeId.Span) },
                CommandId = request.Meta.CommandId,
                Method = RoutedMethod.CancelNodeTask,
                RequestSha256 = ByteString.CopyFrom(SHA256.HashData(payload.Span)),
                RequestSize = (uint)payload.Length,
                IssuedAt = ProtoTime.ToInstant(now.AddSeconds(-1)),
                ExpiresAt = ProtoTime.ToInstant(now.AddSeconds(60)),
                Deadline = ProtoTime.ToInstant(now.AddSeconds(10)),
            };
            return Assert.IsType<RoutedAnswer>(
                await Dispatcher.DispatchAsync(new VerifiedCall(header, payload, 0), new RoutedCalls.TestLink(), Ct));
        }
    }

    private sealed class RoutedAdoptionPlatform : IExecutionPlatform, IAdoptedContainer
    {
        public const string RecordedName = "routed-adoption-fixture";
        public const int RecordedPid = int.MaxValue;
        public int Reopens { get; private set; }
        public int Terminations { get; private set; }
        public string Name => RecordedName;
        public string ContainerName => RecordedName;
        public MachineCapacity Capacity => new(4, 1L << 30);

        public IAdoptedContainer ReopenAdopted(string containerName)
        {
            Assert.Equal(RecordedName, containerName);
            Reopens++;
            return this;
        }

        public IReadOnlyList<int> Processes() => [RecordedPid];
        public void Terminate() => Terminations++;
        public CapabilityReport Evaluate() => new();
        public void UpdateRootLimits(RootLimits limits) { }
        public bool AcknowledgeRecorded(string nodeName, string attemptName) => false;
        public IAttemptHandle? Reopen(string nodeName, AttemptFiles files, RootProcess? root, bool stopping) => throw new NotSupportedException();
        public void Start(string nodeName, RootLimits limits, string helperExecutable) => throw new NotSupportedException();
        public void Dispose() { }
    }

    private sealed class RoutedWallClock : TimeProvider
    {
        private long _utcTicks = DateTimeOffset.UtcNow.Ticks;

        public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);

        public void Advance(TimeSpan elapsed) => Interlocked.Add(ref _utcTicks, elapsed.Ticks);
    }

    private static Task<TaskServiceSubmitTaskResponse> SeedHistoricalSubmitAsync(InProcessNode node, CenterCaller owner,
        TaskServiceSubmitTaskRequest request, bool retainQueued = false, string? historicalWarning = null) =>
        node.Runtime.Processor.ExecuteAsync(command =>
        {
            var tx = command.Transaction;
            var id = request.Meta.CommandId;
            var actor = new ActorRef { Origin = Origin.Remote, ClientKind = ClientKind.Unspecified, CenterCaller = owner, RemoteCommandId = id };
            var task = LegacyTaskHistoryFixture.SeedQueued(tx, actor);
            var spec = request.Spec;
            var storedSpec = spec.ToByteArray();
            var summary = CommandText.Summary(spec.Command, SecretNameMatcher.Default);
            var title = spec.HasTitle ? spec.Title : summary;
            var labels = JsonSerializer.Serialize(new Dictionary<string, string>(spec.Labels, StringComparer.Ordinal),
                ExecutionJsonContext.Default.DictionaryStringString);
            tx.Execute("""
                UPDATE task SET remote_command_id = $id, spec = $spec, spec_digest = $digest, title = $title, command_summary = $summary,
                                labels_json = $labels, command_fingerprint = $fingerprint, command_digest = $commandDigest
                WHERE task_id = $task;
                """, ("$id", id.Value.ToByteArray()), ("$spec", storedSpec), ("$digest", SHA256.HashData(storedSpec)),
                ("$title", title), ("$summary", summary), ("$labels", labels), ("$fingerprint", CommandText.Fingerprint(spec.Command)),
                ("$commandDigest", CommandText.Digest(spec, [])), ("$task", task.Value.ToByteArray()));
            var queued = TaskRecords.GetTask(tx, task.Value.Span, full: true);
            Assert.NotNull(queued);
            Assert.Equal(TaskState.Queued, queued.State);
            Assert.Equal(spec, queued.Spec);
            Assert.Equal((title, summary), (queued.Title, queued.CommandSummary));
            Assert.Equal(spec.Labels, queued.Labels);
            Assert.NotNull(queued.Queue);
            var outcome = new TaskServiceSubmitTaskResponse
            {
                Meta = new() { CorrelationId = request.Meta.CorrelationId },
                Value = new()
                {
                    TaskId = queued.TaskId,
                    State = queued.State,
                    Queue = queued.Queue,
                    Receipt = new Receipt { CommandId = id, Effect = EffectCertainty.Happened },
                },
            };
            if (historicalWarning is not null)
            {
                outcome.Value.Warnings.Add(historicalWarning);
            }

            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, id.Value.Span, "arcforges.node.v1.TaskService/SubmitTask",
                PayloadDigest.Compute(request.ToByteArray()), Origin.Remote).Status);
            CommandDeduplication.Complete(tx, id.Value.Span, outcome.ToByteArray());
            RoutedCommandOwnership.Record(tx, id.Value.Span, actor);
            if (!retainQueued)
            {
                tx.Execute("UPDATE task SET state = $state, finished_at = $finished WHERE task_id = $task;",
                    ("$state", (int)TaskState.Succeeded), ("$finished", tx.NowMicroseconds), ("$task", task.Value.ToByteArray()));
            }

            return outcome;
        }, CommitDurability.Full).WaitAsync(Ct);

    /// <summary>
    /// A copy of <paramref name="request"/>'s bytes that parses to the same message with its spec's top-level fields in reverse order: another
    /// encoder's bytes of the same request (TaskSpec carries maps, whose order is not canonical across encoders; verifier N-2).
    /// </summary>
    private static byte[] Reorder(TaskServiceSubmitTaskRequest request)
    {
        // Reverse field groups, not individual repeated/map entries: parsing and re-encoding then produces the original bytes.
        var spec = Fields(request.Spec.ToByteArray()).GroupBy(field => field.Number).Reverse().SelectMany(group => group).ToList();
        var output = new MemoryStream();
        foreach (var (number, field) in Fields(request.ToByteArray()))
        {
            if (number == TaskServiceSubmitTaskRequest.SpecFieldNumber)
            {
                var writer = new CodedOutputStream(output, leaveOpen: true);
                writer.WriteTag(number, WireFormat.WireType.LengthDelimited);
                writer.WriteBytes(ByteString.CopyFrom(spec.SelectMany(pair => pair.Bytes).ToArray()));
                writer.Flush();
            }
            else
            {
                output.Write(field);
            }
        }

        return output.ToArray();
    }

    private static List<(int Number, byte[] Bytes)> Fields(byte[] message)
    {
        var fields = new List<(int, byte[])>();
        var input = new CodedInputStream(message);
        while (true)
        {
            var start = (int)input.Position;
            var tag = input.ReadTag();
            if (tag == 0)
            {
                return fields;
            }

            input.SkipLastField();
            fields.Add((WireFormat.GetTagFieldNumber(tag), message[start..(int)input.Position]));
        }
    }
    private static void AssertRetiredSubmit(TaskServiceSubmitTaskResponse response)
    {
        Assert.Null(response.Value);
        var error = Assert.IsType<ArcError>(response.Error);
        Assert.Equal("operation_failed", error.Code);
        Assert.Equal("LEGACY_DRAIN", error.Details.State.State);
        Assert.Equal("legacy_task_outcome_unavailable", error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
    }
}
