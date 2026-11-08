// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// AF-CTR-05 part N2b on real nodes, through the routed test seam (<see cref="RoutedCalls"/>): the center-routed policy and the routed column
/// (N2-1, PB-2), the AGENT narrowing (N2-4, decisions B-4), approvals (N2-5), MR-08 (N2-2, N2-3), the owner and what a routed read shows
/// (N2-6, PN-8), command deduplication over the exact bytes with Q-5 replay fidelity (N2-7, N2-8), the in-progress duplicate (decisions
/// B-2), the cross-part rule for handler errors (decisions B-1), the link and stop re-checks (B-3), the expiry re-check (PN-15),
/// <c>routed_call_log</c> (N2-10) and the bounded local submission (N2-11..N2-13).
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

    /// <summary>N2-1, N2-6, N2-10: a routed submission by each caller kind; its owner, its records and what other callers read of it.</summary>
    [Fact(Timeout = 180_000)]
    public async Task ARoutedSubmissionIsOwnedByItsCenterCallerAndOthersReadOnlyItsSummary()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var owner = RoutedCalls.Session();
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
        spec.Environment.Set["VISIBLE_NAME"] = "a value";
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec, CancelWhenCallerGone = true };
        var (answer, response) = await routed.SubmitAsync(owner, request);
        Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
        Assert.True(response!.Error is null, $"{response.Error?.Category}/{response.Error?.Code}");
        Assert.Contains(response.Value.Warnings, warning => warning.Contains("cancel_when_caller_gone", StringComparison.Ordinal));
        Assert.Equal(3, answer.Risk);
        var taskId = response.Value.TaskId;
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

        // Every routed caller kind of this node submits: an own-node relay of each local origin.
        foreach (var origin in (Origin[])[Origin.Human, Origin.Script, Origin.Agent])
        {
            var relayed = await routed.SubmitAsync(routed.Relay(origin), new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100") });
            Assert.True(relayed.Response?.Error is null, $"{origin}: {relayed.Answer?.Outcome} {relayed.Response?.Error?.Code}");
        }

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
    }

    /// <summary>Two own-node relayed caller origins share the same queue, resource budget and fixed global parallelism.</summary>
    [Fact(Timeout = 120_000)]
    public async Task RelayedHumanAndScriptShareQueueAndBudget()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await Sched.SetParallelismAsync(human, ParallelismScope.Global, string.Empty, ParallelismMode.Fixed, 1);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "120000");
        spec.Resources = new ResourceSpec { Hint = new ResourceDemand { CpuMillicores = 100, MemExpectedBytes = 64UL << 20 } };
        var first = (await routed.SubmitAsync(routed.Relay(Origin.Human), new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec })).Response!;
        var second = (await routed.SubmitAsync(routed.Relay(Origin.Script), new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec })).Response!;
        Assert.Null(first.Error);
        Assert.Null(second.Error);
        var watch = Stopwatch.StartNew();
        QueueServiceGetQueueValue queue;
        while (true)
        {
            queue = await Sched.QueueAsync(human);
            if (queue.Entries.Count(entry => entry.TaskId.Equals(first.Value.TaskId) || entry.TaskId.Equals(second.Value.TaskId)) == 2)
            {
                break;
            }

            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(30), "both routed tasks appear in the shared queue");
            await Task.Delay(50, Ct);
        }

        var entries = queue.Entries.Where(entry => entry.TaskId.Equals(first.Value.TaskId) || entry.TaskId.Equals(second.Value.TaskId)).ToArray();
        Assert.Equal(2, entries.Length);
        Assert.NotEqual(entries[0].Queue.Position, entries[1].Queue.Position);
        Assert.Equal(Origin.Human, entries.Single(entry => entry.TaskId.Equals(first.Value.TaskId)).Owner.CenterCaller.LocalOrigin);
        Assert.Equal(Origin.Script, entries.Single(entry => entry.TaskId.Equals(second.Value.TaskId)).Owner.CenterCaller.LocalOrigin);
        Assert.All(entries, entry => Assert.Equal((100u, 64UL << 20), (entry.Request.CpuMillicores, entry.Request.MemExpectedBytes)));
        var policy = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct);
        Assert.Null(policy.Error);
        Assert.Contains(policy.Value.Document.Parallelism, rule => rule.Scope == ParallelismScope.Global && rule.Mode == ParallelismMode.Fixed && rule.Fixed == 1);
        Assert.True(queue.Budget.GlobalMaxRunning > 0);
        Assert.Null((await human.Queue.ResumePoolAsync(new QueueServiceResumePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        await Tasks.WaitForAsync(() => node.Runtime.Execution.RunningAttempts.Count() == 1, TimeSpan.FromSeconds(30), "one task in the shared budget");
        var running = await Sched.QueueAsync(human);
        Assert.Equal(1u, running.Budget.GlobalRunning);
        Assert.Equal(queue.Budget.GlobalMaxRunning, running.Budget.GlobalMaxRunning);
        Assert.True(running.Budget.AccountedMemBytes > 0);
        var states = new[] { (await Tasks.GetAsync(human, first.Value.TaskId)).State, (await Tasks.GetAsync(human, second.Value.TaskId)).State };
        Assert.Equal(new[] { TaskState.Queued, TaskState.Running }, states.OrderBy(state => state));
        await Sched.CancelAsync(human, first.Value.TaskId);
        await Sched.CancelAsync(human, second.Value.TaskId);
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
        TaskServiceSubmitTaskRequest Request() => new() { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100") };
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
        Assert.Null((await routed.SubmitAsync(routed.Relay(Origin.Human), Request())).Response?.Error);
        Assert.Equal(CenterRouting.AgentOwnNodeOnly, (await routed.SubmitAsync(routed.Relay(Origin.Agent, ownNode: false), Request())).Answer!.Error?.Details.State.Reason);
        Assert.Equal(1, TaskCount());

        // Off: every routed call is refused before any effect.
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.CenterRouted.Enabled = false)).Error);
        Assert.Equal(CenterRouting.Disabled, (await routed.SubmitAsync(RoutedCalls.Session(), Request())).Answer!.Error?.Details.State.Reason);
        Assert.Equal(1, TaskCount());
    }

    /// <summary>
    /// Decisions B-4: a relayed AGENT gets the AGENT rules: patterns (N2-4), its PURE claim not accepted; INTERACTIVE priority is refused for
    /// every routed caller with the error of a local AGENT.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task ARelayedAgentGetsTheNarrowerAgentRulesAndNoRoutedCallerSubmitsInteractive()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        TaskSpec Pure()
        {
            var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
            spec.SideEffect = SideEffectClass.Pure;
            return spec;
        }

        var agent = (await routed.SubmitAsync(routed.Relay(Origin.Agent), new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Pure() })).Response!;
        Assert.Contains(agent.Value.Warnings, warning => warning.Contains("accept_agent_assertions", StringComparison.Ordinal));
        Assert.Equal(SideEffectClass.Unknown, (await Tasks.GetAsync(human, agent.Value.TaskId)).SideEffect);
        var script = (await routed.SubmitAsync(routed.Relay(Origin.Script), new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Pure() })).Response!;
        Assert.Equal(SideEffectClass.Pure, (await Tasks.GetAsync(human, script.Value.TaskId)).SideEffect);

        foreach (var caller in (CenterCaller[])[routed.Relay(Origin.Human), RoutedCalls.Session()])
        {
            var interactive = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
            interactive.Priority = Priority.Interactive;
            var refused = (await routed.SubmitAsync(caller, new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = interactive })).Answer!;
            Assert.Equal((RoutedOutcome.RefusedByPolicy, "permission_denied", "task.submit"), (refused.Outcome, refused.Error?.Code, refused.Error?.Details.State.State));
        }
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
        var first = await Tasks.SubmitAsync(human, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100"));
        var second = await Tasks.SubmitAsync(human, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100"));

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
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy =>
        {
            policy.Permissions.Add(new PermissionOverride { Operation = PermissionMatrix.ProcessTerminate, Origin = Origin.Script, Decision = A });
            policy.Permissions.Add(new PermissionOverride { Operation = PermissionMatrix.ProcessTerminate, Origin = Origin.Agent, Decision = A });
        })).Error);
        var routed = new RoutedCalls(node);
        var nodeId = node.Runtime.NodeId.ToArray();
        var adopted = new Id { Value = ByteString.CopyFrom(await node.Runtime.Processor.ExecuteAsync(context => GateAndReplayTests.SeedAdopted(context, nodeId))) };
        foreach (var caller in (CenterCaller[])[RoutedCalls.Session(), routed.Relay(Origin.Human), routed.Relay(Origin.Script), routed.Relay(Origin.Agent)])
        {
            var denied = (await routed.CancelAsync(caller, adopted)).Answer!;
            Assert.Equal((RoutedOutcome.RefusedByPolicy, "permission_denied", PermissionMatrix.ProcessTerminate), (denied.Outcome, denied.Error?.Code, denied.Error?.Details.State.State));
        }

        Assert.Equal(TaskState.Running, (await Tasks.GetAsync(human, adopted)).State);
        Assert.Empty((await human.Approvals.ListApprovalsAsync(new ApprovalServiceListApprovalsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Approvals);
        Assert.Contains(node.Runtime.Store.Read(reader => AuditLog.Recent(reader)), entry => entry.Operation == PermissionMatrix.ProcessTerminate + " TaskService.CancelTask"
            && entry.Decision == D && entry.Actor.Origin == Origin.Remote);

        // Verifier N-7: an approved routed cancel of another owner's task that became ADOPTED before it executed is still denied.
        var queued = await Tasks.SubmitAsync(human, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100"));
        var approval = (await routed.CancelAsync(RoutedCalls.Session(), queued)).Answer!.Error!.Details.State.Resource.Id;
        await node.Runtime.Processor.ExecuteAsync(context => context.Transaction.Execute("UPDATE task SET kind = 3 WHERE task_id = $id;", ("$id", queued.Value.ToByteArray())));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        await using var restartedHuman = await node.ChannelAsync(helloAsHuman: true);
        Assert.Equal(3L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT kind FROM task WHERE task_id = $id;", ("$id", queued.Value.ToByteArray()))));
        var decided = (await restartedHuman.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest { Meta = Tasks.Meta(), ApprovalId = approval, Decision = ApprovalDecisionKind.Approve },
            cancellationToken: Ct)).Value.Approval;
        Assert.Equal(ApprovalState.Failed, decided.State);
        Assert.NotEqual(TaskState.Cancelled, (await Tasks.GetAsync(restartedHuman, queued)).State);
    }

    /// <summary>
    /// N2-7, Q-5, decisions Q6: one task per command ID and exact bytes; a replay equals the recorded bytes (outside the volatile fields, here
    /// all of them); other bytes under the command ID, a re-encoded equivalent included, are <c>command_id_reused</c>.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task ARoutedSubmitDeduplicatesByTheExactBytesAndReplaysTheRecordedOutcome()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var caller = routed.Relay(Origin.Script);
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
        spec.Labels["a"] = "1";
        spec.Labels["b"] = "2";
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec };
        var first = (await routed.SubmitAsync(caller, request)).Answer!;

        // The same bytes under a new call ID (and a new local session of the same origin): the recorded bytes, exactly.
        var again = (await routed.SubmitAsync(routed.Relay(Origin.Script), request)).Answer!;
        Assert.Equal(first.Response!.ToByteArray(), again.Response!.ToByteArray());

        // A new correlation ID: the same outcome outside the volatile fields (the center's OutcomeDigest).
        var correlated = request.Clone();
        correlated.Meta.CorrelationId = CommandIds.New();
        var other = (await routed.SubmitAsync(caller, correlated)).Answer!;
        Assert.Equal(RoutedCalls.OutcomeDigest(first.Response.Span), RoutedCalls.OutcomeDigest(other.Response!.Span));

        // Another caller under the command ID: the normal path, whose deduplication replays the same outcome.
        var session = (await routed.SubmitAsync(RoutedCalls.Session(), request)).Answer!;
        Assert.Equal(RoutedCalls.OutcomeDigest(first.Response.Span), RoutedCalls.OutcomeDigest(session.Response!.Span));
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

    /// <summary>A stopped node refuses even a recorded replay before looking up the previous outcome (decisions B-2 and B-3).</summary>
    [Fact(Timeout = 180_000)]
    public async Task ARecordedRoutedCommandIsNotReplayedAfterStopping()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var caller = RoutedCalls.Session();
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100") };
        Assert.Null((await routed.SubmitAsync(caller, request)).Response!.Error);

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
            Origin.Remote, _ => result);
        await log.CompleteAsync(prior.Value, RoutedCallDecision.Executed, null, task.Value.ToByteArray(), 2,
            System.Security.Cryptography.SHA256.HashData(result), result.Length);

        var (answer, _) = await routed.CallAsync(other, RoutedMethod.CancelNodeTask, bytes, request.Meta.CommandId);
        Assert.Equal((RoutedOutcome.RefusedByPolicy, adopted ? "permission_denied" : "approval_required",
                adopted ? PermissionMatrix.ProcessTerminate : PermissionMatrix.TaskCancelOthers),
            (answer!.Outcome, answer.Error?.Code, answer.Error?.Details.State.State));
    }

    /// <summary>Decisions B-2: a duplicate while the first call is admitted answers effect UNKNOWN; the first then completes and replays.</summary>
    [Fact(Timeout = 180_000)]
    public async Task ADuplicateWhileTheFirstIsAdmittedAnswersEffectUnknownAndNeverFinal()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var caller = RoutedCalls.Session();
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100") };

        // The writer is held, so the first call waits in its admission.
        using var hold = new ManualResetEventSlim();
        var held = node.Runtime.Processor.ExecuteAsync(_ =>
        {
            hold.Wait(TimeSpan.FromSeconds(60));
            return 0;
        });
        var first = routed.SubmitAsync(caller, request, record: false);
        await Tasks.WaitForAsync(() => node.Runtime.Processor.Queued >= 1, TimeSpan.FromSeconds(30), "the first submission to wait for the writer");
        try
        {
            var duplicate = (await routed.SubmitAsync(caller, request, record: false)).Answer!;
            var error = TaskServiceSubmitTaskResponse.Parser.ParseFrom(duplicate.Response).Error;
            Assert.Equal((RoutedOutcome.Executed, "operation_failed", EffectCertainty.Unknown, RetryMode.SameCommand, "command_in_progress"),
                (duplicate.Outcome, error?.Code, error?.Effect ?? EffectCertainty.Unspecified, error?.Retry.Mode ?? RetryMode.Unspecified, error?.Details.State.Reason));

            // Once stopping begins, even a duplicate of an in-progress command is refused before replay/in-progress lookup.
            routed.Link.Reset(notStoppingFor: 0);
            var afterStop = (await routed.SubmitAsync(caller, request, record: false)).Response!.Error;
            Assert.Equal(("node_stopping", EffectCertainty.DidNotHappen, RetryMode.AfterTime), (afterStop?.Code, afterStop?.Effect, afterStop?.Retry.Mode));
            routed.Link.Reset();
        }
        finally
        {
            hold.Set();
        }

        await held;
        var done = (await first).Answer!;
        Assert.Null(TaskServiceSubmitTaskResponse.Parser.ParseFrom(done.Response).Error);
        var resent = (await routed.SubmitAsync(caller, request)).Answer!;
        Assert.Equal(RoutedCalls.OutcomeDigest(done.Response!.Span), RoutedCalls.OutcomeDigest(resent.Response!.Span));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
    }

    /// <summary>
    /// Decisions B-1 and B-3: every routed handler error is recorded and replayed, or decided before any effect with DID_NOT_HAPPEN; the
    /// link and the stop are read again immediately before the effect; PN-15's expiry re-check.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task EveryRoutedHandlerErrorIsRecordedOrDidNotHappenAndTheLinkIsReadBeforeTheEffect()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var caller = RoutedCalls.Session();
        TaskServiceSubmitTaskRequest Request() => new() { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100") };
        long Count(string table) => (long)node.Runtime.Store.Read(reader => reader.Scalar(table == "command_dedup"
            ? "SELECT count(*) FROM command_dedup WHERE method LIKE 'arcforges.node.v1.TaskService/%';" : $"SELECT count(*) FROM {table};"))!;
        (long Decision, string? Code) Row(long logId) => node.Runtime.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("SELECT decision, refusal_code FROM routed_call_log WHERE log_id = $id;");
            command.Parameters.AddWithValue("$id", logId);
            using var row = command.ExecuteReader();
            Assert.True(row.Read());
            return (row.GetInt64(0), row.IsDBNull(1) ? null : row.GetString(1));
        });

        // A validation error before the deduplication: DID_NOT_HAPPEN, nothing recorded.
        var invalid = Request();
        invalid.Spec.TimeoutMs = 5;
        var refused = await routed.SubmitAsync(caller, invalid);
        Assert.Equal((RoutedOutcome.Executed, EffectCertainty.DidNotHappen), (refused.Answer!.Outcome, refused.Response!.Error.Effect));
        Assert.Equal(0L, Count("command_dedup"));

        // A mismatching inner command ID: VALIDATION/invalid_argument, DID_NOT_HAPPEN.
        var mismatched = Request();
        var (wrong, wrongLog) = await routed.CallAsync(caller, RoutedMethod.SubmitNodeTask, mismatched.ToByteArray(), CommandIds.New());
        var mismatch = TaskServiceSubmitTaskResponse.Parser.ParseFrom(wrong!.Response).Error;
        Assert.Equal(("invalid_argument", EffectCertainty.DidNotHappen), (mismatch.Code, mismatch.Effect));
        Assert.Equal((1L, "VALIDATION/invalid_argument"), Row(wrongLog));

        // The node's stop began: STATE/node_stopping, DID_NOT_HAPPEN, AFTER_TIME with retry_at; after the restart the same bytes execute once.
        var stopped = Request();
        routed.Link.Reset(notStoppingFor: 0);
        var stopping = (await routed.SubmitAsync(caller, stopped)).Response!.Error;
        Assert.Equal(("node_stopping", EffectCertainty.DidNotHappen, RetryMode.AfterTime, true), (stopping.Code, stopping.Effect, stopping.Retry.Mode, stopping.Retry.RetryAt is not null));

        // ... also when the stop begins immediately before the effect (decisions B-3): nothing is stored.
        routed.Link.Reset(notStoppingFor: 1);
        Assert.Equal("node_stopping", (await routed.SubmitAsync(caller, stopped)).Response!.Error?.Code);
        Assert.Equal((0L, 0L), (Count("task"), Count("command_dedup")));
        routed.Link.Reset();
        Assert.Null((await routed.SubmitAsync(caller, stopped)).Response!.Error);
        Assert.Equal(1L, Count("task"));

        // The link ends immediately before the effect: the call is dropped, nothing is stored and its row stays pending.
        var dropped = Request();
        routed.Link.Reset(usableFor: 2);
        var (gone, goneLog) = await routed.CallAsync(caller, RoutedMethod.SubmitNodeTask, dropped.ToByteArray(), dropped.Meta.CommandId);
        Assert.Null(gone);
        Assert.Equal((5L, (string?)null), Row(goneLog));
        Assert.Equal(1L, Count("task"));
        routed.Link.Reset();

        // PN-15: inside the 120 s skew band the call executes; past it, EXPIRED (decision 4) and nothing is stored.
        var late = Request();
        var (lateAnswer, _) = await routed.CallAsync(caller, RoutedMethod.SubmitNodeTask, late.ToByteArray(), late.Meta.CommandId, node.Runtime.Clock.GetUtcNow().AddSeconds(-60));
        Assert.Null(TaskServiceSubmitTaskResponse.Parser.ParseFrom(lateAnswer!.Response).Error);
        var expired = Request();
        var (expiredAnswer, expiredLog) = await routed.CallAsync(caller, RoutedMethod.SubmitNodeTask, expired.ToByteArray(), expired.Meta.CommandId,
            node.Runtime.Clock.GetUtcNow().AddSeconds(-121));
        Assert.Equal((RoutedOutcome.Expired, "expired"), (expiredAnswer!.Outcome, expiredAnswer.Error?.Code));
        Assert.Equal((4L, "STATE/expired"), Row(expiredLog));
        Assert.Equal(2L, Count("task"));
    }

    /// <summary>N2-12 (CTR5-NODE-12): routed output by offset, other owners' output only by policy, the routed cap, and waits within the deadline.</summary>
    [Fact(Timeout = 180_000)]
    public async Task RoutedOutputIsReadByOffsetWithinTheCapAndTheDeadline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var routed = new RoutedCalls(node);
        var owner = RoutedCalls.Session();
        var printed = (await routed.SubmitAsync(owner, new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "output", "--bytes", "4096") })).Response!;
        var task = await Tasks.WaitAsync(human, printed.Value.TaskId);
        Assert.Equal(TaskState.Succeeded, task.State);
        var read = new TaskServiceReadTaskOutputRequest { Meta = Tasks.Meta(), AttemptId = task.CurrentAttempt.AttemptId, FromOffset = 1000, MaxBytes = 100 };
        var own = (await routed.ReadAsync(owner, RoutedMethod.ReadNodeTaskOutput, read, TaskServiceReadTaskOutputResponse.Parser)).Response!.Value;
        Assert.Equal((100, 1100UL), (own.Data.Length, own.NextOffset));
        var others = (await routed.ReadAsync(RoutedCalls.Session(), RoutedMethod.ReadNodeTaskOutput, read, TaskServiceReadTaskOutputResponse.Parser)).Answer!;
        Assert.Equal((RoutedOutcome.RefusedByPolicy, PermissionMatrix.TaskReadOutput, "remote_output_tail_off"),
            (others.Outcome, others.Error?.Details.State.State, others.Error?.Details.State.Reason));
        var large = read.Clone();
        large.MaxBytes = 262_145;
        Assert.Equal("invalid_argument", (await routed.ReadAsync(owner, RoutedMethod.ReadNodeTaskOutput, large, TaskServiceReadTaskOutputResponse.Parser)).Response!.Error?.Code);
        Assert.Null((await human.Tasks.ReadTaskOutputAsync(large, cancellationToken: Ct)).Error);

        // wait_ms: a running attempt without new bytes is waited on (local callers too); a routed wait ends before the call's deadline.
        var holding = await Tasks.SubmitAsync(human, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "30000"));
        var started = await Tasks.WaitAsync(human, holding, WaitTarget.Started);
        var wait = new TaskServiceReadTaskOutputRequest { Meta = Tasks.Meta(), AttemptId = started.CurrentAttempt.AttemptId, FromOffset = 1_000_000, WaitMs = 1_500 };
        var clock = Stopwatch.StartNew();
        Assert.Null((await human.Tasks.ReadTaskOutputAsync(wait, cancellationToken: Ct)).Error);
        Assert.InRange(clock.Elapsed, TimeSpan.FromMilliseconds(1_200), TimeSpan.FromSeconds(10));
        var waitTask = new TaskServiceWaitTaskRequest { Meta = Tasks.Meta(), TaskId = holding, WaitMs = 20_000 };
        clock.Restart();
        var (bounded, _) = await routed.CallAsync(RoutedCalls.Session(), RoutedMethod.WaitNodeTask, waitTask.ToByteArray(), null, node.Runtime.Clock.GetUtcNow().AddSeconds(3));
        Assert.Equal(RoutedOutcome.Executed, bounded!.Outcome);
        Assert.False(TaskServiceWaitTaskResponse.Parser.ParseFrom(bounded.Response).Value.Reached);
        Assert.InRange(clock.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(4));
        Assert.Null((await human.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = holding }, cancellationToken: Ct)).Error);
        var ended = await Tasks.WaitAsync(human, holding);
        Assert.Equal(TaskState.Cancelled, ended.State);
    }

    /// <summary>N2-11, N2-12, N2-13 (AD-0021 section 5, Q8): a local submission is HUMAN only and diagnostic; the test allowance needs test mode.</summary>
    [Fact(Timeout = 180_000)]
    public async Task ALocalSubmissionIsHumanOnlyAndDiagnostic()
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
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
        foreach (var channel in (NodeChannel[])[script, agent, bare])
        {
            var refused = (await Tasks.SubmitRawAsync(channel, spec)).Error;
            Assert.Equal(("permission_denied", "task.submit", "local_submission_human_only", EffectCertainty.DidNotHappen),
                (refused?.Code, refused?.Details.State.State, refused?.Details.State.Reason, refused?.Effect ?? EffectCertainty.Unspecified));
        }

        var local = await Tasks.GetAsync(human, await Tasks.SubmitAsync(human, spec));
        Assert.True(local.LocalDiagnostic);
        var routed = (await new RoutedCalls(node).SubmitOkAsync(RoutedCalls.Session(), spec)).Value.TaskId;
        Assert.False((await Tasks.GetAsync(human, routed)).HasLocalDiagnostic);

        // CTR5-NODE-14: the allowance holds only in test mode and only for exactly "1".
        Assert.True(LocalSubmission.ScriptAllowed(testMode: true, "1"));
        Assert.False(LocalSubmission.ScriptAllowed(testMode: false, "1"));
        Assert.False(LocalSubmission.ScriptAllowed(testMode: true, "true"));
        Assert.False(LocalSubmission.ScriptAllowed(testMode: true, null));
    }

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
}

/// <summary>Shorthands of the routed tests.</summary>
internal static class RoutedCallsExtensions
{
    /// <summary>A routed submission of <paramref name="spec"/> by <paramref name="caller"/>; fails the test unless it executed without an error.</summary>
    public static async Task<TaskServiceSubmitTaskResponse> SubmitOkAsync(this RoutedCalls calls, CenterCaller caller, TaskSpec spec)
    {
        var (answer, response) = await calls.SubmitAsync(caller, new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec });
        Assert.True(answer?.Outcome == RoutedOutcome.Executed && response?.Error is null, $"routed SubmitTask: {answer?.Outcome} {response?.Error?.Code}");
        return response!;
    }
}
