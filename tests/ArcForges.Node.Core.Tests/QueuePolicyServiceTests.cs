// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// <c>QueueService</c> pools and parallelism and <c>PolicyService</c> (queue.proto, policy.proto) through the real client against an
/// in-process node: every pool and parallelism change is a policy revision; built-in pools cannot be deleted; a document with an ERROR issue
/// is refused with its issues; <c>expected_rev</c> is required and checked; revisions are listed and restored; an AGENT caller is refused
/// the operations that need an approval (approvals arrive with AF-SEC-01), and <c>retry_safety</c> changes only from a HUMAN. No processes
/// run, so the tests need no execution platform.
/// </summary>
public sealed class QueuePolicyServiceTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 120_000)]
    public async Task PoolsAreCreatedUpdatedPausedAndDeletedAsPolicyRevisions()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var queue = channel.Queue;
        var pools = (await queue.ListPoolsAsync(new QueueServiceListPoolsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Pools;
        Assert.Contains(pools, pool => pool.Name == "default" && pool.BuiltIn);
        Assert.Contains(pools, pool => pool.Name == "agents" && pool.BuiltIn);

        var created = await queue.CreatePoolAsync(new QueueServiceCreatePoolRequest { Meta = Tasks.Meta(), Name = "builds", Weight = 3, DefaultPriority = Priority.Low }, cancellationToken: Ct);
        Assert.Null(created.Error);
        Assert.Equal(3u, created.Value.Pool.Weight);
        Assert.False(created.Value.Pool.BuiltIn);
        var revision = created.Value.PolicyRevision.Value;
        var policy = await channel.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct);
        Assert.Contains(policy.Value.Document.Pools, pool => pool.Name == "builds" && pool.Weight == 3);

        Assert.Equal("already_exists", (await queue.CreatePoolAsync(new QueueServiceCreatePoolRequest { Meta = Tasks.Meta(), Name = "builds" }, cancellationToken: Ct)).Error?.Code);
        Assert.NotNull((await queue.CreatePoolAsync(new QueueServiceCreatePoolRequest { Meta = Tasks.Meta(), Name = "Bad Name" }, cancellationToken: Ct)).Error);
        Assert.NotNull((await queue.CreatePoolAsync(new QueueServiceCreatePoolRequest { Meta = Tasks.Meta(), Name = "hot", DefaultPriority = Priority.Interactive }, cancellationToken: Ct)).Error);

        var updated = await queue.UpdatePoolAsync(new QueueServiceUpdatePoolRequest
        {
            Meta = Tasks.Meta(),
            Name = "builds",
            MaxParallelMode = ParallelismMode.Fixed,
            MaxParallelFixed = 2,
        }, cancellationToken: Ct);
        Assert.Null(updated.Error);
        Assert.Equal(2u, updated.Value.Pool.MaxParallelFixed);
        Assert.True(updated.Value.PolicyRevision.Value > revision);

        Assert.Null((await queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), Pool = "builds" }, cancellationToken: Ct)).Error);
        Assert.True((await queue.ListPoolsAsync(new QueueServiceListPoolsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Pools.Single(pool => pool.Name == "builds").Paused);
        Assert.Null((await queue.ResumePoolAsync(new QueueServiceResumePoolRequest { Meta = Tasks.Meta(), Pool = "builds" }, cancellationToken: Ct)).Error);
        Assert.False((await queue.ListPoolsAsync(new QueueServiceListPoolsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Pools.Single(pool => pool.Name == "builds").Paused);

        Assert.NotNull((await queue.DeletePoolAsync(new QueueServiceDeletePoolRequest { Meta = Tasks.Meta(), Name = "default" }, cancellationToken: Ct)).Error);
        Assert.Equal("not_found", (await queue.DeletePoolAsync(new QueueServiceDeletePoolRequest { Meta = Tasks.Meta(), Name = "missing" }, cancellationToken: Ct)).Error?.Code);
        Assert.Null((await queue.DeletePoolAsync(new QueueServiceDeletePoolRequest { Meta = Tasks.Meta(), Name = "builds" }, cancellationToken: Ct)).Error);
        Assert.DoesNotContain((await queue.ListPoolsAsync(new QueueServiceListPoolsRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Pools, pool => pool.Name == "builds");

        // Parallelism rules are policy revisions too; AUTO removes the rule.
        var rule = await queue.SetParallelismAsync(new QueueServiceSetParallelismRequest { Meta = Tasks.Meta(), Scope = ParallelismScope.Global, Mode = ParallelismMode.Fixed, Fixed = 3 }, cancellationToken: Ct);
        Assert.Null(rule.Error);
        Assert.Contains((await channel.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Document.Parallelism,
            parallelism => parallelism.Scope == ParallelismScope.Global && parallelism.Fixed == 3);
        Assert.Null((await queue.SetParallelismAsync(new QueueServiceSetParallelismRequest { Meta = Tasks.Meta(), Scope = ParallelismScope.Global, Mode = ParallelismMode.Auto }, cancellationToken: Ct)).Error);
        Assert.DoesNotContain((await channel.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Document.Parallelism,
            parallelism => parallelism.Scope == ParallelismScope.Global);
        Assert.Equal("not_found", (await queue.SetParallelismAsync(new QueueServiceSetParallelismRequest
        {
            Meta = Tasks.Meta(),
            Scope = ParallelismScope.Workspace,
            Target = IdText.Format(new byte[16]),
            Mode = ParallelismMode.Disabled,
        }, cancellationToken: Ct)).Error?.Code);
        Assert.Empty((await Sched.QueueAsync(channel)).Entries);
    }

    [Fact(Timeout = 120_000)]
    public async Task APolicyIsValidatedUpdatedAgainstItsRevisionListedAndRestored()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var policy = channel.Policy;
        var defaults = (await policy.GetDefaultPolicyAsync(new PolicyServiceGetDefaultPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Document;
        var current = (await policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value;
        Assert.Equal(defaults, current.Document);

        var invalid = current.Document.Clone();
        invalid.Resources.OvercommitCpu = 9;
        invalid.Resources.Pressure = new PressureThresholds { TightAvailableFraction = 0.01, PressureAvailableFraction = 0.05 };
        var validated = (await policy.ValidatePolicyAsync(new PolicyServiceValidatePolicyRequest { Meta = Tasks.Meta(), Document = invalid }, cancellationToken: Ct)).Value;
        Assert.False(validated.Valid);
        Assert.Contains(validated.Issues, issue => issue.Path == "resources.overcommit_cpu" && issue.Severity == Severity.Error);
        Assert.Contains(validated.Issues, issue => issue.Path == "resources.pressure" && issue.Severity == Severity.Error);

        RequestMeta At(long revision)
        {
            var meta = Tasks.Meta();
            meta.ExpectedRev = new Revision { Value = revision };
            return meta;
        }

        Assert.Equal("invalid_policy", (await policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = At(current.Revision.Revision.Value), Document = invalid }, cancellationToken: Ct)).Error?.Code);
        var changed = current.Document.Clone();
        changed.Resources.GlobalMaxRunning = 7;
        Assert.NotNull((await policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = Tasks.Meta(), Document = changed }, cancellationToken: Ct)).Error);
        Assert.NotNull((await policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = At(current.Revision.Revision.Value + 5), Document = changed }, cancellationToken: Ct)).Error);
        var updated = await policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = At(current.Revision.Revision.Value), Document = changed, Comment = "seven" }, cancellationToken: Ct);
        Assert.True(updated.Error is null, $"UpdatePolicy: {updated.Error?.Code} {updated.Error?.Details}");
        Assert.Equal(current.Revision.Revision.Value + 1, updated.Value.Revision.Revision.Value);
        Assert.Equal(7, node.Runtime.Execution!.Settings.GlobalMaxRunning);

        var revisions = (await policy.ListPolicyRevisionsAsync(new PolicyServiceListPolicyRevisionsRequest { Meta = Tasks.Meta(), Page = new PageRequest { Limit = 10 } }, cancellationToken: Ct)).Value.Revisions;
        Assert.Contains(revisions, revision => revision.Revision.Value == updated.Value.Revision.Revision.Value && revision.Comment == "seven");
        Assert.Contains(revisions, revision => revision.Revision.Value == current.Revision.Revision.Value);

        var restored = await policy.RestorePolicyRevisionAsync(new PolicyServiceRestorePolicyRevisionRequest
        {
            Meta = At(updated.Value.Revision.Revision.Value),
            Revision = new Revision { Value = current.Revision.Revision.Value },
            Comment = "back",
        }, cancellationToken: Ct);
        Assert.True(restored.Error is null, $"RestorePolicyRevision: {restored.Error?.Code} {restored.Error?.Details}");
        var after = (await policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value;
        Assert.Equal(current.Document, after.Document);
        Assert.True(after.Revision.Revision.Value > updated.Value.Revision.Revision.Value);
        Assert.NotEqual(7, node.Runtime.Execution!.Settings.GlobalMaxRunning);
    }

    /// <summary>
    /// The interim gate per origin (11 section 1, until AF-SEC-01): HUMAN may do everything; SCRIPT may change a task's priority and pause or
    /// resume a pool, while parallelism, policy and pool changes need an approval and are refused; AGENT is refused all of them. A refusal
    /// of a <c>P</c> cell says that approvals arrive with AF-SEC-01, and nothing changes.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task TheInterimGateFollowsTheDefaultMatrixPerOrigin()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        var revision = (await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Revision.Revision.Value;

        async Task<ArcError?> CreatePoolAsync(NodeChannel channel, string name) =>
            (await channel.Queue.CreatePoolAsync(new QueueServiceCreatePoolRequest { Meta = Tasks.Meta(), Name = name }, cancellationToken: Ct)).Error;
        async Task<ArcError?> ParallelismAsync(NodeChannel channel) => (await channel.Queue.SetParallelismAsync(new QueueServiceSetParallelismRequest
        {
            Meta = Tasks.Meta(),
            Scope = ParallelismScope.Global,
            Mode = ParallelismMode.Fixed,
            Fixed = 4,
        }, cancellationToken: Ct)).Error;
        async Task<ArcError?> PauseAsync(NodeChannel channel)
        {
            var paused = (await channel.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), Pool = "background" }, cancellationToken: Ct)).Error;
            return paused ?? (await channel.Queue.ResumePoolAsync(new QueueServiceResumePoolRequest { Meta = Tasks.Meta(), Pool = "background" }, cancellationToken: Ct)).Error;
        }

        async Task<ArcError?> PriorityAsync(NodeChannel channel) => (await channel.Tasks.SetTaskPriorityAsync(new TaskServiceSetTaskPriorityRequest
        {
            Meta = Tasks.Meta(),
            TaskId = new Id { Value = Google.Protobuf.ByteString.CopyFrom(new byte[16]) },
            Priority = Priority.Low,
        }, cancellationToken: Ct)).Error;
        // PauseTask: HUMAN A, SCRIPT A, AGENT P; ResumeTask: A for all three (api-catalogue). A missing task is not_found once allowed.
        async Task<ArcError?> PauseTaskAsync(NodeChannel channel) => (await channel.Tasks.PauseTaskAsync(new TaskServicePauseTaskRequest
        {
            Meta = Tasks.Meta(),
            TaskId = new Id { Value = Google.Protobuf.ByteString.CopyFrom(new byte[16]) },
        }, cancellationToken: Ct)).Error;
        async Task<ArcError?> ResumeTaskAsync(NodeChannel channel) => (await channel.Tasks.ResumeTaskAsync(new TaskServiceResumeTaskRequest
        {
            Meta = Tasks.Meta(),
            TaskId = new Id { Value = Google.Protobuf.ByteString.CopyFrom(new byte[16]) },
        }, cancellationToken: Ct)).Error;
        void Approval(ArcError? error)
        {
            Assert.Equal("permission_denied", error?.Code);
            Assert.Contains("AF-SEC-01", error!.ToString(), StringComparison.Ordinal);
        }

        // SCRIPT: priority and pool pausing are A; parallelism, policy and pools are P.
        Approval(await CreatePoolAsync(script, "script-pool"));
        Approval(await ParallelismAsync(script));
        Approval((await Sched.ChangePolicyAsync(script, policy => policy.Resources.GlobalMaxRunning = 3)).Error);
        Assert.Null(await PauseAsync(script));
        Assert.Equal("not_found", (await PriorityAsync(script))?.Code);
        Assert.Equal("not_found", (await PauseTaskAsync(script))?.Code);
        Assert.Equal("not_found", (await ResumeTaskAsync(script))?.Code);

        // AGENT: everything here is P, except ResumeTask (A).
        Approval(await CreatePoolAsync(agent, "agent-pool"));
        Approval(await ParallelismAsync(agent));
        Approval((await Sched.ChangePolicyAsync(agent, policy => policy.Resources.GlobalMaxRunning = 3)).Error);
        Approval(await PauseAsync(agent));
        Approval(await PriorityAsync(agent));
        Approval(await PauseTaskAsync(agent));
        Assert.Equal("not_found", (await ResumeTaskAsync(agent))?.Code);

        // Nothing changed; reads are allowed for every origin.
        Assert.Equal(revision, (await agent.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Value.Revision.Revision.Value);
        Assert.Null((await script.Queue.GetQueueAsync(new QueueServiceGetQueueRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Error);

        // HUMAN: all A, retry_safety included.
        Assert.Null(await CreatePoolAsync(human, "human-pool"));
        Assert.Null(await ParallelismAsync(human));
        Assert.Null(await PauseAsync(human));
        Assert.Equal("not_found", (await PriorityAsync(human))?.Code);
        Assert.Equal("not_found", (await PauseTaskAsync(human))?.Code);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => (policy.RetrySafety ??= new RetrySafetyPolicy()).AcceptAgentAssertions = true)).Error);
    }

    /// <summary>
    /// Cancelling, pausing or re-prioritising another owner's task (11 section 1: HUMAN A, SCRIPT and AGENT P): a task an agent session owns
    /// is refused to a SCRIPT caller (approvals arrive with AF-SEC-01) and cancelled by a HUMAN; the SCRIPT caller's own task is its own. The
    /// tasks wait in a paused pool, so no process runs.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task AnotherOwnersTaskIsCancelledOnlyByAHumanUntilApprovalsExist()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        byte[] session = [];
        node.Runtime.Store.Write(transaction => session = Sched.SeedSession(transaction));
        var others = await Sched.SubmitAsSessionAsync(node, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100"), session);
        var own = await Tasks.SubmitAsync(script, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100"));

        var refused = (await script.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = others }, cancellationToken: Ct)).Error;
        Assert.Equal("permission_denied", refused?.Code);
        Assert.Contains("AF-SEC-01", refused!.ToString(), StringComparison.Ordinal);
        Assert.Equal("permission_denied", (await script.Tasks.SetTaskPriorityAsync(new TaskServiceSetTaskPriorityRequest
        {
            Meta = Tasks.Meta(),
            TaskId = others,
            Priority = Priority.High,
        }, cancellationToken: Ct)).Error?.Code);
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(human, others)).State);

        // A SCRIPT caller re-prioritises and cancels its own task; a HUMAN cancels the session's.
        var moved = await script.Tasks.SetTaskPriorityAsync(new TaskServiceSetTaskPriorityRequest { Meta = Tasks.Meta(), TaskId = own, Priority = Priority.Low }, cancellationToken: Ct);
        Assert.Null(moved.Error);
        Assert.Equal(Priority.Low, (await Tasks.GetAsync(script, own)).EffectivePriority);
        Assert.Equal(TaskState.Cancelled, (await script.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = own }, cancellationToken: Ct)).Value.State);
        Assert.Equal(TaskState.Cancelled, (await human.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = others }, cancellationToken: Ct)).Value.State);
        Assert.Equal("invalid_state", (await human.Tasks.SetTaskPriorityAsync(new TaskServiceSetTaskPriorityRequest
        {
            Meta = Tasks.Meta(),
            TaskId = others,
            Priority = Priority.High,
        }, cancellationToken: Ct)).Error?.Code);
    }
}
