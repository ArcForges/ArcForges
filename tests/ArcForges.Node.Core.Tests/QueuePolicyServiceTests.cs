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
        await using var channel = await node.ChannelAsync();
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

    [Fact(Timeout = 120_000)]
    public async Task AnAgentIsRefusedPolicyAndPoolChangesThatNeedAnApproval()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        await using var script = await node.ChannelAsync();
        Assert.Equal("permission_denied", (await agent.Queue.CreatePoolAsync(new QueueServiceCreatePoolRequest { Meta = Tasks.Meta(), Name = "mine" }, cancellationToken: Ct)).Error?.Code);
        Assert.Equal("permission_denied", (await agent.Queue.SetParallelismAsync(new QueueServiceSetParallelismRequest
        {
            Meta = Tasks.Meta(),
            Scope = ParallelismScope.Global,
            Mode = ParallelismMode.Disabled,
        }, cancellationToken: Ct)).Error?.Code);
        Assert.Equal("permission_denied", (await Sched.ChangePolicyAsync(agent, policy => policy.Resources.GlobalMaxRunning = 3)).Error?.Code);

        // Reading is allowed; a SCRIPT may change the resource policy but not retry_safety.
        Assert.Null((await agent.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Error);
        Assert.Null((await agent.Queue.GetQueueAsync(new QueueServiceGetQueueRequest { Meta = Tasks.Meta() }, cancellationToken: Ct)).Error);
        Assert.Null((await Sched.ChangePolicyAsync(script, policy => policy.Resources.GlobalMaxRunning = 3)).Error);
        Assert.Equal("permission_denied", (await Sched.ChangePolicyAsync(script, policy => (policy.RetrySafety ??= new RetrySafetyPolicy()).AcceptAgentAssertions = true)).Error?.Code);
    }
}
