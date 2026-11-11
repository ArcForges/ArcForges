// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Actual local policy and caller classification for the 06a rows. This does not expose or execute a file mutation,
/// establish center step-up, or prove a HUMAN approval flow for staged bytes.
/// </summary>
public sealed class FileMutationPermissionTests
{
    [Theory]
    [InlineData(PermissionMatrix.FileWrite)]
    [InlineData(PermissionMatrix.FileRemove)]
    public void AgentNeedsExplicitAllowAndRemoteMayOnlyNarrow(string operation)
    {
        var approval = new PermissionOverride { Operation = operation, Origin = Origin.Agent, Decision = PermissionDecision.Approval };
        var allow = new PermissionOverride { Operation = operation, Origin = Origin.Agent, Decision = PermissionDecision.Allow };
        var remoteDeny = new PermissionOverride { Operation = operation, Origin = Origin.Remote, Decision = PermissionDecision.Deny };
        Assert.Null(PermissionMatrix.Valid(approval));
        Assert.Null(PermissionMatrix.Valid(allow));
        Assert.Equal(PermissionDecision.Allow, PermissionMatrix.DecideRouted(operation, Origin.Human, []).Decision);
        Assert.Equal(PermissionDecision.Approval, PermissionMatrix.DecideRouted(operation, Origin.Script, []).Decision);
        Assert.Equal(PermissionDecision.Deny, PermissionMatrix.DecideRouted(operation, Origin.Agent, []).Decision);
        Assert.Equal(PermissionDecision.Deny, PermissionMatrix.DecideRouted(operation, Origin.Agent, [approval]).Decision);
        Assert.Equal(PermissionDecision.Allow, PermissionMatrix.DecideRouted(operation, Origin.Agent, [approval, allow]).Decision);
        Assert.Equal(PermissionDecision.Deny, PermissionMatrix.DecideRouted(operation, Origin.Agent, [allow, approval]).Decision);
        Assert.Equal(PermissionDecision.Deny, PermissionMatrix.DecideRouted(operation, Origin.Agent, [allow, remoteDeny]).Decision);
        Assert.NotNull(PermissionMatrix.Valid(new PermissionOverride
        {
            Operation = operation,
            Origin = Origin.Remote,
            Decision = PermissionDecision.Allow,
        }));
        Assert.Equal(PermissionDecision.Allow, PermissionMatrix.DecideRouted(operation, Origin.Remote, []).Decision);
        Assert.Equal(PermissionDecision.Deny, PermissionMatrix.DecideRouted(operation, Origin.Remote, [remoteDeny]).Decision);
    }

    [Fact]
    public void FileWriteAllowDoesNotAuthorizeRemovalOrCleanup()
    {
        var allow = new PermissionOverride
        {
            Operation = PermissionMatrix.FileWrite,
            Origin = Origin.Agent,
            Decision = PermissionDecision.Allow,
        };
        Assert.Equal(PermissionDecision.Allow, PermissionMatrix.DecideRouted(PermissionMatrix.FileWrite, Origin.Agent, [allow]).Decision);
        Assert.Equal(PermissionDecision.Deny, PermissionMatrix.DecideRouted(PermissionMatrix.FileRemove, Origin.Agent, [allow]).Decision);
        Assert.Equal(PermissionDecision.Allow, PermissionMatrix.DecideRouted(PermissionMatrix.CleanupPlan, Origin.Agent, [allow]).Decision);
        Assert.Equal(PermissionDecision.Approval, PermissionMatrix.DecideRouted(PermissionMatrix.CleanupExecute, Origin.Agent, [allow]).Decision);
        Assert.Equal(PermissionDecision.Deny, PermissionMatrix.DecideRouted(PermissionMatrix.ProcessTerminate, Origin.Human, [allow]).Decision);
    }

    [Fact(Timeout = 120_000)]
    public async Task ActualPolicyServiceRequiresHumanAndPersistsNarrowRoutedDecisionsAcrossRestart()
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        await using (var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter))
        {
            var unauthorized = await Sched.ChangePolicyAsync(agent, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileWrite,
                Origin = Origin.Agent,
                Decision = PermissionDecision.Allow,
            }));
            Assert.Equal("permission_denied", unauthorized.Error?.Code);
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileWrite,
                Origin = Origin.Agent,
                Decision = PermissionDecision.Approval,
            }))).Error);
            var explained = await agent.Policy.ExplainPermissionAsync(new PolicyServiceExplainPermissionRequest
            {
                Meta = Tasks.Meta(),
                Operation = PermissionMatrix.FileWrite,
                Origin = Origin.Agent,
            }, cancellationToken: token);
            Assert.Equal(PermissionDecision.Deny, explained.Value.Decision);
            Assert.Contains("explicit AGENT ALLOW required", explained.Value.Source, StringComparison.Ordinal);
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileWrite,
                Origin = Origin.Agent,
                Decision = PermissionDecision.Allow,
            }))).Error);
            var permissions = node.Runtime.Store.Read(r => PolicyRules.Current(r).Document.Permissions.ToArray());
            Assert.Equal(PermissionDecision.Allow,
                PermissionMatrix.DecideRouted(PermissionMatrix.FileWrite, Origin.Agent, permissions).Decision);
            Assert.Equal(PermissionDecision.Deny,
                PermissionMatrix.DecideRouted(PermissionMatrix.FileRemove, Origin.Agent, permissions).Decision);
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileWrite,
                Origin = Origin.Remote,
                Decision = PermissionDecision.Deny,
            }))).Error);
        }

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var restarted = node.Runtime.Store.Read(r => PolicyRules.Current(r).Document.Permissions.ToArray());
        Assert.Equal(PermissionDecision.Allow, PermissionMatrix.Decide(Origin.Agent, PermissionMatrix.FileWrite, restarted).Decision);
        Assert.Equal(PermissionDecision.Deny, PermissionMatrix.DecideRouted(PermissionMatrix.FileWrite, Origin.Agent, restarted).Decision);
        Assert.Equal(PermissionDecision.Deny, PermissionMatrix.DecideRouted(PermissionMatrix.FileRemove, Origin.Agent, restarted).Decision);
        Assert.Equal(PermissionDecision.Approval, PermissionMatrix.DecideRouted(PermissionMatrix.FileWrite, Origin.Script, []).Decision);
    }
}
