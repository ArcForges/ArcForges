// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real native targets, routed plan capture and SQLite; synthetic callers do not claim Center acceptance.</summary>
public sealed class RemovalPlanWorkspaceLifetimeTests
{
    [Fact(Timeout = 120_000)]
    public async Task ARealPendingPlanPreventsUnregistrationAcrossRestartWithoutHoldingAnUnrelatedWorkspace()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "planned-workspace")).FullName;
        var target = Path.Combine(root, "kept.txt");
        File.WriteAllText(target, "owned plan lifetime fixture");
        var registered = manager.RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var unrelatedRoot = Directory.CreateDirectory(Path.Combine(node.Root, "unrelated-workspace")).FullName;
        var unrelated = manager.RegisterFromVerifiedHuman(unrelatedRoot, cancellationToken: ct);
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath
            {
                WorkspaceId = new ArcForges.Contracts.Foundation.V1.Id { Value = ByteString.CopyFrom(registered.Id) },
                Path = "kept.txt",
            },
        };
        var response = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, response.Answer!.Outcome);
        var planned = FileServicePlanRemovalResponse.Parser.ParseFrom(response.Answer.Response);
        Assert.Null(planned.Error);
        Assert.Single(planned.Value.Plan.Items);

        Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.UnregisterFromVerifiedHuman(registered.Id, ct)).Reason);
        manager.UnregisterFromVerifiedHuman(unrelated.Id, ct);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM workspace WHERE workspace_id = $id AND removed_at IS NOT NULL;", ("$id", unrelated.Id))));
        Assert.Equal("owned plan lifetime fixture", File.ReadAllText(target));

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        manager = new RegisteredWorkspaces(node.Runtime.Store);
        Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.UnregisterFromVerifiedHuman(registered.Id, ct)).Reason);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM file_removal_plan WHERE workspace_id = $id;", ("$id", registered.Id))));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM workspace WHERE workspace_id = $id AND removed_at IS NULL;", ("$id", registered.Id))));
        Assert.Equal("owned plan lifetime fixture", File.ReadAllText(target));
    }

    [Theory(Timeout = 120_000)]
    [InlineData(CleanupPlanState.Planned, false, true)]
    [InlineData(CleanupPlanState.AwaitingApproval, false, true)]
    [InlineData(CleanupPlanState.Executing, false, true)]
    [InlineData(CleanupPlanState.Executing, true, true)]
    [InlineData(CleanupPlanState.Planned, true, false)]
    [InlineData(CleanupPlanState.AwaitingApproval, true, false)]
    [InlineData(CleanupPlanState.Completed, false, false)]
    [InlineData(CleanupPlanState.Partial, false, false)]
    [InlineData(CleanupPlanState.Expired, false, false)]
    [InlineData(CleanupPlanState.Cancelled, false, false)]
    public async Task OnlyLiveOrExecutingWorkspacePlansHoldRegistration(CleanupPlanState state, bool pastExpiry, bool holds)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "plan-state-workspace")).FullName;
        var target = Path.Combine(root, "kept.txt");
        File.WriteAllText(target, "state predicate fixture; no removal");
        var registered = manager.RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var calls = new RoutedCalls(node);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath
            {
                WorkspaceId = new ArcForges.Contracts.Foundation.V1.Id { Value = ByteString.CopyFrom(registered.Id) },
                Path = "kept.txt",
            },
        };
        var response = await calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.PlanNodeRemoval,
            request.ToByteArray(), request.Meta.CommandId);
        var planned = FileServicePlanRemovalResponse.Parser.ParseFrom(response.Answer!.Response);
        Assert.Null(planned.Error);
        var planId = planned.Value.Plan.PlanId.Value.ToByteArray();

        // Only the state/expiry inputs to this registration predicate are synthetic.
        // This does not execute cleanup, shorten the product's 60-minute lifetime, or claim a wall-clock retention pass.
        node.Runtime.Store.Write(transaction => transaction.Execute("""
            UPDATE cleanup_plan SET state = $state, expires_at = $expires, rev = rev + 1 WHERE plan_id = $plan;
            """, ("$state", (int)state), ("$expires", pastExpiry ? transaction.NowMicroseconds : transaction.NowMicroseconds + 60_000_000),
            ("$plan", planId)), CommitDurability.Full);

        if (holds)
        {
            Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(
                () => manager.UnregisterFromVerifiedHuman(registered.Id, ct)).Reason);
        }
        else
        {
            manager.UnregisterFromVerifiedHuman(registered.Id, ct);
        }

        Assert.Equal(holds ? 0L : 1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM workspace WHERE workspace_id = $id AND removed_at IS NOT NULL;", ("$id", registered.Id))));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM file_removal_plan WHERE plan_id = $plan;", ("$plan", planId))));
        Assert.Equal("state predicate fixture; no removal", File.ReadAllText(target));
    }
}
