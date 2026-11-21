// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Retained removal plans in real SQLite and the current owner-authorized workspace lifetime checks.</summary>
public sealed class RemovalPlanWorkspaceLifetimeTests
{
    [Fact(Timeout = 120_000)]
    public async Task ARetainedPendingPlanPreventsUnregistrationAcrossRestartWithoutHoldingAnUnrelatedWorkspace()
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
        var plan = SeedRetainedPlan(node, registered, ct);
        Assert.Single(plan.Items);

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
        var planId = SeedRetainedPlan(node, registered, ct).PlanId.Value.ToByteArray();

        // Set the historical state against the same validation boundary the current unregistration reads.
        node.Runtime.Store.Write(transaction =>
        {
            var sample = RoutedFileValidationTime.Sample(transaction);
            Assert.True(sample.Healthy);
            var expiry = sample.BoundaryMicroseconds + (pastExpiry ? 0 : 60_000_000);
            Assert.Equal(1, transaction.Execute("""
                UPDATE cleanup_plan SET state = $state, expires_at = $expires, rev = rev + 1 WHERE plan_id = $plan;
                """, ("$state", (int)state), ("$expires", expiry), ("$plan", planId)));
        }, CommitDurability.Full);

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

    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AWallClockJumpOrPersistedFutureFloorCannotReleaseThePlanHold(bool persistForwardObservation)
    {
        var ct = TestContext.Current.CancellationToken;
        var clock = new OffsetClock();
        await using var node = InProcessNode.Create();
        node.Clock = clock;
        await node.StartAsync();
        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "clock-plan-workspace")).FullName;
        var target = Path.Combine(root, "kept.txt");
        File.WriteAllText(target, "clock-disagreement fixture; no removal");
        var registered = manager.RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var plan = SeedRetainedPlan(node, registered, ct);
        var expires = StoreTime.ToMicroseconds(ProtoTime.ToDateTimeOffset(plan.ExpiresAt)!.Value);
        long HighWater() => (long)node.Runtime.Store.Read(reader =>
            reader.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;"))!;
        var initialFloor = HighWater();
        Assert.True(initialFloor < expires);

        // A test-only clock offset exercises the real clock-health/floor code; no host clock or product deadline changes.
        clock.Offset = TimeSpan.FromHours(2);
        var forward = node.Runtime.Store.Read(RoutedFileValidationTime.Sample);
        Assert.False(forward.Healthy);
        Assert.True(forward.BoundaryMicroseconds > expires);
        var expectedFloor = initialFloor;
        if (persistForwardObservation)
        {
            var persisted = node.Runtime.Store.Write(RoutedFileValidationTime.Advance, CommitDurability.Full);
            Assert.False(persisted.Healthy);
            expectedFloor = persisted.BoundaryMicroseconds;
            Assert.True(expectedFloor >= forward.BoundaryMicroseconds);
        }

        Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.UnregisterFromVerifiedHuman(registered.Id, ct)).Reason);
        clock.Offset = TimeSpan.Zero;
        Assert.Equal(!persistForwardObservation, node.Runtime.Store.Read(RoutedFileValidationTime.Sample).Healthy);
        Assert.Equal(expectedFloor, HighWater());
        Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(
            () => manager.UnregisterFromVerifiedHuman(registered.Id, ct)).Reason);
        if (persistForwardObservation)
        {
            Assert.Equal(0, await node.StopAsync());
            await node.StartAsync();
            Assert.Equal(expectedFloor, HighWater());
            Assert.False(node.Runtime.Store.Read(RoutedFileValidationTime.Sample).Healthy);
            manager = new RegisteredWorkspaces(node.Runtime.Store);
            Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(
                () => manager.UnregisterFromVerifiedHuman(registered.Id, ct)).Reason);
        }
        Assert.Equal("clock-disagreement fixture; no removal", File.ReadAllText(target));
    }

    private static FileRemovalPlan SeedRetainedPlan(InProcessNode node, RegisteredWorkspace workspace, CancellationToken ct)
    {
        var caller = new RoutedCalls(node).Relay(Origin.Human);
        var path = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "kept.txt" };
        var request = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), WorkspacePath = path };
        var command = request.Meta.CommandId.Value.ToByteArray();
        var digest = SHA256.HashData(request.ToByteArray());
        using var root = WorkspacePath.OpenRoot(workspace.RootPath);
        var snapshot = WorkspaceRemovalPlan.Capture(root, path.Path, ct);
        return node.Runtime.Store.Write(transaction =>
        {
            var time = RoutedFileValidationTime.Advance(transaction);
            Assert.True(time.Healthy);
            var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId };
            var prepared = FileRemovalPlans.PrepareWorkspace(transaction, command, digest, caller, actor, path, workspace.RootPath,
                snapshot, time.BoundaryMicroseconds, quarantineAvailable: true);
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, command,
                "arcforges.node.v1.FileService/PlanRemoval", digest, Origin.Remote).Status);
            FileRemovalPlans.RecordWorkspace(transaction, prepared);
            transaction.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);",
                ("$id", command), ("$caller", caller.ToByteArray()));
            var receipt = new FileServicePlanRemovalResponse
            {
                Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
                Value = new FileServicePlanRemovalValue { Plan = prepared.Plan },
            };
            CommandDeduplication.Complete(transaction, command, receipt.ToByteArray());
            return prepared.Plan;
        }, CommitDurability.Full);
    }

    private sealed class OffsetClock : TimeProvider
    {
        private long _offsetTicks;

        public TimeSpan Offset { set => Interlocked.Exchange(ref _offsetTicks, value.Ticks); }

        public override DateTimeOffset GetUtcNow() => TimeProvider.System.GetUtcNow().AddTicks(Interlocked.Read(ref _offsetTicks));
    }
}
