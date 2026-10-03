// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;
using Xunit;
using Instant = ArcForges.Foundation.Instant;

namespace ArcForges.Security.Tests;

public sealed class LeaseManagerTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    // ---------------------------------------------------------------------------------------------------------------- issue

    [Fact]
    public async Task AnIssuedLeaseIsStoredActiveAndCoversExactlyWhatWasRequested()
    {
        var h = new LeaseHarness();
        var chain = h.DirectChain();
        var request = h.Request(issuedBy: chain, resources: ["b/2", "a/1"], risk: RiskLevel.R2, basis: LeaseIssueBasis.StepUpSatisfied, origin: DecisionOrigin.Remote, lifetime: TimeSpan.FromMinutes(20));
        var before = h.Now;

        var result = await h.Manager.IssueAsync(request, Token);

        Assert.True(result.Issued);
        Assert.Equal(LeaseIssueRefusal.None, result.Refusal);
        Assert.Equal(string.Empty, result.RegisteredCode);
        var lease = result.Lease!;
        Assert.Same(lease, h.Store.Peek(request.Id));
        Assert.Equal(request.Id, lease.Id);
        Assert.Equal(h.Owner, lease.Owner);
        Assert.Equal(h.Scope, lease.Scope);
        Assert.Equal(h.Task, lease.Task);
        Assert.Equal(request.Holder, lease.Holder);
        Assert.Equal(LeaseHarness.Capability, lease.CapabilityKey);
        Assert.Equal(["a/1", "b/2"], lease.ResourceIds);
        Assert.Equal(RiskLevel.R2, lease.EffectiveRisk);
        Assert.Equal(DecisionOrigin.Remote, lease.Origin);
        Assert.Equal(LeaseIssueBasis.StepUpSatisfied, lease.Basis);
        Assert.Same(chain, lease.IssuedBy);
        Assert.Equal(LeaseState.Active, lease.State);
        Assert.Equal(1, lease.Version);
        Assert.Null(lease.EndedAt);
        Assert.Equal(LeaseRevocationReason.None, lease.RevocationReason);
        Assert.False(lease.EndEventRecorded);
        Assert.Equal(before, lease.IssuedAt);
        Assert.Equal(h.Now, lease.IssuedAt);
        Assert.Equal(20 * 60, lease.ExpiresAt.UnixSeconds - lease.IssuedAt.UnixSeconds);
        Assert.Equal(lease.IssuedAt.Nanoseconds, lease.ExpiresAt.Nanoseconds);
    }

    [Fact]
    public async Task TheIssuedFactIsDurableBeforeTheLeaseExistsAndCarriesTheSameIdentity()
    {
        var h = new LeaseHarness();
        var request = h.Request();
        h.Sink.Behavior = (leaseEvent, _) =>
        {
            Assert.Null(h.Store.Peek(leaseEvent.LeaseId));
            return ValueTask.CompletedTask;
        };

        var lease = await h.IssueAsync(request);

        var leaseEvent = Assert.Single(h.Sink.Events);
        Assert.Equal(LeaseEventKind.Issued, leaseEvent.Kind);
        Assert.Equal(request.Id, leaseEvent.LeaseId);
        Assert.Equal(lease.Id, leaseEvent.Lease.Id);
        Assert.Equal(request.Id.Value, leaseEvent.Lease.Id.Value);
        Assert.Equal(lease.IssuedAt, leaseEvent.OccurredAt);
        Assert.Same(lease, leaseEvent.Lease);
    }

    [Fact]
    public async Task TheCeilingIsLookedUpForTheDelegatorsPrincipalCapabilityAndScopeExactly()
    {
        var h = new LeaseHarness();
        (string Principal, string Capability, string Scope)? seen = null;
        h.Ceilings.Override = (principal, capability, scope) =>
        {
            seen = (principal, capability, scope);
            return new PermissionGrantRecord("owner.test", principal, capability, scope, PermissionGrantState.Granted, [], h.Clock.UtcNow.AddHours(-1), h.Clock.UtcNow.AddHours(2), "generation-1");
        };

        _ = await h.IssueAsync();

        Assert.Equal(($"principal:{h.Owner.Realm.Value:N}/{h.Owner.Id.Value:N}", LeaseHarness.Capability, h.Scope.Key), seen);
        Assert.Equal(1, h.Ceilings.Calls);
    }

    [Theory]
    [InlineData(ActorKind.Agent)]
    [InlineData(ActorKind.Extension)]
    public async Task AHolderOfDelegatedAuthorityCannotIssueALease(ActorKind kind)
    {
        var h = new LeaseHarness();
        var chain = h.ChainOf(LeaseHarness.Actor(kind));

        await AssertRefusedAsync(h, h.Request(issuedBy: chain), LeaseIssueRefusal.IssuerCannotDelegate, "perm.capability_denied");
        Assert.Equal(0, h.Ceilings.Calls);
    }

    [Fact]
    public async Task ASubDelegationThroughALongerChainIsRefusedWhateverIsEarlierInTheChain()
    {
        var h = new LeaseHarness();

        await AssertRefusedAsync(h, h.Request(issuedBy: h.ChainOf(LeaseHarness.Actor(ActorKind.Automation), LeaseHarness.Actor(ActorKind.Agent))), LeaseIssueRefusal.IssuerCannotDelegate, "perm.capability_denied");
        await AssertRefusedAsync(h, h.Request(issuedBy: h.ChainOf(LeaseHarness.Actor(ActorKind.Agent), LeaseHarness.Actor(ActorKind.Extension))), LeaseIssueRefusal.IssuerCannotDelegate, "perm.capability_denied");
    }

    [Theory]
    [InlineData(ActorKind.Automation)]
    [InlineData(ActorKind.InternalService)]
    public async Task TheOwnersAutomationOrServiceMayIssueOnTheOwnersBehalf(ActorKind kind)
    {
        var h = new LeaseHarness();

        var lease = await h.IssueAsync(h.Request(issuedBy: h.ChainOf(LeaseHarness.Actor(kind))));

        Assert.Equal(LeaseState.Active, lease.State);
        Assert.Equal(kind, lease.IssuedBy.Actors[^1].Kind);
    }

    [Theory]
    [InlineData(ActorKind.Automation)]
    [InlineData(ActorKind.InternalService)]
    public async Task ALeaseCannotBeIssuedToAnActorThatCannotHoldOne(ActorKind kind)
    {
        var h = new LeaseHarness();

        await AssertRefusedAsync(h, h.Request(holder: new LeaseHolder(kind, Guid.NewGuid())), LeaseIssueRefusal.HolderCannotHoldLease, "perm.capability_denied");
    }

    [Fact]
    public async Task ALifetimeIsPositiveAndAtMostTheConfiguredMaximumToTheTick()
    {
        var h = new LeaseHarness(new LeaseOptions { MaximumLifetime = TimeSpan.FromMinutes(45) });

        await AssertRefusedAsync(h, h.Request(lifetime: TimeSpan.Zero), LeaseIssueRefusal.InvalidRequest, "validation.invalid_request");
        await AssertRefusedAsync(h, h.Request(lifetime: TimeSpan.FromTicks(-1)), LeaseIssueRefusal.InvalidRequest, "validation.invalid_request");
        await AssertRefusedAsync(h, h.Request(lifetime: TimeSpan.FromMinutes(45) + TimeSpan.FromTicks(1)), LeaseIssueRefusal.ExceedsMaximumLifetime, "validation.invalid_request");
        await AssertRefusedAsync(h, h.Request(lifetime: TimeSpan.FromHours(24)), LeaseIssueRefusal.ExceedsMaximumLifetime, "validation.invalid_request");
        var longest = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(45)));
        var shortest = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromTicks(1)));
        Assert.Equal(TimeSpan.FromMinutes(45).Ticks, (longest.ExpiresAt.UnixSeconds - longest.IssuedAt.UnixSeconds) * TimeSpan.TicksPerSecond);
        Assert.Equal(100L, ((long)shortest.ExpiresAt.Nanoseconds - shortest.IssuedAt.Nanoseconds + 1_000_000_000L) % 1_000_000_000L);
    }

    [Fact]
    public async Task TheDefaultMaximumIsOneHourAndAnOptionCanNeverExceedTwentyFour()
    {
        var h = new LeaseHarness();
        h.Ceilings.Until = TimeSpan.FromHours(30);

        _ = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromHours(1)));
        await AssertRefusedAsync(h, h.Request(lifetime: TimeSpan.FromHours(1) + TimeSpan.FromTicks(1)), LeaseIssueRefusal.ExceedsMaximumLifetime, "validation.invalid_request");
        var day = new LeaseHarness(new LeaseOptions { MaximumLifetime = TimeSpan.FromHours(24) });
        day.Ceilings.Until = TimeSpan.FromHours(30);
        _ = await day.IssueAsync(day.Request(lifetime: TimeSpan.FromHours(24)));
        var clock = h.Clock.Clock;
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new CapabilityLeaseManager(clock, h.Store, h.Sink, h.Ceilings, new LeaseOptions { MaximumLifetime = TimeSpan.Zero }));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new CapabilityLeaseManager(clock, h.Store, h.Sink, h.Ceilings, new LeaseOptions { MaximumLifetime = TimeSpan.FromTicks(-1) }));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new CapabilityLeaseManager(clock, h.Store, h.Sink, h.Ceilings, new LeaseOptions { MaximumLifetime = TimeSpan.FromHours(24) + TimeSpan.FromTicks(1) }));
        _ = Assert.Throws<ArgumentNullException>(() => new CapabilityLeaseManager(null!, h.Store, h.Sink, h.Ceilings));
        _ = Assert.Throws<ArgumentNullException>(() => new CapabilityLeaseManager(clock, null!, h.Sink, h.Ceilings));
        _ = Assert.Throws<ArgumentNullException>(() => new CapabilityLeaseManager(clock, h.Store, null!, h.Ceilings));
        _ = Assert.Throws<ArgumentNullException>(() => new CapabilityLeaseManager(clock, h.Store, h.Sink, null!));
    }

    [Fact]
    public async Task ALeaseForAnotherRealmThanTheDelegatorsIsRefused()
    {
        var h = new LeaseHarness();

        await AssertRefusedAsync(h, h.Request(scope: new DecisionScope(new RealmId(Guid.NewGuid()), null)), LeaseIssueRefusal.InvalidRequest, "validation.invalid_request");
        Assert.Equal(0, h.Ceilings.Calls);
    }

    [Fact]
    public async Task AScopeEscalationAttemptFindsNoCeiling()
    {
        var h = new LeaseHarness();
        var other = new DecisionScope(h.Owner.Realm, new WorkspaceId(Guid.NewGuid()));
        // The delegator holds the permission only in the harness workspace; the lease asks for another workspace of the same realm.
        h.Ceilings.Override = (principal, capability, scope) => scope == h.Scope.Key
            ? new PermissionGrantRecord("owner.test", principal, capability, scope, PermissionGrantState.Granted, [], h.Clock.UtcNow.AddHours(-1), h.Clock.UtcNow.AddHours(2), "generation-1")
            : null;

        await AssertRefusedAsync(h, h.Request(scope: other), LeaseIssueRefusal.CeilingMissing, "perm.capability_denied");
        _ = await h.IssueAsync(h.Request());
    }

    [Fact]
    public async Task ACapabilityTheDelegatorDoesNotHoldCannotBeLeased()
    {
        var h = new LeaseHarness();
        h.Ceilings.Override = (principal, capability, scope) => capability == "other.capability"
            ? new PermissionGrantRecord("owner.test", principal, capability, scope, PermissionGrantState.Granted, [], h.Clock.UtcNow.AddHours(-1), h.Clock.UtcNow.AddHours(2), "generation-1")
            : null;

        await AssertRefusedAsync(h, h.Request(), LeaseIssueRefusal.CeilingMissing, "perm.capability_denied");
        _ = await h.IssueAsync(h.Request(capability: "other.capability"));
    }

    [Theory]
    [InlineData("principal")]
    [InlineData("capability")]
    [InlineData("scope")]
    public async Task APermissionRecordForAnotherPrincipalCapabilityOrScopeIsNoCeiling(string which)
    {
        var h = new LeaseHarness();
        h.Ceilings.Override = (principal, capability, scope) => new PermissionGrantRecord(
            "owner.test",
            which == "principal" ? "principal:someone-else" : principal,
            which == "capability" ? "another.capability" : capability,
            which == "scope" ? "realm:other/workspace:other" : scope,
            PermissionGrantState.Granted, [], h.Clock.UtcNow.AddHours(-1), h.Clock.UtcNow.AddHours(2), "generation-1");

        await AssertRefusedAsync(h, h.Request(), LeaseIssueRefusal.CeilingMissing, "perm.capability_denied");
    }

    [Theory]
    [InlineData(PermissionGrantState.NotGranted)]
    [InlineData(PermissionGrantState.ExplicitlyDenied)]
    public async Task APermissionThatIsNotGrantedIsNoCeiling(PermissionGrantState state)
    {
        var h = new LeaseHarness();
        h.Ceilings.State = state;

        await AssertRefusedAsync(h, h.Request(), LeaseIssueRefusal.CeilingNotGranted, "perm.capability_denied");
    }

    [Fact]
    public async Task APermissionOutsideItsLifetimeNowIsNoCeilingAndItsEndIsExclusive()
    {
        var h = new LeaseHarness();

        h.Ceilings.From = TimeSpan.FromTicks(1);
        await AssertRefusedAsync(h, h.Request(), LeaseIssueRefusal.CeilingNotGranted, "perm.capability_denied");
        h.Ceilings.From = TimeSpan.Zero;
        _ = await h.IssueAsync(h.Request());
        h.Ceilings.From = TimeSpan.FromHours(-1);
        h.Ceilings.Until = TimeSpan.Zero;
        await AssertRefusedAsync(h, h.Request(), LeaseIssueRefusal.CeilingNotGranted, "perm.capability_denied");
        h.Ceilings.Until = TimeSpan.FromHours(-1) + TimeSpan.FromTicks(1);
        h.Ceilings.From = TimeSpan.FromHours(-2);
        await AssertRefusedAsync(h, h.Request(), LeaseIssueRefusal.CeilingNotGranted, "perm.capability_denied");
    }

    [Fact]
    public async Task APermissionThatExpiresDuringTheLookupIsJudgedAtTheInstantTheSourceAnswered()
    {
        var h = new LeaseHarness();
        h.Ceilings.Override = (principal, capability, scope) =>
        {
            var grant = new PermissionGrantRecord("owner.test", principal, capability, scope, PermissionGrantState.Granted, [], h.Clock.UtcNow.AddHours(-1), h.Clock.UtcNow.AddMinutes(10), "generation-1");
            h.Clock.Advance(TimeSpan.FromMinutes(10));
            return grant;
        };

        await AssertRefusedAsync(h, h.Request(lifetime: TimeSpan.FromMinutes(1)), LeaseIssueRefusal.CeilingNotGranted, "perm.capability_denied");
    }

    [Fact]
    public async Task ALeaseCannotOutliveTheDelegatorsPermissionAndMayEndWithIt()
    {
        var h = new LeaseHarness();
        h.Ceilings.Until = TimeSpan.FromMinutes(20);

        await AssertRefusedAsync(h, h.Request(lifetime: TimeSpan.FromMinutes(20) + TimeSpan.FromTicks(1)), LeaseIssueRefusal.ExceedsCeilingLifetime, "perm.capability_denied");
        await AssertRefusedAsync(h, h.Request(lifetime: TimeSpan.FromMinutes(30)), LeaseIssueRefusal.ExceedsCeilingLifetime, "perm.capability_denied");
        var lease = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(20)));
        Assert.Equal(20 * 60, lease.ExpiresAt.UnixSeconds - lease.IssuedAt.UnixSeconds);
    }

    [Fact]
    public async Task APermissionConstraintThatTheRequestDoesNotMeetIsNotNarrowedAwayByALease()
    {
        var h = new LeaseHarness();
        h.Ceilings.Constraints = [PermissionConstraints.LocalOriginOnly];

        await AssertRefusedAsync(h, h.Request(origin: DecisionOrigin.Remote), LeaseIssueRefusal.CeilingConstraintUnmet, "perm.capability_denied");
        _ = await h.IssueAsync(h.Request(origin: DecisionOrigin.Local));
        h.Ceilings.Constraints = [PermissionConstraints.DeviceBound(new DeviceId(Guid.NewGuid()))];
        await AssertRefusedAsync(h, h.Request(), LeaseIssueRefusal.CeilingConstraintUnmet, "perm.capability_denied");
        h.Ceilings.Constraints = [PermissionConstraints.DeviceBound(h.Device), PermissionConstraints.LocalOriginOnly];
        _ = await h.IssueAsync(h.Request());
        h.Ceilings.Constraints = [PermissionConstraints.DeviceBound(h.Device), PermissionConstraints.LocalOriginOnly];
        await AssertRefusedAsync(h, h.Request(origin: DecisionOrigin.Remote), LeaseIssueRefusal.CeilingConstraintUnmet, "perm.capability_denied");
    }

    [Fact]
    public async Task APermissionConstraintTheManagerCannotReadIsNeverIgnored()
    {
        var h = new LeaseHarness();
        h.Ceilings.Constraints = ["max-volume:10"];

        await AssertRefusedAsync(h, h.Request(), LeaseIssueRefusal.CeilingConstraintUnknown, "perm.capability_denied");
        h.Ceilings.Constraints = [PermissionConstraints.LocalOriginOnly, "time-window:office-hours"];
        await AssertRefusedAsync(h, h.Request(origin: DecisionOrigin.Remote), LeaseIssueRefusal.CeilingConstraintUnknown, "perm.capability_denied");
    }

    [Fact]
    public async Task APermissionSourceThatFailsIssuesNothingAndOnlyTheCallersCancellationPropagates()
    {
        var h = new LeaseHarness();
        h.Ceilings.Override = (_, _, _) => throw new InvalidOperationException("grants offline");

        await AssertRefusedAsync(h, h.Request(), LeaseIssueRefusal.CeilingUnavailable, "resource.unavailable");
        h.Ceilings.Override = (_, _, _) => throw new OperationCanceledException();
        await AssertRefusedAsync(h, h.Request(), LeaseIssueRefusal.CeilingUnavailable, "resource.unavailable");
        using var cancelled = new CancellationTokenSource();
        h.Ceilings.Override = (_, _, _) =>
        {
            cancelled.Cancel();
            throw new OperationCanceledException(cancelled.Token);
        };
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await h.Manager.IssueAsync(h.Request(), cancelled.Token));
        Assert.Empty(h.Store.All);
        Assert.Empty(h.Sink.Events);
    }

    [Fact]
    public async Task ALeaseWhoseIssuedFactCannotBeMadeDurableIsNotIssued()
    {
        var h = new LeaseHarness();
        h.Sink.Fail = true;
        var request = h.Request();

        var result = await h.Manager.IssueAsync(request, Token);

        Assert.False(result.Issued);
        Assert.Equal(LeaseIssueRefusal.AuditUnavailable, result.Refusal);
        Assert.Equal("resource.unavailable", result.RegisteredCode);
        Assert.Empty(h.Store.All);
        Assert.Equal(LeaseUseVerdict.OutOfScope, await h.ValidateAsync(new LeaseUse(request.Id, h.Owner, h.Scope, request.Holder, LeaseHarness.Capability, LeaseHarness.ResourceId)));
    }

    [Fact]
    public async Task AStoreThatFailsAfterTheFactLeavesNoUsableLease()
    {
        var h = new LeaseHarness();
        h.Store.FailCreates = true;
        var request = h.Request();

        var result = await h.Manager.IssueAsync(request, Token);

        Assert.False(result.Issued);
        Assert.Equal(LeaseIssueRefusal.StoreUnavailable, result.Refusal);
        Assert.Empty(h.Store.All);
        // The fact was durable first, so an audit record of an issue that never took effect is the one cost of this order.
        Assert.Equal([LeaseEventKind.Issued], h.Sink.Kinds);
        h.Store.FailCreates = false;
        Assert.Equal(LeaseUseVerdict.OutOfScope, await h.ValidateAsync(new LeaseUse(request.Id, h.Owner, h.Scope, request.Holder, LeaseHarness.Capability, LeaseHarness.ResourceId)));
    }

    [Fact]
    public async Task AStoreThatCannotBeReadBeforeTheFactIssuesNothing()
    {
        var h = new LeaseHarness();
        h.Store.FailReads = true;

        var result = await h.Manager.IssueAsync(h.Request(), Token);

        Assert.Equal(LeaseIssueRefusal.StoreUnavailable, result.Refusal);
        Assert.Empty(h.Sink.Events);
    }

    [Fact]
    public async Task AReplayedRequestIsADuplicateAndWritesNoSecondFact()
    {
        var h = new LeaseHarness();
        var request = h.Request();
        var first = await h.IssueAsync(request);

        var replay = await h.Manager.IssueAsync(request, Token);

        Assert.False(replay.Issued);
        Assert.Equal(LeaseIssueRefusal.Duplicate, replay.Refusal);
        Assert.Equal("conflict.duplicate_identifier", replay.RegisteredCode);
        Assert.Same(first, h.Store.Peek(request.Id));
        Assert.Equal([LeaseEventKind.Issued], h.Sink.Kinds);
    }

    [Fact]
    public async Task ARaceOnTheSameIdentityStoresOneLease()
    {
        var h = new LeaseHarness();
        var request = h.Request();
        var gate = new TaskCompletionSource();
        h.Sink.Behavior = async (_, token) => await gate.Task.WaitAsync(token);

        var results = Enumerable.Range(0, 4).Select(_ => h.Manager.IssueAsync(request, Token).AsTask()).ToArray();
        gate.SetResult();
        var finished = await Task.WhenAll(results);

        Assert.Equal(1, finished.Count(result => result.Issued));
        Assert.Equal(3, finished.Count(result => result.Refusal == LeaseIssueRefusal.Duplicate));
        _ = Assert.Single(h.Store.All);
    }

    [Fact]
    public async Task IssueRequiresARequestAndHonoursTheCallersCancellation()
    {
        var h = new LeaseHarness();
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await h.Manager.IssueAsync(null!, Token));
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await h.Manager.IssueAsync(h.Request(), cancelled.Token));
        Assert.Empty(h.Store.All);
        Assert.Empty(h.Sink.Events);
    }

    // ---------------------------------------------------------------------------------------------------------------- use

    [Fact]
    public async Task AUseThatTheLeaseCoversIsValid()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync(h.Request(resources: ["resource/42", "resource/43"]));

        Assert.Equal(LeaseUseVerdict.Valid, await h.ValidateAsync(h.Use(lease)));
        Assert.Equal(LeaseUseVerdict.Valid, await h.ValidateAsync(h.Use(lease, resource: "resource/43")));
        Assert.Equal(1, h.Store.All.Single().Version);
        Assert.Equal([LeaseEventKind.Issued], h.Sink.Kinds);
    }

    [Fact]
    public async Task EveryDifferenceBetweenTheUseAndTheLeaseIsOutOfScope()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        var otherOwner = new HumanPrincipal(h.Owner.Realm, new UserId(Guid.NewGuid()), HumanIdentityKind.CloudUser);
        var otherKind = new HumanPrincipal(h.Owner.Realm, h.Owner.Id, HumanIdentityKind.LocalHuman);
        var otherWorkspace = new DecisionScope(h.Owner.Realm, new WorkspaceId(Guid.NewGuid()));
        var noWorkspace = new DecisionScope(h.Owner.Realm, null);
        var otherRealm = new DecisionScope(new RealmId(Guid.NewGuid()), h.Scope.Workspace);

        var uses = new LeaseUse[]
        {
            h.Use(lease, owner: otherOwner),
            h.Use(lease, owner: otherKind),
            h.Use(lease, scope: otherWorkspace),
            h.Use(lease, scope: noWorkspace),
            h.Use(lease, scope: otherRealm),
            h.Use(lease, actor: LeaseHarness.Actor(ActorKind.Extension)),
            h.Use(lease, actor: new DelegatedActor(ActorKind.Agent, h.Extension.ActorId, h.Extension.Executor, "owned.extension/1")),
            h.Use(lease, actor: LeaseHarness.Actor(ActorKind.Automation)),
            h.Use(lease, capability: "test.capability.write"),
            h.Use(lease, resource: "resource/43"),
            h.Use(lease, resource: "RESOURCE/42"),
            h.Use(lease, resource: "resource/4"),
            h.Use(lease, capability: LeaseHarness.Capability.ToUpperInvariant()),
        };
        foreach (var use in uses)
        {
            Assert.Equal(LeaseUseVerdict.OutOfScope, await h.ValidateAsync(use));
        }

        Assert.Equal(LeaseUseVerdict.OutOfScope, await h.ValidateAsync(new LeaseUse(CapabilityLeaseId.New(), h.Owner, h.Scope, LeaseHarness.HolderOf(h.Extension), LeaseHarness.Capability, LeaseHarness.ResourceId)));
        Assert.Equal(LeaseUseVerdict.Valid, await h.ValidateAsync(h.Use(lease)));
    }

    [Fact]
    public async Task ALeaseExpiresAtUseNotOnlyAtIssueAndItsEndIsExclusiveToTheTick()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(30)));

        h.Clock.Advance(TimeSpan.FromMinutes(30) - TimeSpan.FromTicks(1));
        Assert.Equal(LeaseUseVerdict.Valid, await h.ValidateAsync(h.Use(lease)));
        h.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.Equal(LeaseUseVerdict.Expired, await h.ValidateAsync(h.Use(lease)));

        var stored = h.Store.Peek(lease.Id)!;
        Assert.Equal(LeaseState.Expired, stored.State);
        Assert.Equal(lease.ExpiresAt, stored.EndedAt);
        Assert.Equal(LeaseRevocationReason.None, stored.RevocationReason);
        Assert.True(stored.EndEventRecorded);
        Assert.Equal(3, stored.Version);
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Expired], h.Sink.Kinds);
        Assert.Equal(lease.Id, h.Sink.Events[1].LeaseId);
        Assert.Equal(LeaseState.Expired, h.Sink.Events[1].Lease.State);
        Assert.Equal(stored.EndedAt, h.Sink.Events[1].OccurredAt);
    }

    [Fact]
    public async Task AnObservedExpiryIsStoredOnceAndIsNotAuditedAgain()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        h.Clock.Advance(TimeSpan.FromHours(2));

        for (var index = 0; index < 5; index++)
        {
            Assert.Equal(LeaseUseVerdict.Expired, await h.ValidateAsync(h.Use(lease)));
        }

        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Expired], h.Sink.Kinds);
        Assert.Equal(3, h.Store.Peek(lease.Id)!.Version);
    }

    [Fact]
    public async Task AnExpiredLeaseCannotBeRevivedByAWallClockStepBackOrByANewManager()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(30)));
        h.Clock.Advance(TimeSpan.FromMinutes(31));
        Assert.Equal(LeaseUseVerdict.Expired, await h.ValidateAsync(h.Use(lease)));

        h.Clock.StepWallClock(TimeSpan.FromHours(-3));

        Assert.Equal(LeaseUseVerdict.Expired, await h.ValidateAsync(h.Use(lease)));
        var restarted = new CapabilityLeaseManager(h.Clock.Clock, h.Store, h.Sink, h.Ceilings);
        Assert.Equal(LeaseUseVerdict.Expired, await restarted.ValidateAsync(h.Use(lease), Token));
        Assert.Equal(LeaseState.Expired, h.Store.Peek(lease.Id)!.State);
    }

    [Fact]
    public async Task AWallClockStepBackBeforeTheExpiryIsSeenCannotExtendALease()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(30)));

        // Thirty-one minutes pass on the monotonic clock while the wall clock is set back to where it started.
        h.Clock.Advance(TimeSpan.FromMinutes(31));
        h.Clock.StepWallClock(TimeSpan.FromMinutes(-31));

        Assert.Equal(h.Now, lease.IssuedAt);
        Assert.Equal(LeaseUseVerdict.Expired, await h.ValidateAsync(h.Use(lease)));
    }

    [Fact]
    public async Task AWallClockStepForwardShortensALease()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(30)));

        h.Clock.StepWallClock(TimeSpan.FromMinutes(31));

        Assert.Equal(LeaseUseVerdict.Expired, await h.ValidateAsync(h.Use(lease)));
    }

    [Fact]
    public async Task ARevocationReachesTheNextUseWithNoCaching()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        Assert.Equal(LeaseUseVerdict.Valid, await h.ValidateAsync(h.Use(lease)));
        Assert.Equal(LeaseUseVerdict.Valid, await h.ValidateAsync(h.Use(lease)));

        var revoked = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);

        Assert.True(revoked.TryGetValue(out var transition));
        Assert.Equal(LeaseUseVerdict.Revoked, await h.ValidateAsync(h.Use(lease)));
        Assert.Equal(LeaseState.Revoked, transition.Lease.State);
    }

    [Fact]
    public async Task AUseThatIsNotTheLeasesIsOutOfScopeEvenOnceTheLeaseHasEnded()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        _ = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);

        Assert.Equal(LeaseUseVerdict.OutOfScope, await h.ValidateAsync(h.Use(lease, actor: LeaseHarness.Actor(ActorKind.Extension))));
        Assert.Equal(LeaseUseVerdict.OutOfScope, await h.ValidateAsync(h.Use(lease, resource: "resource/43")));
        Assert.Equal(LeaseUseVerdict.Revoked, await h.ValidateAsync(h.Use(lease)));
    }

    [Fact]
    public async Task AStoreThatCannotBeReadFailsTheCheckLoudlyRatherThanAnswering()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        h.Store.FailReads = true;

        _ = await Assert.ThrowsAsync<InvalidOperationException>(async () => await h.ValidateAsync(h.Use(lease)));
    }

    [Fact]
    public async Task ACheckThatKeepsLosingTheRaceToExpireAnswersUnknownNotValid()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        h.Clock.Advance(TimeSpan.FromHours(2));
        h.Store.ConflictReplaces = true;

        Assert.Equal(LeaseUseVerdict.Unknown, await h.ValidateAsync(h.Use(lease)));
        Assert.Equal(LeaseState.Active, h.Store.Peek(lease.Id)!.State);
        Assert.Equal(8, h.Store.Reads - 1);
    }

    [Fact]
    public async Task AValidateCallRequiresAUse()
    {
        var h = new LeaseHarness();

        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await h.Manager.ValidateAsync(null!, Token));
    }

    // ---------------------------------------------------------------------------------------------------------------- revoke

    [Fact]
    public async Task RevocationStoresTheEndThenRecordsTheFactWithTheSameIdentity()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        h.Clock.Advance(TimeSpan.FromMinutes(5));

        var outcome = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.PolicyDenied, Token);

        Assert.True(outcome.TryGetValue(out var transition));
        Assert.True(transition.Changed);
        Assert.True(transition.EndRecorded);
        Assert.Equal(LeaseState.Revoked, transition.Lease.State);
        Assert.Equal(LeaseRevocationReason.PolicyDenied, transition.Lease.RevocationReason);
        Assert.Equal(h.Now, transition.Lease.EndedAt);
        Assert.True(transition.Lease.EndEventRecorded);
        Assert.Equal(3, transition.Lease.Version);
        Assert.Same(transition.Lease, h.Store.Peek(lease.Id));
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Revoked], h.Sink.Kinds);
        var fact = h.Sink.Events[1];
        Assert.Equal(lease.Id, fact.LeaseId);
        Assert.Equal(LeaseState.Revoked, fact.Lease.State);
        Assert.Equal(LeaseRevocationReason.PolicyDenied, fact.Lease.RevocationReason);
        Assert.Equal(h.Now, fact.OccurredAt);
        Assert.Equal(lease.Id.Value, fact.Lease.Id.Value);
    }

    [Theory]
    [InlineData(LeaseRevocationReason.OwnerRevoked)]
    [InlineData(LeaseRevocationReason.PolicyDenied)]
    [InlineData(LeaseRevocationReason.RiskRejected)]
    [InlineData(LeaseRevocationReason.AuthorityLost)]
    public async Task EveryRevocationReasonIsKept(LeaseRevocationReason reason)
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();

        var outcome = await h.Manager.RevokeAsync(lease.Id, h.Owner, reason, Token);

        Assert.True(outcome.TryGetValue(out var transition));
        Assert.Equal(reason, transition.Lease.RevocationReason);
        Assert.Equal(reason, h.Sink.Events[1].Lease.RevocationReason);
    }

    [Fact]
    public async Task OnlyTheLeasesOwnerCanRevokeIt()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        var stranger = new HumanPrincipal(h.Owner.Realm, new UserId(Guid.NewGuid()), HumanIdentityKind.CloudUser);
        var otherRealm = new HumanPrincipal(new RealmId(Guid.NewGuid()), h.Owner.Id, HumanIdentityKind.CloudUser);

        foreach (var principal in new[] { stranger, otherRealm })
        {
            var outcome = await h.Manager.RevokeAsync(lease.Id, principal, LeaseRevocationReason.OwnerRevoked, Token);

            Assert.True(outcome.TryGetFailure(out var failure));
            Assert.Equal("perm.capability_denied", failure.Code);
        }

        Assert.Equal(LeaseState.Active, h.Store.Peek(lease.Id)!.State);
        Assert.Equal([LeaseEventKind.Issued], h.Sink.Kinds);
        Assert.Equal(LeaseUseVerdict.Valid, await h.ValidateAsync(h.Use(lease)));
    }

    [Fact]
    public async Task RevokingAnUnknownLeaseIsNotFound()
    {
        var h = new LeaseHarness();

        var outcome = await h.Manager.RevokeAsync(CapabilityLeaseId.New(), h.Owner, LeaseRevocationReason.OwnerRevoked, Token);

        Assert.True(outcome.TryGetFailure(out var failure));
        Assert.Equal("state.not_found", failure.Code);
    }

    [Fact]
    public async Task RevokingTwiceChangesNothingAndWritesNoSecondFact()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        _ = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);

        var again = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.RiskRejected, Token);

        Assert.True(again.TryGetValue(out var transition));
        Assert.False(transition.Changed);
        Assert.True(transition.EndRecorded);
        Assert.Equal(LeaseRevocationReason.OwnerRevoked, transition.Lease.RevocationReason);
        Assert.Equal(3, h.Store.Peek(lease.Id)!.Version);
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Revoked], h.Sink.Kinds);
    }

    [Fact]
    public async Task ALeasePastItsExpiryThatNobodyObservedEndsAsExpiredWhenRevoked()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(30)));
        h.Clock.Advance(TimeSpan.FromMinutes(40));

        var outcome = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);

        Assert.True(outcome.TryGetValue(out var transition));
        Assert.True(transition.Changed);
        Assert.Equal(LeaseState.Expired, transition.Lease.State);
        Assert.Equal(LeaseRevocationReason.None, transition.Lease.RevocationReason);
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Expired], h.Sink.Kinds);
    }

    [Fact]
    public async Task ARevocationEndsAuthorityEvenWhenTheFactCannotBeWrittenAndTheFactStaysOwedUntilItIs()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        h.Sink.Fail = true;

        var outcome = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);

        Assert.True(outcome.TryGetValue(out var transition));
        Assert.True(transition.Changed);
        Assert.False(transition.EndRecorded);
        var stored = h.Store.Peek(lease.Id)!;
        Assert.Equal(LeaseState.Revoked, stored.State);
        Assert.False(stored.EndEventRecorded);
        Assert.Equal(2, stored.Version);
        Assert.Equal([LeaseEventKind.Issued], h.Sink.Kinds);
        // Authority is already gone while the audit is down, and a use of an ended lease writes nothing.
        Assert.Equal(LeaseUseVerdict.Revoked, await h.ValidateAsync(h.Use(lease)));
        h.Sink.Fail = false;
        Assert.Equal(LeaseUseVerdict.Revoked, await h.ValidateAsync(h.Use(lease)));
        Assert.Equal([LeaseEventKind.Issued], h.Sink.Kinds);
        Assert.False(h.Store.Peek(lease.Id)!.EndEventRecorded);

        var sweep = await h.Manager.ExpireDueAsync(Token);

        Assert.Equal(new LeaseSweep(0, 1, 0), sweep);
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Revoked], h.Sink.Kinds);
        Assert.Equal(LeaseRevocationReason.OwnerRevoked, h.Sink.Events[1].Lease.RevocationReason);
        Assert.True(h.Store.Peek(lease.Id)!.EndEventRecorded);
        Assert.Equal(LeaseUseVerdict.Revoked, await h.ValidateAsync(h.Use(lease)));
        Assert.Equal(new LeaseSweep(0, 0, 0), await h.Manager.ExpireDueAsync(Token));
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Revoked], h.Sink.Kinds);
    }

    [Fact]
    public async Task ARepeatedRevokeWritesNothingAndReportsAnOwedFactAsStillOwed()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        h.Sink.Fail = true;
        _ = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);
        h.Sink.Fail = false;

        var again = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);

        Assert.True(again.TryGetValue(out var transition));
        Assert.False(transition.Changed);
        Assert.False(transition.EndRecorded);
        Assert.Equal([LeaseEventKind.Issued], h.Sink.Kinds);
        Assert.Equal(2, h.Store.Peek(lease.Id)!.Version);
    }

    [Fact]
    public async Task AFactWrittenButNotMarkedStaysOwedAndIsWrittenAgainRatherThanLost()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        h.Store.Seed(LeaseHarness.Ended(h.Store.Peek(lease.Id)!, LeaseState.Revoked, h.Now, LeaseRevocationReason.OwnerRevoked));
        // The sink succeeds but the store then refuses the mark, so the fact is written and still owed.
        h.Sink.Behavior = (_, _) =>
        {
            h.Store.FailReplaces = true;
            return ValueTask.CompletedTask;
        };

        var first = await h.Manager.ExpireDueAsync(Token);

        Assert.Equal(new LeaseSweep(0, 0, 1), first);
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Revoked], h.Sink.Kinds);
        Assert.False(h.Store.Peek(lease.Id)!.EndEventRecorded);
        h.Sink.Behavior = null;
        h.Store.FailReplaces = false;
        var second = await h.Manager.ExpireDueAsync(Token);
        Assert.Equal(new LeaseSweep(0, 1, 0), second);
        Assert.True(h.Store.Peek(lease.Id)!.EndEventRecorded);
        // At least once: the lease identity and the kind identify the repeated fact.
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Revoked, LeaseEventKind.Revoked], h.Sink.Kinds);
        Assert.All(h.Sink.Events.Skip(1), item => Assert.Equal(lease.Id, item.LeaseId));
    }

    [Fact]
    public async Task AStoreThatFailsToRecordTheRevocationLeavesTheLeaseActiveAndTheFailureVisible()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        h.Store.FailReplaces = true;

        _ = await Assert.ThrowsAsync<InvalidOperationException>(async () => await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token));

        Assert.Equal(LeaseState.Active, h.Store.Peek(lease.Id)!.State);
        Assert.Equal([LeaseEventKind.Issued], h.Sink.Kinds);
    }

    [Fact]
    public async Task ARevokeThatKeepsLosingTheRaceIsAConflictAndNeverASilentSuccess()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();
        h.Store.ConflictReplaces = true;

        var outcome = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);

        Assert.True(outcome.TryGetFailure(out var failure));
        Assert.Equal("conflict.revision_mismatch", failure.Code);
        Assert.Equal(LeaseState.Active, h.Store.Peek(lease.Id)!.State);
    }

    [Fact]
    public async Task RevokeValidatesItsArguments()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();

        _ = await Assert.ThrowsAsync<ArgumentException>(async () => await h.Manager.RevokeAsync(default, h.Owner, LeaseRevocationReason.OwnerRevoked, Token));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await h.Manager.RevokeAsync(lease.Id, null!, LeaseRevocationReason.OwnerRevoked, Token));
        _ = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.None, Token));
        _ = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await h.Manager.RevokeAsync(lease.Id, h.Owner, (LeaseRevocationReason)40, Token));
        Assert.Equal(LeaseState.Active, h.Store.Peek(lease.Id)!.State);
    }

    [Fact]
    public async Task SimultaneousRevocationsEndTheLeaseOnceAndRecordOneFact()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync();

        var tasks = Enumerable.Range(0, 16).Select(_ => Task.Run(
            async () => await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token), Token)).ToArray();
        var outcomes = await Task.WhenAll(tasks);

        var transitions = outcomes.Select(outcome => outcome.TryGetValue(out var value) ? value : throw new InvalidOperationException()).ToArray();
        Assert.Equal(1, transitions.Count(transition => transition.Changed));
        Assert.Equal(LeaseState.Revoked, h.Store.Peek(lease.Id)!.State);
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Revoked], h.Sink.Kinds);
    }

    [Fact]
    public async Task UsesAndRevocationsRacingAtTheExpiryEndTheLeaseOnceAndAuditOnceWithNoValidAnswerAfterwards()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(30)));
        h.Clock.Advance(TimeSpan.FromMinutes(30));

        var verdicts = await Task.WhenAll(Enumerable.Range(0, 12).Select(index => Task.Run(
            async () =>
            {
                if (index % 2 == 0)
                {
                    return await h.ValidateAsync(h.Use(lease));
                }

                _ = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);
                return LeaseUseVerdict.Expired;
            },
            Token)));

        Assert.All(verdicts, verdict => Assert.Equal(LeaseUseVerdict.Expired, verdict));
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Expired], h.Sink.Kinds);
        Assert.Equal(LeaseState.Expired, h.Store.Peek(lease.Id)!.State);
    }

    // ---------------------------------------------------------------------------------------------------------------- task end and sweeps

    [Fact]
    public async Task TheEndOfATaskEndsOnlyThatTasksLeasesAutomatically()
    {
        var h = new LeaseHarness();
        var other = TaskId.New();
        var a1 = await h.IssueAsync(h.Request());
        var a2 = await h.IssueAsync(h.Request(resources: ["resource/43"]));
        var b1 = await h.IssueAsync(h.Request(task: other));
        Assert.Equal(LeaseUseVerdict.Valid, await h.ValidateAsync(h.Use(a1)));

        var sweep = await h.Manager.EndTaskAsync(h.Task, Token);

        Assert.Equal(new LeaseSweep(2, 2, 0), sweep);
        Assert.Equal(LeaseUseVerdict.Expired, await h.ValidateAsync(h.Use(a1)));
        Assert.Equal(LeaseUseVerdict.Expired, await h.ValidateAsync(h.Use(a2, resource: "resource/43")));
        Assert.Equal(LeaseUseVerdict.Valid, await h.ValidateAsync(h.Use(b1)));
        Assert.Equal(LeaseState.TaskEnded, h.Store.Peek(a1.Id)!.State);
        Assert.Equal(LeaseState.Active, h.Store.Peek(b1.Id)!.State);
        Assert.Equal(2, h.Sink.Kinds.Count(kind => kind == LeaseEventKind.TaskEnded));
        Assert.All(h.Sink.Events.Where(item => item.Kind == LeaseEventKind.TaskEnded), item => Assert.Equal(h.Task, item.Lease.Task));
        Assert.Contains(h.Sink.Events, item => item.Kind == LeaseEventKind.TaskEnded && item.LeaseId == a1.Id);
        Assert.Contains(h.Sink.Events, item => item.Kind == LeaseEventKind.TaskEnded && item.LeaseId == a2.Id);
        Assert.Equal(new LeaseSweep(0, 0, 0), await h.Manager.EndTaskAsync(h.Task, Token));
        Assert.Equal(2, h.Sink.Kinds.Count(kind => kind == LeaseEventKind.TaskEnded));
    }

    [Fact]
    public async Task ALeaseAlreadyPastItsExpiryWhenItsTaskEndsEndsAsExpired()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(10)));
        h.Clock.Advance(TimeSpan.FromMinutes(11));

        var sweep = await h.Manager.EndTaskAsync(h.Task, Token);

        Assert.Equal(new LeaseSweep(1, 1, 0), sweep);
        Assert.Equal(LeaseState.Expired, h.Store.Peek(lease.Id)!.State);
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Expired], h.Sink.Kinds);
    }

    [Fact]
    public async Task ATaskThatEndsWhileTheAuditIsDownOwesItsFactsAndAnotherSweepWritesEachOnce()
    {
        var h = new LeaseHarness();
        _ = await h.IssueAsync(h.Request());
        _ = await h.IssueAsync(h.Request(resources: ["resource/43"]));
        h.Sink.Fail = true;

        var first = await h.Manager.EndTaskAsync(h.Task, Token);

        Assert.Equal(new LeaseSweep(2, 0, 2), first);
        Assert.All(h.Store.All, lease => Assert.Equal((LeaseState.TaskEnded, false), (lease.State, lease.EndEventRecorded)));
        h.Sink.Fail = false;
        var second = await h.Manager.EndTaskAsync(h.Task, Token);
        Assert.Equal(new LeaseSweep(0, 2, 0), second);
        Assert.Equal(2, h.Sink.Kinds.Count(kind => kind == LeaseEventKind.TaskEnded));
        Assert.Equal(new LeaseSweep(0, 0, 0), await h.Manager.EndTaskAsync(h.Task, Token));
    }

    [Fact]
    public async Task ASweepWalksEveryPageOfLeases()
    {
        var h = new LeaseHarness();
        h.Ceilings.Until = TimeSpan.FromHours(2);
        for (var index = 0; index < 150; index++)
        {
            _ = await h.IssueAsync(h.Request(resources: [$"resource/{index}"]));
        }

        var sweep = await h.Manager.EndTaskAsync(h.Task, Token);

        Assert.Equal(new LeaseSweep(150, 150, 0), sweep);
        Assert.All(h.Store.All, lease => Assert.Equal(LeaseState.TaskEnded, lease.State));
        Assert.Equal(150, h.Sink.Kinds.Count(kind => kind == LeaseEventKind.TaskEnded));
    }

    [Fact]
    public async Task ASweepThatCannotAdvanceTheStoreStopsInsteadOfLooping()
    {
        var h = new LeaseHarness();
        _ = await h.IssueAsync();
        h.Store.ConflictReplaces = true;

        var sweep = await h.Manager.EndTaskAsync(h.Task, Token).AsTask().WaitAsync(TimeSpan.FromSeconds(30), Token);

        Assert.Equal(new LeaseSweep(0, 0, 0), sweep);
        Assert.Equal(LeaseState.Active, h.Store.All.Single().State);
    }

    [Fact]
    public async Task ASweepOverAFailingStoreFailsLoudly()
    {
        var h = new LeaseHarness();
        _ = await h.IssueAsync();
        h.Store.FailReplaces = true;

        _ = await Assert.ThrowsAsync<InvalidOperationException>(async () => await h.Manager.EndTaskAsync(h.Task, Token));
        _ = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            h.Clock.Advance(TimeSpan.FromHours(2));
            _ = await h.Manager.ExpireDueAsync(Token);
        });
    }

    [Fact]
    public async Task ExpireDueEndsExactlyTheLeasesWhoseTimeIsOver()
    {
        var h = new LeaseHarness();
        var shortLived = await h.IssueAsync(h.Request(lifetime: TimeSpan.FromMinutes(10)));
        var longLived = await h.IssueAsync(h.Request(resources: ["resource/43"], lifetime: TimeSpan.FromMinutes(30)));
        Assert.Equal(new LeaseSweep(0, 0, 0), await h.Manager.ExpireDueAsync(Token));

        h.Clock.Advance(TimeSpan.FromMinutes(10) - TimeSpan.FromTicks(1));
        Assert.Equal(new LeaseSweep(0, 0, 0), await h.Manager.ExpireDueAsync(Token));
        h.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.Equal(new LeaseSweep(1, 1, 0), await h.Manager.ExpireDueAsync(Token));

        Assert.Equal(LeaseState.Expired, h.Store.Peek(shortLived.Id)!.State);
        Assert.Equal(LeaseState.Active, h.Store.Peek(longLived.Id)!.State);
        h.Clock.Advance(TimeSpan.FromMinutes(20));
        Assert.Equal(new LeaseSweep(1, 1, 0), await h.Manager.ExpireDueAsync(Token));
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Issued, LeaseEventKind.Expired, LeaseEventKind.Expired], h.Sink.Kinds);
        Assert.Equal(new LeaseSweep(0, 0, 0), await h.Manager.ExpireDueAsync(Token));
    }

    [Fact]
    public async Task ExpireDueRetriesFactsOwedByEarlierRevocationsOfAnyTask()
    {
        var h = new LeaseHarness();
        var lease = await h.IssueAsync(h.Request(task: TaskId.New()));
        h.Sink.Fail = true;
        _ = await h.Manager.RevokeAsync(lease.Id, h.Owner, LeaseRevocationReason.OwnerRevoked, Token);
        h.Sink.Fail = false;

        var sweep = await h.Manager.ExpireDueAsync(Token);

        Assert.Equal(new LeaseSweep(0, 1, 0), sweep);
        Assert.Equal([LeaseEventKind.Issued, LeaseEventKind.Revoked], h.Sink.Kinds);
    }

    [Fact]
    public async Task EndingATaskRequiresATask()
    {
        var h = new LeaseHarness();

        _ = await Assert.ThrowsAsync<ArgumentException>(async () => await h.Manager.EndTaskAsync(default, Token));
    }

    // ---------------------------------------------------------------------------------------------------------------- helpers

    private static async Task AssertRefusedAsync(LeaseHarness h, LeaseRequest request, LeaseIssueRefusal refusal, string code)
    {
        var storedBefore = h.Store.All.Count;
        var eventsBefore = h.Sink.Events.Count;

        var result = await h.Manager.IssueAsync(request, Token);

        Assert.False(result.Issued);
        Assert.Null(result.Lease);
        Assert.Equal(refusal, result.Refusal);
        Assert.Equal(code, result.RegisteredCode);
        Assert.Equal(storedBefore, h.Store.All.Count);
        Assert.Equal(eventsBefore, h.Sink.Events.Count);
        Assert.Null(h.Store.Peek(request.Id));
    }
}
