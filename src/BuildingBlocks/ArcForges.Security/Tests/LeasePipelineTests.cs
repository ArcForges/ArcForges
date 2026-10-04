// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>
/// Leases through the real decision pipeline with the real lease manager: the lease is checked at use in the permission step and again
/// at the owner's final validation, in addition to (never instead of) the delegator's own permission.
/// </summary>
public sealed class LeasePipelineTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task AnAgentActsUnderALeaseThroughEveryStepAndTheAuditNamesTheLease()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        var request = w.Request(lease);

        var execution = await w.Pipeline().ExecuteAsync(request, w.Owner.OwnerOperation.Operation, Token);

        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        Assert.Equal(StepDisposition.Passed, execution.Decision.Steps[5].Disposition);
        Assert.Equal(StepDisposition.Passed, execution.Decision.Steps[10].Disposition);
        Assert.Equal(1, w.Owner.OwnerOperation.Calls);
        var audit = Assert.Single(w.Decisions.Audit.Records);
        Assert.Equal(SecurityAuditKind.Executed, audit.Kind);
        Assert.Equal(lease.Id, audit.Lease);
        var use = w.Owner.OwnerOperation.LastTicket!.Lease!;
        Assert.Equal(lease.Id, use.Lease);
        Assert.Equal(w.Leases.Owner, use.Owner);
        Assert.Equal(w.Leases.Scope, use.Scope);
        Assert.Equal(LeaseHarness.HolderOf(w.Leases.Agent), use.Holder);
        Assert.Equal(LeaseHarness.Capability, use.CapabilityKey);
        Assert.Equal(LeaseHarness.ResourceId, use.ResourceId);
    }

    [Theory]
    [InlineData(ActorKind.Agent)]
    [InlineData(ActorKind.Extension)]
    public async Task AnAgentOrAnExtensionWithoutALeaseIsRefusedEvenWithEveryOtherStepSatisfied(ActorKind kind)
    {
        var w = new World();
        var actor = kind == ActorKind.Agent ? w.Leases.Agent : w.Leases.Extension;
        var builder = w.Builder(null, actor);
        builder.OmitLease = true;

        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, builder.Build(), Token);

        Assert.False(decision.Allowed);
        Assert.Equal(DecisionReason.S06LeaseRequired, decision.Reason);
        Assert.Equal(DecisionStep.CapabilityPermission, decision.FailedStep);
        Assert.Equal("perm.capability_denied", decision.RegisteredCode);
        Assert.Equal(StepDisposition.Passed, decision.Steps[4].Disposition);
        Assert.Equal(0, w.Owner.OwnerOperation.Calls);
    }

    [Fact]
    public async Task ALeaseNeverReplacesTheDelegatorsPermission()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        var readsAfterIssue = w.Leases.Store.Reads;
        w.Decisions.Permissions.Behavior = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(null);

        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, w.Request(lease), Token);

        Assert.Equal(DecisionReason.S06NotGranted, decision.Reason);
        Assert.Equal(readsAfterIssue, w.Leases.Store.Reads);

        w.Decisions.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(
            w.Decisions.Grant(request, validFromOffset: TimeSpan.FromHours(-3), validUntilOffset: TimeSpan.FromHours(-2)));
        var expired = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, w.Request(lease), Token);
        Assert.Equal(DecisionReason.S06OutsideLifetime, expired.Reason);

        w.Decisions.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(
            w.Decisions.Grant(request, PermissionGrantState.ExplicitlyDenied));
        var denied = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, w.Request(lease), Token);
        Assert.Equal(DecisionReason.S06ExplicitlyDenied, denied.Reason);
        Assert.Equal(readsAfterIssue, w.Leases.Store.Reads);
    }

    [Fact]
    public async Task APermissionConstraintStillBindsAnInvocationUnderALease()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        w.Decisions.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(
            w.Decisions.Grant(request, constraints: [PermissionConstraints.LocalOriginOnly]));
        var builder = w.Builder(lease);
        builder.Origin = DecisionOrigin.Remote;

        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, builder.Build(), Token);

        Assert.Equal(DecisionReason.S06ConstraintUnmet, decision.Reason);
    }

    [Fact]
    public async Task ALeaseThatHasExpiredAtUseIsRefusedWithTheRegisteredLeaseExpiredCode()
    {
        var w = new World();
        var lease = await w.IssueAsync(TimeSpan.FromMinutes(10));
        var request = w.Request(lease);
        Assert.True((await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, request, Token)).Allowed);

        w.Clock.Advance(TimeSpan.FromMinutes(10));
        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, w.Request(lease), Token);

        Assert.Equal(DecisionReason.S06LeaseExpired, decision.Reason);
        Assert.Equal("perm.lease_expired", decision.RegisteredCode);
        Assert.Equal("decision.s06.lease_expired", decision.ReasonCode);
        Assert.Equal(DecisionAuditStatus.Written, decision.Audit);
        Assert.Equal(lease.Id, Assert.Single(w.Decisions.Audit.Records).Lease);
        Assert.Equal(LeaseState.Expired, w.Leases.Store.Peek(lease.Id)!.State);
    }

    [Fact]
    public async Task ARevokedLeaseIsRefusedAtTheNextUse()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        Assert.True((await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, w.Request(lease), Token)).Allowed);
        _ = await w.Leases.Manager.RevokeAsync(lease.Id, w.Leases.Owner, LeaseRevocationReason.OwnerRevoked, Token);

        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, w.Request(lease), Token);

        Assert.Equal(DecisionReason.S06LeaseRevoked, decision.Reason);
        Assert.Equal("perm.capability_denied", decision.RegisteredCode);
    }

    [Fact]
    public async Task ALeaseEndedByTheEndOfItsTaskIsRefusedAsExpired()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        _ = await w.Leases.Manager.EndTaskAsync(w.Leases.Task, Token);

        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, w.Request(lease), Token);

        Assert.Equal(DecisionReason.S06LeaseExpired, decision.Reason);
        Assert.Equal("perm.lease_expired", decision.RegisteredCode);
    }

    [Fact]
    public async Task ARevocationAfterTheServiceDecisionStopsTheOwnerOperationAtTheFinalValidation()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        var request = w.Request(lease);
        var pipeline = w.Pipeline();
        var service = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, Token);
        Assert.True(service.Allowed);
        _ = await w.Leases.Manager.RevokeAsync(lease.Id, w.Leases.Owner, LeaseRevocationReason.PolicyDenied, Token);

        var execution = await pipeline.ExecuteDecidedAsync(service, request, w.Owner.OwnerOperation.Operation, Token);

        Assert.Equal(ExecutionStatus.Refused, execution.Status);
        Assert.Equal(DecisionReason.S11LeaseRevoked, execution.Decision.Reason);
        Assert.Equal(DecisionStep.OwnerValidation, execution.Decision.FailedStep);
        Assert.Equal("perm.capability_denied", DecisionHarness.FailureCode(execution.Result));
        Assert.Equal(0, w.Owner.OwnerOperation.Calls);
        Assert.Equal(0, w.Owner.Log.Count("owner"));
        var audit = w.Decisions.Audit.Records[^1];
        Assert.Equal(SecurityAuditKind.Refused, audit.Kind);
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, audit.Point);
        Assert.Equal(lease.Id, audit.Lease);
    }

    [Fact]
    public async Task AnExpiryAfterTheServiceDecisionStopsTheOwnerOperationAtTheFinalValidation()
    {
        var w = new World();
        var lease = await w.IssueAsync(TimeSpan.FromSeconds(30));
        var request = w.Request(lease);
        var pipeline = w.Pipeline();
        var service = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, Token);
        Assert.True(service.Allowed);
        w.Clock.Advance(TimeSpan.FromSeconds(30));

        var execution = await pipeline.ExecuteDecidedAsync(service, request, w.Owner.OwnerOperation.Operation, Token);

        Assert.Equal(DecisionReason.S11LeaseExpired, execution.Decision.Reason);
        Assert.Equal("perm.lease_expired", DecisionHarness.FailureCode(execution.Result));
        Assert.Equal(0, w.Owner.OwnerOperation.Calls);
    }

    [Fact]
    public async Task ARevocationMidOperationReachesTheNextSecurityBoundaryOfTheOperation()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        var verdicts = new List<LeaseUseVerdict>();
        var effects = 0;
        w.Owner.OwnerOperation.Behavior = async (ticket, token) =>
        {
            var first = await w.Leases.Manager.ValidateAsync(ticket.Lease!, token);
            verdicts.Add(first);
            effects++;
            _ = await w.Leases.Manager.RevokeAsync(lease.Id, w.Leases.Owner, LeaseRevocationReason.OwnerRevoked, token);
            var second = await w.Leases.Manager.ValidateAsync(ticket.Lease!, token);
            verdicts.Add(second);
            return second == LeaseUseVerdict.Valid
                ? Outcome.Success("done")
                : Outcome.Failure<string>(TypedFailure.Create("perm.capability_denied"));
        };

        var execution = await w.Pipeline().ExecuteAsync(w.Request(lease), w.Owner.OwnerOperation.Operation, Token);

        Assert.Equal([LeaseUseVerdict.Valid, LeaseUseVerdict.Revoked], verdicts);
        Assert.Equal(1, effects);
        Assert.Equal(ExecutionStatus.OwnerFailed, execution.Status);
        Assert.Equal("perm.capability_denied", DecisionHarness.FailureCode(execution.Result));
    }

    [Fact]
    public async Task AnExpiryMidOperationReachesTheNextSecurityBoundaryOfTheOperation()
    {
        var w = new World();
        var lease = await w.IssueAsync(TimeSpan.FromMinutes(5));
        var verdicts = new List<LeaseUseVerdict>();
        w.Owner.OwnerOperation.Behavior = async (ticket, token) =>
        {
            verdicts.Add(await w.Leases.Manager.ValidateAsync(ticket.Lease!, token));
            w.Clock.Advance(TimeSpan.FromMinutes(5));
            verdicts.Add(await w.Leases.Manager.ValidateAsync(ticket.Lease!, token));
            return Outcome.Success("done");
        };

        _ = await w.Pipeline().ExecuteAsync(w.Request(lease), w.Owner.OwnerOperation.Operation, Token);

        Assert.Equal([LeaseUseVerdict.Valid, LeaseUseVerdict.Expired], verdicts);
    }

    [Fact]
    public async Task ATicketOfADirectRequestCarriesNoLeaseUse()
    {
        var w = new World();
        var builder = w.Owner.Request();
        builder.Actors = w.Leases.DirectChain();
        builder.Scope = w.Leases.Scope;

        var execution = await w.Pipeline().ExecuteAsync(builder.Build(), w.Owner.OwnerOperation.Operation, Token);

        Assert.Equal(ExecutionStatus.Succeeded, execution.Status);
        Assert.Null(w.Owner.OwnerOperation.LastTicket!.Lease);
        Assert.Equal(0, w.Leases.Store.Reads);
    }

    [Fact]
    public async Task EveryScopeEscalationAttemptOfALeaseHolderIsRefusedAsOutOfScope()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        var otherWorkspace = new DecisionScope(w.Leases.Owner.Realm, new WorkspaceId(Guid.NewGuid()));

        // Another resource, another capability, another workspace and another agent, each with the same lease.
        var anotherResource = w.Builder(lease);
        anotherResource.Resource = new ResourceReference("resource/43", "revision:7");
        var anotherWorkspace = w.Builder(lease);
        anotherWorkspace.Scope = otherWorkspace;
        var anotherAgent = w.Builder(lease, LeaseHarness.Actor(ActorKind.Agent));
        var anotherKind = w.Builder(lease, LeaseHarness.Actor(ActorKind.Extension));
        var attempts = new[] { anotherResource, anotherWorkspace, anotherAgent, anotherKind };

        foreach (var builder in attempts)
        {
            var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, builder.Build(), Token);

            Assert.Equal(DecisionReason.S06LeaseOutOfScope, decision.Reason);
            Assert.Equal("perm.capability_denied", decision.RegisteredCode);
        }

        w.Decisions.Descriptor = DecisionHarness.Describe("test.capability.write", "R1", "none", "none");
        var anotherCapability = w.Builder(lease);
        anotherCapability.Capability = "test.capability.write";
        var write = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, anotherCapability.Build(), Token);
        Assert.Equal(DecisionReason.S06LeaseOutOfScope, write.Reason);
        Assert.Equal(0, w.Owner.OwnerOperation.Calls);
    }

    [Fact]
    public async Task ALeaseOfAnotherOwnerDoesNotCoverThisOwnersAgent()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        var stranger = new HumanPrincipal(w.Leases.Owner.Realm, new UserId(Guid.NewGuid()), HumanIdentityKind.CloudUser);
        var chain = new ActorChain(stranger, w.Leases.Device, w.Leases.Installation, ArcForges.Foundation.Execution.SessionId.New(), w.Leases.Caller, [w.Leases.Agent]);
        var builder = w.Builder(lease);
        builder.Actors = chain;

        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, builder.Build(), Token);

        Assert.Equal(DecisionReason.S06LeaseOutOfScope, decision.Reason);
    }

    [Fact]
    public async Task AnOwnerActingDirectlyNeedsNoLeaseAndAClaimedLeaseIsOutOfScope()
    {
        var w = new World();
        var direct = w.Owner.Request();
        direct.Actors = w.Leases.DirectChain();
        direct.Scope = w.Leases.Scope;
        Assert.True((await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, direct.Build(), Token)).Allowed);
        Assert.Equal(0, w.Leases.Store.Reads);

        var lease = await w.IssueAsync();
        var claimed = w.Owner.Request();
        claimed.Actors = w.Leases.DirectChain();
        claimed.Scope = w.Leases.Scope;
        claimed.Lease = lease.Id;
        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, claimed.Build(), Token);
        Assert.Equal(DecisionReason.S06LeaseOutOfScope, decision.Reason);
    }

    [Theory]
    [InlineData(ActorKind.Automation)]
    [InlineData(ActorKind.InternalService)]
    public async Task AutomationAndInternalServiceAreReauthorizedByPermissionAtEachTriggerAndNeedNoLease(ActorKind kind)
    {
        var w = new World();
        var builder = w.Builder(null, LeaseHarness.Actor(kind));
        builder.OmitLease = true;

        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, builder.Build(), Token);

        Assert.True(decision.Allowed);
        Assert.Equal(0, w.Leases.Store.Reads);
    }

    [Fact]
    public async Task ALeaseHeldByAnAutomationActorCannotBeUsedAsItsOwn()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        var builder = w.Builder(lease, LeaseHarness.Actor(ActorKind.Automation));

        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, builder.Build(), Token);

        Assert.Equal(DecisionReason.S06LeaseOutOfScope, decision.Reason);
    }

    [Theory]
    [InlineData(ActorKind.Agent, ActorKind.Automation)]
    [InlineData(ActorKind.Extension, ActorKind.InternalService)]
    public async Task AnAgentOrExtensionAnywhereInTheChainNeedsALeaseEvenWhenAnotherActorFollowsIt(ActorKind delegated, ActorKind after)
    {
        var w = new World();
        var holder = delegated == ActorKind.Agent ? w.Leases.Agent : w.Leases.Extension;
        var chain = w.Leases.ChainOf(holder, LeaseHarness.Actor(after));
        var without = w.Builder(null, holder);
        without.Actors = chain;
        without.OmitLease = true;

        var refused = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, without.Build(), Token);

        Assert.Equal(DecisionReason.S06LeaseRequired, refused.Reason);
        var lease = await w.Leases.IssueAsync(w.Leases.Request(holder: LeaseHarness.HolderOf(holder)));
        var covered = w.Builder(lease, holder);
        covered.Actors = chain;
        var other = w.Builder(await w.Leases.IssueAsync(w.Leases.Request(holder: LeaseHarness.HolderOf(LeaseHarness.Actor(delegated)))), holder);
        other.Actors = chain;
        var wrong = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, other.Build(), Token);
        Assert.Equal(DecisionReason.S06LeaseOutOfScope, wrong.Reason);
        var ok = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, covered.Build(), Token);
        Assert.NotEqual(DecisionStep.CapabilityPermission, ok.FailedStep);
        Assert.Equal(StepDisposition.Passed, ok.Steps[5].Disposition);
    }

    [Fact]
    public async Task TheOwnerPointAloneRequiresTheLeaseToo()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        var without = w.Builder(null, w.Leases.Agent);
        without.OmitLease = true;

        var refused = await w.Pipeline().EvaluateAsync(EnforcementPoint.OwnerFinalValidation, without.Build(), Token);

        Assert.Equal(DecisionReason.S11LeaseRequired, refused.Reason);
        Assert.Equal("perm.capability_denied", refused.RegisteredCode);
        Assert.Equal(0, w.Owner.Log.Count("owner"));
        var allowed = await w.Pipeline().EvaluateAsync(EnforcementPoint.OwnerFinalValidation, w.Request(lease), Token);
        Assert.True(allowed.Allowed);
        Assert.Equal(1, w.Owner.Log.Count("owner"));
    }

    [Fact]
    public async Task AnUnconfiguredLeaseCheckRefusesALeaseBearingRequestAndStillRequiresALease()
    {
        var w = new World();
        var h = w.Decisions;
        var services = new DecisionPipelineServices(
            h.Clock.Clock, h.Catalogue, h.Policy, h.Identity, h.Scope, h.Trust, h.Permissions, h.Resources, h.DataBoundary,
            h.Approvals, h.StepUp, h.Sensitive, h.Owner, h.Recorder, h.Audit);
        Assert.Null(services.Leases);
        var pipeline = new SecurityDecisionPipeline(services);
        var lease = await w.IssueAsync();

        var bearing = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, w.Request(lease), Token);
        var without = w.Builder(null, w.Leases.Agent);
        without.OmitLease = true;
        var missing = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, without.Build(), Token);
        var direct = w.Owner.Request();
        direct.Actors = w.Leases.DirectChain();
        direct.Scope = w.Leases.Scope;
        var human = await pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, direct.Build(), Token);

        Assert.Equal(DecisionReason.S06LeaseUnavailable, bearing.Reason);
        Assert.Equal(DecisionReason.S06LeaseRequired, missing.Reason);
        Assert.True(human.Allowed);
    }

    [Fact]
    public async Task ALeaseStoreThatIsDownRefusesTheStepAsUnavailableAndNeverAllows()
    {
        var w = new World();
        var lease = await w.IssueAsync();
        w.Leases.Store.FailReads = true;

        var decision = await w.Pipeline().EvaluateAsync(EnforcementPoint.ServiceDecision, w.Request(lease), Token);

        Assert.Equal(DecisionReason.S06LeaseUnavailable, decision.Reason);
        Assert.Equal("resource.unavailable", decision.RegisteredCode);
    }

    [Fact]
    public void AnEmptyLeaseIdentityCannotBeNamedByARequest()
    {
        var w = new World();
        var builder = w.Builder(null, w.Leases.Agent);
        _ = builder.Build();

        _ = Assert.Throws<ArgumentException>(() => new DecisionRequest(
            builder.Actors, builder.Capability, builder.Scope, builder.CommandId, builder.Resource, builder.Effect, builder.Origin,
            builder.Transport, lease: default(CapabilityLeaseId)));
    }

    /// <summary>The pipeline harness and the lease harness on one clock, with the real lease manager as the pipeline's lease check.</summary>
    private sealed class World
    {
        internal World()
        {
            Clock = new DecisionClock();
            Decisions = new DecisionHarness(clock: Clock);
            Leases = new LeaseHarness(clock: Clock);
            Decisions.RealLeases = Leases.Manager;
            Decisions.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(Decisions.Grant(request));
        }

        internal DecisionClock Clock { get; }

        internal DecisionHarness Decisions { get; }

        internal LeaseHarness Leases { get; }

        /// <summary>The pipeline harness named for the owner operation and its log.</summary>
        internal DecisionHarness Owner => Decisions;

        internal SecurityDecisionPipeline Pipeline() => Decisions.Pipeline();

        internal async Task<CapabilityLease> IssueAsync(TimeSpan? lifetime = null) =>
            await Leases.IssueAsync(Leases.Request(holder: LeaseHarness.HolderOf(Leases.Agent), lifetime: lifetime ?? TimeSpan.FromMinutes(30)));

        internal DecisionRequest Request(CapabilityLease lease) => Builder(lease).Build();

        internal RequestBuilder Builder(CapabilityLease? lease, DelegatedActor? actor = null)
        {
            var builder = Decisions.Request();
            builder.Actors = Leases.ChainOf(actor ?? Leases.Agent);
            builder.Scope = Leases.Scope;
            builder.Lease = lease?.Id;
            return builder;
        }
    }
}
