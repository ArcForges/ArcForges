// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Approvals;
using ArcForges.Security.CapabilityEnforcement;
using ArcForges.Security.Decisions;
using ArcForges.Security.Egress;
using ArcForges.Security.Leases;
using ArcForges.Security.Trust;
using Xunit;

namespace ArcForges.Security.Tests;

/// <summary>
/// One product instance end to end (WP-09.07, WP-11.02): a real first-party capability is resolved, checked for availability against
/// real evidence, its context frozen, authorized by the real decision pipeline over the real trust evaluator, lease manager, egress
/// authority and approval coordinators, invoked through the owner's ticket-bound operation, recorded and audited. The doubles are the
/// facts and sinks other tasks own, listed on <see cref="EnforcementWorld"/>; nothing here proves a durable store, a process boundary
/// or an operating-system isolation.
/// </summary>
public sealed class CapabilityEnforcementEndToEndTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    private static readonly string[] AllowedOrder =
    [
        "trace.started", "availability", "context.freeze", "evidence", "policy", "transport", "identity", "scope", "permission",
        "resource", "sensitive", "record.begin", "owner", "owner-op", "record", "audit", "record.complete", "trace.completed",
    ];

    [Fact]
    public async Task ARealCapabilityRunsEveryStageInOrderAndIsRecordedAndAudited()
    {
        var w = new EnforcementWorld();
        w.OwnerComparesRevision();

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        Assert.Equal(OutcomeKind.Success, outcome.Kind);
        Assert.Equal("owner-result", outcome.Value!.Result.Value.Text);
        Assert.Equal(12, outcome.Value.Version.Revision!.Value);
        Assert.Equal(AllowedOrder, w.Log.Entries);
        Assert.Equal(1, w.OwnerRuns);
        Assert.Equal([TrustKind.SoftwareIdentity], w.Facts.Reads);

        var record = Assert.Single(w.Decisions.Recorder.Records);
        Assert.Equal(EnforcementWorld.GetSession, record.CapabilityKey);
        Assert.Equal(DecisionResultKind.Success, record.Result);
        Assert.Equal(RiskLevel.R1, record.EffectiveRisk);
        Assert.Equal(EffectCertainty.Happened, record.Effect);
        var audit = Assert.Single(w.Decisions.Audit.Records);
        Assert.Equal(SecurityAuditKind.Executed, audit.Kind);
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, audit.Point);
        Assert.Equal(EnforcementWorld.GetSession, audit.CapabilityKey);
        Assert.Equal(EnforcementWorld.ResourceId, audit.Resource.Id);
        Assert.Equal(EnforcementWorld.ResourceRevision, audit.Resource.Revision);
        Assert.Equal(DecisionOrigin.Local, audit.Origin);
        Assert.Null(audit.Lease);
        Assert.Equal(record.CommandId, audit.Correlation);

        var stored = Assert.Single(w.Records.Outcomes);
        Assert.Equal(OutcomeKind.Success, stored.Kind);
        Assert.Equal(2, w.Trace.Records.Count);
        Assert.Equal(EnforcementWorld.GetSession, w.Trace.Records[1].CapabilityKey);
        Assert.Equal(OutcomeKind.Success, w.Trace.Records[1].OutcomeKind);

        var ticket = w.LastTicket!;
        Assert.Equal(EnforcementWorld.GetSession, ticket.CapabilityKey);
        Assert.Equal(EnforcementWorld.ResourceId, ticket.Resource.Id);
        Assert.True(ticket.Decision.Allowed);
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, ticket.Decision.Point);
    }

    [Fact]
    public async Task AnAgentActsOnlyUnderItsLeaseAndTheAuditNamesTheLease()
    {
        var w = new EnforcementWorld();
        w.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(w.DefaultEvidence(w.AgentChain()));
        var lease = await w.IssueLeaseAsync(w.Leases.Agent);

        var outcome = await w.InvokeAsync(w.Invocation(lease: lease.Id), cancellationToken: Token);

        Assert.Equal(OutcomeKind.Success, outcome.Kind);
        Assert.Equal(1, w.OwnerRuns);
        var audit = Assert.Single(w.Decisions.Audit.Records);
        Assert.Equal(lease.Id, audit.Lease);
        Assert.Equal(SecurityAuditKind.Executed, audit.Kind);
        var use = w.LastTicket!.Lease!;
        Assert.Equal(lease.Id, use.Lease);
        Assert.Equal(LeaseHarness.HolderOf(w.Leases.Agent), use.Holder);
        Assert.Equal(EnforcementWorld.GetSession, use.CapabilityKey);
        Assert.Equal(EnforcementWorld.ResourceId, use.ResourceId);
        Assert.Equal(RiskLevel.R2, Assert.Single(w.Decisions.Recorder.Records).EffectiveRisk);
    }

    [Fact]
    public async Task AnExtensionNeedsItsLeaseAndAnApprovalBecauseTheRealRiskModelRaisesItsRisk()
    {
        var w = new EnforcementWorld();
        w.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(w.DefaultEvidence(w.ExtensionChain()));
        DecisionRequest? seen = null;
        w.Decisions.Permissions.Behavior = (request, _) =>
        {
            seen = request;
            return ValueTask.FromResult<PermissionGrantRecord?>(w.Decisions.Grant(request));
        };
        var lease = await w.IssueLeaseAsync(w.Leases.Extension);
        var command = Guid.NewGuid();

        var unapproved = await w.InvokeAsync(w.Invocation(lease: lease.Id, command: command), cancellationToken: Token);
        AssertRefusedAtAuthorize(w, unapproved, "perm.approval_required", DecisionReason.S10ApprovalRequired);
        Assert.Contains(TrustKind.ExtensionState, w.Facts.Reads);
        Assert.Contains(TrustKind.Package, w.Facts.Reads);

        var approval = await w.Decisions.ApproveAsync(seen!, RiskLevel.R3);
        var approved = await w.InvokeAsync(w.Invocation(lease: lease.Id, approval: approval, command: command), cancellationToken: Token);

        Assert.Equal(OutcomeKind.Success, approved.Kind);
        Assert.Equal(1, w.OwnerRuns);
        Assert.Equal(RiskLevel.R3, Assert.Single(w.Decisions.Recorder.Records).EffectiveRisk);
        Assert.Equal(lease.Id, w.Decisions.Audit.Records.Single(record => record.Kind == SecurityAuditKind.Executed).Lease);
    }

    [Fact]
    public async Task AnExtensionWhoseTrustWasRevokedIsRefusedEvenWithItsLease()
    {
        var w = new EnforcementWorld();
        w.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(w.DefaultEvidence(w.ExtensionChain()));
        var lease = await w.IssueLeaseAsync(w.Leases.Extension);
        w.Facts.Extension = ExtensionTrustState.Revoked;

        var outcome = await w.InvokeAsync(w.Invocation(lease: lease.Id), cancellationToken: Token);

        AssertRefusedAtAuthorize(w, outcome, "perm.capability_denied", DecisionReason.S05TrustRevoked);
    }

    [Theory]
    [InlineData(ActorKind.Agent)]
    [InlineData(ActorKind.Extension)]
    public async Task ADelegatedActorWithoutALeaseIsRefusedBeforeAnythingIsRecordedOrInvoked(ActorKind kind)
    {
        var w = new EnforcementWorld();
        var chain = kind == ActorKind.Agent ? w.AgentChain() : w.ExtensionChain();
        w.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(w.DefaultEvidence(chain));

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        AssertRefusedAtAuthorize(w, outcome, "perm.capability_denied", DecisionReason.S06LeaseRequired);
        Assert.Equal(kind, w.Decisions.Audit.Records.Single().Actors.Actors.Single().Kind);
    }

    [Fact]
    public async Task ALeaseForAnotherCapabilityOrResourceDoesNotCoverThisInvocation()
    {
        var other = new EnforcementWorld();
        other.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(other.DefaultEvidence(other.AgentChain()));
        var wrongCapability = await other.IssueLeaseAsync(capability: "IScopeOperations.ListSessions");
        var refusedCapability = await other.InvokeAsync(other.Invocation(lease: wrongCapability.Id), cancellationToken: Token);
        AssertRefusedAtAuthorize(other, refusedCapability, "perm.capability_denied", DecisionReason.S06LeaseOutOfScope);

        var second = new EnforcementWorld();
        second.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(second.DefaultEvidence(second.AgentChain()));
        var wrongResource = await second.IssueLeaseAsync(resource: "resource/other");
        var refusedResource = await second.InvokeAsync(second.Invocation(lease: wrongResource.Id), cancellationToken: Token);
        AssertRefusedAtAuthorize(second, refusedResource, "perm.capability_denied", DecisionReason.S06LeaseOutOfScope);
    }

    [Fact]
    public async Task AnExpiredOrRevokedLeaseIsRefusedWithItsRegisteredCode()
    {
        var expired = new EnforcementWorld();
        expired.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(expired.DefaultEvidence(expired.AgentChain()));
        var shortLease = await expired.IssueLeaseAsync(lifetime: TimeSpan.FromMinutes(10));
        expired.Clock.Advance(TimeSpan.FromMinutes(10));
        var late = await expired.InvokeAsync(expired.Invocation(lease: shortLease.Id), cancellationToken: Token);
        AssertRefusedAtAuthorize(expired, late, "perm.lease_expired", DecisionReason.S06LeaseExpired);

        var revoked = new EnforcementWorld();
        revoked.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(revoked.DefaultEvidence(revoked.AgentChain()));
        var lease = await revoked.IssueLeaseAsync();
        _ = await revoked.Leases.Manager.RevokeAsync(lease.Id, revoked.Leases.Owner, LeaseRevocationReason.OwnerRevoked, Token);
        var refused = await revoked.InvokeAsync(revoked.Invocation(lease: lease.Id), cancellationToken: Token);
        AssertRefusedAtAuthorize(revoked, refused, "perm.capability_denied", DecisionReason.S06LeaseRevoked);
    }

    [Fact]
    public async Task ALeaseRevokedAfterAuthorizationStopsTheOwnerAtItsFinalValidation()
    {
        var w = new EnforcementWorld();
        w.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(w.DefaultEvidence(w.AgentChain()));
        var lease = await w.IssueLeaseAsync();
        w.Records.BeforeDispatch = async () =>
        {
            _ = await w.Leases.Manager.RevokeAsync(lease.Id, w.Leases.Owner, LeaseRevocationReason.OwnerRevoked, Token);
        };

        var outcome = await w.InvokeAsync(w.Invocation(lease: lease.Id), cancellationToken: Token);

        Assert.Equal(OutcomeKind.Failure, outcome.Kind);
        Assert.Equal("perm.capability_denied", outcome.Failure!.Code);
        Assert.Equal(0, w.OwnerRuns);
        Assert.Equal(1, w.Records.BeginCalls);
        Assert.Equal(1, w.Records.CompleteCalls);
        var audit = Assert.Single(w.Decisions.Audit.Records);
        Assert.Equal(SecurityAuditKind.Refused, audit.Kind);
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, audit.Point);
        Assert.Equal(DecisionStep.OwnerValidation, audit.FailedStep);
        Assert.Equal("decision.s11.lease_revoked", audit.ReasonCode);
        Assert.Equal(lease.Id, audit.Lease);
        Assert.Empty(w.Decisions.Recorder.Records);
        Assert.DoesNotContain("owner", w.Log.Entries);
    }

    [Theory]
    [InlineData("policy-disabled", DecisionReason.S02PolicyDisabled, "perm.capability_denied")]
    [InlineData("policy-offline", DecisionReason.S02Unavailable, "resource.unavailable")]
    [InlineData("unauthenticated", DecisionReason.S03Unauthenticated, "auth.unauthenticated")]
    [InlineData("session-expired", DecisionReason.S03SessionExpired, "auth.session_expired")]
    [InlineData("transport-revoked", DecisionReason.S03TransportRefused, "auth.unauthenticated")]
    [InlineData("scope-invalid", DecisionReason.S04WorkspaceInvalid, "perm.resource_denied")]
    [InlineData("trust-mismatched", DecisionReason.S05TrustRevoked, "perm.capability_denied")]
    [InlineData("trust-unknown", DecisionReason.S05TrustUnknown, "perm.capability_denied")]
    [InlineData("trust-offline", DecisionReason.S05Unavailable, "resource.unavailable")]
    [InlineData("permission-missing", DecisionReason.S06NotGranted, "perm.capability_denied")]
    [InlineData("permission-denied", DecisionReason.S06ExplicitlyDenied, "perm.capability_denied")]
    [InlineData("permission-expired", DecisionReason.S06OutsideLifetime, "perm.capability_denied")]
    [InlineData("permission-offline", DecisionReason.S06Unavailable, "resource.unavailable")]
    [InlineData("resource-denied", DecisionReason.S07ResourceDenied, "perm.resource_denied")]
    public async Task EveryFailingSourceRefusesTheRealInvocationAtItsOwnStepAndCodeWithoutRecordingOrInvoking(
        string failure,
        DecisionReason reason,
        string code)
    {
        var w = new EnforcementWorld();
        Configure(w, failure);

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        AssertRefusedAtAuthorize(w, outcome, code, reason);
        Assert.Empty(w.Decisions.Recorder.Records);
    }

    [Fact]
    public async Task EvidenceThatIsMissingOrThrowsRefusesBeforeAnyDecisionStepRuns()
    {
        var missing = new EnforcementWorld();
        missing.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(null);
        var none = await missing.InvokeAsync(missing.Invocation(), cancellationToken: Token);
        AssertFailedClosedBeforeDecision(missing, none, "resource.unavailable");

        var broken = new EnforcementWorld();
        broken.Evidence.Behavior = (_, _, _) => throw new InvalidOperationException("host session store offline");
        var thrown = await broken.InvokeAsync(broken.Invocation(), cancellationToken: Token);
        AssertFailedClosedBeforeDecision(broken, thrown, "resource.unavailable");

        var invalid = new EnforcementWorld();
        invalid.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(new CapabilityEvidence(
            invalid.DirectChain(),
            invalid.Leases.Scope,
            new ResourceReference("resource/1", "revision:1"),
            DecisionOrigin.None,
            invalid.Decisions.Transport));
        var malformed = await invalid.InvokeAsync(invalid.Invocation(), cancellationToken: Token);
        AssertFailedClosedBeforeDecision(invalid, malformed, "validation.invalid_request");
    }

    [Fact]
    public async Task ACancelledInvocationIsReportedCancelledAndNeverReachesTheOwner()
    {
        var w = new EnforcementWorld();
        using var source = CancellationTokenSource.CreateLinkedTokenSource(Token);
        w.Evidence.Behavior = async (_, _, token) =>
        {
            await source.CancelAsync();
            token.ThrowIfCancellationRequested();
            return w.DefaultEvidence();
        };

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: source.Token);

        Assert.Equal(OutcomeKind.Cancelled, outcome.Kind);
        Assert.Equal(0, w.OwnerRuns);
        Assert.Equal(0, w.Records.BeginCalls);
        Assert.Empty(w.Decisions.Audit.Records);
    }

    [Fact]
    public async Task AResourceRevisionThatChangedAfterTheContextWasFrozenIsRefusedByTheOwnerLast()
    {
        var w = new EnforcementWorld();
        w.OwnerComparesRevision();
        w.Records.BeforeDispatch = () =>
        {
            w.CurrentRevision = "revision:8";
            return Task.CompletedTask;
        };

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        Assert.Equal(OutcomeKind.Failure, outcome.Kind);
        Assert.Equal("conflict.revision_mismatch", outcome.Failure!.Code);
        Assert.Equal(0, w.OwnerRuns);
        Assert.Equal(1, w.Records.CompleteCalls);
        var audit = Assert.Single(w.Decisions.Audit.Records);
        Assert.Equal(SecurityAuditKind.Refused, audit.Kind);
        Assert.Equal(DecisionStep.OwnerValidation, audit.FailedStep);
        Assert.Equal("decision.s11.owner_revision_changed", audit.ReasonCode);
        Assert.Equal(EnforcementWorld.ResourceRevision, audit.Resource.Revision);
        Assert.Empty(w.Decisions.Recorder.Records);
        Assert.Equal("conflict.revision_mismatch", w.Trace.Records[^1].FailureCode);
    }

    [Fact]
    public async Task AServiceDecisionThatWaitedPastItsLifetimeIsStaleAndTheOwnerDoesNotRun()
    {
        var w = new EnforcementWorld(options: new DecisionPipelineOptions { ServiceDecisionLifetime = TimeSpan.FromSeconds(30) });
        w.Records.BeforeDispatch = () =>
        {
            w.Clock.Advance(TimeSpan.FromSeconds(31));
            return Task.CompletedTask;
        };

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        Assert.Equal(OutcomeKind.Failure, outcome.Kind);
        Assert.Equal("perm.capability_denied", outcome.Failure!.Code);
        Assert.Equal(0, w.OwnerRuns);
        var audit = Assert.Single(w.Decisions.Audit.Records);
        Assert.Equal("decision.s11.service_decision_stale", audit.ReasonCode);
        Assert.Equal(EnforcementPoint.OwnerFinalValidation, audit.Point);
    }

    [Fact]
    public async Task AvailabilityEvidenceThatWasStaleAtCaptureStopsTheInvocationBeforeTheDecisionPipelineIsConsulted()
    {
        var w = new EnforcementWorld(freshness: AvailabilityFreshnessDisposition.StaleAtCapture);

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        Assert.Equal(OutcomeKind.Failure, outcome.Kind);
        Assert.Equal("dependency.unavailable", outcome.Failure!.Code);
        Assert.Equal(["trace.started", "availability", "trace.completed"], w.Log.Entries);
        Assert.Equal(0, w.Evidence.Calls);
        Assert.Empty(w.Decisions.Audit.Records);
        Assert.Equal(0, w.OwnerRuns);
    }

    [Fact]
    public async Task ATargetCapturedAtAnEarlierEpochIsRefusedAtResolutionBeforeAuthorization()
    {
        var w = new EnforcementWorld(epoch: 2);
        var earlier = new InstanceIdentity(w.Identity.Installation, w.Identity.InstanceId, 1);

        var outcome = await w.InvokeAsync(w.Invocation(), capturedTarget: earlier, cancellationToken: Token);

        Assert.Equal(OutcomeKind.Failure, outcome.Kind);
        Assert.Equal("dependency.unavailable", outcome.Failure!.Code);
        Assert.Equal(0, w.Evidence.Calls);
        Assert.Equal(0, w.Records.BeginCalls);
        Assert.Empty(w.Decisions.Audit.Records);
        Assert.Equal(0, w.OwnerRuns);
    }

    [Fact]
    public async Task AReplayedCommandIsAuthorizedAgainAndDoesNotRunTheOwnerTwice()
    {
        var w = new EnforcementWorld();
        var first = w.Invocation();
        var retry = first.Clone();
        retry.InvocationId = ArcForges.Foundation.Execution.InvocationId.New().ToWire();

        var one = await w.InvokeAsync(first, cancellationToken: Token);
        var two = await w.InvokeAsync(retry, cancellationToken: Token);

        Assert.Equal(OutcomeKind.Success, one.Kind);
        Assert.Equal(OutcomeKind.Success, two.Kind);
        Assert.Equal(1, w.OwnerRuns);
        Assert.Equal(2, w.Evidence.Calls);
        Assert.Equal(2, w.Log.Count("permission"));
        Assert.Single(w.Decisions.Audit.Records);
        Assert.Single(w.Decisions.Recorder.Records);

        // A replay whose permission was withdrawn is refused before the journal can replay the recorded success.
        w.Decisions.Permissions.Behavior = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(null);
        var withdrawn = await w.InvokeAsync(first.Clone(), cancellationToken: Token);
        Assert.Equal("perm.capability_denied", withdrawn.Failure!.Code);
        Assert.Equal(1, w.OwnerRuns);
    }

    [Fact]
    public async Task AnOwnerFailureOrCancellationIsRecordedAndAuditedWithItsEffect()
    {
        var failed = new EnforcementWorld();
        failed.OwnerBehavior = () => Outcome.Failure<EnforcedOwnerResult>(TypedFailure.Create("dependency.unavailable"));
        var failure = await failed.InvokeAsync(failed.Invocation(), cancellationToken: Token);
        Assert.Equal("dependency.unavailable", failure.Failure!.Code);
        Assert.Equal(SecurityAuditKind.OwnerFailed, Assert.Single(failed.Decisions.Audit.Records).Kind);
        Assert.Equal(DecisionResultKind.Failure, Assert.Single(failed.Decisions.Recorder.Records).Result);
        Assert.Equal(1, failed.Records.CompleteCalls);

        var cancelled = new EnforcementWorld();
        cancelled.OwnerBehavior = () => Outcome.Cancelled<EnforcedOwnerResult>(EffectCertainty.DidNotHappen);
        var cancellation = await cancelled.InvokeAsync(cancelled.Invocation(), cancellationToken: Token);
        Assert.Equal(OutcomeKind.Cancelled, cancellation.Kind);
        Assert.Equal(EffectCertainty.DidNotHappen, cancellation.CancellationEffect);
        Assert.Equal(SecurityAuditKind.OwnerCancelled, Assert.Single(cancelled.Decisions.Audit.Records).Kind);
    }

    [Fact]
    public async Task AnAuditSinkThatFailsAfterTheOwnerRanIsReportedAsAFailureNotAsSuccess()
    {
        var w = new EnforcementWorld();
        w.Decisions.Audit.Behavior = (_, _) => throw new InvalidOperationException("audit store offline");

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        Assert.Equal(1, w.OwnerRuns);
        Assert.Equal(OutcomeKind.Failure, outcome.Kind);
        Assert.Equal("internal.unexpected", outcome.Failure!.Code);
        Assert.Equal(1, w.Records.CompleteCalls);
    }

    [Fact]
    public async Task ARefusalWhoseAuditCannotBeWrittenIsStillARefusal()
    {
        var w = new EnforcementWorld();
        Configure(w, "permission-missing");
        w.Decisions.Audit.Behavior = (_, _) => throw new InvalidOperationException("audit store offline");

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        Assert.Equal(OutcomeKind.Failure, outcome.Kind);
        Assert.Equal("perm.capability_denied", outcome.Failure!.Code);
        Assert.Equal(0, w.OwnerRuns);
        Assert.Equal(0, w.Records.BeginCalls);
    }

    [Fact]
    public async Task AnApprovalIsBoundToTheExactInvocationEffectTheGateComputes()
    {
        var w = new EnforcementWorld(EnforcementWorld.StartCapture);
        DecisionRequest? seen = null;
        w.Decisions.Permissions.Behavior = (request, _) =>
        {
            seen = request;
            return ValueTask.FromResult<PermissionGrantRecord?>(w.Decisions.Grant(request));
        };
        var command = Guid.NewGuid();

        var withoutApproval = await w.InvokeAsync(w.Invocation(command: command), cancellationToken: Token);
        AssertRefusedAtAuthorize(w, withoutApproval, "perm.approval_required", DecisionReason.S10ApprovalRequired);

        var approval = await w.Decisions.ApproveAsync(seen!, RiskLevel.R3);
        var changed = await w.InvokeAsync(w.Invocation("a different effect", approval: approval, command: command), cancellationToken: Token);
        Assert.Equal("perm.approval_required", changed.Failure!.Code);
        Assert.Equal("decision.s10.approval_mismatch", w.Decisions.Audit.Records[^1].ReasonCode);
        Assert.Equal(0, w.OwnerRuns);

        var exact = await w.InvokeAsync(w.Invocation(approval: approval, command: command), cancellationToken: Token);
        Assert.Equal(OutcomeKind.Success, exact.Kind);
        Assert.Equal(1, w.OwnerRuns);
        Assert.Equal(RiskLevel.R3, Assert.Single(w.Decisions.Recorder.Records).EffectiveRisk);
    }

    [Fact]
    public async Task AnExternalDestinationIsDecidedByTheRealEgressAuthorityAndAuditedBeforeTheOwnerRuns()
    {
        var w = new EnforcementWorld(EnforcementWorld.AppendUserMessage);
        w.PermitEgress();

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        Assert.Equal(OutcomeKind.Success, outcome.Kind);
        var egress = Assert.Single(w.EgressAudit.Records);
        Assert.Equal(EgressAuditKind.Authorized, egress.Kind);
        Assert.Equal(EnforcementWorld.Destination, egress.Destination);
        Assert.Equal(EnforcementWorld.AppendUserMessage, egress.CapabilityKey);
        Assert.True(w.Log.Entries.ToList().IndexOf("egress-audit") < w.Log.Entries.ToList().IndexOf("owner-op"));
        Assert.Equal(1, w.OwnerRuns);
    }

    [Fact]
    public async Task AnEgressTheAllowlistDoesNotNameIsDeniedAndTheDenialIsAudited()
    {
        var w = new EnforcementWorld(EnforcementWorld.AppendUserMessage);
        w.Classifier.Behavior = (_, _, _) => ValueTask.FromResult<EgressContentFacts?>(new EgressContentFacts(EgressDataClass.WorkspaceContent, true));

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        AssertRefusedAtAuthorize(w, outcome, "perm.egress_denied", DecisionReason.S08EgressDenied);
        var egress = Assert.Single(w.EgressAudit.Records);
        Assert.Equal(EgressAuditKind.Refused, egress.Kind);
        Assert.Equal(EgressReason.NotAllowlisted, egress.Reason);
        Assert.DoesNotContain("owner-op", w.Log.Entries);
    }

    [Fact]
    public async Task AnEgressWithoutTheUsersOwnGrantIsDeniedEvenWhenTheDestinationIsAllowlisted()
    {
        var w = new EnforcementWorld(EnforcementWorld.AppendUserMessage);
        w.PermitEgress();
        w.EgressGrants.Behavior = (_, _, _) => ValueTask.FromResult<IReadOnlyList<EgressGrantRecord>>([]);

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        AssertRefusedAtAuthorize(w, outcome, "perm.egress_denied", DecisionReason.S08EgressDenied);
        Assert.Equal(EgressReason.NoGrant, Assert.Single(w.EgressAudit.Records).Reason);
    }

    [Fact]
    public async Task ADestinationTheHostDoesNotDeclareIsRefusedWithoutConsultingTheEgressAuthority()
    {
        var w = new EnforcementWorld(EnforcementWorld.AppendUserMessage);
        w.PermitEgress();
        w.Evidence.Behavior = (_, _, _) => ValueTask.FromResult<CapabilityEvidence?>(new CapabilityEvidence(
            w.DirectChain(), w.Leases.Scope, new ResourceReference(EnforcementWorld.ResourceId, EnforcementWorld.ResourceRevision),
            DecisionOrigin.Local, w.Decisions.Transport));

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        AssertRefusedAtAuthorize(w, outcome, "perm.egress_denied", DecisionReason.S08EgressDestinationUnspecified);
        Assert.Empty(w.EgressAudit.Records);
    }

    [Fact]
    public async Task AnEgressDecisionThatCannotBeMadeDurableIsNotReleasedAndTheInvocationFailsClosed()
    {
        var w = new EnforcementWorld(EnforcementWorld.AppendUserMessage);
        w.PermitEgress();
        w.EgressAudit.Behavior = (_, _) => throw new InvalidOperationException("egress audit offline");

        var outcome = await w.InvokeAsync(w.Invocation(), cancellationToken: Token);

        AssertRefusedAtAuthorize(w, outcome, "resource.unavailable", DecisionReason.S08Unavailable);
        Assert.Equal(0, w.OwnerRuns);
    }

    private static void Configure(EnforcementWorld w, string failure)
    {
        var d = w.Decisions;
        switch (failure)
        {
            case "policy-disabled":
                d.Policy.Behavior = (_, _) => ValueTask.FromResult(PolicyVerdict.Disabled);
                break;
            case "policy-offline":
                d.Policy.Behavior = (_, _) => throw new InvalidOperationException("policy store offline");
                break;
            case "unauthenticated":
                d.Identity.Behavior = (_, _) => ValueTask.FromResult(ActorIdentityVerdict.Unauthenticated);
                break;
            case "session-expired":
                d.Identity.Behavior = (_, _) => ValueTask.FromResult(ActorIdentityVerdict.SessionExpired);
                break;
            case "transport-revoked":
                d.Transport.Behavior = _ => ValueTask.FromResult(new TransportVerdict(TransportRefusal.Revoked, null));
                break;
            case "scope-invalid":
                d.Scope.Behavior = (_, _) => ValueTask.FromResult(ScopeVerdict.Invalid);
                break;
            case "trust-mismatched":
                w.Facts.Software = SoftwareIdentityState.Mismatched;
                break;
            case "trust-unknown":
                w.Facts.Software = SoftwareIdentityState.Unknown;
                break;
            case "trust-offline":
                w.Facts.Throw = true;
                break;
            case "permission-missing":
                d.Permissions.Behavior = (_, _) => ValueTask.FromResult<PermissionGrantRecord?>(null);
                break;
            case "permission-denied":
                d.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(d.Grant(request, PermissionGrantState.ExplicitlyDenied));
                break;
            case "permission-expired":
                d.Permissions.Behavior = (request, _) => ValueTask.FromResult<PermissionGrantRecord?>(
                    d.Grant(request, validFromOffset: TimeSpan.FromHours(-3), validUntilOffset: TimeSpan.FromHours(-2)));
                break;
            case "permission-offline":
                d.Permissions.Behavior = (_, _) => throw new InvalidOperationException("permission store offline");
                break;
            case "resource-denied":
                d.Resources.Behavior = (_, _) => ValueTask.FromResult<ResourceVerdict?>(new ResourceVerdict(ResourceDisposition.Denied, RiskFacts.None));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(failure));
        }
    }

    private static void AssertRefusedAtAuthorize(EnforcementWorld w, InvocationOutcome outcome, string code, DecisionReason reason)
    {
        Assert.Equal(OutcomeKind.Failure, outcome.Kind);
        Assert.Equal(code, outcome.Failure!.Code);
        Assert.Equal(0, w.OwnerRuns);
        Assert.Equal(0, w.Records.BeginCalls);
        Assert.DoesNotContain("owner-op", w.Log.Entries);
        Assert.DoesNotContain("owner", w.Log.Entries);
        var info = DecisionReasons.Describe(reason);
        var audit = Assert.Single(w.Decisions.Audit.Records);
        Assert.Equal(SecurityAuditKind.Refused, audit.Kind);
        Assert.Equal(EnforcementPoint.ServiceDecision, audit.Point);
        Assert.Equal(info.Step, audit.FailedStep);
        Assert.Equal(info.Code, audit.ReasonCode);
        Assert.Equal(info.RegisteredCode, audit.RegisteredCode);
        Assert.Equal(EffectCertainty.DidNotHappen, audit.Effect);
        var completed = w.Trace.Records[^1];
        Assert.Equal(InvocationTracePhase.Completed, completed.Phase);
        Assert.Equal(OutcomeKind.Failure, completed.OutcomeKind);
        Assert.Equal(code, completed.FailureCode);
    }

    private static void AssertFailedClosedBeforeDecision(EnforcementWorld w, InvocationOutcome outcome, string code)
    {
        Assert.Equal(OutcomeKind.Failure, outcome.Kind);
        Assert.Equal(code, outcome.Failure!.Code);
        Assert.Equal(0, w.OwnerRuns);
        Assert.Equal(0, w.Records.BeginCalls);
        Assert.Empty(w.Decisions.Audit.Records);
        Assert.DoesNotContain("policy", w.Log.Entries);
        Assert.Equal(code, w.Trace.Records[^1].FailureCode);
    }
}
