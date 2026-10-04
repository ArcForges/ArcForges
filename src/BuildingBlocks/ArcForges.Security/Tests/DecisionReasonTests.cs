// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation.Errors;
using ArcForges.Security.Decisions;
using Xunit;

namespace ArcForges.Security.Tests;

public sealed class DecisionReasonTests
{
    // The specification of the closed reason table, written out independently of the implementation so that changing a step, a
    // stable code or a registered mapping fails here.
    private static readonly (DecisionReason Reason, DecisionStep Step, string Code, string Registered)[] Expected =
    [
        (DecisionReason.S01CapabilityUnknown, DecisionStep.CapabilityExists, "decision.s01.capability_unknown", "validation.invalid_request"),
        (DecisionReason.S01Unavailable, DecisionStep.CapabilityExists, "decision.s01.unavailable", "resource.unavailable"),
        (DecisionReason.S02PolicyDisabled, DecisionStep.ProductPolicy, "decision.s02.policy_disabled", "perm.capability_denied"),
        (DecisionReason.S02PolicyUnknown, DecisionStep.ProductPolicy, "decision.s02.policy_unknown", "perm.capability_denied"),
        (DecisionReason.S02Unavailable, DecisionStep.ProductPolicy, "decision.s02.unavailable", "resource.unavailable"),
        (DecisionReason.S03Unauthenticated, DecisionStep.ActorIdentity, "decision.s03.unauthenticated", "auth.unauthenticated"),
        (DecisionReason.S03SessionExpired, DecisionStep.ActorIdentity, "decision.s03.session_expired", "auth.session_expired"),
        (DecisionReason.S03TransportRefused, DecisionStep.ActorIdentity, "decision.s03.transport_refused", "auth.unauthenticated"),
        (DecisionReason.S03CallerInstanceMismatch, DecisionStep.ActorIdentity, "decision.s03.caller_instance_mismatch", "auth.unauthenticated"),
        (DecisionReason.S03Unavailable, DecisionStep.ActorIdentity, "decision.s03.unavailable", "resource.unavailable"),
        (DecisionReason.S04RealmMismatch, DecisionStep.ScopeValid, "decision.s04.realm_mismatch", "perm.resource_denied"),
        (DecisionReason.S04WorkspaceInvalid, DecisionStep.ScopeValid, "decision.s04.workspace_invalid", "perm.resource_denied"),
        (DecisionReason.S04Unavailable, DecisionStep.ScopeValid, "decision.s04.unavailable", "resource.unavailable"),
        (DecisionReason.S05TrustRevoked, DecisionStep.TrustEligible, "decision.s05.trust_revoked", "perm.capability_denied"),
        (DecisionReason.S05TrustUnknown, DecisionStep.TrustEligible, "decision.s05.trust_unknown", "perm.capability_denied"),
        (DecisionReason.S05Unavailable, DecisionStep.TrustEligible, "decision.s05.unavailable", "resource.unavailable"),
        (DecisionReason.S06NotGranted, DecisionStep.CapabilityPermission, "decision.s06.not_granted", "perm.capability_denied"),
        (DecisionReason.S06ExplicitlyDenied, DecisionStep.CapabilityPermission, "decision.s06.explicitly_denied", "perm.capability_denied"),
        (DecisionReason.S06GrantMismatch, DecisionStep.CapabilityPermission, "decision.s06.grant_mismatch", "perm.capability_denied"),
        (DecisionReason.S06OutsideLifetime, DecisionStep.CapabilityPermission, "decision.s06.outside_lifetime", "perm.capability_denied"),
        (DecisionReason.S06ConstraintUnmet, DecisionStep.CapabilityPermission, "decision.s06.constraint_unmet", "perm.capability_denied"),
        (DecisionReason.S06ConstraintUnknown, DecisionStep.CapabilityPermission, "decision.s06.constraint_unknown", "perm.capability_denied"),
        (DecisionReason.S06Unavailable, DecisionStep.CapabilityPermission, "decision.s06.unavailable", "resource.unavailable"),
        (DecisionReason.S06LeaseRequired, DecisionStep.CapabilityPermission, "decision.s06.lease_required", "perm.capability_denied"),
        (DecisionReason.S06LeaseExpired, DecisionStep.CapabilityPermission, "decision.s06.lease_expired", "perm.lease_expired"),
        (DecisionReason.S06LeaseRevoked, DecisionStep.CapabilityPermission, "decision.s06.lease_revoked", "perm.capability_denied"),
        (DecisionReason.S06LeaseOutOfScope, DecisionStep.CapabilityPermission, "decision.s06.lease_out_of_scope", "perm.capability_denied"),
        (DecisionReason.S06LeaseUnavailable, DecisionStep.CapabilityPermission, "decision.s06.lease_unavailable", "resource.unavailable"),
        (DecisionReason.S07ResourceDenied, DecisionStep.ResourceAuthorization, "decision.s07.resource_denied", "perm.resource_denied"),
        (DecisionReason.S07Unavailable, DecisionStep.ResourceAuthorization, "decision.s07.unavailable", "resource.unavailable"),
        (DecisionReason.S08EgressDestinationUnspecified, DecisionStep.DataBoundary, "decision.s08.egress_destination_unspecified", "perm.egress_denied"),
        (DecisionReason.S08EgressNotDeclared, DecisionStep.DataBoundary, "decision.s08.egress_not_declared", "perm.egress_denied"),
        (DecisionReason.S08EgressDenied, DecisionStep.DataBoundary, "decision.s08.egress_denied", "perm.egress_denied"),
        (DecisionReason.S08SecretUseDenied, DecisionStep.DataBoundary, "decision.s08.secret_use_denied", "perm.capability_denied"),
        (DecisionReason.S08Unavailable, DecisionStep.DataBoundary, "decision.s08.unavailable", "resource.unavailable"),
        (DecisionReason.S09RiskUnclassifiable, DecisionStep.EffectiveRisk, "decision.s09.risk_unclassifiable", "validation.invalid_request"),
        (DecisionReason.S10ApprovalRequired, DecisionStep.ApprovalAndPresence, "decision.s10.approval_required", "perm.approval_required"),
        (DecisionReason.S10ApprovalPending, DecisionStep.ApprovalAndPresence, "decision.s10.approval_pending", "perm.approval_required"),
        (DecisionReason.S10ApprovalDenied, DecisionStep.ApprovalAndPresence, "decision.s10.approval_denied", "perm.capability_denied"),
        (DecisionReason.S10ApprovalExpired, DecisionStep.ApprovalAndPresence, "decision.s10.approval_expired", "perm.approval_expired"),
        (DecisionReason.S10ApprovalMismatch, DecisionStep.ApprovalAndPresence, "decision.s10.approval_mismatch", "perm.approval_required"),
        (DecisionReason.S10StepUpRequired, DecisionStep.ApprovalAndPresence, "decision.s10.step_up_required", "auth.step_up_required"),
        (DecisionReason.S10StepUpInvalid, DecisionStep.ApprovalAndPresence, "decision.s10.step_up_invalid", "auth.step_up_required"),
        (DecisionReason.S10StepUpOperationUnspecified, DecisionStep.ApprovalAndPresence, "decision.s10.step_up_operation_unspecified", "auth.step_up_required"),
        (DecisionReason.S10LocalPresenceRequired, DecisionStep.ApprovalAndPresence, "decision.s10.local_presence_required", "auth.local_presence_required"),
        (DecisionReason.S10Unavailable, DecisionStep.ApprovalAndPresence, "decision.s10.unavailable", "resource.unavailable"),
        (DecisionReason.S11OwnerRefused, DecisionStep.OwnerValidation, "decision.s11.owner_refused", "perm.resource_denied"),
        (DecisionReason.S11OwnerRevisionChanged, DecisionStep.OwnerValidation, "decision.s11.owner_revision_changed", "conflict.revision_mismatch"),
        (DecisionReason.S11ServiceDecisionInvalid, DecisionStep.OwnerValidation, "decision.s11.service_decision_invalid", "perm.capability_denied"),
        (DecisionReason.S11ServiceDecisionStale, DecisionStep.OwnerValidation, "decision.s11.service_decision_stale", "perm.capability_denied"),
        (DecisionReason.S11Unavailable, DecisionStep.OwnerValidation, "decision.s11.unavailable", "resource.unavailable"),
        (DecisionReason.S11LeaseRequired, DecisionStep.OwnerValidation, "decision.s11.lease_required", "perm.capability_denied"),
        (DecisionReason.S11LeaseExpired, DecisionStep.OwnerValidation, "decision.s11.lease_expired", "perm.lease_expired"),
        (DecisionReason.S11LeaseRevoked, DecisionStep.OwnerValidation, "decision.s11.lease_revoked", "perm.capability_denied"),
        (DecisionReason.S11LeaseOutOfScope, DecisionStep.OwnerValidation, "decision.s11.lease_out_of_scope", "perm.capability_denied"),
        (DecisionReason.S11LeaseUnavailable, DecisionStep.OwnerValidation, "decision.s11.lease_unavailable", "resource.unavailable"),
        (DecisionReason.S12OwnerFailed, DecisionStep.Execution, "decision.s12.owner_failed", "internal.unexpected"),
        (DecisionReason.S13RecordFailed, DecisionStep.ResultRecording, "decision.s13.record_failed", "internal.unexpected"),
        (DecisionReason.S14AuditFailed, DecisionStep.AuditWrite, "decision.s14.audit_failed", "internal.unexpected"),
    ];

    public static TheoryData<DecisionReason> Reasons => [.. Expected.Select(entry => entry.Reason)];

    [Theory]
    [MemberData(nameof(Reasons))]
    public void EachReasonHasItsOwnStepStableCodeAndRegisteredMapping(DecisionReason reason)
    {
        var expected = Expected.Single(entry => entry.Reason == reason);
        var info = DecisionReasons.Describe(reason);
        Assert.Equal(reason, info.Reason);
        Assert.Equal(expected.Step, info.Step);
        Assert.Equal(expected.Code, info.Code);
        Assert.Equal(expected.Registered, info.RegisteredCode);
        Assert.True(ReasonCodes.TryGet(info.RegisteredCode, out _));
    }

    [Fact]
    public void TheTableCoversEveryDefinedReasonExactlyOnceAndEveryStepHasAReason()
    {
        var defined = Enum.GetValues<DecisionReason>().Where(reason => reason != DecisionReason.None).ToArray();
        Assert.Equal(defined.OrderBy(reason => (int)reason), Expected.Select(entry => entry.Reason).OrderBy(reason => (int)reason));
        Assert.Equal(defined.Length, DecisionReasons.All.Count);
        Assert.Equal(defined.Length, DecisionReasons.All.Select(info => info.Reason).Distinct().Count());
        Assert.Equal(defined.Length, DecisionReasons.All.Select(info => info.Code).Distinct(StringComparer.Ordinal).Count());
        foreach (var step in Enum.GetValues<DecisionStep>().Where(step => step != DecisionStep.None))
        {
            Assert.Contains(DecisionReasons.All, info => info.Step == step);
        }

        // A reason's number names its step, so a reason can never be filed under another step.
        foreach (var info in DecisionReasons.All)
        {
            Assert.Equal((int)info.Step, (int)info.Reason / 100);
        }
    }

    [Fact]
    public void NoneAndUndefinedReasonsAreNotDescribed()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => DecisionReasons.Describe(DecisionReason.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => DecisionReasons.Describe((DecisionReason)99_999));
    }

    [Fact]
    public void EveryStepOfTheFourteenIsNamedInOrder()
    {
        var steps = Enum.GetValues<DecisionStep>().Where(step => step != DecisionStep.None).ToArray();
        Assert.Equal(Enumerable.Range(1, 14).Select(value => (DecisionStep)value), steps);
        Assert.Equal(DecisionStep.OwnerValidation, steps[10]);
        Assert.Equal(DecisionStep.AuditWrite, steps[13]);
    }
}
