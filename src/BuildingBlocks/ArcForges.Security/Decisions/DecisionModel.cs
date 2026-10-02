// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Approvals;

namespace ArcForges.Security.Decisions;

/// <summary>
/// The four places authorization is enforced (architecture 08, section 2). Each point runs the same pipeline
/// implementation over the steps it owns; only the last point can release an execution.
/// </summary>
public enum EnforcementPoint
{
    None = 0,

    /// <summary>Caller-side pre-check: user experience and early failure, never authority.</summary>
    CallerPreCheck = 1,

    /// <summary>Transport boundary: who is connected at all (the local IPC handshake, or Cloud authentication).</summary>
    TransportBoundary = 2,

    /// <summary>Service-side decision: the substantive decision, taken by the application runtime or a Cloud module.</summary>
    ServiceDecision = 3,

    /// <summary>Owner-side final validation: the owner of the resource decides last, always.</summary>
    OwnerFinalValidation = 4,
}

/// <summary>The fourteen ordered steps of the security decision pipeline (requirements 07, section 11).</summary>
public enum DecisionStep
{
    None = 0,
    CapabilityExists = 1,
    ProductPolicy = 2,
    ActorIdentity = 3,
    ScopeValid = 4,
    TrustEligible = 5,
    CapabilityPermission = 6,
    ResourceAuthorization = 7,
    DataBoundary = 8,
    EffectiveRisk = 9,
    ApprovalAndPresence = 10,
    OwnerValidation = 11,
    Execution = 12,
    ResultRecording = 13,
    AuditWrite = 14,
}

/// <summary>What one step did. <see cref="NotRun"/> means the enforcement point does not own the step or an earlier step refused.</summary>
public enum StepDisposition
{
    NotRun = 0,

    /// <summary>The step ran and its requirement was satisfied.</summary>
    Passed = 1,

    /// <summary>The step ran and found that nothing was required of it (for example no egress and no approval).</summary>
    NotRequired = 2,

    /// <summary>The step ran and refused, or could not decide and therefore refused.</summary>
    Refused = 3,
}

/// <summary>Whether the request came through this machine's own interface or arrived remotely.</summary>
public enum DecisionOrigin
{
    None = 0,
    Local = 1,
    Remote = 2,
}

/// <summary>Whether a refusal or an execution reached the audit sink.</summary>
public enum DecisionAuditStatus
{
    /// <summary>No audit event is due for this decision (an advisory pre-check, or an allowed decision that has not executed).</summary>
    NotDue = 0,

    Written = 1,

    /// <summary>The audit sink failed or timed out; the decision itself is unchanged.</summary>
    Failed = 2,
}

/// <summary>The typed outcome of one step: which step, what it did, and why it refused.</summary>
public readonly record struct StepOutcome(DecisionStep Step, StepDisposition Disposition, DecisionReason Reason);

/// <summary>Stable identity of one refusal reason: its step, its own code and the registered semantic code it maps to.</summary>
public sealed record DecisionReasonInfo(DecisionReason Reason, DecisionStep Step, string Code, string RegisteredCode);

/// <summary>
/// Every reason a step can refuse. Reasons are closed, stable and belong to exactly one step, so a refusal names its step;
/// each also maps to a code of the closed registered reason-code set that callers and the client contract see.
/// </summary>
public enum DecisionReason
{
    None = 0,

    S01CapabilityUnknown = 101,
    S01Unavailable = 102,

    S02PolicyDisabled = 201,
    S02PolicyUnknown = 202,
    S02Unavailable = 203,

    S03Unauthenticated = 301,
    S03SessionExpired = 302,
    S03TransportRefused = 303,
    S03CallerInstanceMismatch = 304,
    S03Unavailable = 305,

    S04RealmMismatch = 401,
    S04WorkspaceInvalid = 402,
    S04Unavailable = 403,

    S05TrustRevoked = 501,
    S05TrustUnknown = 502,
    S05Unavailable = 503,

    S06NotGranted = 601,
    S06ExplicitlyDenied = 602,
    S06GrantMismatch = 603,
    S06OutsideLifetime = 604,
    S06ConstraintUnmet = 605,
    S06ConstraintUnknown = 606,
    S06Unavailable = 607,

    S07ResourceDenied = 701,
    S07Unavailable = 702,

    S08EgressDestinationUnspecified = 801,
    S08EgressNotDeclared = 802,
    S08EgressDenied = 803,
    S08SecretUseDenied = 804,
    S08Unavailable = 805,

    S09RiskUnclassifiable = 901,

    S10ApprovalRequired = 1001,
    S10ApprovalPending = 1002,
    S10ApprovalDenied = 1003,
    S10ApprovalExpired = 1004,
    S10ApprovalMismatch = 1005,
    S10StepUpRequired = 1006,
    S10StepUpInvalid = 1007,
    S10StepUpOperationUnspecified = 1008,
    S10LocalPresenceRequired = 1009,
    S10Unavailable = 1010,

    S11OwnerRefused = 1101,
    S11OwnerRevisionChanged = 1102,
    S11ServiceDecisionInvalid = 1103,
    S11ServiceDecisionStale = 1104,
    S11Unavailable = 1105,

    S12OwnerFailed = 1201,

    S13RecordFailed = 1301,

    S14AuditFailed = 1401,
}

/// <summary>The closed table of reasons, with their stable codes and registered semantic codes.</summary>
public static class DecisionReasons
{
    private static readonly ReadOnlyCollection<DecisionReasonInfo> Entries = Array.AsReadOnly(
    [
        Info(DecisionReason.S01CapabilityUnknown, DecisionStep.CapabilityExists, "decision.s01.capability_unknown", "validation.invalid_request"),
        Info(DecisionReason.S01Unavailable, DecisionStep.CapabilityExists, "decision.s01.unavailable", "resource.unavailable"),

        Info(DecisionReason.S02PolicyDisabled, DecisionStep.ProductPolicy, "decision.s02.policy_disabled", "perm.capability_denied"),
        Info(DecisionReason.S02PolicyUnknown, DecisionStep.ProductPolicy, "decision.s02.policy_unknown", "perm.capability_denied"),
        Info(DecisionReason.S02Unavailable, DecisionStep.ProductPolicy, "decision.s02.unavailable", "resource.unavailable"),

        Info(DecisionReason.S03Unauthenticated, DecisionStep.ActorIdentity, "decision.s03.unauthenticated", "auth.unauthenticated"),
        Info(DecisionReason.S03SessionExpired, DecisionStep.ActorIdentity, "decision.s03.session_expired", "auth.session_expired"),
        Info(DecisionReason.S03TransportRefused, DecisionStep.ActorIdentity, "decision.s03.transport_refused", "auth.unauthenticated"),
        Info(DecisionReason.S03CallerInstanceMismatch, DecisionStep.ActorIdentity, "decision.s03.caller_instance_mismatch", "auth.unauthenticated"),
        Info(DecisionReason.S03Unavailable, DecisionStep.ActorIdentity, "decision.s03.unavailable", "resource.unavailable"),

        Info(DecisionReason.S04RealmMismatch, DecisionStep.ScopeValid, "decision.s04.realm_mismatch", "perm.resource_denied"),
        Info(DecisionReason.S04WorkspaceInvalid, DecisionStep.ScopeValid, "decision.s04.workspace_invalid", "perm.resource_denied"),
        Info(DecisionReason.S04Unavailable, DecisionStep.ScopeValid, "decision.s04.unavailable", "resource.unavailable"),

        Info(DecisionReason.S05TrustRevoked, DecisionStep.TrustEligible, "decision.s05.trust_revoked", "perm.capability_denied"),
        Info(DecisionReason.S05TrustUnknown, DecisionStep.TrustEligible, "decision.s05.trust_unknown", "perm.capability_denied"),
        Info(DecisionReason.S05Unavailable, DecisionStep.TrustEligible, "decision.s05.unavailable", "resource.unavailable"),

        Info(DecisionReason.S06NotGranted, DecisionStep.CapabilityPermission, "decision.s06.not_granted", "perm.capability_denied"),
        Info(DecisionReason.S06ExplicitlyDenied, DecisionStep.CapabilityPermission, "decision.s06.explicitly_denied", "perm.capability_denied"),
        Info(DecisionReason.S06GrantMismatch, DecisionStep.CapabilityPermission, "decision.s06.grant_mismatch", "perm.capability_denied"),
        Info(DecisionReason.S06OutsideLifetime, DecisionStep.CapabilityPermission, "decision.s06.outside_lifetime", "perm.capability_denied"),
        Info(DecisionReason.S06ConstraintUnmet, DecisionStep.CapabilityPermission, "decision.s06.constraint_unmet", "perm.capability_denied"),
        Info(DecisionReason.S06ConstraintUnknown, DecisionStep.CapabilityPermission, "decision.s06.constraint_unknown", "perm.capability_denied"),
        Info(DecisionReason.S06Unavailable, DecisionStep.CapabilityPermission, "decision.s06.unavailable", "resource.unavailable"),

        Info(DecisionReason.S07ResourceDenied, DecisionStep.ResourceAuthorization, "decision.s07.resource_denied", "perm.resource_denied"),
        Info(DecisionReason.S07Unavailable, DecisionStep.ResourceAuthorization, "decision.s07.unavailable", "resource.unavailable"),

        Info(DecisionReason.S08EgressDestinationUnspecified, DecisionStep.DataBoundary, "decision.s08.egress_destination_unspecified", "perm.egress_denied"),
        Info(DecisionReason.S08EgressNotDeclared, DecisionStep.DataBoundary, "decision.s08.egress_not_declared", "perm.egress_denied"),
        Info(DecisionReason.S08EgressDenied, DecisionStep.DataBoundary, "decision.s08.egress_denied", "perm.egress_denied"),
        Info(DecisionReason.S08SecretUseDenied, DecisionStep.DataBoundary, "decision.s08.secret_use_denied", "perm.capability_denied"),
        Info(DecisionReason.S08Unavailable, DecisionStep.DataBoundary, "decision.s08.unavailable", "resource.unavailable"),

        Info(DecisionReason.S09RiskUnclassifiable, DecisionStep.EffectiveRisk, "decision.s09.risk_unclassifiable", "validation.invalid_request"),

        Info(DecisionReason.S10ApprovalRequired, DecisionStep.ApprovalAndPresence, "decision.s10.approval_required", "perm.approval_required"),
        Info(DecisionReason.S10ApprovalPending, DecisionStep.ApprovalAndPresence, "decision.s10.approval_pending", "perm.approval_required"),
        Info(DecisionReason.S10ApprovalDenied, DecisionStep.ApprovalAndPresence, "decision.s10.approval_denied", "perm.capability_denied"),
        Info(DecisionReason.S10ApprovalExpired, DecisionStep.ApprovalAndPresence, "decision.s10.approval_expired", "perm.approval_expired"),
        Info(DecisionReason.S10ApprovalMismatch, DecisionStep.ApprovalAndPresence, "decision.s10.approval_mismatch", "perm.approval_required"),
        Info(DecisionReason.S10StepUpRequired, DecisionStep.ApprovalAndPresence, "decision.s10.step_up_required", "auth.step_up_required"),
        Info(DecisionReason.S10StepUpInvalid, DecisionStep.ApprovalAndPresence, "decision.s10.step_up_invalid", "auth.step_up_required"),
        Info(DecisionReason.S10StepUpOperationUnspecified, DecisionStep.ApprovalAndPresence, "decision.s10.step_up_operation_unspecified", "auth.step_up_required"),
        Info(DecisionReason.S10LocalPresenceRequired, DecisionStep.ApprovalAndPresence, "decision.s10.local_presence_required", "auth.local_presence_required"),
        Info(DecisionReason.S10Unavailable, DecisionStep.ApprovalAndPresence, "decision.s10.unavailable", "resource.unavailable"),

        Info(DecisionReason.S11OwnerRefused, DecisionStep.OwnerValidation, "decision.s11.owner_refused", "perm.resource_denied"),
        Info(DecisionReason.S11OwnerRevisionChanged, DecisionStep.OwnerValidation, "decision.s11.owner_revision_changed", "conflict.revision_mismatch"),
        Info(DecisionReason.S11ServiceDecisionInvalid, DecisionStep.OwnerValidation, "decision.s11.service_decision_invalid", "perm.capability_denied"),
        Info(DecisionReason.S11ServiceDecisionStale, DecisionStep.OwnerValidation, "decision.s11.service_decision_stale", "perm.capability_denied"),
        Info(DecisionReason.S11Unavailable, DecisionStep.OwnerValidation, "decision.s11.unavailable", "resource.unavailable"),

        Info(DecisionReason.S12OwnerFailed, DecisionStep.Execution, "decision.s12.owner_failed", "internal.unexpected"),

        Info(DecisionReason.S13RecordFailed, DecisionStep.ResultRecording, "decision.s13.record_failed", "internal.unexpected"),

        Info(DecisionReason.S14AuditFailed, DecisionStep.AuditWrite, "decision.s14.audit_failed", "internal.unexpected"),
    ]);

    private static readonly Dictionary<DecisionReason, DecisionReasonInfo> ByReason = Entries.ToDictionary(entry => entry.Reason);

    /// <summary>Every refusal reason in step order.</summary>
    public static IReadOnlyList<DecisionReasonInfo> All => Entries;

    /// <summary>Describes a reason; an undefined or <see cref="DecisionReason.None"/> value is refused.</summary>
    public static DecisionReasonInfo Describe(DecisionReason reason) =>
        ByReason.TryGetValue(reason, out var info) ? info : throw new ArgumentOutOfRangeException(nameof(reason));

    private static DecisionReasonInfo Info(DecisionReason reason, DecisionStep step, string code, string registered) =>
        ReasonCodes.TryGet(registered, out _)
            ? new DecisionReasonInfo(reason, step, code, registered)
            : throw new InvalidOperationException("A decision reason maps to an unregistered code.");
}

/// <summary>Which steps each enforcement point owns. The pipeline runs a point's steps in ascending order and stops at the first refusal.</summary>
public static class DecisionProfiles
{
    private static readonly DecisionStep[] PreCheck =
    [
        DecisionStep.CapabilityExists, DecisionStep.ProductPolicy, DecisionStep.ActorIdentity, DecisionStep.ScopeValid,
        DecisionStep.TrustEligible, DecisionStep.CapabilityPermission, DecisionStep.EffectiveRisk,
    ];

    private static readonly DecisionStep[] Transport = [DecisionStep.ActorIdentity, DecisionStep.TrustEligible];

    private static readonly DecisionStep[] Service =
    [
        DecisionStep.CapabilityExists, DecisionStep.ProductPolicy, DecisionStep.ActorIdentity, DecisionStep.ScopeValid,
        DecisionStep.TrustEligible, DecisionStep.CapabilityPermission, DecisionStep.ResourceAuthorization,
        DecisionStep.DataBoundary, DecisionStep.EffectiveRisk, DecisionStep.ApprovalAndPresence,
    ];

    private static readonly DecisionStep[] Owner = [DecisionStep.OwnerValidation];

    /// <summary>The ordered decision steps (1 through 11) that <paramref name="point"/> runs.</summary>
    public static IReadOnlyList<DecisionStep> StepsFor(EnforcementPoint point) => point switch
    {
        EnforcementPoint.CallerPreCheck => Array.AsReadOnly(PreCheck),
        EnforcementPoint.TransportBoundary => Array.AsReadOnly(Transport),
        EnforcementPoint.ServiceDecision => Array.AsReadOnly(Service),
        EnforcementPoint.OwnerFinalValidation => Array.AsReadOnly(Owner),
        _ => throw new ArgumentOutOfRangeException(nameof(point)),
    };

    internal static DecisionStep[] Raw(EnforcementPoint point) => point switch
    {
        EnforcementPoint.CallerPreCheck => PreCheck,
        EnforcementPoint.TransportBoundary => Transport,
        EnforcementPoint.ServiceDecision => Service,
        EnforcementPoint.OwnerFinalValidation => Owner,
        _ => throw new ArgumentOutOfRangeException(nameof(point)),
    };
}

/// <summary>
/// The decision at one enforcement point: the typed outcome of all fourteen steps in order and, for a refusal, the failing step
/// and its reason. A decision from <see cref="EnforcementPoint.CallerPreCheck"/> is advisory and never authority; a decision never
/// grants anything by itself, it is only data the pipeline's execution route consumes.
/// </summary>
public sealed class SecurityDecision
{
    private readonly StepOutcome[] _steps;
    private int _consumed;

    internal SecurityDecision(
        object issuer,
        EnforcementPoint point,
        DecisionRequest request,
        StepOutcome[] steps,
        RiskAssessment? risk,
        PermissionAvailabilityEvidence? permission,
        TransportBinding? transport,
        Instant decidedAt,
        MonotonicTimestamp decidedMonotonic,
        DecisionAuditStatus audit)
    {
        Issuer = issuer;
        Point = point;
        Request = request;
        _steps = steps;
        Risk = risk;
        Permission = permission;
        Transport = transport;
        DecidedAt = decidedAt;
        DecidedMonotonic = decidedMonotonic;
        Audit = audit;
        var failed = steps.FirstOrDefault(step => step.Disposition == StepDisposition.Refused && step.Step <= DecisionStep.OwnerValidation);
        FailedStep = failed.Disposition == StepDisposition.Refused ? failed.Step : DecisionStep.None;
        Reason = failed.Disposition == StepDisposition.Refused ? failed.Reason : DecisionReason.None;
        ReasonCode = Reason == DecisionReason.None ? string.Empty : DecisionReasons.Describe(Reason).Code;
        RegisteredCode = Reason == DecisionReason.None ? string.Empty : DecisionReasons.Describe(Reason).RegisteredCode;
        Steps = Array.AsReadOnly(steps);
    }

    public EnforcementPoint Point { get; }

    /// <summary>True when no decision step (1 through 11) refused. For a decision at an earlier point this is not yet permission to execute.</summary>
    public bool Allowed => FailedStep == DecisionStep.None;

    /// <summary>False for the caller-side pre-check, which is a user-experience optimisation only.</summary>
    public bool IsAuthority => Point != EnforcementPoint.CallerPreCheck;

    /// <summary>All fourteen step outcomes in order (index 0 is step 1).</summary>
    public IReadOnlyList<StepOutcome> Steps { get; }

    /// <summary>The first refusing decision step, or <see cref="DecisionStep.None"/>.</summary>
    public DecisionStep FailedStep { get; }

    public DecisionReason Reason { get; }

    /// <summary>The stable code of the reason (empty when allowed).</summary>
    public string ReasonCode { get; }

    /// <summary>The registered semantic code the reason maps to (empty when allowed).</summary>
    public string RegisteredCode { get; }

    public RiskAssessment? Risk { get; }

    public PermissionAvailabilityEvidence? Permission { get; }

    public TransportBinding? Transport { get; }

    public Instant DecidedAt { get; }

    public DecisionAuditStatus Audit { get; }

    internal object Issuer { get; }

    internal MonotonicTimestamp DecidedMonotonic { get; }

    internal DecisionRequest Request { get; }

    internal StepOutcome[] StepArray => _steps;

    /// <summary>Single use: only the first caller can spend a service decision.</summary>
    internal bool TryConsume() => Interlocked.CompareExchange(ref _consumed, 1, 0) == 0;

    /// <summary>
    /// Maps a service-side or owner-side decision to the shape of the invocation pipeline's authorize step: success for an
    /// allowed decision, otherwise a typed failure with the registered code of the failing step's reason. Earlier points are
    /// advisory or admission only and are refused.
    /// </summary>
    public Outcome<bool> ToAuthorizationOutcome()
    {
        if (Point is not (EnforcementPoint.ServiceDecision or EnforcementPoint.OwnerFinalValidation))
        {
            throw new InvalidOperationException("Only a service-side or owner-side decision can answer an authorization question.");
        }

        return Allowed ? Outcome.Success(true) : Outcome.Failure<bool>(TypedFailure.Create(RegisteredCode));
    }
}

/// <summary>The scope of a request: the realm and, for a cloud workspace, the workspace. A task has exactly one of each.</summary>
public sealed record DecisionScope
{
    public DecisionScope(RealmId realm, WorkspaceId? workspace)
    {
        _ = realm.ToWire();
        if (workspace is { } value)
        {
            _ = value.ToWire();
        }

        Realm = realm;
        Workspace = workspace;
    }

    public RealmId Realm { get; }

    public WorkspaceId? Workspace { get; }

    /// <summary>A canonical key of the scope, used by permission records and projections.</summary>
    public string Key => string.Create(
        System.Globalization.CultureInfo.InvariantCulture,
        $"realm:{Realm.Value:N}/workspace:{(Workspace is { } workspace ? workspace.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture) : "-")}");
}

/// <summary>The exact resource a request acts on and the revision it was approved and validated against.</summary>
public sealed record ResourceReference
{
    public ResourceReference(string id, string revision)
    {
        SecurityText.Validate(id, 512, nameof(id));
        SecurityText.Validate(revision, 256, nameof(revision));
        Id = id;
        Revision = revision;
    }

    public string Id { get; }

    public string Revision { get; }
}

/// <summary>
/// Runtime facts that can only raise a request's risk. The caller declares what it knows, the resource owner may add facts at the
/// resource-authorization step, and the pipeline takes the more severe of every field.
/// </summary>
public sealed record RiskFacts
{
    public RiskFacts(RiskScope scope, RiskTarget target, RiskReversibility reversibility, bool isLargeDataVolume)
    {
        if (!Enum.IsDefined(scope) || !Enum.IsDefined(target) || !Enum.IsDefined(reversibility))
        {
            throw new ArgumentOutOfRangeException(nameof(scope), "Risk facts must be classified.");
        }

        Scope = scope;
        Target = target;
        Reversibility = reversibility;
        IsLargeDataVolume = isLargeDataVolume;
    }

    /// <summary>The least severe facts: a single, ordinary, reversible, small operation.</summary>
    public static RiskFacts None { get; } = new(RiskScope.SingleOperation, RiskTarget.Ordinary, RiskReversibility.Reversible, false);

    public RiskScope Scope { get; }

    public RiskTarget Target { get; }

    public RiskReversibility Reversibility { get; }

    public bool IsLargeDataVolume { get; }

    internal RiskFacts MostSevere(RiskFacts other) => new(
        (RiskScope)Math.Max((int)Scope, (int)other.Scope),
        (RiskTarget)Math.Max((int)Target, (int)other.Target),
        (RiskReversibility)Math.Max((int)Reversibility, (int)other.Reversibility),
        IsLargeDataVolume || other.IsLargeDataVolume);
}
