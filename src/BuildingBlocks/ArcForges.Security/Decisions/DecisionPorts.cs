// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Security.Decisions;

// Each port is the authoritative source of one fact the pipeline must not decide itself. A verdict enum starts at Unknown so a
// default or undefined value can never be read as permission: the pipeline treats everything but the one affirmative value as a
// refusal. Ports are read-only evaluators; none of them may consume evidence or cause an effect.

/// <summary>Step 1 source: the authoritative capability catalogue (the owner's registered descriptors).</summary>
public interface ICapabilityCatalogue
{
    /// <summary>Returns the registered descriptor of the exact capability key, or null when no such capability exists.</summary>
    ValueTask<CapabilityDescriptor?> FindAsync(string capabilityKey, CancellationToken cancellationToken);
}

public enum PolicyVerdict
{
    Unknown = 0,
    Enabled = 1,
    Disabled = 2,
}

/// <summary>Step 2 source: product and workspace policy. Policy may only be stricter than the capability contract, never laxer.</summary>
public interface IProductPolicy
{
    ValueTask<PolicyVerdict> EvaluateAsync(DecisionRequest request, CancellationToken cancellationToken);
}

public enum ActorIdentityVerdict
{
    Unknown = 0,
    Authenticated = 1,
    Unauthenticated = 2,
    SessionExpired = 3,
}

/// <summary>Step 3 source: whether the session and actor chain are authenticated and current. Presence of a chain is not authentication.</summary>
public interface IActorIdentityVerifier
{
    ValueTask<ActorIdentityVerdict> VerifyAsync(DecisionRequest request, CancellationToken cancellationToken);
}

public enum ScopeVerdict
{
    Unknown = 0,
    Valid = 1,
    Invalid = 2,
}

/// <summary>Step 4 source: whether the realm and workspace are the owner's current, active scope.</summary>
public interface IScopeAuthority
{
    ValueTask<ScopeVerdict> ValidateAsync(DecisionRequest request, CancellationToken cancellationToken);
}

public enum TrustVerdict
{
    Unknown = 0,

    /// <summary>The software or package is verified and eligible.</summary>
    Verified = 1,

    /// <summary>Eligible but unverified: allowed to proceed with a higher risk floor, never with more permission.</summary>
    Unverified = 2,

    Revoked = 3,
}

/// <summary>Step 5 source: typed software and package trust. Trust is not permission and not entitlement.</summary>
public interface ITrustEvaluator
{
    ValueTask<TrustVerdict> EvaluateAsync(DecisionRequest request, TransportBinding? transport, CancellationToken cancellationToken);
}

/// <summary>Step 6 source: the owner-issued permission grants. A grant carries principal, capability, scope, constraints and lifetime.</summary>
public interface IPermissionSource
{
    /// <summary>
    /// Returns the grant record that applies to the request's principal, capability and scope, or null when none exists. The
    /// pipeline re-checks that the returned record names exactly the requested principal, capability and scope.
    /// </summary>
    ValueTask<PermissionGrantRecord?> FindAsync(DecisionRequest request, CancellationToken cancellationToken);
}

public enum ResourceDisposition
{
    Unknown = 0,
    Authorized = 1,
    Denied = 2,
}

/// <summary>The resource owner's verdict at the service-side step, with the risk facts only the owner can establish.</summary>
public sealed record ResourceVerdict(ResourceDisposition Disposition, RiskFacts Facts);

/// <summary>Step 7 source: resource authorization, a decision separate from capability permission.</summary>
public interface IResourceAuthorizer
{
    ValueTask<ResourceVerdict?> AuthorizeAsync(DecisionRequest request, CancellationToken cancellationToken);
}

public enum BoundaryVerdict
{
    Unknown = 0,
    Allowed = 1,
    Denied = 2,
}

/// <summary>Step 8 source: secret use (never reveal) and data egress to an exact destination, each its own authorization.</summary>
public interface IDataBoundaryAuthorizer
{
    ValueTask<BoundaryVerdict> AuthorizeSecretUseAsync(DecisionRequest request, CancellationToken cancellationToken);

    ValueTask<BoundaryVerdict> AuthorizeEgressAsync(DecisionRequest request, string destination, CancellationToken cancellationToken);
}

public enum OwnerVerdict
{
    Unknown = 0,
    Valid = 1,
    Refused = 2,
    RevisionChanged = 3,
}

/// <summary>
/// What the capability owner is asked to validate last. The risk assessment and the service-side decision are present when the
/// pipeline's own service decision preceded the call and absent when the owner is asked directly; the owner never relies on either.
/// </summary>
public sealed record OwnerValidationRequest(DecisionRequest Request, RiskAssessment? Risk, SecurityDecision? ServiceDecision);

/// <summary>Step 11 source: the owner of the resource, which always has the last word and never trusts an earlier point.</summary>
public interface IOwnerValidator
{
    ValueTask<OwnerVerdict> ValidateAsync(OwnerValidationRequest request, CancellationToken cancellationToken);
}

public enum DecisionResultKind
{
    None = 0,
    Success = 1,
    Failure = 2,
    Cancelled = 3,
}

/// <summary>The recorded result and effect certainty of an executed invocation (step 13). It carries no payload.</summary>
public sealed record DecisionRecord(
    ArcForges.Contracts.Foundation.Values.CommandId CommandId,
    string CapabilityKey,
    ResourceReference Resource,
    RiskLevel EffectiveRisk,
    DecisionResultKind Result,
    string? FailureCode,
    EffectCertainty Effect,
    ArcForges.Foundation.Instant RecordedAt);

/// <summary>Step 13 sink. It must return only after the record is durable and throw on any failure.</summary>
public interface IDecisionRecorder
{
    ValueTask RecordAsync(DecisionRecord record, CancellationToken cancellationToken);
}

public enum SecurityAuditKind
{
    None = 0,
    Refused = 1,
    Executed = 2,
    OwnerFailed = 3,
    OwnerCancelled = 4,
}

/// <summary>
/// The audit fact of one refusal or execution (step 14): kind, point, failing step and reason, the complete actor chain,
/// executor and software identity, capability, resource reference, effective risk, decision, origin, device, workspace, realm and
/// correlation. It carries no payload, secret or content.
/// </summary>
public sealed record SecurityAuditRecord(
    SecurityAuditKind Kind,
    EnforcementPoint Point,
    DecisionStep FailedStep,
    string ReasonCode,
    string RegisteredCode,
    ArcForges.Foundation.Instant OccurredAt,
    ActorChain Actors,
    ArcForges.Contracts.Foundation.Values.InstanceId Executor,
    string? SoftwareIdentity,
    string CapabilityKey,
    ResourceReference Resource,
    RiskLevel? EffectiveRisk,
    DecisionOrigin Origin,
    ArcForges.Contracts.Foundation.Values.DeviceId Device,
    DecisionScope Scope,
    ArcForges.Contracts.Foundation.Values.CommandId Correlation,
    EffectCertainty Effect);

/// <summary>Step 14 sink. It owns audit durability; Security never references the audit store.</summary>
public interface ISecurityAuditSink
{
    ValueTask WriteAsync(SecurityAuditRecord record, CancellationToken cancellationToken);
}
