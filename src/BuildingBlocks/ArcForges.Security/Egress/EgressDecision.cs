// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.Egress;

/// <summary>
/// Why an egress decision refused. Reasons are stable, each maps to a registered semantic code, and none of them reveals the
/// content or whether a destination exists beyond the policy's own answer (SR-02).
/// </summary>
public enum EgressReason
{
    None = 0,

    /// <summary>The invocation declared no destination, or a different one than the transfer is about to use.</summary>
    DestinationNotDeclared = 1,

    /// <summary>The destination is not an exact HTTPS destination identity.</summary>
    DestinationMalformed = 2,

    /// <summary>The classifier did not name a data class that may be sent.</summary>
    ContentUnclassified = 3,

    /// <summary>The content is secret material, which never leaves.</summary>
    SecretMaterial = 4,

    /// <summary>The scope's allowlist does not name the destination.</summary>
    NotAllowlisted = 5,

    /// <summary>The allowlist source answered with an entry for another scope or destination.</summary>
    AllowlistMismatch = 6,

    /// <summary>The content is more sensitive than the allowlist entry admits for the destination.</summary>
    DataClassAboveAllowlist = 7,

    /// <summary>The destination is a Cloud model provider and the knowledge policy does not make the content AI-eligible.</summary>
    AiIneligibleContent = 8,

    /// <summary>The principal holds no egress grant for the capability, scope and destination. Read access does not substitute.</summary>
    NoGrant = 9,

    /// <summary>A standing prohibition covers the destination.</summary>
    GrantExplicitlyDenied = 10,

    /// <summary>Every record the grant source returned names another principal, capability, scope or destination.</summary>
    GrantMismatch = 11,

    /// <summary>The matching grant is not yet valid or is over.</summary>
    GrantOutsideLifetime = 12,

    /// <summary>The content is more sensitive than the matching grant admits.</summary>
    DataClassAboveGrant = 13,

    ClassifierUnavailable = 20,
    AllowlistUnavailable = 21,
    GrantSourceUnavailable = 22,

    /// <summary>The decision could not be made durable in the audit sink, so it is not released.</summary>
    AuditUnavailable = 23,
}

/// <summary>A reason with its stable code and the registered semantic code a typed refusal carries.</summary>
public sealed record EgressReasonInfo(EgressReason Reason, string Code, string RegisteredCode, bool IsUnavailable);

/// <summary>The closed table of egress reasons.</summary>
public static class EgressReasons
{
    private static readonly ReadOnlyCollection<EgressReasonInfo> Entries = Array.AsReadOnly(
    [
        Denied(EgressReason.DestinationNotDeclared, "egress.destination_not_declared"),
        Denied(EgressReason.DestinationMalformed, "egress.destination_malformed"),
        Denied(EgressReason.ContentUnclassified, "egress.content_unclassified"),
        Denied(EgressReason.SecretMaterial, "egress.secret_material"),
        Denied(EgressReason.NotAllowlisted, "egress.not_allowlisted"),
        Denied(EgressReason.AllowlistMismatch, "egress.allowlist_mismatch"),
        Denied(EgressReason.DataClassAboveAllowlist, "egress.data_class_above_allowlist"),
        Denied(EgressReason.AiIneligibleContent, "egress.ai_ineligible_content"),
        Denied(EgressReason.NoGrant, "egress.no_grant"),
        Denied(EgressReason.GrantExplicitlyDenied, "egress.grant_explicitly_denied"),
        Denied(EgressReason.GrantMismatch, "egress.grant_mismatch"),
        Denied(EgressReason.GrantOutsideLifetime, "egress.grant_outside_lifetime"),
        Denied(EgressReason.DataClassAboveGrant, "egress.data_class_above_grant"),
        Unavailable(EgressReason.ClassifierUnavailable, "egress.classifier_unavailable"),
        Unavailable(EgressReason.AllowlistUnavailable, "egress.allowlist_unavailable"),
        Unavailable(EgressReason.GrantSourceUnavailable, "egress.grant_source_unavailable"),
        Unavailable(EgressReason.AuditUnavailable, "egress.audit_unavailable"),
    ]);

    /// <summary>Every reason that can refuse a decision, in definition order.</summary>
    public static IReadOnlyList<EgressReasonInfo> All => Entries;

    /// <summary>Returns the entry of a reason that can refuse, or throws for <see cref="EgressReason.None"/> and undefined values.</summary>
    public static EgressReasonInfo Describe(EgressReason reason) =>
        Entries.FirstOrDefault(entry => entry.Reason == reason)
        ?? throw new ArgumentOutOfRangeException(nameof(reason));

    private static EgressReasonInfo Denied(EgressReason reason, string code) => new(reason, code, "perm.egress_denied", false);

    private static EgressReasonInfo Unavailable(EgressReason reason, string code) => new(reason, code, "resource.unavailable", true);
}

public enum EgressAuditKind
{
    None = 0,

    /// <summary>The transfer was authorized. This is a decision, not proof that bytes were sent.</summary>
    Authorized = 1,

    /// <summary>The transfer was refused.</summary>
    Refused = 2,
}

/// <summary>
/// The audit fact of one egress decision (EG-04, AU-02, UI-07): what class of content, to which exact destination, under whose
/// authority, when, and for whom. It carries no payload, content, secret or free text, only classes, identities and references.
/// </summary>
public sealed record EgressAuditRecord(
    EgressAuditKind Kind,
    EgressReason Reason,
    string? ReasonCode,
    string? RegisteredCode,
    Instant OccurredAt,
    ActorChain Actors,
    InstanceId Executor,
    string? SoftwareIdentity,
    string CapabilityKey,
    ResourceReference Resource,
    DecisionScope Scope,
    DecisionOrigin Origin,
    DeviceId Device,
    CommandId Correlation,
    string? Destination,
    EgressDestinationClass DestinationClass,
    EgressDataClass DataClass,
    bool AiEligible,
    EgressAuthorityKind Authority,
    string? AuthorityReference,
    string? GrantIssuer,
    string? GrantGeneration,
    string? AllowlistGeneration);

/// <summary>The complete outcome of one egress decision. A refusal names its reason; an allowed decision names its authority.</summary>
public sealed class EgressDecision
{
    internal EgressDecision(
        EgressReason reason,
        EgressDestinationIdentity? destination,
        EgressDestinationClass destinationClass,
        EgressDataClass dataClass,
        EgressAuthorityKind authority,
        string? authorityReference,
        EgressAuditRecord audit)
    {
        Reason = reason;
        Destination = destination;
        DestinationClass = destinationClass;
        DataClass = dataClass;
        Authority = authority;
        AuthorityReference = authorityReference;
        Audit = audit;
    }

    public bool Allowed => Reason == EgressReason.None;

    public EgressReason Reason { get; }

    public string? ReasonCode => Allowed ? null : EgressReasons.Describe(Reason).Code;

    /// <summary>The registered semantic code of the refusal, or null for an allowed decision.</summary>
    public string? RegisteredCode => Allowed ? null : EgressReasons.Describe(Reason).RegisteredCode;

    public EgressDestinationIdentity? Destination { get; }

    public EgressDestinationClass DestinationClass { get; }

    public EgressDataClass DataClass { get; }

    public EgressAuthorityKind Authority { get; }

    public string? AuthorityReference { get; }

    /// <summary>The audit record this decision wrote (or tried to write) before it was released.</summary>
    public EgressAuditRecord Audit { get; }

    /// <summary>The verdict the pipeline's data-boundary port expects: allowed, denied, or unknown when a source could not answer.</summary>
    public BoundaryVerdict ToBoundaryVerdict() =>
        Allowed ? BoundaryVerdict.Allowed
        : EgressReasons.Describe(Reason).IsUnavailable ? BoundaryVerdict.Unknown
        : BoundaryVerdict.Denied;

    /// <summary>Success for an allowed decision, otherwise a typed failure with the registered code of the reason.</summary>
    public Outcome<bool> ToAuthorizationOutcome() =>
        Allowed ? Outcome.Success(true) : Outcome.Failure<bool>(TypedFailure.Create(EgressReasons.Describe(Reason).RegisteredCode));
}

/// <summary>
/// Proof that this transfer was decided and audited. It has no public constructor or factory: only the authority's transfer route
/// creates one, immediately before it calls the owner's send operation, so an operation that requires it as its parameter cannot be
/// reached without an egress decision. It is proof of one decision, not a credential: it is not serializable and carries no single-use or expiry state, so a send operation must use only the destination it names and must not keep it for a later transfer, which is decided again anyway.
/// </summary>
public sealed class AuthorizedEgress
{
    internal AuthorizedEgress(EgressDecision decision)
    {
        Decision = decision;
        Destination = decision.Destination!;
    }

    /// <summary>The exact destination the transfer may use; the send operation connects here and nowhere else.</summary>
    public EgressDestinationIdentity Destination { get; }

    public EgressDestinationClass DestinationClass => Decision.DestinationClass;

    public EgressDataClass DataClass => Decision.DataClass;

    public EgressAuthorityKind Authority => Decision.Authority;

    public string? AuthorityReference => Decision.AuthorityReference;

    public EgressDecision Decision { get; }
}

/// <summary>The owner's send operation. It receives the ticket, sends, and reports a typed result.</summary>
public delegate ValueTask<Outcome<TResult>> EgressOperation<TResult>(AuthorizedEgress ticket, CancellationToken cancellationToken);

/// <summary>The result of a guarded transfer: the decision, and what the caller sees.</summary>
public sealed class EgressTransfer<TResult>
{
    internal EgressTransfer(EgressDecision decision, Outcome<TResult> result, bool operationRan)
    {
        Decision = decision;
        Result = result;
        OperationRan = operationRan;
    }

    public EgressDecision Decision { get; }

    /// <summary>The operation's own outcome, or a typed refusal with a registered code when the decision refused.</summary>
    public Outcome<TResult> Result { get; }

    /// <summary>False when the decision refused: the send operation was never called.</summary>
    public bool OperationRan { get; }
}
