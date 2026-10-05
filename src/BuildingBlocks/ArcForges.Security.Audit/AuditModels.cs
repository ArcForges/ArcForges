// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security;

namespace ArcForges.Security.Audit;

public enum AuditEventType
{
    None = 0,
    AuthenticationSucceeded = 1,
    AuthenticationFailed = 2,
    StepUpPerformed = 3,
    PermissionGranted = 4,
    PermissionChanged = 5,
    PermissionRevoked = 6,
    ApprovalRequested = 7,
    ApprovalDecided = 8,
    HighRiskCapabilityInvoked = 9,
    SecretUsed = 10,
    SecretRevealed = 11,
    SecretCreated = 12,
    SecretRotated = 13,
    SecretDeleted = 14,
    DataEgressAuthorized = 15,
    DataEgressDenied = 16,
    DeviceTrustChanged = 17,
    DeviceRevoked = 18,
    RemotePermissionChanged = 19,
    PackageTrustChanged = 20,
    RealmTransferred = 21,
    WorkspaceTransferred = 22,
    SecurityPolicyChanged = 23,
    PasskeyAdded = 24,
    PasskeyRemoved = 25,
    SessionRevoked = 26,
    AdministrativeGrant = 27,
    AdministrativeGrantRevoked = 28,
    CompensationIssued = 29,
    CompensationAdjusted = 30,
    RefundProposed = 31,
    RefundDecided = 32,
    RefundProviderOutcome = 33,
    EntitlementChanged = 34,
    RemoteActionApproved = 35,
    BreakGlassAccessed = 36,
    EnforcementAction = 37,
    ExportRequested = 38,
    DeletionRequested = 39,
    LocalPresenceProved = 40,
    CapabilityLeaseIssued = 41,
    CapabilityLeaseRevoked = 42,
    CapabilityLeaseExpired = 43,
    CapabilityLeaseTaskEnded = 44,
}

/// <summary>The closed R0-R4 effective-risk scale of <see cref="RiskLevel"/>, preserved without loss.</summary>
public enum AuditRisk
{
    None = 0,
    R0 = 1,
    R1 = 2,
    R2 = 3,
    R3 = 4,
    R4 = 5,

    /// <summary>
    /// Effective risk was not assessed when the decision was made. Only an egress event may carry it: the egress decision is pipeline
    /// step 8 and risk is assessed at step 9, so the egress authority has none to give. It is never an inferred value.
    /// </summary>
    NotAssessed = 6,
}

public enum AuditDecision
{
    None = 0,
    Allowed = 1,
    Denied = 2,
    Requested = 3,
    Approved = 4,
    Rejected = 5,
    Completed = 6,
}

public enum AuditDecisionReason
{
    None = 0,
    PolicyAllowed = 1,
    PolicyDenied = 2,
    UserApproved = 3,
    UserRejected = 4,
    StepUpSatisfied = 5,
    StepUpRequired = 6,
    PolicyExpired = 7,
    AuthorityMissing = 8,
    ResourceUnavailable = 9,
    RiskAccepted = 10,
    RiskRejected = 11,
    BreakGlass = 12,
    NotApplicable = 13,
}

public enum AuditOrigin
{
    None = 0,
    Local = 1,
    Remote = 2,
}

public enum AuditResourceKind
{
    None = 0,
    Account = 1,
    Device = 2,
    Installation = 3,
    Session = 4,
    Workspace = 5,
    Capability = 6,
    Secret = 7,
    Package = 8,
    Approval = 9,
    Export = 10,
    Deletion = 11,
    Entitlement = 12,
    Payment = 13,
    Policy = 14,
    Task = 15,
    CapabilityLease = 16,
}

/// <summary>
/// Closed sensitivity tier of the data an egress decision concerns, exactly as the PLT.41 egress authority classifies it (never the
/// content itself). <see cref="Unclassified"/> is the explicit marker of a decision refused before any class was determined.
/// </summary>
public enum AuditEgressDataClass
{
    None = 0,
    Unclassified = 1,
    Public = 2,
    Diagnostic = 3,
    WorkspaceContent = 4,
    SensitiveContent = 5,
    SecretMaterial = 6,
}

/// <summary>
/// Closed trust-boundary class of an egress destination. <see cref="Undetermined"/> is the explicit marker of a decision refused before
/// the workspace allowlist named the destination's class.
/// </summary>
public enum AuditEgressDestinationClass
{
    None = 0,
    CloudAiProvider = 1,
    Connector = 2,
    ThirdParty = 3,
    Public = 4,
    Undetermined = 5,
}

/// <summary>Whose authority an allowed egress rests on; <see cref="NoAuthority"/> for every refusal.</summary>
public enum AuditEgressAuthorityKind
{
    None = 0,
    NoAuthority = 1,
    UserConsent = 2,
    WorkspacePolicy = 3,
    ProductRoute = 4,
}

/// <summary>The exact egress decision outcome and refusal reason, one to one with the PLT.41 reasons.</summary>
public enum AuditEgressReason
{
    None = 0,
    Authorized = 1,
    DestinationNotDeclared = 2,
    DestinationMalformed = 3,
    ContentUnclassified = 4,
    SecretMaterial = 5,
    NotAllowlisted = 6,
    AllowlistMismatch = 7,
    DataClassAboveAllowlist = 8,
    AiIneligibleContent = 9,
    NoGrant = 10,
    GrantExplicitlyDenied = 11,
    GrantMismatch = 12,
    GrantOutsideLifetime = 13,
    DataClassAboveGrant = 14,
    ClassifierUnavailable = 15,
    AllowlistUnavailable = 16,
    GrantSourceUnavailable = 17,
    AuditUnavailable = 18,
}

public enum AuditHoldReason
{
    None = 0,
    LegalPreservation = 1,
    FinancialRecord = 2,
    AccountDeletionReview = 3,
    SecurityIncident = 4,
}

internal static class AuditEnumValidation
{
    internal static bool IsWireValue<TEnum>(TEnum value) where TEnum : struct, Enum =>
        !EqualityComparer<TEnum>.Default.Equals(value, default) && Enum.IsDefined(value);

    /// <summary>Total, lossless mapping of the PLT.37 R0-R4 scale; any other value is refused.</summary>
    internal static AuditRisk FromRiskLevel(RiskLevel level) => level switch
    {
        RiskLevel.R0 => AuditRisk.R0,
        RiskLevel.R1 => AuditRisk.R1,
        RiskLevel.R2 => AuditRisk.R2,
        RiskLevel.R3 => AuditRisk.R3,
        RiskLevel.R4 => AuditRisk.R4,
        _ => throw new ArgumentOutOfRangeException(nameof(level)),
    };
}

/// <summary>A bounded software identifier; it is not an event message or a user-content field.</summary>
public sealed record AuditSoftwareIdentity
{
    public AuditSoftwareIdentity(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 256 || value.Any(char.IsControl))
        {
            throw new ArgumentException("Software identity must be bounded and contain no control characters.", nameof(value));
        }

        _ = new UTF8Encoding(false, true).GetByteCount(value);
        Value = value;
    }

    public string Value { get; }
}

/// <summary>A capability registry key, not free-form event data.</summary>
public sealed record AuditCapabilityId
{
    public AuditCapabilityId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 128 || value[0] is < 'a' or > 'z')
        {
            throw new ArgumentException("Capability identifier is not a bounded canonical key.", nameof(value));
        }

        var previousSeparator = false;
        foreach (var character in value)
        {
            var separator = character is '.' or '-';
            if (!(character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-') || (separator && previousSeparator))
            {
                throw new ArgumentException("Capability identifier is not a bounded canonical key.", nameof(value));
            }

            previousSeparator = separator;
        }

        if (previousSeparator)
        {
            throw new ArgumentException("Capability identifier is not a bounded canonical key.", nameof(value));
        }

        Value = value;
    }

    public string Value { get; }
}

/// <summary>Opaque, typed resource identity. Paths, payloads and descriptive content are not accepted.</summary>
public readonly record struct AuditResourceReference
{
    public AuditResourceReference(AuditResourceKind kind, Guid id)
    {
        if (!AuditEnumValidation.IsWireValue(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        if (id == Guid.Empty)
        {
            throw new ArgumentException("A resource identity is required.", nameof(id));
        }

        Kind = kind;
        Id = id;
    }

    public AuditResourceKind Kind { get; }
    public Guid Id { get; }
}

/// <summary>
/// Canonical egress destination identity: a lower-case host name with an optional port, or a lower-case
/// registry label. Schemes, paths, queries, fragments and user information are not representable.
/// </summary>
public sealed record AuditEgressDestinationId
{
    public AuditEgressDestinationId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 260) throw new ArgumentException("Destination identity is not a bounded canonical key.", nameof(value));
        var host = value;
        var colon = value.IndexOf(':', StringComparison.Ordinal);
        if (colon >= 0)
        {
            host = value[..colon];
            var port = value[(colon + 1)..];
            if (port.Length is < 1 or > 5 || port[0] == '0' || port.Any(character => character is < '0' or > '9')
                || int.Parse(port, System.Globalization.CultureInfo.InvariantCulture) > 65535)
            {
                throw new ArgumentException("Destination identity is not a bounded canonical key.", nameof(value));
            }
        }

        if (host.Length is < 1 or > 253) throw new ArgumentException("Destination identity is not a bounded canonical key.", nameof(value));
        foreach (var label in host.Split('.'))
        {
            if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-'
                || label.Any(character => !(character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')))
            {
                throw new ArgumentException("Destination identity is not a bounded canonical key.", nameof(value));
            }
        }

        Value = value;
    }

    public string Value { get; }
}

/// <summary>A bounded reference text (an authority reference or a grant generation); never an event message or content.</summary>
public sealed record AuditReferenceText
{
    public const int MaximumLength = 256;

    public AuditReferenceText(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > MaximumLength || value.Any(char.IsControl))
        {
            throw new ArgumentException("A reference must be bounded and contain no control characters.", nameof(value));
        }

        _ = new UTF8Encoding(false, true).GetByteCount(value);
        Value = value;
    }

    public string Value { get; }
}

/// <summary>
/// The SHA-256 content reference of an egress decision's opaque resource id and revision. It is a fingerprint, not an identity and not
/// a secrecy mechanism: it is unsalted, so a low-entropy or path-like id can be confirmed by guessing by anyone who can read the audit
/// file. The exact reference stays in the correlated security audit record of the same command.
/// </summary>
public sealed record AuditEgressContentReference
{
    public AuditEgressContentReference(string sha256Hex)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sha256Hex);
        if (sha256Hex.Length != 64 || sha256Hex.Any(character => !(character is >= '0' and <= '9' or >= 'A' and <= 'F')))
        {
            throw new ArgumentException("An upper-case SHA-256 hex digest is required.", nameof(sha256Hex));
        }

        Value = sha256Hex;
    }

    public string Value { get; }

    /// <summary>The domain-separated digest of the length-prefixed UTF-8 resource id and revision.</summary>
    public static AuditEgressContentReference From(string resourceId, string resourceRevision)
    {
        ArgumentException.ThrowIfNullOrEmpty(resourceId);
        ArgumentException.ThrowIfNullOrEmpty(resourceRevision);
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true), leaveOpen: true))
        {
            writer.Write("ArcForges.audit.egress-content.v1");
            writer.Write(resourceId);
            writer.Write(resourceRevision);
        }

        return new AuditEgressContentReference(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream.ToArray())));
    }
}

/// <summary>
/// The typed facts of one egress decision that are not generic audit fields, as the PLT.41 egress authority knew them: the exact
/// outcome or refusal reason, the data tier or the explicit unclassified marker, the destination class or the explicit undetermined
/// marker, the canonical destination identity (absent only when the destination was malformed), the authority kind, reference and
/// grant generation of an allowed decision (none for a refusal), and the content reference fingerprint. Nothing is inferred: a
/// combination the decision could not have produced is refused. There is no content, secret value, path or property bag.
/// </summary>
public sealed record AuditEgressDetail
{
    public AuditEgressDetail(AuditEgressReason reason, AuditEgressDataClass dataClass,
        AuditEgressDestinationClass destinationClass, AuditEgressDestinationId? destination,
        AuditEgressAuthorityKind authorityKind, AuditReferenceText? authorityReference,
        AuditReferenceText? grantGeneration, AuditEgressContentReference content)
    {
        if (!AuditEnumValidation.IsWireValue(reason)) throw new ArgumentOutOfRangeException(nameof(reason));
        if (!AuditEnumValidation.IsWireValue(dataClass)) throw new ArgumentOutOfRangeException(nameof(dataClass));
        if (!AuditEnumValidation.IsWireValue(destinationClass)) throw new ArgumentOutOfRangeException(nameof(destinationClass));
        if (!AuditEnumValidation.IsWireValue(authorityKind)) throw new ArgumentOutOfRangeException(nameof(authorityKind));
        ArgumentNullException.ThrowIfNull(content);

        var allowed = reason == AuditEgressReason.Authorized;
        if (allowed)
        {
            if (dataClass is AuditEgressDataClass.Unclassified or AuditEgressDataClass.SecretMaterial
                || destinationClass == AuditEgressDestinationClass.Undetermined || destination is null
                || authorityKind == AuditEgressAuthorityKind.NoAuthority || authorityReference is null || grantGeneration is null)
            {
                throw new ArgumentException("An authorized egress is classified, has a destination class and identity and rests on an authority.");
            }
        }
        else
        {
            if (authorityKind != AuditEgressAuthorityKind.NoAuthority || authorityReference is not null || grantGeneration is not null)
            {
                throw new ArgumentException("A refused egress rests on no authority.");
            }

            var (classKnown, destinationClassKnown, destinationPresent) = AuditEgressReasons.Phase(reason);
            if (classKnown == (dataClass == AuditEgressDataClass.Unclassified)
                || (reason == AuditEgressReason.SecretMaterial) != (dataClass == AuditEgressDataClass.SecretMaterial)
                || destinationClassKnown == (destinationClass == AuditEgressDestinationClass.Undetermined)
                || destinationPresent != (destination is not null))
            {
                throw new ArgumentException("The data class, destination class and destination do not agree with the refusal reason.");
            }
        }

        Reason = reason;
        DataClass = dataClass;
        DestinationClass = destinationClass;
        Destination = destination;
        AuthorityKind = authorityKind;
        AuthorityReference = authorityReference;
        GrantGeneration = grantGeneration;
        Content = content;
    }

    public AuditEgressReason Reason { get; }
    public AuditEgressDataClass DataClass { get; }
    public AuditEgressDestinationClass DestinationClass { get; }
    /// <summary>The canonical destination identity; null only when the destination was malformed.</summary>
    public AuditEgressDestinationId? Destination { get; }
    public AuditEgressAuthorityKind AuthorityKind { get; }
    /// <summary>The consent, policy or route the grant rests on; null for a refusal.</summary>
    public AuditReferenceText? AuthorityReference { get; }
    /// <summary>The grant's committed generation; null for a refusal.</summary>
    public AuditReferenceText? GrantGeneration { get; }
    public AuditEgressContentReference Content { get; }
}

/// <summary>The closed table tying an egress reason to what the decision had determined when it refused, and to the generic audit reason.</summary>
internal static class AuditEgressReasons
{
    /// <summary>
    /// For a refusal reason: whether a data class was determined, whether the destination class was determined, and whether a
    /// well-formed destination existed. A refusal with a secret-material reason has determined a class, which is the secret tier.
    /// </summary>
    internal static (bool ClassKnown, bool DestinationClassKnown, bool DestinationPresent) Phase(AuditEgressReason reason) => reason switch
    {
        AuditEgressReason.DestinationMalformed => (false, false, false),
        AuditEgressReason.DestinationNotDeclared or AuditEgressReason.ClassifierUnavailable
            or AuditEgressReason.ContentUnclassified => (false, false, true),
        AuditEgressReason.SecretMaterial or AuditEgressReason.AllowlistUnavailable or AuditEgressReason.NotAllowlisted
            or AuditEgressReason.AllowlistMismatch => (true, false, true),
        AuditEgressReason.DataClassAboveAllowlist or AuditEgressReason.AiIneligibleContent or AuditEgressReason.NoGrant
            or AuditEgressReason.GrantExplicitlyDenied or AuditEgressReason.GrantMismatch or AuditEgressReason.GrantOutsideLifetime
            or AuditEgressReason.DataClassAboveGrant or AuditEgressReason.GrantSourceUnavailable
            or AuditEgressReason.AuditUnavailable => (true, true, true),
        _ => throw new ArgumentOutOfRangeException(nameof(reason)),
    };

    /// <summary>The generic audit reason of an egress reason; an allowed decision follows its real authority kind.</summary>
    internal static AuditDecisionReason Generic(AuditEgressReason reason, AuditEgressAuthorityKind authority) => reason switch
    {
        AuditEgressReason.Authorized => authority == AuditEgressAuthorityKind.UserConsent
            ? AuditDecisionReason.UserApproved : AuditDecisionReason.PolicyAllowed,
        AuditEgressReason.NoGrant => AuditDecisionReason.AuthorityMissing,
        AuditEgressReason.GrantOutsideLifetime => AuditDecisionReason.PolicyExpired,
        AuditEgressReason.ClassifierUnavailable or AuditEgressReason.AllowlistUnavailable
            or AuditEgressReason.GrantSourceUnavailable or AuditEgressReason.AuditUnavailable => AuditDecisionReason.ResourceUnavailable,
        AuditEgressReason.None => throw new ArgumentOutOfRangeException(nameof(reason)),
        _ => AuditDecisionReason.PolicyDenied,
    };
}

/// <summary>Immutable security decision fact; intentionally has no payload or arbitrary property bag.</summary>
public sealed class AuditEvent
{
    public AuditEvent(AuditEventType eventType, ActorChain actorChain,
        AuditSoftwareIdentity softwareIdentity, AuditCapabilityId capability, AuditResourceReference resource,
        AuditRisk risk, AuditDecision decision, AuditDecisionReason reason, AuditOrigin origin,
        WorkspaceId? workspace = null, TaskId? task = null, CorrelationId? correlation = null,
        AuditEgressDetail? egress = null)
    {
        if (!AuditEnumValidation.IsWireValue(eventType)) throw new ArgumentOutOfRangeException(nameof(eventType));
        if (!AuditEnumValidation.IsWireValue(risk)) throw new ArgumentOutOfRangeException(nameof(risk));
        if (!AuditEnumValidation.IsWireValue(decision)) throw new ArgumentOutOfRangeException(nameof(decision));
        if (!AuditEnumValidation.IsWireValue(reason)) throw new ArgumentOutOfRangeException(nameof(reason));
        if (!AuditEnumValidation.IsWireValue(origin)) throw new ArgumentOutOfRangeException(nameof(origin));
        ArgumentNullException.ThrowIfNull(actorChain);
        ArgumentNullException.ThrowIfNull(softwareIdentity);
        ArgumentNullException.ThrowIfNull(capability);
        var egressEvent = eventType is AuditEventType.DataEgressAuthorized or AuditEventType.DataEgressDenied;
        if (egressEvent)
        {
            // An egress event identifies its content by the fingerprint of its detail; it has no typed resource Guid.
            if (resource != default) throw new ArgumentException("An egress event carries no typed resource reference.", nameof(resource));
        }
        else
        {
            _ = new AuditResourceReference(resource.Kind, resource.Id);
        }

        if (actorChain.Actors.Count > 0 && !StringComparer.Ordinal.Equals(actorChain.Actors[^1].SoftwareIdentity, softwareIdentity.Value))
        {
            throw new ArgumentException("Software identity must match the final delegated actor.", nameof(softwareIdentity));
        }

        if (workspace is { } workspaceValue) _ = workspaceValue.ToWire();
        if (task is { } taskValue) _ = taskValue.ToWire();
        if (correlation is { } correlationValue) _ = correlationValue.ToWire();
        AuditEventShape.Validate(eventType, resource, risk, decision, reason, correlation, egress);

        EventType = eventType;
        ActorChain = actorChain;
        SoftwareIdentity = softwareIdentity;
        Capability = capability;
        Resource = resource;
        Risk = risk;
        Decision = decision;
        Reason = reason;
        Origin = origin;
        Workspace = workspace;
        Task = task;
        Correlation = correlation;
        Egress = egress;
    }

    public AuditEventType EventType { get; }
    public ActorChain ActorChain { get; }
    /// <summary>Explicit executor: final delegated actor executor, otherwise the entry-point instance.</summary>
    public InstanceId Executor => ActorChain.Actors.Count > 0 ? ActorChain.Actors[^1].Executor : ActorChain.CallerInstance;
    public AuditSoftwareIdentity SoftwareIdentity { get; }
    public AuditCapabilityId Capability { get; }
    public AuditResourceReference Resource { get; }
    public AuditRisk Risk { get; }
    public AuditDecision Decision { get; }
    public AuditDecisionReason Reason { get; }
    public AuditOrigin Origin { get; }
    public WorkspaceId? Workspace { get; }
    public TaskId? Task { get; }
    public CorrelationId? Correlation { get; }
    /// <summary>Present exactly for the two closed data-egress decision event types.</summary>
    public AuditEgressDetail? Egress { get; }
}

/// <summary>
/// Closed per-type event shapes. Egress decisions and capability-lease lifecycle facts cannot be stored
/// as generic events: their decision, reason, resource kind and typed detail must agree with the type.
/// </summary>
internal static class AuditEventShape
{
    private static readonly AuditDecisionReason[] LeaseIssuedReasons =
    [
        AuditDecisionReason.PolicyAllowed, AuditDecisionReason.UserApproved, AuditDecisionReason.StepUpSatisfied,
        AuditDecisionReason.RiskAccepted,
    ];

    private static readonly AuditDecisionReason[] LeaseRevokedReasons =
    [
        AuditDecisionReason.PolicyDenied, AuditDecisionReason.UserRejected, AuditDecisionReason.RiskRejected,
        AuditDecisionReason.AuthorityMissing,
    ];

    private static bool IsLease(AuditEventType type) => type is AuditEventType.CapabilityLeaseIssued
        or AuditEventType.CapabilityLeaseRevoked or AuditEventType.CapabilityLeaseExpired
        or AuditEventType.CapabilityLeaseTaskEnded;

    internal static void Validate(AuditEventType type, AuditResourceReference resource, AuditRisk risk, AuditDecision decision,
        AuditDecisionReason reason, CorrelationId? correlation, AuditEgressDetail? egress)
    {
        var egressType = type is AuditEventType.DataEgressAuthorized or AuditEventType.DataEgressDenied;
        if (egressType != (egress is not null))
        {
            throw new ArgumentException("Typed egress detail is required for, and only for, data-egress decisions.", nameof(egress));
        }

        if (egressType)
        {
            ArgumentNullException.ThrowIfNull(egress);
            var allowed = type == AuditEventType.DataEgressAuthorized;
            if (correlation is null) throw new ArgumentException("An egress decision requires its correlation identity.", nameof(correlation));
            if (decision != (allowed ? AuditDecision.Allowed : AuditDecision.Denied)
                || allowed != (egress.Reason == AuditEgressReason.Authorized)
                || reason != AuditEgressReasons.Generic(egress.Reason, egress.AuthorityKind))
            {
                throw new ArgumentException("Egress decision and reason do not match the event type.", nameof(decision));
            }
        }

        if (risk == AuditRisk.NotAssessed && !egressType)
        {
            throw new ArgumentException("Only an egress event may leave the effective risk unassessed.", nameof(risk));
        }

        var lease = IsLease(type);
        if (lease != (resource.Kind == AuditResourceKind.CapabilityLease))
        {
            throw new ArgumentException("A capability-lease resource is required for, and only for, lease lifecycle events.", nameof(resource));
        }

        if (!lease) return;
        var valid = type switch
        {
            AuditEventType.CapabilityLeaseIssued => decision == AuditDecision.Allowed && LeaseIssuedReasons.Contains(reason),
            AuditEventType.CapabilityLeaseRevoked => decision == AuditDecision.Completed && LeaseRevokedReasons.Contains(reason),
            AuditEventType.CapabilityLeaseExpired => decision == AuditDecision.Completed && reason == AuditDecisionReason.PolicyExpired,
            _ => decision == AuditDecision.Completed && reason == AuditDecisionReason.NotApplicable,
        };
        if (!valid) throw new ArgumentException("Lease decision and reason do not match the lifecycle event type.", nameof(decision));
    }
}

/// <summary>Owner-scoped UTC calendar-month retention unit.</summary>
public readonly record struct AuditPartition
{
    public AuditPartition(RealmId realm, UserId owner, int year, int month)
    {
        _ = realm.ToWire();
        _ = owner.ToWire();
        if (year is < 1 or > 9998) throw new ArgumentOutOfRangeException(nameof(year));
        if (month is < 1 or > 12) throw new ArgumentOutOfRangeException(nameof(month));
        Realm = realm;
        Owner = owner;
        Year = year;
        Month = month;
    }

    public RealmId Realm { get; }
    public UserId Owner { get; }
    public int Year { get; }
    public int Month { get; }
    public DateTimeOffset StartUtc => new(new DateTime(Year, Month, 1, 0, 0, 0, DateTimeKind.Utc));
    public DateTimeOffset EndExclusiveUtc => StartUtc.AddMonths(1);
    public static AuditPartition For(HumanPrincipal owner, DateTimeOffset occurredAt)
    {
        ArgumentNullException.ThrowIfNull(owner);
        var utc = occurredAt.ToUniversalTime();
        return new(owner.Realm, owner.Id, utc.Year, utc.Month);
    }

    internal static AuditPartition For(HumanPrincipal owner, Instant occurredAt)
    {
        ArgumentNullException.ThrowIfNull(owner);
        var utc = DateTimeOffset.FromUnixTimeSeconds(occurredAt.UnixSeconds);
        return new(owner.Realm, owner.Id, utc.Year, utc.Month);
    }
}

/// <summary>A persisted fact with its store-observed occurrence instant and integrity digest.</summary>
public sealed class AuditEventRecord(long sequence, Guid eventId, Instant occurredAt, AuditEvent auditEvent, string integritySha256)
{
    public long Sequence { get; } = sequence > 0 ? sequence : throw new ArgumentOutOfRangeException(nameof(sequence));
    public Guid EventId { get; } = eventId != Guid.Empty ? eventId : throw new ArgumentException("An event identity is required.", nameof(eventId));
    public Instant OccurredAt { get; } = occurredAt;
    public AuditEvent Event { get; } = auditEvent ?? throw new ArgumentNullException(nameof(auditEvent));
    public string IntegritySha256 { get; } = integritySha256 ?? throw new ArgumentNullException(nameof(integritySha256));
}

/// <summary>Bounded owner-scoped query; no SQL or raw predicate is accepted.</summary>
public sealed class AuditQuery
{
    public const int MaximumPageSize = 1000;

    public AuditQuery(DateTimeOffset fromInclusive, DateTimeOffset toExclusive, int limit, AuditEventType? eventType = null, long afterSequence = 0)
    {
        if (fromInclusive >= toExclusive) throw new ArgumentException("Query interval must be nonempty.");
        if (limit is < 1 or > MaximumPageSize) throw new ArgumentOutOfRangeException(nameof(limit));
        if (eventType is { } type && !AuditEnumValidation.IsWireValue(type)) throw new ArgumentOutOfRangeException(nameof(eventType));
        ArgumentOutOfRangeException.ThrowIfNegative(afterSequence);
        FromInclusive = fromInclusive.ToUniversalTime();
        ToExclusive = toExclusive.ToUniversalTime();
        Limit = limit;
        EventType = eventType;
        AfterSequence = afterSequence;
    }

    public DateTimeOffset FromInclusive { get; }
    public DateTimeOffset ToExclusive { get; }
    public int Limit { get; }
    public AuditEventType? EventType { get; }
    public long AfterSequence { get; }
}

public sealed class AuditHoldRecord(long sequence, Guid holdId, AuditPartition partition, AuditHoldReason reason,
    Instant occurredAt, bool released, ActorChain actorChain, AuditSoftwareIdentity softwareIdentity,
    AuditOrigin origin)
{
    public long Sequence { get; } = sequence > 0 ? sequence : throw new ArgumentOutOfRangeException(nameof(sequence));
    public Guid HoldId { get; } = holdId != Guid.Empty ? holdId : throw new ArgumentException("A hold identity is required.", nameof(holdId));
    public AuditPartition Partition { get; } = partition;
    public AuditHoldReason Reason { get; } = AuditEnumValidation.IsWireValue(reason) ? reason : throw new ArgumentOutOfRangeException(nameof(reason));
    public Instant OccurredAt { get; } = occurredAt;
    public bool Released { get; } = released;
    public ActorChain ActorChain { get; } = actorChain ?? throw new ArgumentNullException(nameof(actorChain));
    public AuditSoftwareIdentity SoftwareIdentity { get; } = softwareIdentity ?? throw new ArgumentNullException(nameof(softwareIdentity));
    public AuditOrigin Origin { get; } = AuditEnumValidation.IsWireValue(origin) ? origin : throw new ArgumentOutOfRangeException(nameof(origin));
}

/// <summary>Append-only evidence for one maintenance-authorized, owner-partition retention purge.</summary>
public sealed class AuditPurgeReceipt(long sequence, AuditMaintenanceReceipt authority, AuditPartition partition,
    Instant purgedAt, long eventCount, long firstEventSequence, long lastEventSequence, string eventsSha256)
{
    public long Sequence { get; } = sequence > 0 ? sequence : throw new ArgumentOutOfRangeException(nameof(sequence));
    public AuditMaintenanceReceipt Authority { get; } = authority ?? throw new ArgumentNullException(nameof(authority));
    public AuditPartition Partition { get; } = partition;
    public Instant PurgedAt { get; } = purgedAt;
    public long EventCount { get; } = eventCount > 0 ? eventCount : throw new ArgumentOutOfRangeException(nameof(eventCount));
    public long FirstEventSequence { get; } = firstEventSequence > 0 ? firstEventSequence : throw new ArgumentOutOfRangeException(nameof(firstEventSequence));
    public long LastEventSequence { get; } = lastEventSequence >= firstEventSequence ? lastEventSequence : throw new ArgumentOutOfRangeException(nameof(lastEventSequence));
    public string EventsSha256 { get; } = ValidateHash(eventsSha256);

    private static string ValidateHash(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException("A SHA-256 hex digest is required.", nameof(value));
        }

        return value.ToUpperInvariant();
    }
}
