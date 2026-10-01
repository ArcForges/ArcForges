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

/// <summary>Closed content classification of the data an egress decision concerns (never the content itself).</summary>
public enum AuditEgressDataClass
{
    None = 0,
    CanonicalUserData = 1,
    ManagedAsset = 2,
    ExternalReference = 3,
    DerivedData = 4,
    DeviceLocalState = 5,
    Secret = 6,
    EphemeralData = 7,
    OperationalData = 8,
    AuditOrCommercial = 9,
}

/// <summary>Closed trust-boundary class of an egress destination.</summary>
public enum AuditEgressDestinationClass
{
    None = 0,
    CloudAiProvider = 1,
    Connector = 2,
    ThirdParty = 3,
    Public = 4,
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

/// <summary>
/// The typed facts of one egress decision that are not generic audit fields: what class of data, to which
/// destination class and canonical identity, under which authority and committed authority revision.
/// There is no content, secret value or property bag.
/// </summary>
public sealed record AuditEgressDetail
{
    public AuditEgressDetail(AuditEgressDataClass dataClass, AuditEgressDestinationClass destinationClass,
        AuditEgressDestinationId destination, Revision authority)
    {
        if (!AuditEnumValidation.IsWireValue(dataClass)) throw new ArgumentOutOfRangeException(nameof(dataClass));
        if (!AuditEnumValidation.IsWireValue(destinationClass)) throw new ArgumentOutOfRangeException(nameof(destinationClass));
        ArgumentNullException.ThrowIfNull(destination);
        if (authority.ObjectId == Guid.Empty || authority.Value.Value <= 0)
        {
            throw new ArgumentException("A committed authority identity and revision are required.", nameof(authority));
        }

        DataClass = dataClass;
        DestinationClass = destinationClass;
        Destination = destination;
        Authority = authority;
    }

    public AuditEgressDataClass DataClass { get; }
    public AuditEgressDestinationClass DestinationClass { get; }
    public AuditEgressDestinationId Destination { get; }
    /// <summary>The authority object identity and its committed revision.</summary>
    public Revision Authority { get; }
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
        _ = new AuditResourceReference(resource.Kind, resource.Id);
        if (actorChain.Actors.Count > 0 && !StringComparer.Ordinal.Equals(actorChain.Actors[^1].SoftwareIdentity, softwareIdentity.Value))
        {
            throw new ArgumentException("Software identity must match the final delegated actor.", nameof(softwareIdentity));
        }

        if (workspace is { } workspaceValue) _ = workspaceValue.ToWire();
        if (task is { } taskValue) _ = taskValue.ToWire();
        if (correlation is { } correlationValue) _ = correlationValue.ToWire();
        AuditEventShape.Validate(eventType, resource, decision, reason, correlation, egress);

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
    private static readonly AuditDecisionReason[] EgressAllowedReasons =
    [
        AuditDecisionReason.PolicyAllowed, AuditDecisionReason.UserApproved, AuditDecisionReason.StepUpSatisfied,
        AuditDecisionReason.RiskAccepted, AuditDecisionReason.BreakGlass,
    ];

    private static readonly AuditDecisionReason[] EgressDeniedReasons =
    [
        AuditDecisionReason.PolicyDenied, AuditDecisionReason.UserRejected, AuditDecisionReason.StepUpRequired,
        AuditDecisionReason.PolicyExpired, AuditDecisionReason.AuthorityMissing,
        AuditDecisionReason.ResourceUnavailable, AuditDecisionReason.RiskRejected,
    ];

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

    internal static void Validate(AuditEventType type, AuditResourceReference resource, AuditDecision decision,
        AuditDecisionReason reason, CorrelationId? correlation, AuditEgressDetail? egress)
    {
        var egressType = type is AuditEventType.DataEgressAuthorized or AuditEventType.DataEgressDenied;
        if (egressType != (egress is not null))
        {
            throw new ArgumentException("Typed egress detail is required for, and only for, data-egress decisions.", nameof(egress));
        }

        if (egressType)
        {
            var allowed = type == AuditEventType.DataEgressAuthorized;
            if (correlation is null) throw new ArgumentException("An egress decision requires its correlation identity.", nameof(correlation));
            if (decision != (allowed ? AuditDecision.Allowed : AuditDecision.Denied)
                || !(allowed ? EgressAllowedReasons : EgressDeniedReasons).Contains(reason))
            {
                throw new ArgumentException("Egress decision and reason do not match the event type.", nameof(decision));
            }
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
