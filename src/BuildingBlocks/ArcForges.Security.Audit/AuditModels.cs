// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;
using ArcForges.Security;

namespace ArcForges.Security.Audit;

public enum AuditEventType
{
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
}

public enum AuditRisk
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public enum AuditDecision
{
    Allowed = 1,
    Denied = 2,
    Requested = 3,
    Approved = 4,
    Rejected = 5,
    Completed = 6,
}

public enum AuditDecisionReason
{
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
    Local = 1,
    Remote = 2,
}

public enum AuditResourceKind
{
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
}

public enum AuditHoldReason
{
    LegalPreservation = 1,
    FinancialRecord = 2,
    AccountDeletionReview = 3,
    SecurityIncident = 4,
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
        if (!Enum.IsDefined(kind))
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

/// <summary>Immutable security decision fact; intentionally has no payload or arbitrary property bag.</summary>
public sealed class AuditEvent
{
    public AuditEvent(AuditEventType eventType, DateTimeOffset occurredAt, ActorChain actorChain,
        AuditSoftwareIdentity softwareIdentity, AuditCapabilityId capability, AuditResourceReference resource,
        AuditRisk risk, AuditDecision decision, AuditDecisionReason reason, AuditOrigin origin,
        WorkspaceId? workspace = null, TaskId? task = null, CorrelationId? correlation = null)
    {
        if (!Enum.IsDefined(eventType)) throw new ArgumentOutOfRangeException(nameof(eventType));
        if (!Enum.IsDefined(risk)) throw new ArgumentOutOfRangeException(nameof(risk));
        if (!Enum.IsDefined(decision)) throw new ArgumentOutOfRangeException(nameof(decision));
        if (!Enum.IsDefined(reason)) throw new ArgumentOutOfRangeException(nameof(reason));
        if (!Enum.IsDefined(origin)) throw new ArgumentOutOfRangeException(nameof(origin));
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

        EventType = eventType;
        OccurredAt = occurredAt.ToUniversalTime();
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
    }

    public AuditEventType EventType { get; }
    public DateTimeOffset OccurredAt { get; }
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
}

public sealed class AuditEventRecord(long sequence, Guid eventId, AuditEvent auditEvent, string integritySha256)
{
    public long Sequence { get; } = sequence > 0 ? sequence : throw new ArgumentOutOfRangeException(nameof(sequence));
    public Guid EventId { get; } = eventId != Guid.Empty ? eventId : throw new ArgumentException("An event identity is required.", nameof(eventId));
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
        if (eventType is { } type && !Enum.IsDefined(type)) throw new ArgumentOutOfRangeException(nameof(eventType));
        if (afterSequence < 0) throw new ArgumentOutOfRangeException(nameof(afterSequence));
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
    DateTimeOffset occurredAt, bool released, ActorChain actorChain, AuditSoftwareIdentity softwareIdentity,
    AuditOrigin origin)
{
    public long Sequence { get; } = sequence > 0 ? sequence : throw new ArgumentOutOfRangeException(nameof(sequence));
    public Guid HoldId { get; } = holdId != Guid.Empty ? holdId : throw new ArgumentException("A hold identity is required.", nameof(holdId));
    public AuditPartition Partition { get; } = partition;
    public AuditHoldReason Reason { get; } = Enum.IsDefined(reason) ? reason : throw new ArgumentOutOfRangeException(nameof(reason));
    public DateTimeOffset OccurredAt { get; } = occurredAt.ToUniversalTime();
    public bool Released { get; } = released;
    public ActorChain ActorChain { get; } = actorChain ?? throw new ArgumentNullException(nameof(actorChain));
    public AuditSoftwareIdentity SoftwareIdentity { get; } = softwareIdentity ?? throw new ArgumentNullException(nameof(softwareIdentity));
    public AuditOrigin Origin { get; } = Enum.IsDefined(origin) ? origin : throw new ArgumentOutOfRangeException(nameof(origin));
}

/// <summary>Append-only evidence for one maintenance-authorized, owner-partition retention purge.</summary>
public sealed class AuditPurgeReceipt(long sequence, AuditMaintenanceReceipt authority, AuditPartition partition,
    DateTimeOffset purgedAt, long eventCount, long firstEventSequence, long lastEventSequence, string eventsSha256)
{
    public long Sequence { get; } = sequence > 0 ? sequence : throw new ArgumentOutOfRangeException(nameof(sequence));
    public AuditMaintenanceReceipt Authority { get; } = authority ?? throw new ArgumentNullException(nameof(authority));
    public AuditPartition Partition { get; } = partition;
    public DateTimeOffset PurgedAt { get; } = purgedAt.ToUniversalTime();
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

        return value.ToLowerInvariant();
    }
}
