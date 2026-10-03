// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security.Approvals;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.Leases;

public enum LeaseState
{
    None = 0,

    /// <summary>The lease may be used until its expiry, its revocation or the end of its task, whichever comes first.</summary>
    Active = 1,

    /// <summary>The owner (or the owner's policy) ended it. Terminal.</summary>
    Revoked = 2,

    /// <summary>Its expiry passed. Terminal.</summary>
    Expired = 3,

    /// <summary>Its task ended, which ends the lease automatically (CL-02). Terminal.</summary>
    TaskEnded = 4,
}

public enum LeaseRevocationReason
{
    None = 0,
    OwnerRevoked = 1,
    PolicyDenied = 2,
    RiskRejected = 3,

    /// <summary>The delegator's own authority for the capability ended, so nothing derived from it may outlive it.</summary>
    AuthorityLost = 4,
}

/// <summary>Why the owner's side accepted the delegation. It is audit evidence only and never widens the lease.</summary>
public enum LeaseIssueBasis
{
    None = 0,
    PolicyAllowed = 1,
    UserApproved = 2,
    StepUpSatisfied = 3,
    RiskAccepted = 4,
}

/// <summary>What the lease says about one use. Anything but <see cref="Valid"/> refuses the use.</summary>
public enum LeaseUseVerdict
{
    Unknown = 0,
    Valid = 1,

    /// <summary>The lease's time is over, or its task ended, which ends it automatically.</summary>
    Expired = 2,

    Revoked = 3,

    /// <summary>No such lease, or the use is not what the lease covers (holder, owner, scope, capability or resource).</summary>
    OutOfScope = 4,
}

public enum LeaseEventKind
{
    None = 0,
    Issued = 1,
    Revoked = 2,
    Expired = 3,
    TaskEnded = 4,
}

/// <summary>Why an issue was refused. Each is a distinct, stable cause; none of them issues anything.</summary>
public enum LeaseIssueRefusal
{
    None = 0,

    /// <summary>The request is malformed or its expiry cannot be represented.</summary>
    InvalidRequest = 1,

    /// <summary>The issuing chain's last actor is an agent or extension: a holder of delegated authority cannot delegate it again.</summary>
    IssuerCannotDelegate = 2,

    /// <summary>The holder is not an agent or an extension.</summary>
    HolderCannotHoldLease = 3,

    ExceedsMaximumLifetime = 4,

    /// <summary>The delegator holds no permission for the capability in this scope (or the source does not name exactly it).</summary>
    CeilingMissing = 5,

    /// <summary>The delegator's permission is not granted, or is not in its lifetime now.</summary>
    CeilingNotGranted = 6,

    /// <summary>The lease would outlive the delegator's permission.</summary>
    ExceedsCeilingLifetime = 7,

    CeilingConstraintUnmet = 8,

    CeilingConstraintUnknown = 9,

    /// <summary>The permission source failed, so no ceiling is known.</summary>
    CeilingUnavailable = 10,

    /// <summary>The issued event could not be durably audited, so nothing was issued.</summary>
    AuditUnavailable = 11,

    /// <summary>The store failed, so nothing was issued.</summary>
    StoreUnavailable = 12,

    /// <summary>A lease with this identity already exists.</summary>
    Duplicate = 13,
}

/// <summary>The delegated actor a lease is bound to: its kind and its exact identity.</summary>
public sealed record LeaseHolder
{
    public LeaseHolder(ActorKind kind, Guid actorId)
    {
        if (!Enum.IsDefined(kind) || kind == ActorKind.None)
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        if (actorId == Guid.Empty)
        {
            throw new ArgumentException("An actor identity is required.", nameof(actorId));
        }

        Kind = kind;
        ActorId = actorId;
    }

    public ActorKind Kind { get; }

    public Guid ActorId { get; }

    /// <summary>Whether a lease can be issued to this kind of actor (CL-01: tool and extension invocations, not automation).</summary>
    public bool CanHoldLease => Kind is ActorKind.Agent or ActorKind.Extension;

    internal static LeaseHolder From(DelegatedActor actor) => new(actor.Kind, actor.ActorId);
}

/// <summary>One use of a lease, compared with what the lease covers. Every field is evidence; none of them grants anything.</summary>
public sealed record LeaseUse
{
    public LeaseUse(
        CapabilityLeaseId lease,
        HumanPrincipal owner,
        DecisionScope scope,
        LeaseHolder holder,
        string capabilityKey,
        string resourceId)
    {
        if (!lease.IsValid)
        {
            throw new ArgumentException("A capability lease identity is required.", nameof(lease));
        }

        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(holder);
        SecurityText.Validate(capabilityKey, 256, nameof(capabilityKey));
        SecurityText.Validate(resourceId, 512, nameof(resourceId));
        Lease = lease;
        Owner = owner;
        Scope = scope;
        Holder = holder;
        CapabilityKey = capabilityKey;
        ResourceId = resourceId;
    }

    public CapabilityLeaseId Lease { get; }

    public HumanPrincipal Owner { get; }

    public DecisionScope Scope { get; }

    public LeaseHolder Holder { get; }

    public string CapabilityKey { get; }

    public string ResourceId { get; }
}

/// <summary>
/// A delegation to issue a lease for: who delegates (the issuing chain's owner), to whom, for which task, for exactly one capability
/// over an exact set of resources, for how long. The request is a proposal; the manager checks it against the delegator's own authority.
/// </summary>
public sealed class LeaseRequest
{
    public LeaseRequest(
        ActorChain issuedBy,
        DecisionScope scope,
        TaskId task,
        LeaseHolder holder,
        string capabilityKey,
        IEnumerable<string> resourceIds,
        RiskLevel effectiveRisk,
        DecisionOrigin origin,
        LeaseIssueBasis basis,
        TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(issuedBy);
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(holder);
        SecurityText.Validate(capabilityKey, 256, nameof(capabilityKey));
        ArgumentNullException.ThrowIfNull(resourceIds);
        if (task.Value == Guid.Empty)
        {
            throw new ArgumentException("A task identity is required.", nameof(task));
        }

        if (!Enum.IsDefined(effectiveRisk) || !Enum.IsDefined(origin) || origin == DecisionOrigin.None
            || !Enum.IsDefined(basis) || basis == LeaseIssueBasis.None)
        {
            throw new ArgumentOutOfRangeException(nameof(effectiveRisk));
        }

        IssuedBy = issuedBy;
        Scope = scope;
        Task = task;
        Holder = holder;
        CapabilityKey = capabilityKey;
        ResourceIds = CapabilityLease.NormalizeResources(resourceIds, nameof(resourceIds));
        EffectiveRisk = effectiveRisk;
        Origin = origin;
        Basis = basis;
        Lifetime = lifetime;
        Id = CapabilityLeaseId.New();
    }

    /// <summary>The identity the lease will have. A request object issues at most one lease: a replay is a duplicate.</summary>
    public CapabilityLeaseId Id { get; }

    public ActorChain IssuedBy { get; }

    public DecisionScope Scope { get; }

    public TaskId Task { get; }

    public LeaseHolder Holder { get; }

    public string CapabilityKey { get; }

    public ReadOnlyCollection<string> ResourceIds { get; }

    public RiskLevel EffectiveRisk { get; }

    public DecisionOrigin Origin { get; }

    public LeaseIssueBasis Basis { get; }

    public TimeSpan Lifetime { get; }
}

/// <summary>
/// The durable aggregate of one lease: what it covers and its lifecycle. The coverage fields are immutable for the life of the lease,
/// so a stored lease can only ever end, never be widened or extended. Every transition increments the version by exactly one.
/// </summary>
public sealed class CapabilityLease
{
    /// <summary>The most resources one lease may name.</summary>
    public const int MaximumResources = 64;

    public CapabilityLease(
        CapabilityLeaseId id,
        HumanPrincipal owner,
        DecisionScope scope,
        TaskId task,
        LeaseHolder holder,
        string capabilityKey,
        IEnumerable<string> resourceIds,
        RiskLevel effectiveRisk,
        DecisionOrigin origin,
        LeaseIssueBasis basis,
        ActorChain issuedBy,
        Instant issuedAt,
        Instant expiresAt,
        LeaseState state,
        long version,
        Instant? endedAt = null,
        LeaseRevocationReason revocationReason = LeaseRevocationReason.None,
        bool endEventRecorded = false)
    {
        if (!id.IsValid)
        {
            throw new ArgumentException("A capability lease identity is required.", nameof(id));
        }

        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(holder);
        ArgumentNullException.ThrowIfNull(issuedBy);
        SecurityText.Validate(capabilityKey, 256, nameof(capabilityKey));
        if (task.Value == Guid.Empty)
        {
            throw new ArgumentException("A task identity is required.", nameof(task));
        }

        if (!holder.CanHoldLease)
        {
            throw new ArgumentException("Only an agent or an extension holds a lease.", nameof(holder));
        }

        if (owner != issuedBy.Owner || scope.Realm != owner.Realm)
        {
            throw new ArgumentException("A lease is bound to the delegator's own realm.", nameof(owner));
        }

        if (!Enum.IsDefined(effectiveRisk) || !Enum.IsDefined(origin) || origin == DecisionOrigin.None
            || !Enum.IsDefined(basis) || basis == LeaseIssueBasis.None || !Enum.IsDefined(state) || state == LeaseState.None
            || !Enum.IsDefined(revocationReason) || version <= 0)
        {
            throw new ArgumentException("The lease has an invalid risk, origin, basis, state, reason or version.");
        }

        if (expiresAt <= issuedAt || LeaseTime.NanosecondsBetween(issuedAt, expiresAt) > LeaseTime.MaximumLifetimeNanoseconds)
        {
            throw new ArgumentException("A lease lives for a positive time of at most twenty-four hours.", nameof(expiresAt));
        }

        var terminal = state != LeaseState.Active;
        if (terminal != endedAt.HasValue
            || (endedAt is { } ended && ended < issuedAt)
            || (state == LeaseState.Revoked) != (revocationReason != LeaseRevocationReason.None)
            || (endEventRecorded && !terminal))
        {
            throw new ArgumentException("The lease's end does not match its state.");
        }

        Id = id;
        Owner = owner;
        Scope = scope;
        Task = task;
        Holder = holder;
        CapabilityKey = capabilityKey;
        ResourceIds = NormalizeResources(resourceIds, nameof(resourceIds));
        EffectiveRisk = effectiveRisk;
        Origin = origin;
        Basis = basis;
        IssuedBy = issuedBy;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        State = state;
        Version = version;
        EndedAt = endedAt;
        RevocationReason = revocationReason;
        EndEventRecorded = endEventRecorded;
    }

    /// <summary>No lease outlives this, whatever the issuing policy says.</summary>
    public static TimeSpan AbsoluteMaximumLifetime { get; } = TimeSpan.FromHours(24);

    public CapabilityLeaseId Id { get; }

    /// <summary>The delegator: the human whose authority the lease narrows.</summary>
    public HumanPrincipal Owner { get; }

    public DecisionScope Scope { get; }

    /// <summary>The task whose end ends the lease.</summary>
    public TaskId Task { get; }

    public LeaseHolder Holder { get; }

    /// <summary>The one capability the lease covers.</summary>
    public string CapabilityKey { get; }

    /// <summary>The exact resources the lease covers, sorted and unique. A lease narrows authority; resource authorization still applies.</summary>
    public ReadOnlyCollection<string> ResourceIds { get; }

    public RiskLevel EffectiveRisk { get; }

    public DecisionOrigin Origin { get; }

    public LeaseIssueBasis Basis { get; }

    /// <summary>The chain that issued it, kept so the lifecycle facts can name who delegated.</summary>
    public ActorChain IssuedBy { get; }

    public Instant IssuedAt { get; }

    /// <summary>Exclusive: at this exact instant the lease is already over.</summary>
    public Instant ExpiresAt { get; }

    public LeaseState State { get; }

    public long Version { get; }

    public Instant? EndedAt { get; }

    public LeaseRevocationReason RevocationReason { get; }

    /// <summary>True once the end's lifecycle fact reached the sink. A terminal lease with false is still owed that fact.</summary>
    public bool EndEventRecorded { get; }

    internal bool IsTerminal => State != LeaseState.Active;

    internal static ReadOnlyCollection<string> NormalizeResources(IEnumerable<string> resourceIds, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(resourceIds);
        var sorted = new SortedSet<string>(StringComparer.Ordinal);
        var count = 0;
        foreach (var resource in resourceIds)
        {
            SecurityText.Validate(resource, 512, parameterName);
            count++;
            if (count > MaximumResources)
            {
                throw new ArgumentException("A lease names a bounded set of resources.", parameterName);
            }

            if (!sorted.Add(resource))
            {
                throw new ArgumentException("A lease names each resource once.", parameterName);
            }
        }

        return count == 0
            ? throw new ArgumentException("A lease names at least one resource.", parameterName)
            : Array.AsReadOnly([.. sorted]);
    }

    internal CapabilityLease End(LeaseState state, Instant endedAt, LeaseRevocationReason reason = LeaseRevocationReason.None) => new(
        Id, Owner, Scope, Task, Holder, CapabilityKey, ResourceIds, EffectiveRisk, Origin, Basis, IssuedBy, IssuedAt, ExpiresAt,
        state, checked(Version + 1), endedAt, reason, endEventRecorded: false);

    internal CapabilityLease WithEndEventRecorded() => new(
        Id, Owner, Scope, Task, Holder, CapabilityKey, ResourceIds, EffectiveRisk, Origin, Basis, IssuedBy, IssuedAt, ExpiresAt,
        State, checked(Version + 1), EndedAt, RevocationReason, endEventRecorded: true);

    internal bool Covers(LeaseUse use) =>
        use.Lease == Id && use.Owner == Owner && use.Scope == Scope && use.Holder == Holder
        && string.Equals(use.CapabilityKey, CapabilityKey, StringComparison.Ordinal)
        && ResourceIds.Contains(use.ResourceId, StringComparer.Ordinal);
}

internal static class LeaseTime
{
    internal static Int128 MaximumLifetimeNanoseconds { get; } = (Int128)CapabilityLease.AbsoluteMaximumLifetime.Ticks * 100;

    internal static Instant Add(Instant instant, TimeSpan duration)
    {
        var wholeSeconds = duration.Ticks / TimeSpan.TicksPerSecond;
        var remainingTicks = duration.Ticks % TimeSpan.TicksPerSecond;
        var seconds = checked(instant.UnixSeconds + wholeSeconds);
        var nanoseconds = instant.Nanoseconds + (remainingTicks * 100);
        if (nanoseconds >= 1_000_000_000L)
        {
            seconds = checked(seconds + 1);
            nanoseconds -= 1_000_000_000L;
        }

        return new Instant(seconds, checked((uint)nanoseconds));
    }

    internal static Int128 NanosecondsBetween(Instant from, Instant to) =>
        (((Int128)to.UnixSeconds - from.UnixSeconds) * 1_000_000_000) + ((long)to.Nanoseconds - from.Nanoseconds);

    internal static Instant Max(Instant left, Instant right) => left >= right ? left : right;
}
