// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Execution;
using ArcForges.Security;

namespace ArcForges.Security.Audit;

public enum AuditMaintenanceAction
{
    None = 0,
    PurgeExpiredPartition = 1,
    ReleaseLegalHold = 2,
}

/// <summary>Finite retention declaration, bound immutably to an owner-scoped audit file.</summary>
public sealed class AuditRetentionPolicy
{
    public AuditRetentionPolicy(Guid policyId, int retentionDays)
    {
        if (policyId == Guid.Empty) throw new ArgumentException("A retention policy identity is required.", nameof(policyId));
        if (retentionDays is < 1 or > 36500) throw new ArgumentOutOfRangeException(nameof(retentionDays), "Retention must be finite and no longer than 100 years.");
        PolicyId = policyId;
        RetentionDays = retentionDays;
    }

    public Guid PolicyId { get; }
    public int RetentionDays { get; }
}

/// <summary>
/// Non-authorizing, immutable record of an in-process maintenance capability that was consumed.
/// Its wall-clock fields are audit evidence only; capability validity uses the in-process monotonic
/// timestamp. This receipt is not a cryptographic signature or portable authorization token.
/// </summary>
public sealed class AuditMaintenanceReceipt
{
    internal AuditMaintenanceReceipt(Guid capabilityId, AuditMaintenanceAction action, Guid policyId,
        AuditPartition partition, Instant issuedAt, Instant expiresAt, Guid? holdId,
        ActorChain authorityActor, AuditSoftwareIdentity softwareIdentity)
    {
        if (capabilityId == Guid.Empty) throw new ArgumentException("A maintenance capability identity is required.", nameof(capabilityId));
        if (!AuditEnumValidation.IsWireValue(action)) throw new ArgumentOutOfRangeException(nameof(action));
        if (policyId == Guid.Empty) throw new ArgumentException("A retention policy identity is required.", nameof(policyId));
        _ = new AuditPartition(partition.Realm, partition.Owner, partition.Year, partition.Month);
        ArgumentNullException.ThrowIfNull(authorityActor);
        ArgumentNullException.ThrowIfNull(softwareIdentity);
        if (action == AuditMaintenanceAction.ReleaseLegalHold)
        {
            if (holdId is null || holdId == Guid.Empty) throw new ArgumentException("A hold identity is required for release.", nameof(holdId));
        }
        else if (holdId is not null)
        {
            throw new ArgumentException("Only a hold release may name a hold identity.", nameof(holdId));
        }

        if (expiresAt <= issuedAt || ExceedsMaximumLifetime(issuedAt, expiresAt))
        {
            throw new ArgumentException("Maintenance capability lifetime is invalid.");
        }

        if (authorityActor.Actors.Count > 0 && !StringComparer.Ordinal.Equals(authorityActor.Actors[^1].SoftwareIdentity, softwareIdentity.Value))
        {
            throw new ArgumentException("Software identity must match the final delegated authority actor.", nameof(softwareIdentity));
        }

        CapabilityId = capabilityId;
        Action = action;
        PolicyId = policyId;
        Partition = partition;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        HoldId = holdId;
        AuthorityActor = authorityActor;
        SoftwareIdentity = softwareIdentity;
    }

    public Guid CapabilityId { get; }
    public AuditMaintenanceAction Action { get; }
    public Guid PolicyId { get; }
    public AuditPartition Partition { get; }
    public Instant IssuedAt { get; }
    public Instant ExpiresAt { get; }
    public Guid? HoldId { get; }
    public ActorChain AuthorityActor { get; }
    public AuditSoftwareIdentity SoftwareIdentity { get; }

    private static bool ExceedsMaximumLifetime(Instant issuedAt, Instant expiresAt)
    {
        var seconds = expiresAt.UnixSeconds - issuedAt.UnixSeconds;
        var nanoseconds = (long)expiresAt.Nanoseconds - issuedAt.Nanoseconds;
        if (nanoseconds < 0)
        {
            seconds--;
            nanoseconds += 1_000_000_000;
        }

        return seconds > (long)AuditMaintenanceAuthority.MaximumCapabilityLifetime.TotalSeconds
            || (seconds == (long)AuditMaintenanceAuthority.MaximumCapabilityLifetime.TotalSeconds && nanoseconds > 0);
    }
}

/// <summary>
/// In-process authority object. Only this assembly can mint a capability; each instance has a private
/// reference identity, so a capability cannot be serialized, reconstructed, or replayed at another store.
/// Expiry is enforced against the issuing clock's monotonic timestamp, never the wall-clock receipt fields.
/// </summary>
internal sealed class AuditMaintenanceAuthority
{
    internal static readonly TimeSpan MaximumCapabilityLifetime = TimeSpan.FromMinutes(5);

    private readonly object identity = new();
    private readonly Guid policyId;
    private readonly RealmId realm;
    private readonly UserId owner;

    internal AuditMaintenanceAuthority(AuditRetentionPolicy policy, RealmId realm, UserId owner)
    {
        ArgumentNullException.ThrowIfNull(policy);
        _ = realm.ToWire();
        _ = owner.ToWire();
        policyId = policy.PolicyId;
        this.realm = realm;
        this.owner = owner;
    }

    internal AuditMaintenanceCapability Mint(AuditMaintenanceAction action, AuditPartition partition,
        Guid? holdId, ActorChain authorityActor, AuditSoftwareIdentity softwareIdentity,
        Instant issuedAt, MonotonicTimestamp mintedAt, TimeSpan lifetime)
    {
        if (!AuditEnumValidation.IsWireValue(action)) throw new ArgumentOutOfRangeException(nameof(action));
        EnsureOwner(partition);
        ArgumentNullException.ThrowIfNull(authorityActor);
        ArgumentNullException.ThrowIfNull(softwareIdentity);
        if (authorityActor.Owner.Realm != realm || authorityActor.Owner.Id != owner)
            throw new UnauthorizedAccessException("The maintenance actor belongs to another realm/account owner.");
        if (lifetime <= TimeSpan.Zero || lifetime > MaximumCapabilityLifetime)
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Maintenance capability lifetime must be positive and no longer than five minutes.");

        var id = Guid.NewGuid();
        var expiresAt = Add(issuedAt, lifetime);
        var receipt = new AuditMaintenanceReceipt(id, action, policyId, partition, issuedAt, expiresAt,
            holdId, authorityActor, softwareIdentity);
        return new AuditMaintenanceCapability(identity, receipt, mintedAt, lifetime);
    }

    internal AuditMaintenanceReceipt Validate(AuditMaintenanceCapability capability,
        AuditMaintenanceAction expectedAction, IClock clock, MonotonicTimestamp now)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(clock);
        var receipt = capability.Receipt;
        if (!capability.IsIssuedBy(identity))
        {
            throw new UnauthorizedAccessException("The in-process maintenance capability was not issued by this store.");
        }

        var elapsed = clock.GetElapsedTime(capability.MintedAt, now);
        if (elapsed < TimeSpan.Zero || receipt.PolicyId != policyId
            || receipt.Partition.Realm != realm || receipt.Partition.Owner != owner
            || receipt.Action != expectedAction || elapsed >= capability.Lifetime)
        {
            throw new UnauthorizedAccessException("The in-process maintenance capability is invalid, expired, or outside its exact policy/owner/action scope.");
        }

        return receipt;
    }

    private static Instant Add(Instant value, TimeSpan duration)
    {
        var additionalNanoseconds = checked(duration.Ticks * 100L);
        var seconds = checked(value.UnixSeconds + additionalNanoseconds / 1_000_000_000L);
        var nanoseconds = checked((long)value.Nanoseconds + additionalNanoseconds % 1_000_000_000L);
        if (nanoseconds >= 1_000_000_000L)
        {
            seconds = checked(seconds + 1);
            nanoseconds -= 1_000_000_000L;
        }

        return new Instant(seconds, checked((uint)nanoseconds));
    }

    private void EnsureOwner(AuditPartition partition)
    {
        _ = new AuditPartition(partition.Realm, partition.Owner, partition.Year, partition.Month);
        if (partition.Realm != realm || partition.Owner != owner)
            throw new UnauthorizedAccessException("The maintenance capability belongs to another realm/account owner.");
    }
}

/// <summary>Unserializable bearer object minted only by this assembly's dedicated authority.</summary>
internal sealed class AuditMaintenanceCapability
{
    private readonly object issuerIdentity;

    internal AuditMaintenanceCapability(object issuerIdentity, AuditMaintenanceReceipt receipt,
        MonotonicTimestamp mintedAt, TimeSpan lifetime)
    {
        this.issuerIdentity = issuerIdentity ?? throw new ArgumentNullException(nameof(issuerIdentity));
        Receipt = receipt ?? throw new ArgumentNullException(nameof(receipt));
        MintedAt = mintedAt;
        Lifetime = lifetime;
    }

    internal AuditMaintenanceReceipt Receipt { get; }
    internal MonotonicTimestamp MintedAt { get; }
    internal TimeSpan Lifetime { get; }
    internal bool IsIssuedBy(object authorityIdentity) => ReferenceEquals(issuerIdentity, authorityIdentity);
}
