// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Execution;
using ArcForges.Security;

namespace ArcForges.Security.Audit;

public enum AuditMaintenanceAction
{
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
/// This receipt is audit evidence, not a cryptographic signature or portable authorization token.
/// </summary>
public sealed class AuditMaintenanceReceipt
{
    internal AuditMaintenanceReceipt(Guid capabilityId, AuditMaintenanceAction action, Guid policyId,
        AuditPartition partition, DateTimeOffset issuedAt, DateTimeOffset expiresAt, Guid? holdId,
        ActorChain authorityActor, AuditSoftwareIdentity softwareIdentity)
    {
        if (capabilityId == Guid.Empty) throw new ArgumentException("A maintenance capability identity is required.", nameof(capabilityId));
        if (!Enum.IsDefined(action)) throw new ArgumentOutOfRangeException(nameof(action));
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

        var issued = issuedAt.ToUniversalTime();
        var expires = expiresAt.ToUniversalTime();
        if (expires <= issued || expires - issued > AuditMaintenanceAuthority.MaximumCapabilityLifetime)
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
        IssuedAt = issued;
        ExpiresAt = expires;
        HoldId = holdId;
        AuthorityActor = authorityActor;
        SoftwareIdentity = softwareIdentity;
    }

    public Guid CapabilityId { get; }
    public AuditMaintenanceAction Action { get; }
    public Guid PolicyId { get; }
    public AuditPartition Partition { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public Guid? HoldId { get; }
    public ActorChain AuthorityActor { get; }
    public AuditSoftwareIdentity SoftwareIdentity { get; }
}

/// <summary>
/// In-process authority object. Only this assembly can mint a capability; each instance has a private
/// reference identity, so a capability cannot be serialized, reconstructed, or replayed at another store.
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
        DateTimeOffset issuedAt, TimeSpan lifetime)
    {
        if (!Enum.IsDefined(action)) throw new ArgumentOutOfRangeException(nameof(action));
        EnsureOwner(partition);
        ArgumentNullException.ThrowIfNull(authorityActor);
        ArgumentNullException.ThrowIfNull(softwareIdentity);
        if (authorityActor.Owner.Realm != realm || authorityActor.Owner.Id != owner)
            throw new UnauthorizedAccessException("The maintenance actor belongs to another realm/account owner.");
        if (issuedAt.Offset != TimeSpan.Zero) throw new ArgumentException("Capability issue time must be UTC.", nameof(issuedAt));
        if (lifetime <= TimeSpan.Zero || lifetime > MaximumCapabilityLifetime)
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Maintenance capability lifetime must be positive and no longer than five minutes.");

        var id = Guid.NewGuid();
        var expiresAt = issuedAt.Add(lifetime);
        var receipt = new AuditMaintenanceReceipt(id, action, policyId, partition, issuedAt, expiresAt,
            holdId, authorityActor, softwareIdentity);
        return new AuditMaintenanceCapability(identity, receipt);
    }

    internal AuditMaintenanceReceipt Validate(AuditMaintenanceCapability capability,
        AuditMaintenanceAction expectedAction, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(capability);
        var receipt = capability.Receipt;
        if (!capability.IsIssuedBy(identity) || receipt.PolicyId != policyId
            || receipt.Partition.Realm != realm || receipt.Partition.Owner != owner
            || receipt.Action != expectedAction || now < receipt.IssuedAt || now >= receipt.ExpiresAt)
        {
            throw new UnauthorizedAccessException("The in-process maintenance capability is invalid, expired, or outside its exact policy/owner/action scope.");
        }

        return receipt;
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

    internal AuditMaintenanceCapability(object issuerIdentity, AuditMaintenanceReceipt receipt)
    {
        this.issuerIdentity = issuerIdentity ?? throw new ArgumentNullException(nameof(issuerIdentity));
        Receipt = receipt ?? throw new ArgumentNullException(nameof(receipt));
    }

    internal AuditMaintenanceReceipt Receipt { get; }
    internal bool IsIssuedBy(object authorityIdentity) => ReferenceEquals(issuerIdentity, authorityIdentity);
}
