// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;

namespace ArcForges.Contributions;

/// <summary>
/// A process-local child connection binding returned by the owner-composed admission port.
/// This is not an application InstanceIdentity, wire value, or attestation proof.
/// </summary>
public sealed record ChildConnectionIdentity
{
    public ChildConnectionIdentity(Guid value, ulong epoch)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("A child connection identity must be initialized.", nameof(value));
        }

        if (epoch == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(epoch), "A child connection epoch must be positive.");
        }

        Value = value;
        Epoch = epoch;
    }

    public Guid Value { get; }
    public ulong Epoch { get; }
}

/// <summary>The current local admission state reported by the owning host seam.</summary>
public enum ChildContributionAdmissionState
{
    Unavailable = 0,
    Admitted = 1,
    Expired = 2,
    Revoked = 3,
}

/// <summary>
/// Immutable owner-host snapshot binding its current child connection to one exact catalog descriptor.
/// It reports the host's prior admission decision; it does not mint, interpret, or transport authority.
/// </summary>
public sealed record ChildContributionAdmissionSnapshot
{
    public ChildContributionAdmissionSnapshot(
        AppIdentity ownerProduct,
        ChildConnectionIdentity? currentChild,
        ContributionDefinition descriptor,
        ChildContributionAdmissionState state,
        DateTimeOffset expiresAt)
    {
        OwnerProduct = ownerProduct ?? throw new ArgumentNullException(nameof(ownerProduct));
        ArgumentNullException.ThrowIfNull(descriptor);
        ContributionId = descriptor.Id;
        Kind = descriptor.Kind;
        ToolSchemaId = descriptor.ToolSchemaId;
        DescriptorFingerprint = descriptor.Fingerprint;
        CurrentChild = currentChild;
        State = state;
        ExpiresAt = expiresAt.ToUniversalTime();
    }

    public AppIdentity OwnerProduct { get; }
    public ChildConnectionIdentity? CurrentChild { get; }
    public string ContributionId { get; }
    public ContributionKind Kind { get; }
    public string? ToolSchemaId { get; }
    public string DescriptorFingerprint { get; }
    public ChildContributionAdmissionState State { get; }
    public DateTimeOffset ExpiresAt { get; }
}

/// <summary>
/// Owner-composed lookup of the current admitted child for one exact owner catalog descriptor.
/// Implementations report unavailable admission as null or an Unavailable snapshot. This local seam
/// is not an extension host, process attestation, grant authority, or transport contract.
/// </summary>
public interface IChildContributionAdmissionPort
{
    ChildContributionAdmissionSnapshot? GetCurrentAdmission(AppIdentity owner, ContributionDefinition descriptor);
}
