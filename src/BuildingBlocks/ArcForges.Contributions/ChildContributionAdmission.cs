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

/// <summary>The current owner-host boundary and grant decision reported for one exact child descriptor.</summary>
public enum ChildContributionAdmissionState
{
    Unavailable = 0,
    Admitted = 1,
    Expired = 2,
    Revoked = 3,
    GrantDenied = 4,
}

/// <summary>
/// Immutable owner-host snapshot binding its current child connection to one exact catalog descriptor.
/// Admitted means the owning host checked both the current child boundary and its grant decision for
/// this exact child and descriptor. This snapshot is not a grant or invocation authority.
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
/// Owner-composed lookup of the current child decision for one exact owner catalog descriptor.
/// Implementations must return Admitted only after the owning host has verified both the current
/// child boundary and the corresponding grant decision for that exact child and descriptor; otherwise
/// they report GrantDenied, Expired, Revoked, or Unavailable. The registry validates the returned
/// binding and records metadata, but never interprets, mints, transports, or grants invocation rights.
/// This local seam is not an extension host, process attestation, grant authority, or transport contract.
/// </summary>
public interface IChildContributionAdmissionPort
{
    ChildContributionAdmissionSnapshot? GetCurrentAdmission(AppIdentity owner, ContributionDefinition descriptor);
}
