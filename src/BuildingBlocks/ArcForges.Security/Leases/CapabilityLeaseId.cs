// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Security.Leases;

/// <summary>
/// The stable, non-empty, Guid-backed identity of one capability lease. Every lifecycle fact of a lease (issued, revoked, expired,
/// task-ended) carries this same value, and an audit intake maps <see cref="Value"/> directly, never a string, hash or truncation of it.
/// A lease identity is an address, not a credential: knowing it grants nothing, and every use is judged against the stored lease.
/// </summary>
public readonly record struct CapabilityLeaseId
{
    public CapabilityLeaseId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("A capability lease identity is required.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }

    /// <summary>True for an identity built through the constructor; false for <c>default</c>, which no operation accepts.</summary>
    public bool IsValid => Value != Guid.Empty;

    public static CapabilityLeaseId New() => new(Guid.NewGuid());
}
