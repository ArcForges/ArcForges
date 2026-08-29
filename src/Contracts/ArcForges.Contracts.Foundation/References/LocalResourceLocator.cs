// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// Where a locally owned resource can be fetched from, expressed opaquely.
/// </summary>
/// <remarks>
/// <see cref="LocatorId"/> is an identifier the owning product generates and only the owning product can
/// resolve. It is deliberately not a path: an absolute or relative filesystem path crossing a contract
/// boundary would leak the user's directory layout and would let a caller reach content without going
/// through the owner's authorisation (architecture §5.2).
/// </remarks>
public sealed partial record LocalResourceLocator
{
    /// <summary>The device holding the resource.</summary>
    public required DeviceId DeviceId { get; init; }

    /// <summary>An opaque owner-generated handle. Never a path.</summary>
    public required string LocatorId
    {
        get;
        init => field = string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("A locator id is required.", nameof(LocatorId))
            : value;
    }
}
