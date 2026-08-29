// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// A stable, versioned reference to a resource (architecture §5.2).
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="ResourceRef"/> locates and versions; it does not authorise. It is not a permission token and
/// carries no scope, grant or bearer capability, so holding one never implies the holder may read the bytes —
/// the owning product re-checks authorisation on every access (architecture §7.1).
/// </para>
/// <para>
/// It also carries no absolute path, no database file and no raw bytes. Large content is fetched from the
/// owner or object storage using this reference (architecture §5.2).
/// </para>
/// <para>
/// Field order matches the frozen list in architecture §5.2:
/// <c>resourceId, ownerProduct, kind, availability, revision, contentHash, sizeBytes, sensitivity,
/// displayName, contentType?, localLocator?, cloudObjectId?</c>.
/// </para>
/// </remarks>
public sealed partial record ResourceRef
{
    /// <summary>The resource identity, stable across availability changes.</summary>
    public required ResourceId ResourceId { get; init; }

    /// <summary>
    /// The owning product. Only the four desktop products can own a resource; Cloud, Web and the mobile head
    /// are not owners.
    /// </summary>
    public required ProductId OwnerProduct
    {
        get;
        init => field = value.CanOwnResources
            ? value
            : throw new ArgumentOutOfRangeException(
                nameof(OwnerProduct), value.ToString(), "Only arcchat, arcnotes, arcscope and arcslate own resources.");
    }

    /// <summary>A stable dotted identifier for the resource's shape.</summary>
    public required string Kind
    {
        get;
        init => field = string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("A resource kind is required.", nameof(Kind))
            : value;
    }

    /// <summary>Where the bytes are. Constrains which locator may be present; see <see cref="Validate"/>.</summary>
    public required ResourceAvailability Availability { get; init; }

    /// <summary>The owner's version of this resource.</summary>
    public required Revision Revision { get; init; }

    /// <summary>
    /// Lower-case hex SHA-256 of the content, always 64 characters.
    /// </summary>
    /// <remarks>
    /// There is no such thing as a published <see cref="ResourceRef"/> without a real hash. Content whose
    /// digest is not known yet is not described by this type at all — a placeholder or empty digest would let
    /// an unverifiable reference travel as a verified one.
    /// </remarks>
    public required string ContentHash
    {
        get;
        init => field = IsSha256Hex(value)
            ? value
            : throw new ArgumentException(
                "ContentHash must be a 64-character lower-case hex SHA-256 digest.", nameof(ContentHash));
    }

    /// <summary>Content length in bytes.</summary>
    public required long SizeBytes
    {
        get;
        init => field = value >= 0
            ? value
            : throw new ArgumentOutOfRangeException(nameof(SizeBytes), value, "SizeBytes cannot be negative.");
    }

    /// <summary>How sensitive the content is. An input to egress policy, not an authorisation result.</summary>
    public required ResourceSensitivity Sensitivity { get; init; }

    /// <summary>A human-facing name. Display only; never used to locate the resource.</summary>
    public required string DisplayName
    {
        get;
        init => field = string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("A display name is required.", nameof(DisplayName))
            : value;
    }

    /// <summary>The IANA media type, when known.</summary>
    public string? ContentType { get; init; }

    /// <summary>Where to fetch it locally. Opaque; see <see cref="LocalResourceLocator"/>.</summary>
    public LocalResourceLocator? LocalLocator { get; init; }

    /// <summary>The logical cloud object. Not a storage key and not a URL.</summary>
    public Guid? CloudObjectId { get; init; }

    /// <summary>
    /// Enforces the locator constraints that depend on <see cref="Availability"/>.
    /// </summary>
    /// <remarks>
    /// These are cross-property invariants, so they cannot be checked by an individual property initialiser.
    /// The rules are: a locally available resource has a local locator and no cloud object; a cloud resource
    /// has a cloud object and no local locator; a preparing resource has exactly one of them, because it is
    /// mid-transfer; an unavailable resource has neither.
    /// </remarks>
    /// <exception cref="ArgumentException">The locator combination contradicts the availability.</exception>
    public void Validate()
    {
        var hasLocal = LocalLocator is not null;
        var hasCloud = CloudObjectId is not null;

        switch (Availability)
        {
            case ResourceAvailability.LocalOnline or ResourceAvailability.LocalOffline when !hasLocal || hasCloud:
                throw new ArgumentException(
                    $"{Availability} requires a local locator and no cloud object.", nameof(Availability));

            case ResourceAvailability.Cloud when !hasCloud || hasLocal:
                throw new ArgumentException(
                    "Cloud availability requires a cloud object and no local locator.", nameof(Availability));

            case ResourceAvailability.Preparing when hasLocal == hasCloud:
                throw new ArgumentException(
                    "Preparing availability requires exactly one locator.", nameof(Availability));

            case ResourceAvailability.Unavailable when hasLocal || hasCloud:
                throw new ArgumentException(
                    "Unavailable availability permits no locator.", nameof(Availability));

            default:
                break;
        }
    }

    private static bool IsSha256Hex(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            var isLowerHex = character is >= '0' and <= '9' or >= 'a' and <= 'f';
            if (!isLowerHex)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The revision rendered for diagnostics. Not a wire format.</summary>
    public override string ToString() =>
        string.Create(CultureInfo.InvariantCulture, $"{Kind} {ResourceId} @{Revision}");
}
