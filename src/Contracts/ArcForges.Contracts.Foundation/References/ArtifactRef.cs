// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// A reference to a work product with independent value (architecture §7).
/// </summary>
/// <remarks>
/// <para>
/// An artifact, an attachment and a source resource are three different things. An artifact is something the
/// system produced that is worth keeping on its own; removing it from a conversation is not the same act as
/// deleting the source resource it points at, which needs the owner's own capability.
/// </para>
/// <para>
/// The artifact and the resource it wraps must have the same owner: an artifact cannot claim a resource that
/// belongs to another product. <see cref="Validate"/> enforces that.
/// </para>
/// <para>
/// Field order matches the frozen list in architecture §5.2:
/// <c>artifactId, ownerProduct, kind, displayName, resourceRef, mediaType, provenance, previewAvailability,
/// revision, createdAtUtc, updatedAtUtc</c>.
/// </para>
/// </remarks>
public sealed partial record ArtifactRef
{
    public required Guid ArtifactId { get; init; }

    /// <summary>The owning product. Must equal <c>ResourceRef.OwnerProduct</c>.</summary>
    public required ProductId OwnerProduct
    {
        get;
        init => field = value.CanOwnResources
            ? value
            : throw new ArgumentOutOfRangeException(
                nameof(OwnerProduct), value.ToString(), "Only arcchat, arcnotes, arcscope and arcslate own artifacts.");
    }

    /// <summary>A stable dotted identifier for the artifact's shape.</summary>
    public required string Kind
    {
        get;
        init => field = string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("An artifact kind is required.", nameof(Kind))
            : value;
    }

    /// <summary>A human-facing name. Display only.</summary>
    public required string DisplayName
    {
        get;
        init => field = string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("A display name is required.", nameof(DisplayName))
            : value;
    }

    /// <summary>The resource carrying the artifact's bytes.</summary>
    public required ResourceRef ResourceRef { get; init; }

    /// <summary>The IANA media type of the artifact.</summary>
    public required string MediaType
    {
        get;
        init => field = string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("A media type is required.", nameof(MediaType))
            : value;
    }

    /// <summary>Where the artifact came from. A closed union; see <see cref="ArtifactProvenance"/>.</summary>
    public required ArtifactProvenance Provenance { get; init; }

    /// <summary>How much preview may be requested. Preview bytes themselves are a deletable cache.</summary>
    public required PreviewAvailability PreviewAvailability { get; init; }

    /// <summary>The owner's version of this artifact. Distinct from the resource's revision.</summary>
    public required Revision Revision { get; init; }

    /// <summary>
    /// When the artifact was created, as an instant.
    /// </summary>
    /// <remarks>
    /// Wire time is always <see cref="DateTimeOffset"/> in UTC. Persist the instant and, where the original
    /// zone carries meaning, persist that separately; render with the user's locale but store invariant. The
    /// plan introduces no second time primitive for this.
    /// </remarks>
    public required DateTimeOffset CreatedAtUtc { get; init; }

    /// <summary>When the artifact last changed, as a UTC instant.</summary>
    public required DateTimeOffset UpdatedAtUtc { get; init; }

    /// <summary>
    /// Enforces the cross-property invariants: same owner as the wrapped resource, a valid resource, and a
    /// non-decreasing timeline.
    /// </summary>
    /// <exception cref="ArgumentException">An invariant is violated.</exception>
    public void Validate()
    {
        ResourceRef.Validate();

        if (OwnerProduct != ResourceRef.OwnerProduct)
        {
            throw new ArgumentException(
                $"Artifact owner '{OwnerProduct}' does not match resource owner '{ResourceRef.OwnerProduct}'.",
                nameof(OwnerProduct));
        }

        if (UpdatedAtUtc < CreatedAtUtc)
        {
            throw new ArgumentException("UpdatedAtUtc cannot precede CreatedAtUtc.", nameof(UpdatedAtUtc));
        }
    }
}
