// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// Where an artifact came from, as a closed union.
/// </summary>
/// <remarks>
/// <para>
/// Four branches, each carrying only its own fields. The union is closed: an unknown discriminator is a
/// contract mismatch and fails the read rather than degrading to a default branch, so an artifact whose
/// origin this build cannot understand is never presented as user-created.
/// </para>
/// <para>
/// The discriminator property is <c>kind</c>, matching the <c>provenance.kind</c> projection the data
/// catalog stores alongside the canonical JSON. Wire values follow the plan's lower-case snake_case
/// convention for closed enums.
/// </para>
/// </remarks>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(UserCreatedProvenance), "user_created")]
[JsonDerivedType(typeof(ProductActivityProvenance), "product_activity")]
[JsonDerivedType(typeof(CloudTaskProvenance), "cloud_task")]
[JsonDerivedType(typeof(AutomationProvenance), "automation")]
public abstract partial record ArtifactProvenance
{
    /// <summary>Only the four declared branches exist.</summary>
    private protected ArtifactProvenance()
    {
    }
}

/// <summary>The user made it directly.</summary>
public sealed partial record UserCreatedProvenance : ArtifactProvenance;

/// <summary>A local product activity produced it — an import, export, index, capture or render.</summary>
/// <remarks>
/// A product activity is not a Cloud Agent task and never allocates a <see cref="TaskId"/> (README §2.2).
/// </remarks>
public sealed partial record ProductActivityProvenance : ArtifactProvenance
{
    /// <summary>The owning product's activity.</summary>
    public required Guid ActivityId { get; init; }
}

/// <summary>A Cloud Agent task produced it.</summary>
public sealed partial record CloudTaskProvenance : ArtifactProvenance
{
    public required TaskId TaskId { get; init; }

    public required RunId RunId { get; init; }

    /// <summary>The step, when the artifact is attributable to one.</summary>
    public StepId? StepId { get; init; }
}

/// <summary>A scheduled automation run produced it.</summary>
public sealed partial record AutomationProvenance : ArtifactProvenance
{
    public required Guid AutomationId { get; init; }

    public required Guid AutomationRunId { get; init; }
}
