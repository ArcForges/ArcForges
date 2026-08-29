// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Contracts.Foundation;

namespace ArcForges.Tests.ContractCompatibilityTests;

/// <summary>
/// Deterministic instances of every Foundation wire type.
/// </summary>
/// <remarks>
/// Every identity, timestamp and revision here is a literal. Nothing is generated, because a golden sample
/// is only a golden sample if regenerating it produces the same bytes — a <c>Guid.CreateVersion7()</c> or a
/// <c>DateTimeOffset.UtcNow</c> anywhere in this file would make the goldens unstable and the byte-equality
/// assertion meaningless.
/// </remarks>
internal static class FoundationFixtures
{
    internal const string ResourceGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e11";
    internal const string DeviceGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e12";
    internal const string ArtifactGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e13";
    internal const string TaskGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e14";
    internal const string RunGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e15";
    internal const string StepGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e16";
    internal const string ActivityGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e17";
    internal const string AutomationGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e18";
    internal const string AutomationRunGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e19";
    internal const string CloudObjectGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e1a";
    internal const string CorrelationGuid = "0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e1b";

    /// <summary>A 64-character lower-case hex SHA-256, the only digest shape a resource may carry.</summary>
    internal const string ContentHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    internal static readonly DateTimeOffset CreatedAt = new(2026, 8, 28, 9, 15, 0, TimeSpan.Zero);
    internal static readonly DateTimeOffset UpdatedAt = new(2026, 8, 28, 10, 45, 0, TimeSpan.Zero);

    internal static LocalResourceLocator Locator() => new()
    {
        DeviceId = new DeviceId(Guid.Parse(DeviceGuid)),
        LocatorId = "arcnotes/managed/0192f1f4",
    };

    /// <summary>A locally owned resource: local locator present, no cloud object.</summary>
    internal static ResourceRef LocalResource() => new()
    {
        ResourceId = new ResourceId(Guid.Parse(ResourceGuid)),
        OwnerProduct = ProductId.ArcNotes,
        Kind = "arcnotes.document",
        Availability = ResourceAvailability.LocalOnline,
        Revision = new Revision(7),
        ContentHash = ContentHash,
        SizeBytes = 4096,
        Sensitivity = ResourceSensitivity.Internal,
        DisplayName = "Design notes",
        ContentType = "application/vnd.arcforges.arcnotes-document+json",
        LocalLocator = Locator(),
    };

    /// <summary>A cloud-held resource: cloud object present, no local locator.</summary>
    internal static ResourceRef CloudResource() => new()
    {
        ResourceId = new ResourceId(Guid.Parse(ResourceGuid)),
        OwnerProduct = ProductId.ArcSlate,
        Kind = "arcslate.render-output",
        Availability = ResourceAvailability.Cloud,
        Revision = new Revision(2),
        ContentHash = ContentHash,
        SizeBytes = 1048576,
        Sensitivity = ResourceSensitivity.Confidential,
        DisplayName = "Cut 3 export",
        CloudObjectId = Guid.Parse(CloudObjectGuid),
    };

    internal static ArtifactRef Artifact() => new()
    {
        ArtifactId = Guid.Parse(ArtifactGuid),
        OwnerProduct = ProductId.ArcNotes,
        Kind = "arcnotes.summary",
        DisplayName = "Weekly summary",
        ResourceRef = LocalResource(),
        MediaType = "text/markdown",
        Provenance = CloudTask(),
        PreviewAvailability = PreviewAvailability.Thin,
        Revision = new Revision(3),
        CreatedAtUtc = CreatedAt,
        UpdatedAtUtc = UpdatedAt,
    };

    internal static ArtifactProvenance UserCreated() => new UserCreatedProvenance();

    internal static ArtifactProvenance ProductActivity() =>
        new ProductActivityProvenance { ActivityId = Guid.Parse(ActivityGuid) };

    internal static ArtifactProvenance CloudTask() => new CloudTaskProvenance
    {
        TaskId = new TaskId(Guid.Parse(TaskGuid)),
        RunId = new RunId(Guid.Parse(RunGuid)),
        StepId = new StepId(Guid.Parse(StepGuid)),
    };

    internal static ArtifactProvenance Automation() => new AutomationProvenance
    {
        AutomationId = Guid.Parse(AutomationGuid),
        AutomationRunId = Guid.Parse(AutomationRunGuid),
    };

    internal static ArcError Error() => new()
    {
        Code = "conflict.revision_mismatch",
        MessageKey = "error.conflict.revision",
        Detail = "The document changed since it was read.",
        CorrelationId = Guid.Parse(CorrelationGuid),
    };

    internal static ArcResult<ResourceRef> SuccessResult() =>
        ArcResult<ResourceRef>.Success(LocalResource(), new Revision(8));

    internal static ArcResult<ResourceRef> FailureResult() =>
        ArcResult<ResourceRef>.Failure(Error());

    internal static LocalPageQuery PageQuery() => new() { After = "cursor-1", Limit = 25 };

    internal static LocalPage<ResourceRef> LocalPage() => new()
    {
        Items = [LocalResource()],
        NextCursor = "cursor-2",
        HasMore = true,
    };

    internal static CursorPageDto<ResourceRef> CursorPage() => new()
    {
        Items = [CloudResource()],
        NextCursor = "cursor-2",
        ServerTimeUtc = UpdatedAt,
        ProjectionWatermark = new Sequence(42),
    };
}
