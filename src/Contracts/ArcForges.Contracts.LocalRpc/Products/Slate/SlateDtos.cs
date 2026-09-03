// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;

namespace ArcForges.Contracts.LocalRpc.Slate;

// --- Supporting DTOs & Enums ---

public sealed partial record SlateResourceHitDto
{
    public required ResourceRef ResourceRef { get; init; }
    public required string Kind { get; init; }
    public required string Title { get; init; }
    public string? Subtitle { get; init; }
    public required string MatchKind { get; init; }
    public required IReadOnlyList<TypedAnchorDto> Anchors { get; init; }
    public required string Score { get; init; }
}

public sealed partial record ProjectSnapshotDto
{
    public required ResourceRef ProjectRef { get; init; }
    public required string Title { get; init; }
    public required long Revision { get; init; }
    public required Guid RootSequenceId { get; init; }
    public required IReadOnlyList<Guid> AssetIds { get; init; }
    public required IReadOnlyList<Guid> SequenceIds { get; init; }
}

public sealed partial record ProjectMutationResultDto
{
    public required ResourceRef ProjectRef { get; init; }
    public required long NewRevision { get; init; }
}

public sealed partial record RecoveryCandidateDto
{
    public required Guid RecoveryId { get; init; }
    public required Guid CheckpointId { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }
    public bool AutoSaved { get; init; }
    public required string ChangeSummary { get; init; }
}

public sealed partial record CheckpointCreatedDto
{
    public required Guid CheckpointId { get; init; }
    public required long Revision { get; init; }
    public required DateTimeOffset CreatedAtUtc { get; init; }
}

public sealed partial record MediaImportItemDto
{
    public required ResourceRef SourceRef { get; init; }
    public required string DisplayName { get; init; }
    public required string Kind { get; init; }
    public Guid? TargetBinId { get; init; }
}

public sealed partial record MediaImportAcceptedDto
{
    public required ProductActivityRefDto Activity { get; init; }
}

public sealed partial record MediaAssetSnapshotDto
{
    public required ResourceRef AssetRef { get; init; }
    public required string Name { get; init; }
    public RationalDto Duration { get; init; }
    public required string MediaType { get; init; }
    public int? Width { get; init; }
    public int? Height { get; init; }
    public RationalDto? FrameRate { get; init; }
    public int? SampleRate { get; init; }
    public int? Channels { get; init; }
}

public sealed partial record AssetRelinkResultDto
{
    public required ResourceRef AssetRef { get; init; }
    public bool Relinked { get; init; }
    public ResourceRef? NewMediaRef { get; init; }
}

public sealed partial record SequenceSnapshotDto
{
    public required Guid SequenceId { get; init; }
    public required string Name { get; init; }
    public RationalDto TimeBase { get; init; }
    public required IReadOnlyList<Guid> TrackIds { get; init; }
    public RationalDto Duration { get; init; }
}

public sealed partial record TimelineRangeDto
{
    public RationalDto InPoint { get; init; }
    public RationalDto OutPoint { get; init; }
}

public sealed partial record TimelineEditResultDto
{
    public required Guid SequenceId { get; init; }
    public required IReadOnlyList<Guid> ChangedClipIds { get; init; }
    public required long Revision { get; init; }
}

public sealed partial record ColorTokenDto
{
    public byte Red { get; init; }
    public byte Green { get; init; }
    public byte Blue { get; init; }
    public byte Alpha { get; init; } = 255;
}

public sealed partial record TimelineEditOperationDto
{
    public required string OperationType { get; init; }
    public Guid? ClipId { get; init; }
    public Guid? TrackId { get; init; }
    public RationalDto? TargetTime { get; init; }
    public RationalDto? Duration { get; init; }
}

public sealed partial record EditPreviewDto
{
    public required Guid SequenceId { get; init; }
    public required IReadOnlyList<TimelineEditOperationDto> ProposedOperations { get; init; }
    public IReadOnlyList<string>? Warnings { get; init; }
}

public sealed partial record SlateExportAcceptedDto
{
    public required ProductActivityRefDto Activity { get; init; }
}

public sealed partial record SlateExportSnapshotDto
{
    public required Guid ActivityId { get; init; }
    public required string State { get; init; }
    public double Progress { get; init; }
    public ResourceRef? OutputRef { get; init; }
    public DateTimeOffset? FinishedAtUtc { get; init; }
}

public sealed partial record ArtifactDto
{
    public required ArtifactRef ArtifactRef { get; init; }
    public required string Kind { get; init; }
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Wire contract specification pins string format.")]
    public string? DataUri { get; init; }
}

public sealed partial record SlateContextSnapshotDto
{
    public ResourceRef? ProjectRef { get; init; }
    public ResourceRef? ActiveSequenceRef { get; init; }
    public required IReadOnlyList<ResourceRef> SelectedClipRefs { get; init; }
    public RationalDto? PlayheadTime { get; init; }
    public RationalDto? InPoint { get; init; }
    public RationalDto? OutPoint { get; init; }
}

// --- 39 Request / Response Pairs ---

// 1. SearchResources
public sealed partial record SearchResourcesRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public required string Text { get; init; }
    public Guid? ProjectId { get; init; }
    public IReadOnlyList<string>? Kinds { get; init; }
}

public sealed partial record SearchResourcesResponse
{
    public required IReadOnlyList<SlateResourceHitDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 2. GetProjectSnapshot
public sealed partial record GetProjectSnapshotRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef ProjectRef { get; init; }
}

public sealed partial record GetProjectSnapshotResponse
{
    public required ProjectSnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 3. SaveProject
public sealed partial record SaveProjectRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef ProjectRef { get; init; }
}

public sealed partial record SaveProjectResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ProjectMutationResultDto? Value { get; init; }
}

// 4. LoadProject
public sealed partial record LoadProjectRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef ProjectRef { get; init; }
}

public sealed partial record LoadProjectResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ProjectSnapshotDto? Value { get; init; }
}

// 5. Undo
public sealed partial record UndoRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef ProjectRef { get; init; }
}

public sealed partial record UndoResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ProjectMutationResultDto? Value { get; init; }
}

// 6. Redo
public sealed partial record RedoRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef ProjectRef { get; init; }
}

public sealed partial record RedoResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ProjectMutationResultDto? Value { get; init; }
}

// 7. JumpTo
public sealed partial record JumpToRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef ProjectRef { get; init; }
    public required Guid SequenceId { get; init; }
    public RationalDto Time { get; init; }
}

public sealed partial record JumpToResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 8. ListRecoveries
public sealed partial record ListRecoveriesRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public required ResourceRef ProjectRef { get; init; }
}

public sealed partial record ListRecoveriesResponse
{
    public required IReadOnlyList<RecoveryCandidateDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 9. OpenRecovery
public sealed partial record OpenRecoveryRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid RecoveryId { get; init; }
}

public sealed partial record OpenRecoveryResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ProjectSnapshotDto? Value { get; init; }
}

// 10. CreateCheckpoint
public sealed partial record CreateCheckpointRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef ProjectRef { get; init; }
    public string? Label { get; init; }
}

public sealed partial record CreateCheckpointResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public CheckpointCreatedDto? Value { get; init; }
}

// 11. ImportMedia
public sealed partial record ImportMediaRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef ProjectRef { get; init; }
    public required IReadOnlyList<MediaImportItemDto> Items { get; init; }
    public Guid? TargetBinId { get; init; }
    public string DuplicatePolicy { get; init; } = "reuse";
    public string ProxyPolicy { get; init; } = "auto";
}

public sealed partial record ImportMediaResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public MediaImportAcceptedDto? Value { get; init; }
}

// 12. GetAsset
public sealed partial record GetAssetRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef AssetRef { get; init; }
}

public sealed partial record GetAssetResponse
{
    public required MediaAssetSnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 13. ListAssets
public sealed partial record ListAssetsRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public required ResourceRef ProjectRef { get; init; }
    public Guid? BinId { get; init; }
}

public sealed partial record ListAssetsResponse
{
    public required IReadOnlyList<MediaAssetSnapshotDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 14. RelinkAsset
public sealed partial record RelinkAssetRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef AssetRef { get; init; }
    public required ResourceRef NewMediaRef { get; init; }
}

public sealed partial record RelinkAssetResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public AssetRelinkResultDto? Value { get; init; }
}

// 15. GetImportStatus
public sealed partial record GetImportStatusRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required Guid ActivityId { get; init; }
}

public sealed partial record GetImportStatusResponse
{
    public required ProductActivitySnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 16. GetSequence
public sealed partial record GetSequenceRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required Guid SequenceId { get; init; }
}

public sealed partial record GetSequenceResponse
{
    public required SequenceSnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 17. InsertClip
public sealed partial record InsertClipRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid TrackId { get; init; }
    public required ResourceRef AssetRef { get; init; }
    public RationalDto TrackTime { get; init; }
    public RationalDto Duration { get; init; }
}

public sealed partial record InsertClipResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 18. MoveClip
public sealed partial record MoveClipRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid ClipId { get; init; }
    public Guid? TargetTrackId { get; init; }
    public RationalDto TargetTime { get; init; }
}

public sealed partial record MoveClipResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 19. TrimClip
public sealed partial record TrimClipRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid ClipId { get; init; }
    public RationalDto? NewInPoint { get; init; }
    public RationalDto? NewOutPoint { get; init; }
}

public sealed partial record TrimClipResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 20. SplitClip
public sealed partial record SplitClipRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid ClipId { get; init; }
    public RationalDto SplitTime { get; init; }
}

public sealed partial record SplitClipResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 21. DeleteClip
public sealed partial record DeleteClipRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid ClipId { get; init; }
}

public sealed partial record DeleteClipResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 22. RippleDelete
public sealed partial record RippleDeleteRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid ClipId { get; init; }
}

public sealed partial record RippleDeleteResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 23. Extract
public sealed partial record ExtractRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required TimelineRangeDto Range { get; init; }
}

public sealed partial record ExtractResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 24. RippleTrim
public sealed partial record RippleTrimRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid ClipId { get; init; }
    public RationalDto Delta { get; init; }
    public string Edge { get; init; } = "in"; // "in" or "out"
}

public sealed partial record RippleTrimResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 25. Roll
public sealed partial record RollRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid LeftClipId { get; init; }
    public required Guid RightClipId { get; init; }
    public RationalDto Delta { get; init; }
}

public sealed partial record RollResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 26. Slip
public sealed partial record SlipRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid ClipId { get; init; }
    public RationalDto Delta { get; init; }
}

public sealed partial record SlipResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 27. Slide
public sealed partial record SlideRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid ClipId { get; init; }
    public RationalDto Delta { get; init; }
}

public sealed partial record SlideResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 28. LinkClips
public sealed partial record LinkClipsRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required IReadOnlyList<Guid> ClipIds { get; init; }
}

public sealed partial record LinkClipsResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 29. UnlinkClips
public sealed partial record UnlinkClipsRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required IReadOnlyList<Guid> ClipIds { get; init; }
}

public sealed partial record UnlinkClipsResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 30. AddMarker
public sealed partial record AddMarkerRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public RationalDto Time { get; init; }
    public required string Name { get; init; }
    public ColorTokenDto? Color { get; init; }
}

public sealed partial record AddMarkerResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 31. MoveMarker
public sealed partial record MoveMarkerRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required Guid MarkerId { get; init; }
    public RationalDto NewTime { get; init; }
}

public sealed partial record MoveMarkerResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 32. SetInOut
public sealed partial record SetInOutRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public RationalDto? InPoint { get; init; }
    public RationalDto? OutPoint { get; init; }
}

public sealed partial record SetInOutResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 33. PreviewEdit
public sealed partial record PreviewEditRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required IReadOnlyList<TimelineEditOperationDto> Operations { get; init; }
}

public sealed partial record PreviewEditResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public EditPreviewDto? Value { get; init; }
}

// 34. ApplyEdit
public sealed partial record ApplyEditRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required IReadOnlyList<TimelineEditOperationDto> Operations { get; init; }
}

public sealed partial record ApplyEditResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public TimelineEditResultDto? Value { get; init; }
}

// 35. StartExport
public sealed partial record StartExportRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SequenceId { get; init; }
    public required string PresetId { get; init; }
    public required LocalOutputTargetDto Target { get; init; }
    public TimelineRangeDto? Range { get; init; }
}

public sealed partial record StartExportResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public SlateExportAcceptedDto? Value { get; init; }
}

// 36. GetExport
public sealed partial record GetExportRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required Guid ActivityId { get; init; }
}

public sealed partial record GetExportResponse
{
    public required SlateExportSnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 37. CancelExport
public sealed partial record CancelExportRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid ActivityId { get; init; }
}

public sealed partial record CancelExportResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public SlateExportSnapshotDto? Value { get; init; }
}

// 38. GetArtifact
public sealed partial record GetArtifactRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ArtifactRef ArtifactRef { get; init; }
}

public sealed partial record GetArtifactResponse
{
    public required ArtifactDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 39. GetContext
public sealed partial record GetContextRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required IReadOnlyList<string> Include { get; init; }
    public int MaxRefs { get; init; } = 50;
}

public sealed partial record GetContextResponse
{
    public required SlateContextSnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}
