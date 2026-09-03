// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;

namespace ArcForges.Contracts.LocalRpc.Scope;

// --- Supporting DTOs & Enums ---

public sealed partial record UtcRangeDto
{
    public required DateTimeOffset StartUtc { get; init; }
    public required DateTimeOffset EndUtc { get; init; }
}

public sealed partial record ScopeResourceHitDto
{
    public required ResourceRef ResourceRef { get; init; }
    public Guid? ProjectId { get; init; }
    public required string Kind { get; init; }
    public required string Title { get; init; }
    public string? Subtitle { get; init; }
    public UtcRangeDto? TimeRange { get; init; }
    public required string MatchKind { get; init; }
    public required IReadOnlyList<TypedAnchorDto> Anchors { get; init; }
    public required string Score { get; init; }
}

public sealed partial record ScopeSessionSummaryDto
{
    public required Guid SessionId { get; init; }
    public Guid? ProjectId { get; init; }
    public required string Name { get; init; }
    public required string State { get; init; }
    public DateTimeOffset? StartedAtUtc { get; init; }
    public DateTimeOffset? EndedAtUtc { get; init; }
    public long SampleCount { get; init; }
    public long DurationNs { get; init; }
}

public sealed partial record SignalPointDto
{
    public required long TimestampNs { get; init; }
    public required double Value { get; init; }
}

public sealed partial record SignalGapDto
{
    public required long StartNs { get; init; }
    public required long EndNs { get; init; }
    public string? Reason { get; init; }
}

public sealed partial record SignalRangeDto
{
    public required ResourceRef SignalRef { get; init; }
    public required string Unit { get; init; }
    public required long TimeBaseNs { get; init; }
    public required IReadOnlyList<SignalPointDto> Points { get; init; }
    public required IReadOnlyList<SignalGapDto> Gaps { get; init; }
    public required long SourceRevision { get; init; }
}

public sealed partial record CaptureAcceptedDto
{
    public required ResourceRef CaptureRef { get; init; }
    public required ProductActivityRefDto Activity { get; init; }
}

public sealed partial record CaptureControlResultDto
{
    public required ResourceRef CaptureRef { get; init; }
    public required string State { get; init; }
    public string? Outcome { get; init; }
    public long? LastCommittedSequence { get; init; }
}

public sealed partial record CaptureStatusDto
{
    public required ResourceRef CaptureRef { get; init; }
    public required string State { get; init; }
    public string? Outcome { get; init; }
    public long SamplesWritten { get; init; }
    public long BytesWritten { get; init; }
    public int OverflowCount { get; init; }
    public int GapCount { get; init; }
    public int CurrentSegment { get; init; }
    public double DiskWriteBytesPerSecond { get; init; }
    public long? LastSampleTimeNs { get; init; }
    public string? DegradedReason { get; init; }
}

public sealed partial record DecoderDescriptorDto
{
    public required string DecoderId { get; init; }
    public required string Version { get; init; }
    public required string DisplayName { get; init; }
    public required IReadOnlyList<string> InputKinds { get; init; }
    public required IReadOnlyList<string> OutputChannelKinds { get; init; }
    public required string ConfigurationSchemaRef { get; init; }
    public required string LicenseId { get; init; }
}

public sealed partial record DecoderConfigurationDto
{
    public required string ParametersJson { get; init; }
}

public sealed partial record DecodedFrameDto
{
    public required long Sequence { get; init; }
    public required long TimestampNs { get; init; }
    public required string ChannelId { get; init; }
    public required string ValueJson { get; init; }
}

public sealed partial record DecoderErrorDto
{
    public required long Sequence { get; init; }
    public required long Offset { get; init; }
    public required string Code { get; init; }
    public required string MessageKey { get; init; }
    public IReadOnlyList<string>? Arguments { get; init; }
    public bool Recoverable { get; init; }
    public string? RawRange { get; init; }
}

public sealed partial record DecodedRangeDto
{
    public required IReadOnlyList<DecodedFrameDto> Frames { get; init; }
    public required IReadOnlyList<DecoderErrorDto> Errors { get; init; }
    public long? NextSequence { get; init; }
    public long DecoderRevision { get; init; }
}

public sealed partial record PortDescriptorDto
{
    public required string PortId { get; init; }
    public required string Transport { get; init; }
    public required string DisplayName { get; init; }
    public string? StableHardwareId { get; init; }
    public required string Availability { get; init; }
    public required IReadOnlyList<string> Capabilities { get; init; }
    public DateTimeOffset? LastSeenAtUtc { get; init; }
}

public sealed partial record ConnectionProfileDto
{
    public required string Transport { get; init; } // serial|tcp|udp|mqtt|bluetooth|file
    public string? SerialPort { get; init; }
    public int? BaudRate { get; init; }
    public string? TcpHost { get; init; }
    public int? TcpPort { get; init; }
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Wire contract specification pins string format.")]
    public string? MqttBrokerUri { get; init; }
    public string? MqttClientId { get; init; }
    public string? BluetoothDeviceId { get; init; }
    public string? FilePath { get; init; }
}

public sealed partial record BytePayloadDto
{
    public string? DataBase64 { get; init; }
    public int Length { get; init; }
}

public sealed partial record DiagnosticDto
{
    public required string Code { get; init; }
    public required string Message { get; init; }
    public required string Severity { get; init; }
}

public sealed partial record ConnectionTestResultDto
{
    public bool Reachable { get; init; }
    public double? LatencyMs { get; init; }
    public long BytesReceived { get; init; }
    public string? DetectedFormat { get; init; }
    public required IReadOnlyList<DiagnosticDto> Diagnostics { get; init; }
}

public sealed partial record ConnectionSnapshotDto
{
    public required Guid ConnectionId { get; init; }
    public required Guid SessionId { get; init; }
    public required Guid DataSourceId { get; init; }
    public required string Transport { get; init; }
    public required string State { get; init; }
    public int Attempt { get; init; }
    public required DateTimeOffset LastTransitionAtUtc { get; init; }
    public long BytesReceived { get; init; }
    public string? LastErrorCode { get; init; }
}

public sealed partial record LiveStateDto
{
    public required Guid SessionId { get; init; }
    public string? ViewId { get; init; }
    public required string ViewState { get; init; } // following|paused|catching_up
    public required string CaptureState { get; init; }
    public long LatestTimeNs { get; init; }
    public long DisplayedTimeNs { get; init; }
    public long BufferStartNs { get; init; }
    public long BufferEndNs { get; init; }
    public int DroppedDisplayFrames { get; init; }
    public int GapCount { get; init; }
}

public sealed partial record FindingDto
{
    public required ResourceRef FindingRef { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    public required string Severity { get; init; } // info|warning|error|critical
    public required string Status { get; init; } // open|acknowledged|resolved
    public required IReadOnlyList<TypedAnchorDto> Anchors { get; init; }
    public required ArtifactProvenance Provenance { get; init; }
    public required DateTimeOffset CreatedAtUtc { get; init; }
    public required DateTimeOffset UpdatedAtUtc { get; init; }
    public required long Revision { get; init; }
}

public sealed partial record SignalRangeSelectionDto
{
    public required IReadOnlyList<ResourceRef> SignalRefs { get; init; }
    public required long StartNs { get; init; }
    public required long EndNs { get; init; }
}

public sealed partial record AnalysisParameterSetDto
{
    public required string ParametersJson { get; init; }
}

public sealed partial record ResourceRevisionDto
{
    public required ResourceRef ResourceRef { get; init; }
    public required long Revision { get; init; }
}

public sealed partial record AnalysisPreviewDto
{
    public required Guid PreviewId { get; init; }
    public required DateTimeOffset ExpiresAtUtc { get; init; }
    public required IReadOnlyList<ResourceRevisionDto> InputRevisions { get; init; }
    public long EstimatedSamples { get; init; }
    public long EstimatedDurationMs { get; init; }
    public long EstimatedOutputBytes { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public required IReadOnlyList<ArtifactRef> ProposedArtifacts { get; init; }
}

public sealed partial record AnalysisAcceptedDto
{
    public required ProductActivityRefDto Activity { get; init; }
}

public sealed partial record AnnotationBodyDto
{
    public required string Text { get; init; }
    public required string Format { get; init; }
}

public sealed partial record AnnotationDto
{
    public required ResourceRef AnnotationRef { get; init; }
    public required ResourceRef TargetRef { get; init; }
    public required TypedAnchorDto Anchor { get; init; }
    public required AnnotationBodyDto Body { get; init; }
    public required DateTimeOffset CreatedAtUtc { get; init; }
    public required long Revision { get; init; }
}

public sealed partial record ReportAcceptedDto
{
    public required ProductActivityRefDto Activity { get; init; }
}

public sealed partial record ScopeExportAcceptedDto
{
    public required ProductActivityRefDto Activity { get; init; }
}

public sealed partial record ScopeContextSnapshotDto
{
    public ResourceRef? ProjectRef { get; init; }
    public ResourceRef? SessionRef { get; init; }
    public ResourceRef? CaptureRef { get; init; }
    public required IReadOnlyList<ResourceRef> SelectedSignalRefs { get; init; }
    public UtcRangeDto? VisibleRange { get; init; }
    public required IReadOnlyList<ResourceRef> FindingRefs { get; init; }
    public required IReadOnlyList<long> SourceRevisionVector { get; init; }
}

// --- 27 Request / Response Pairs ---

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
    public UtcRangeDto? TimeRange { get; init; }
    public bool IncludeOffline { get; init; }
}

public sealed partial record SearchResourcesResponse
{
    public required IReadOnlyList<ScopeResourceHitDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 2. ListSessions
public sealed partial record ListSessionsRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public Guid? ProjectId { get; init; }
    public string? State { get; init; }
}

public sealed partial record ListSessionsResponse
{
    public required IReadOnlyList<ScopeSessionSummaryDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 3. QuerySignalRange
public sealed partial record QuerySignalRangeRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef SignalRef { get; init; }
    public required long StartNs { get; init; }
    public required long EndNs { get; init; }
    public bool StartInclusive { get; init; } = true;
    public bool EndInclusive { get; init; }
    public int MaxPoints { get; init; } = 1000;
    public string Aggregation { get; init; } = "raw";
}

public sealed partial record QuerySignalRangeResponse
{
    public required SignalRangeDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 4. StartCapture
public sealed partial record StartCaptureRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SessionId { get; init; }
    public required IReadOnlyList<Guid> DataSourceIds { get; init; }
    public Guid? TriggerId { get; init; }
    public long PreTriggerNs { get; init; }
    public required string Retention { get; init; }
    public long? MaxDurationNs { get; init; }
    public long? MaxBytes { get; init; }
}

public sealed partial record StartCaptureResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public CaptureAcceptedDto? Value { get; init; }
}

// 5. StopCapture
public sealed partial record StopCaptureRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef CaptureRef { get; init; }
    public string Mode { get; init; } = "finalize";
}

public sealed partial record StopCaptureResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public CaptureControlResultDto? Value { get; init; }
}

// 6. PauseCapture
public sealed partial record PauseCaptureRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef CaptureRef { get; init; }
    public string Reason { get; init; } = "user_requested";
}

public sealed partial record PauseCaptureResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public CaptureControlResultDto? Value { get; init; }
}

// 7. ResumeCapture
public sealed partial record ResumeCaptureRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ResourceRef CaptureRef { get; init; }
}

public sealed partial record ResumeCaptureResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public CaptureControlResultDto? Value { get; init; }
}

// 8. GetCaptureStatus
public sealed partial record GetCaptureStatusRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef CaptureRef { get; init; }
}

public sealed partial record GetCaptureStatusResponse
{
    public required CaptureStatusDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 9. ListDecoders
public sealed partial record ListDecodersRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public string? Transport { get; init; }
    public string? InputFormat { get; init; }
}

public sealed partial record ListDecodersResponse
{
    public required IReadOnlyList<DecoderDescriptorDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 10. DecodeRange
public sealed partial record DecodeRangeRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef CaptureRef { get; init; }
    public required string DecoderId { get; init; }
    public required string DecoderVersion { get; init; }
    public required long StartSequence { get; init; }
    public required long EndSequence { get; init; }
    public required DecoderConfigurationDto Configuration { get; init; }
    public int MaxFrames { get; init; } = 1000;
}

public sealed partial record DecodeRangeResponse
{
    public required DecodedRangeDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 11. GetDecoderErrors
public sealed partial record GetDecoderErrorsRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public required ResourceRef CaptureRef { get; init; }
    public string? DecoderId { get; init; }
    public string? Severity { get; init; }
    public long? StartSequence { get; init; }
    public long? EndSequence { get; init; }
}

public sealed partial record GetDecoderErrorsResponse
{
    public required IReadOnlyList<DecoderErrorDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 12. ListPorts
public sealed partial record ListPortsRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public string? Transport { get; init; }
    public bool IncludeUnavailable { get; init; }
}

public sealed partial record ListPortsResponse
{
    public required IReadOnlyList<PortDescriptorDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 13. TestConnection
public sealed partial record TestConnectionRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required ConnectionProfileDto Profile { get; init; }
    public int TestDurationMs { get; init; } = 2000;
    public BytePayloadDto? SendProbe { get; init; }
}

public sealed partial record TestConnectionResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ConnectionTestResultDto? Value { get; init; }
}

// 14. Connect
public sealed partial record ConnectRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SessionId { get; init; }
    public required Guid DataSourceId { get; init; }
    public required ConnectionProfileDto Profile { get; init; }
    public bool Takeover { get; init; }
}

public sealed partial record ConnectResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ConnectionSnapshotDto? Value { get; init; }
}

// 15. Disconnect
public sealed partial record DisconnectRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid ConnectionId { get; init; }
    public string Mode { get; init; } = "graceful";
}

public sealed partial record DisconnectResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ConnectionSnapshotDto? Value { get; init; }
}

// 16. GetConnections
public sealed partial record GetConnectionsRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public Guid? SessionId { get; init; }
    public string? State { get; init; }
}

public sealed partial record GetConnectionsResponse
{
    public required IReadOnlyList<ConnectionSnapshotDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 17. PauseView
public sealed partial record PauseViewRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SessionId { get; init; }
    public required string ViewId { get; init; }
}

public sealed partial record PauseViewResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public LiveStateDto? Value { get; init; }
}

// 18. ResumeView
public sealed partial record ResumeViewRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid SessionId { get; init; }
    public required string ViewId { get; init; }
    public string CatchUp { get; init; } = "latest";
}

public sealed partial record ResumeViewResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public LiveStateDto? Value { get; init; }
}

// 19. GetLiveState
public sealed partial record GetLiveStateRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required Guid SessionId { get; init; }
    public string? ViewId { get; init; }
}

public sealed partial record GetLiveStateResponse
{
    public required LiveStateDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 20. ListFindings
public sealed partial record ListFindingsRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public string? Cursor { get; init; }
    public int Limit { get; init; } = 50;
    public required Guid ProjectId { get; init; }
    public ResourceRef? SourceResourceRef { get; init; }
    public string? Severity { get; init; }
    public string? Status { get; init; }
}

public sealed partial record ListFindingsResponse
{
    public required IReadOnlyList<FindingDto> Items { get; init; }
    public string? NextCursor { get; init; }
    public long SnapshotRevision { get; init; }
}

// 21. PreviewAnalysis
public sealed partial record PreviewAnalysisRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required string RecipeId { get; init; }
    public required long RecipeRevision { get; init; }
    public required IReadOnlyList<ResourceRef> InputRefs { get; init; }
    public SignalRangeSelectionDto? Range { get; init; }
    public required AnalysisParameterSetDto Parameters { get; init; }
}

public sealed partial record PreviewAnalysisResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public AnalysisPreviewDto? Value { get; init; }
}

// 22. RunAnalysis
public sealed partial record RunAnalysisRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid PreviewId { get; init; }
    public required IReadOnlyList<ResourceRevisionDto> AcceptedInputRevisions { get; init; }
}

public sealed partial record RunAnalysisResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public AnalysisAcceptedDto? Value { get; init; }
}

// 23. CreateAnnotation
public sealed partial record CreateAnnotationRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid ProjectId { get; init; }
    public required ResourceRef TargetRef { get; init; }
    public required TypedAnchorDto Anchor { get; init; }
    public required AnnotationBodyDto Body { get; init; }
    public string? Severity { get; init; }
}

public sealed partial record CreateAnnotationResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public AnnotationDto? Value { get; init; }
}

// 24. GenerateReport
public sealed partial record GenerateReportRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required Guid ProjectId { get; init; }
    public required IReadOnlyList<ResourceRef> SourceRefs { get; init; }
    public required string TemplateId { get; init; }
    public required long TemplateRevision { get; init; }
    public required IReadOnlyList<string> Sections { get; init; }
    public required string OutputFormat { get; init; } // pdf|html|csv
    public required string Title { get; init; }
}

public sealed partial record GenerateReportResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ReportAcceptedDto? Value { get; init; }
}

// 25. StartExport
public sealed partial record StartExportRequest
{
    public required CommandId CommandId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public ResourceRef? TargetResource { get; init; }
    public required long ExpectedRevision { get; init; }
    public required DateTimeOffset IssuedAtUtc { get; init; }
    public required DateTimeOffset DeadlineUtc { get; init; }
    public required Guid CorrelationId { get; init; }

    public required IReadOnlyList<ResourceRef> SourceRefs { get; init; }
    public required string Format { get; init; } // csv|jsonl|binary_capture|parquet
    public required LocalOutputTargetDto Target { get; init; }
    public SignalRangeSelectionDto? Range { get; init; }
    public string ExistingOutputPolicy { get; init; } = "replace";
}

public sealed partial record StartExportResponse
{
    public required Guid CommandId { get; init; }
    public required MutationStatus Status { get; init; }
    public long? NewRevision { get; init; }
    public ProductActivityRefDto? ProductActivity { get; init; }
    public required IReadOnlyList<ArtifactRef> ArtifactRefs { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public ScopeExportAcceptedDto? Value { get; init; }
}

// 26. GetExportStatus
public sealed partial record GetExportStatusRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required Guid ActivityId { get; init; }
}

public sealed partial record GetExportStatusResponse
{
    public required ProductActivitySnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}

// 27. GetContext
public sealed partial record GetContextRequest
{
    public required Guid RequestId { get; init; }
    public required ActorContextDto Actor { get; init; }
    public required IReadOnlyList<string> Include { get; init; }
    public int MaxRefs { get; init; } = 50;
}

public sealed partial record GetContextResponse
{
    public required ScopeContextSnapshotDto Value { get; init; }
    public long SnapshotRevision { get; init; }
}
