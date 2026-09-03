// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using ArcForges.Contracts.LocalRpc.Scope;
using PolyType;
using StreamJsonRpc;

namespace ArcForges.Contracts.LocalRpc;

[JsonRpcContract]
[GenerateShape(IncludeMethods = MethodShapeFlags.PublicInstance)]
public partial interface IArcScopeRpcV1 : IDisposable
{
    Task<ArcResult<SearchResourcesResponse>> SearchResourcesAsync(
        SearchResourcesRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ListSessionsResponse>> ListSessionsAsync(
        ListSessionsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<QuerySignalRangeResponse>> QuerySignalRangeAsync(
        QuerySignalRangeRequest request, CancellationToken cancellationToken);

    Task<ArcResult<StartCaptureResponse>> StartCaptureAsync(
        StartCaptureRequest request, CancellationToken cancellationToken);

    Task<ArcResult<StopCaptureResponse>> StopCaptureAsync(
        StopCaptureRequest request, CancellationToken cancellationToken);

    Task<ArcResult<PauseCaptureResponse>> PauseCaptureAsync(
        PauseCaptureRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ResumeCaptureResponse>> ResumeCaptureAsync(
        ResumeCaptureRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetCaptureStatusResponse>> GetCaptureStatusAsync(
        GetCaptureStatusRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ListDecodersResponse>> ListDecodersAsync(
        ListDecodersRequest request, CancellationToken cancellationToken);

    Task<ArcResult<DecodeRangeResponse>> DecodeRangeAsync(
        DecodeRangeRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetDecoderErrorsResponse>> GetDecoderErrorsAsync(
        GetDecoderErrorsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ListPortsResponse>> ListPortsAsync(
        ListPortsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<TestConnectionResponse>> TestConnectionAsync(
        TestConnectionRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ConnectResponse>> ConnectAsync(
        ConnectRequest request, CancellationToken cancellationToken);

    Task<ArcResult<DisconnectResponse>> DisconnectAsync(
        DisconnectRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetConnectionsResponse>> GetConnectionsAsync(
        GetConnectionsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<PauseViewResponse>> PauseViewAsync(
        PauseViewRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ResumeViewResponse>> ResumeViewAsync(
        ResumeViewRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetLiveStateResponse>> GetLiveStateAsync(
        GetLiveStateRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ListFindingsResponse>> ListFindingsAsync(
        ListFindingsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<PreviewAnalysisResponse>> PreviewAnalysisAsync(
        PreviewAnalysisRequest request, CancellationToken cancellationToken);

    Task<ArcResult<RunAnalysisResponse>> RunAnalysisAsync(
        RunAnalysisRequest request, CancellationToken cancellationToken);

    Task<ArcResult<CreateAnnotationResponse>> CreateAnnotationAsync(
        CreateAnnotationRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GenerateReportResponse>> GenerateReportAsync(
        GenerateReportRequest request, CancellationToken cancellationToken);

    Task<ArcResult<StartExportResponse>> StartExportAsync(
        StartExportRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetExportStatusResponse>> GetExportStatusAsync(
        GetExportStatusRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetContextResponse>> GetContextAsync(
        GetContextRequest request, CancellationToken cancellationToken);
}
