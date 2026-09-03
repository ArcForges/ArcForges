// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using ArcForges.Contracts.LocalRpc.Slate;
using PolyType;
using StreamJsonRpc;

namespace ArcForges.Contracts.LocalRpc;

[JsonRpcContract]
[GenerateShape(IncludeMethods = MethodShapeFlags.PublicInstance)]
public partial interface IArcSlateRpcV1 : IDisposable
{
    Task<ArcResult<SearchResourcesResponse>> SearchResourcesAsync(
        SearchResourcesRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetProjectSnapshotResponse>> GetProjectSnapshotAsync(
        GetProjectSnapshotRequest request, CancellationToken cancellationToken);

    Task<ArcResult<SaveProjectResponse>> SaveProjectAsync(
        SaveProjectRequest request, CancellationToken cancellationToken);

    Task<ArcResult<LoadProjectResponse>> LoadProjectAsync(
        LoadProjectRequest request, CancellationToken cancellationToken);

    Task<ArcResult<UndoResponse>> UndoAsync(
        UndoRequest request, CancellationToken cancellationToken);

    Task<ArcResult<RedoResponse>> RedoAsync(
        RedoRequest request, CancellationToken cancellationToken);

    Task<ArcResult<JumpToResponse>> JumpToAsync(
        JumpToRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ListRecoveriesResponse>> ListRecoveriesAsync(
        ListRecoveriesRequest request, CancellationToken cancellationToken);

    Task<ArcResult<OpenRecoveryResponse>> OpenRecoveryAsync(
        OpenRecoveryRequest request, CancellationToken cancellationToken);

    Task<ArcResult<CreateCheckpointResponse>> CreateCheckpointAsync(
        CreateCheckpointRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ImportMediaResponse>> ImportMediaAsync(
        ImportMediaRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetAssetResponse>> GetAssetAsync(
        GetAssetRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ListAssetsResponse>> ListAssetsAsync(
        ListAssetsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<RelinkAssetResponse>> RelinkAssetAsync(
        RelinkAssetRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetImportStatusResponse>> GetImportStatusAsync(
        GetImportStatusRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetSequenceResponse>> GetSequenceAsync(
        GetSequenceRequest request, CancellationToken cancellationToken);

    Task<ArcResult<InsertClipResponse>> InsertClipAsync(
        InsertClipRequest request, CancellationToken cancellationToken);

    Task<ArcResult<MoveClipResponse>> MoveClipAsync(
        MoveClipRequest request, CancellationToken cancellationToken);

    Task<ArcResult<TrimClipResponse>> TrimClipAsync(
        TrimClipRequest request, CancellationToken cancellationToken);

    Task<ArcResult<SplitClipResponse>> SplitClipAsync(
        SplitClipRequest request, CancellationToken cancellationToken);

    Task<ArcResult<DeleteClipResponse>> DeleteClipAsync(
        DeleteClipRequest request, CancellationToken cancellationToken);

    Task<ArcResult<RippleDeleteResponse>> RippleDeleteAsync(
        RippleDeleteRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ExtractResponse>> ExtractAsync(
        ExtractRequest request, CancellationToken cancellationToken);

    Task<ArcResult<RippleTrimResponse>> RippleTrimAsync(
        RippleTrimRequest request, CancellationToken cancellationToken);

    Task<ArcResult<RollResponse>> RollAsync(
        RollRequest request, CancellationToken cancellationToken);

    Task<ArcResult<SlipResponse>> SlipAsync(
        SlipRequest request, CancellationToken cancellationToken);

    Task<ArcResult<SlideResponse>> SlideAsync(
        SlideRequest request, CancellationToken cancellationToken);

    Task<ArcResult<LinkClipsResponse>> LinkClipsAsync(
        LinkClipsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<UnlinkClipsResponse>> UnlinkClipsAsync(
        UnlinkClipsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<AddMarkerResponse>> AddMarkerAsync(
        AddMarkerRequest request, CancellationToken cancellationToken);

    Task<ArcResult<MoveMarkerResponse>> MoveMarkerAsync(
        MoveMarkerRequest request, CancellationToken cancellationToken);

    Task<ArcResult<SetInOutResponse>> SetInOutAsync(
        SetInOutRequest request, CancellationToken cancellationToken);

    Task<ArcResult<PreviewEditResponse>> PreviewEditAsync(
        PreviewEditRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ApplyEditResponse>> ApplyEditAsync(
        ApplyEditRequest request, CancellationToken cancellationToken);

    Task<ArcResult<StartExportResponse>> StartExportAsync(
        StartExportRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetExportResponse>> GetExportAsync(
        GetExportRequest request, CancellationToken cancellationToken);

    Task<ArcResult<CancelExportResponse>> CancelExportAsync(
        CancelExportRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetArtifactResponse>> GetArtifactAsync(
        GetArtifactRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetContextResponse>> GetContextAsync(
        GetContextRequest request, CancellationToken cancellationToken);
}
