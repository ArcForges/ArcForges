// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using ArcForges.Contracts.LocalRpc.Notes;
using PolyType;
using StreamJsonRpc;

namespace ArcForges.Contracts.LocalRpc;

[JsonRpcContract]
[GenerateShape(IncludeMethods = MethodShapeFlags.PublicInstance)]
public partial interface IArcNotesRpcV1 : IDisposable
{
    Task<ArcResult<SearchDocumentsResponse>> SearchDocumentsAsync(
        SearchDocumentsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<FindByTagResponse>> FindByTagAsync(
        FindByTagRequest request, CancellationToken cancellationToken);

    Task<ArcResult<FindByPropertyResponse>> FindByPropertyAsync(
        FindByPropertyRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetDocumentSummaryResponse>> GetDocumentSummaryAsync(
        GetDocumentSummaryRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetDocumentMetadataResponse>> GetDocumentMetadataAsync(
        GetDocumentMetadataRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ReadDocumentResponse>> ReadDocumentAsync(
        ReadDocumentRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ReadBlocksResponse>> ReadBlocksAsync(
        ReadBlocksRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ReadSelectionResponse>> ReadSelectionAsync(
        ReadSelectionRequest request, CancellationToken cancellationToken);

    Task<ArcResult<CreateDocumentResponse>> CreateDocumentAsync(
        CreateDocumentRequest request, CancellationToken cancellationToken);

    Task<ArcResult<CreateFromArtifactResponse>> CreateFromArtifactAsync(
        CreateFromArtifactRequest request, CancellationToken cancellationToken);

    Task<ArcResult<InsertBlocksResponse>> InsertBlocksAsync(
        InsertBlocksRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ReplaceBlocksResponse>> ReplaceBlocksAsync(
        ReplaceBlocksRequest request, CancellationToken cancellationToken);

    Task<ArcResult<AppendBlocksResponse>> AppendBlocksAsync(
        AppendBlocksRequest request, CancellationToken cancellationToken);

    Task<ArcResult<UpdatePropertiesResponse>> UpdatePropertiesAsync(
        UpdatePropertiesRequest request, CancellationToken cancellationToken);

    Task<ArcResult<AddTagsResponse>> AddTagsAsync(
        AddTagsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<MoveDocumentResponse>> MoveDocumentAsync(
        MoveDocumentRequest request, CancellationToken cancellationToken);

    Task<ArcResult<LinkDocumentsResponse>> LinkDocumentsAsync(
        LinkDocumentsRequest request, CancellationToken cancellationToken);

    Task<ArcResult<OpenArtifactResponse>> OpenArtifactAsync(
        OpenArtifactRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ImportResponse>> ImportAsync(
        ImportRequest request, CancellationToken cancellationToken);

    Task<ArcResult<ExportResponse>> ExportAsync(
        ExportRequest request, CancellationToken cancellationToken);

    Task<ArcResult<TrashDocumentResponse>> TrashDocumentAsync(
        TrashDocumentRequest request, CancellationToken cancellationToken);

    Task<ArcResult<DeleteDocumentPermanentResponse>> DeleteDocumentPermanentAsync(
        DeleteDocumentPermanentRequest request, CancellationToken cancellationToken);

    Task<ArcResult<GetContextResponse>> GetContextAsync(
        GetContextRequest request, CancellationToken cancellationToken);
}
