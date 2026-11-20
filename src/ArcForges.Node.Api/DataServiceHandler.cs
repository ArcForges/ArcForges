// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Sandboxes;
using Google.Protobuf;
using Grpc.Core;
using V2 = ArcForges.Contracts.Sandbox.V2;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

/// <summary>Private Sandbox data operations for the authenticated local owner.</summary>
internal sealed class DataServiceHandler(NodeRuntime node) : V2.DataService.DataServiceBase
{
    private const int MaximumWireBytes = 2 * 1024 * 1024;

    public override Task<V2.DataServiceGetUsageResponse> GetUsage(
        V2.DataServiceGetUsageRequest request, ServerCallContext context) =>
        Call(request, request.Meta, context, V2.DataServiceGetUsageRequest.Parser, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.GetDataUsage(value, cancellation),
            static (meta, error) => new V2.DataServiceGetUsageResponse { Meta = meta, Error = error });

    public override Task<V2.DataServiceListEntriesResponse> ListEntries(
        V2.DataServiceListEntriesRequest request, ServerCallContext context) =>
        Call(request, request.Meta, context, V2.DataServiceListEntriesRequest.Parser, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.ListDataEntries(value, cancellation),
            static (meta, error) => new V2.DataServiceListEntriesResponse { Meta = meta, Error = error });

    public override Task<V2.DataServiceBeginImportResponse> BeginImport(
        V2.DataServiceBeginImportRequest request, ServerCallContext context) =>
        Call(request, request.Meta, context, V2.DataServiceBeginImportRequest.Parser, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.BeginDataImport(value, cancellation),
            static (meta, error) => new V2.DataServiceBeginImportResponse { Meta = meta, Error = error }, mutation: true);

    public override Task<V2.DataServiceWriteImportResponse> WriteImport(
        V2.DataServiceWriteImportRequest request, ServerCallContext context) =>
        Call(request, request.Meta, context, V2.DataServiceWriteImportRequest.Parser, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.WriteDataImport(value, cancellation),
            static (meta, error) => new V2.DataServiceWriteImportResponse { Meta = meta, Error = error }, mutation: true);

    public override Task<V2.DataServiceCommitImportResponse> CommitImport(
        V2.DataServiceCommitImportRequest request, ServerCallContext context) =>
        Call(request, request.Meta, context, V2.DataServiceCommitImportRequest.Parser, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.CommitDataImport(value, cancellation),
            static (meta, error) => new V2.DataServiceCommitImportResponse { Meta = meta, Error = error }, mutation: true);

    public override Task<V2.DataServiceBeginExportResponse> BeginExport(
        V2.DataServiceBeginExportRequest request, ServerCallContext context) =>
        Call(request, request.Meta, context, V2.DataServiceBeginExportRequest.Parser, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.BeginDataExport(value, cancellation),
            static (meta, error) => new V2.DataServiceBeginExportResponse { Meta = meta, Error = error }, mutation: true);

    public override Task<V2.DataServiceReadExportResponse> ReadExport(
        V2.DataServiceReadExportRequest request, ServerCallContext context) =>
        Call(request, request.Meta, context, V2.DataServiceReadExportRequest.Parser, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.ReadDataExport(value, cancellation),
            static (meta, error) => new V2.DataServiceReadExportResponse { Meta = meta, Error = error });

    public override Task<V2.DataServiceInspectTransferResponse> InspectTransfer(
        V2.DataServiceInspectTransferRequest request, ServerCallContext context) =>
        Call(request, request.Meta, context, V2.DataServiceInspectTransferRequest.Parser, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.InspectDataTransfer(value, cancellation),
            static (meta, error) => new V2.DataServiceInspectTransferResponse { Meta = meta, Error = error });

    public override Task<V2.DataServiceCloseTransferResponse> CloseTransfer(
        V2.DataServiceCloseTransferRequest request, ServerCallContext context) =>
        Call(request, request.Meta, context, V2.DataServiceCloseTransferRequest.Parser, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.CloseDataTransfer(value, cancellation),
            static (meta, error) => new V2.DataServiceCloseTransferResponse { Meta = meta, Error = error }, mutation: true);

    private Task<TResponse> Call<TRequest, TResponse>(TRequest request, RequestMeta? requestMeta, ServerCallContext context,
        MessageParser<TRequest> parser, Func<TRequest, bool> isValid,
        Func<SandboxManager, TRequest, CancellationToken, TResponse> execute,
        Func<ResponseMeta, ArcError, TResponse> fail, bool mutation = false)
        where TRequest : class, IMessage<TRequest>
        where TResponse : class, IMessage<TResponse> =>
        SandboxLocalCalls.Execute(node, context, request, requestMeta,
            value => ValidMetadata(requestMeta, mutation) && value.CalculateSize() <= MaximumWireBytes && isValid(value)
                && value.Equals(parser.WithDiscardUnknownFields(true).ParseFrom(value.ToByteArray())),
            (manager, value, cancellation) =>
            {
                var response = execute(manager, value, cancellation);
                if (response.CalculateSize() > MaximumWireBytes)
                    throw new RpcException(new Status(StatusCode.ResourceExhausted, "The Sandbox data response exceeds its wire limit."));
                return response;
            },
            fail);

    internal static bool ValidMetadata(RequestMeta? meta, bool mutation) =>
        meta is { ExpectedNative: null, WorkspaceId: null, ApplicationScope: null, HasRecoveryGeneration: false }
        && (mutation
            ? meta is { CommandId: not null, ExpectedRev: { HasValue: true, Value: > 0 } }
            : meta.ExpectedRev is null);
}
