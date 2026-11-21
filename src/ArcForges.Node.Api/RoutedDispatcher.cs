// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Sandboxes;
using Google.Protobuf;
using V2 = ArcForges.Contracts.Sandbox.V2;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

/// <summary>Dispatches typed Center operations through the Sandbox Core.</summary>
internal sealed class RoutedDispatcher(NodeRuntime node)
{
    private const int MaximumOutputFrameBytes = 65_536;
    // The chunk envelope carries the correlation, a bounded Run epoch, stream and two offsets.
    private const int OutputFrameMetadataBytes = 512;
    private static readonly byte[] IdleWatch = [0];

    /// <summary>Dispatches a request admitted by the authenticated V2 channel on its exact live connection.</summary>
    internal Task<ReadOnlyMemory<byte>> DispatchV2Async(V2ControlCall call, CancellationToken cancellationToken) =>
        Task.FromResult(DispatchV2(call, streamData: false, cancellationToken));

    /// <summary>Dispatches one typed stream observation or transfer under the separate negotiated capability.</summary>
    internal Task<ReadOnlyMemory<byte>> DispatchV2StreamDataAsync(V2ControlCall call, CancellationToken cancellationToken) =>
        Task.FromResult(DispatchV2(call, streamData: true, cancellationToken));

    private ReadOnlyMemory<byte> DispatchV2(V2ControlCall call, bool streamData, CancellationToken cancellationToken)
    {
        node.CountCall();
        return streamData ? StreamData() : Control();

        ReadOnlyMemory<byte> Control() => call.Request.Header.Selector switch
        {
            V2ControlSelector.NodeGetOperation => Route(RemoteGrantAction.GetOperation, V2.NodeServiceGetOperationRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.CommandId),
                static (manager, request, remote, token) => manager.GetOperationFromCenter(request, remote, token),
                static (meta, error) => new V2.NodeServiceGetOperationResponse { Meta = meta, Error = error }),
            V2ControlSelector.NodeListRemoteGrants => Route(RemoteGrantAction.ListRemoteGrants, V2.NodeServiceListRemoteGrantsRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                static (manager, request, remote, token) => manager.ListRemoteGrantsFromCenter(request, remote, token),
                static (meta, error) => new V2.NodeServiceListRemoteGrantsResponse { Meta = meta, Error = error }),
            V2ControlSelector.NodeRevokeRemoteGrant => Route(RemoteGrantAction.RevokeRemoteGrant, V2.NodeServiceRevokeRemoteGrantRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.RevokeRemoteGrantFromCenter(request, remote, token),
                static (meta, error) => new V2.NodeServiceRevokeRemoteGrantResponse { Meta = meta, Error = error }),
            V2ControlSelector.SandboxCreate => Route(RemoteGrantAction.SandboxCreate, V2.SandboxServiceCreateRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.CreateFromCenter(request, remote, token),
                static (meta, error) => new V2.SandboxServiceCreateResponse { Meta = meta, Error = error }),
            V2ControlSelector.SandboxConfigure => Route(RemoteGrantAction.SandboxConfigure, V2.SandboxServiceConfigureRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.ConfigureFromCenter(request, remote, token),
                static (meta, error) => new V2.SandboxServiceConfigureResponse { Meta = meta, Error = error }),
            V2ControlSelector.SandboxList => Route(RemoteGrantAction.SandboxList, V2.SandboxServiceListRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                static (manager, request, remote, token) => manager.ListFromCenter(request, remote, token),
                static (meta, error) => new V2.SandboxServiceListResponse { Meta = meta, Error = error }),
            V2ControlSelector.SandboxInspect => Route(RemoteGrantAction.SandboxInspect, V2.SandboxServiceInspectRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                static (manager, request, remote, token) => manager.InspectFromCenter(request, remote, token),
                static (meta, error) => new V2.SandboxServiceInspectResponse { Meta = meta, Error = error }),
            V2ControlSelector.RunStart => Route(RemoteGrantAction.RunStart, V2.RunServiceStartRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.StartFromCenter(request, remote, token),
                static (meta, error) => new V2.RunServiceStartResponse { Meta = meta, Error = error }),
            V2ControlSelector.RunStop => Route(RemoteGrantAction.RunStop, V2.RunServiceStopRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.StopFromCenter(request, remote, token),
                static (meta, error) => new V2.RunServiceStopResponse { Meta = meta, Error = error }),
            V2ControlSelector.RunList => Route(RemoteGrantAction.RunList, V2.RunServiceListRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                static (manager, request, remote, token) => manager.ListRunsFromCenter(request, remote, token),
                static (meta, error) => new V2.RunServiceListResponse { Meta = meta, Error = error }),
            V2ControlSelector.RunInspect => Route(RemoteGrantAction.RunInspect, V2.RunServiceInspectRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                static (manager, request, remote, token) => manager.InspectRunFromCenter(request, remote, token),
                static (meta, error) => new V2.RunServiceInspectResponse { Meta = meta, Error = error }),
            V2ControlSelector.ResourceGetBudget => Route(RemoteGrantAction.ResourceGetBudget, V2.ResourceServiceGetBudgetRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                static (manager, request, remote, token) => manager.GetResourceBudgetFromCenter(request, remote, token),
                static (meta, error) => new V2.ResourceServiceGetBudgetResponse { Meta = meta, Error = error }),
            V2ControlSelector.ResourceSetPolicy => Route(RemoteGrantAction.ResourceSetPolicy, V2.ResourceServiceSetPolicyRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.SetResourcePolicyFromCenter(request, remote, token),
                static (meta, error) => new V2.ResourceServiceSetPolicyResponse { Meta = meta, Error = error }),
            _ => ReadOnlyMemory<byte>.Empty,
        };

        ReadOnlyMemory<byte> StreamData() => call.Request.Header.Selector switch
        {
            V2ControlSelector.RunWatchOutput => Route(RemoteGrantAction.RunWatchOutput, V2.RunServiceWatchOutputRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                (manager, request, remote, token) => manager.PollRunOutputFromCenter(request, remote,
                    Math.Max(1, OutputFrameBytes(call) - OutputFrameMetadataBytes), token),
                static (meta, error) => new V2.RunServiceWatchOutputFrame { Meta = meta, Error = error }, watch: true),
            V2ControlSelector.NodeWatchEvents => Route(RemoteGrantAction.WatchEvents, V2.NodeServiceWatchEventsRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                static (manager, request, remote, token) => manager.PollEventsFromCenter(request, remote, token),
                static (meta, error) => new V2.NodeServiceWatchEventsFrame { Meta = meta, Error = error }, watch: true),
            V2ControlSelector.ResourceWatchUsage => Route(RemoteGrantAction.ResourceWatchUsage, V2.ResourceServiceWatchUsageRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                static (manager, request, remote, token) => manager.PollResourceUsageFromCenter(request, remote, token),
                static (meta, error) => new V2.ResourceServiceWatchUsageFrame { Meta = meta, Error = error }, watch: true),
            V2ControlSelector.DataBeginImport => Route(RemoteGrantAction.DataBeginImport, V2.DataServiceBeginImportRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.BeginDataImportFromCenter(request, remote, token),
                static (meta, error) => new V2.DataServiceBeginImportResponse { Meta = meta, Error = error }),
            V2ControlSelector.DataWriteImport => Route(RemoteGrantAction.DataWriteImport, V2.DataServiceWriteImportRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.WriteDataImportFromCenter(request, remote, token),
                static (meta, error) => new V2.DataServiceWriteImportResponse { Meta = meta, Error = error }),
            V2ControlSelector.DataCommitImport => Route(RemoteGrantAction.DataCommitImport, V2.DataServiceCommitImportRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.CommitDataImportFromCenter(request, remote, token),
                static (meta, error) => new V2.DataServiceCommitImportResponse { Meta = meta, Error = error }),
            V2ControlSelector.DataBeginExport => Route(RemoteGrantAction.DataBeginExport, V2.DataServiceBeginExportRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.BeginDataExportFromCenter(request, remote, token),
                static (meta, error) => new V2.DataServiceBeginExportResponse { Meta = meta, Error = error }),
            V2ControlSelector.DataReadExport => Route(RemoteGrantAction.DataReadExport, V2.DataServiceReadExportRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                static (manager, request, remote, token) => manager.ReadDataExportFromCenter(request, remote, token),
                static (meta, error) => new V2.DataServiceReadExportResponse { Meta = meta, Error = error }),
            V2ControlSelector.DataInspectTransfer => Route(RemoteGrantAction.DataInspectTransfer, V2.DataServiceInspectTransferRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, null, null),
                static (manager, request, remote, token) => manager.InspectDataTransferFromCenter(request, remote, token),
                static (meta, error) => new V2.DataServiceInspectTransferResponse { Meta = meta, Error = error }),
            V2ControlSelector.DataCloseTransfer => Route(RemoteGrantAction.DataCloseTransfer, V2.DataServiceCloseTransferRequest.Parser, V2Shapes.IsValid,
                static request => (request.Meta, request.OwnerEpoch, request.Meta?.CommandId),
                static (manager, request, remote, token) => manager.CloseDataTransferFromCenter(request, remote, token),
                static (meta, error) => new V2.DataServiceCloseTransferResponse { Meta = meta, Error = error }),
            _ => ReadOnlyMemory<byte>.Empty,
        };

        ReadOnlyMemory<byte> Route<TRequest, TResponse>(RemoteGrantAction action, MessageParser<TRequest> parser, Func<TRequest, bool> valid,
            Func<TRequest, (RequestMeta? Meta, Id? OwnerEpoch, Id? CommandId)> identify,
            Func<SandboxManager, TRequest, VerifiedRemoteGrantCall, CancellationToken, TResponse?> execute,
            Func<ResponseMeta, ArcError, TResponse> refuse, bool watch = false)
            where TRequest : class, IMessage<TRequest>
            where TResponse : class, IMessage<TResponse>
        {
            var header = call.Request.Header;
            bool hasSignedCommand = header.CommandId.Span.IndexOfAnyExcept((byte)0) >= 0;
            RequestMeta? meta = null;
            cancellationToken.ThrowIfCancellationRequested();
            TRequest request;
            Id? ownerEpoch;
            Id? commandId;
            try
            {
                var exactBody = call.Request.Body.Span;
                request = parser.ParseFrom(exactBody);
                (meta, ownerEpoch, commandId) = identify(request);
                if (!valid(request) || !V2Shapes.IsValid(meta?.CorrelationId) ||
                    !request.Equals(parser.WithDiscardUnknownFields(true).ParseFrom(exactBody)) ||
                    (streamData && !DataServiceHandler.ValidMetadata(meta, hasSignedCommand)) ||
                    ((commandId is null || action == RemoteGrantAction.GetOperation) && meta?.CommandId is not null))
                {
                    return Refused(NodeErrors.InvalidArgument("remote_request_shape_invalid"));
                }
            }
            catch (InvalidProtocolBufferException)
            {
                return Refused(NodeErrors.InvalidArgument("remote_request_shape_invalid"));
            }

            if (hasSignedCommand != (commandId is not null && ownerEpoch is not null) ||
                (ownerEpoch is not null && !ownerEpoch.Value.Span.SequenceEqual(header.OriginalOwnerEpoch.Span)) ||
                (commandId is not null && !commandId.Value.Span.SequenceEqual(header.CommandId.Span)))
            {
                return Refused(NodeErrors.PermissionDenied("remote_request_identity_mismatch"));
            }

            if (node.Lifecycle.IsStopping)
            {
                return Refused(NodeErrors.NodeStopping(node.Clock.GetUtcNow()));
            }

            if (node.Sandboxes is not { } manager || call.Enrollment.Center.Scheme != "https")
            {
                var failure = NodeErrors.EnforcementUnavailable("remote_control_unavailable");
                failure.Code = "enforcement_failed";
                failure.MessageKey = "error.resource.enforcement_failed";
                return Refused(failure);
            }

            var (enrollment, channel) = V2Authority(manager, call.Enrollment);
            // The channel verifies the signature and digest of the received bytes before dispatch. Core separately
            // checks this digest of its typed request, independent of the sender's protobuf field order.
            var remote = new VerifiedRemoteGrantCall(enrollment, Convert.ToHexStringLower(header.ActorId.Span),
                Convert.ToHexStringLower(header.GrantId.Span), checked((long)header.GrantRevision), action,
                call.ReceivedAt, call.Deadline, ByteString.CopyFrom(SHA256.HashData(request.ToByteArray())), channel, header.OriginalOwnerEpoch);
            var response = execute(manager, request, remote, cancellationToken);
            if (response is null)
            {
                return watch ? IdleWatch : ReadOnlyMemory<byte>.Empty;
            }

            CompleteV2Error(V2ReplyError(response), node.Clock.GetUtcNow());
            if (watch && response.CalculateSize() > (action == RemoteGrantAction.RunWatchOutput
                ? OutputFrameBytes(call) : call.MaximumResponseBodyBytes))
            {
                return Refused(NodeErrors.Overloaded(node.Clock.GetUtcNow()));
            }

            return Encode(response);

            ReadOnlyMemory<byte> Refused(ArcError error)
            {
                var requested = meta?.CorrelationId;
                var correlation = V2Shapes.IsValid(requested) ? requested.Clone() :
                    new Id { Value = ByteString.CopyFrom(header.CallId.Span) };
                error.CorrelationId = correlation.Clone();
                CompleteV2Error(error, node.Clock.GetUtcNow());
                node.Log.Warning("center.control.routed_refused", new LogField("method", action.ToString()),
                    new LogField("callId", Convert.ToHexStringLower(header.CallId.Span)), new LogField("code", error.Code));
                return Encode(refuse(new ResponseMeta { CorrelationId = correlation }, error));
            }

            ReadOnlyMemory<byte> Encode(TResponse response)
            {
                // Let the verified caller reconcile an effect if its result cannot fit. An oversized response
                // never becomes a typed refusal claiming that an already admitted transfer had no effect.
                if (streamData)
                {
                    int size = response.CalculateSize();
                    if (size == 0 || size > call.MaximumResponseBodyBytes)
                    {
                        return ReadOnlyMemory<byte>.Empty;
                    }
                }

                var body = response.ToByteArray();
                if (!watch)
                {
                    return body;
                }

                var frame = new byte[body.Length + 1];
                frame[0] = 1;
                body.CopyTo(frame, 1);
                return frame;
            }
        }
    }

    private static int OutputFrameBytes(V2ControlCall call) => Math.Min(call.MaximumResponseBodyBytes, MaximumOutputFrameBytes);

    private static ArcError? V2ReplyError(IMessage reply) => reply switch
    {
        V2.NodeServiceGetOperationResponse value => value.Error ?? value.Value?.Operation?.Error,
        V2.NodeServiceListRemoteGrantsResponse value => value.Error,
        V2.NodeServiceRevokeRemoteGrantResponse value => value.Error,
        V2.SandboxServiceCreateResponse value => value.Error,
        V2.SandboxServiceConfigureResponse value => value.Error,
        V2.SandboxServiceListResponse value => value.Error,
        V2.SandboxServiceInspectResponse value => value.Error,
        V2.RunServiceStartResponse value => value.Error,
        V2.RunServiceStopResponse value => value.Error,
        V2.RunServiceListResponse value => value.Error,
        V2.RunServiceInspectResponse value => value.Error,
        V2.ResourceServiceGetBudgetResponse value => value.Error,
        V2.ResourceServiceSetPolicyResponse value => value.Error,
        V2.RunServiceWatchOutputFrame value => value.Error,
        V2.NodeServiceWatchEventsFrame value => value.Error,
        V2.ResourceServiceWatchUsageFrame value => value.Error,
        V2.DataServiceBeginImportResponse value => value.Error,
        V2.DataServiceWriteImportResponse value => value.Error,
        V2.DataServiceCommitImportResponse value => value.Error,
        V2.DataServiceBeginExportResponse value => value.Error,
        V2.DataServiceReadExportResponse value => value.Error,
        V2.DataServiceInspectTransferResponse value => value.Error,
        V2.DataServiceCloseTransferResponse value => value.Error,
        _ => null,
    };

    internal static void CompleteV2Error(ArcError? error, DateTimeOffset now)
    {
        if (error is null)
        {
            return;
        }

        // The published V2 wire shape requires both a state and a reason when state details are present.
        if (error.Details?.State is { HasState: false } state)
        {
            state.State = "operation";
        }

        switch (error.Category, error.Code, error.Effect)
        {
            case (ErrorCategory.State, "busy", EffectCertainty.DidNotHappen):
            case (ErrorCategory.Resource, "budget_unavailable", EffectCertainty.DidNotHappen):
            case (ErrorCategory.Resource, "disk_space", EffectCertainty.DidNotHappen):
                if (error.Retry is not
                    {
                        Mode: RetryMode.AfterTime,
                        HasReconciliationOperation: false,
                        RetryAt:
                        {
                            HasUnixSeconds: true,
                            UnixSeconds: >= -62_135_596_800L and <= 253_402_300_799L,
                            HasNanos: true,
                            Nanos: <= 999_999_999
                        },
                    })
                {
                    error.Retry = NodeErrors.Overloaded(now).Retry;
                }

                break;
            case (ErrorCategory.Internal, "store_corrupt", EffectCertainty.Unknown):
                if (error.Retry is not { Mode: RetryMode.Never, RetryAt: null, HasReconciliationOperation: false })
                {
                    error.Retry = new RetryAdvice { Mode = RetryMode.Never };
                }

                break;
            case (ErrorCategory.State, "receipt_compacted", EffectCertainty.DidNotHappen or EffectCertainty.Happened):
                if (error.Retry is { Mode: RetryMode.Never } retry)
                {
                    retry.ClearReconciliationOperation();
                }

                break;
        }
    }

    internal static (ActiveRemoteEnrollment Enrollment, ActiveRemoteChannel Channel) V2Authority(SandboxManager manager,
        V2ChannelEnrollment accepted) => (new(manager.OwnerId, accepted.EnrollmentId, accepted.AccountId, accepted.Center.Url,
            accepted.Center.Url, accepted.ProtocolEpoch), new(accepted.ConnectionId, accepted.HubFence));
}
