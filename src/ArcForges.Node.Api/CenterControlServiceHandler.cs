// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Store;
using Google.Protobuf;
using Grpc.Core;
using Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

/// <summary>Owner-local Center control over the same durable command authority as the Sandbox API.</summary>
internal sealed class CenterControlServiceHandler(NodeRuntime node, CloudLinkService cloud) : CenterControlService.CenterControlServiceBase, IDisposable
{
    private const string Service = "CenterControlService.";
    private readonly SemaphoreSlim _mutations = new(1, 1);
    private bool _recoveryReady;
    private volatile bool _linkLoaded;

    internal void RecoverAccepted(NodeStore store, SandboxManager manager)
    {
        string revocation = "unknown";
        try
        {
            lock (manager.OwnershipGate)
            {
                if (DurableCommandStore.HasExistingAuthority(store, manager.OwnerId))
                {
                    manager.Receipts.RecoverInterruptedCenterControls();
                    revocation = manager.Receipts.LatestCenterRemoteRevocation();
                }
                else
                {
                    revocation = "not_requested";
                }
                _recoveryReady = true;
            }
        }
        catch (Exception failure) when (StorageUnavailable(failure))
        {
            node.Log.Warning("center.control.recovery", new LogField("reason", "center_control_metadata_unavailable"),
                new LogField("errorType", failure.GetType().Name));
        }

        cloud.RestoreCenterRemoteRevocation(revocation);
    }

    public void Dispose() => _mutations.Dispose();

    internal void MarkLinkLoaded() => _linkLoaded = true;

    public override Task<CenterControlServiceGetStatusResponse> GetStatus(
        CenterControlServiceGetStatusRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta,
            value => IsRead(value.Meta) && Exact(value, CenterControlServiceGetStatusRequest.Parser),
            (_, value, _) => _linkLoaded
                ? new CenterControlServiceGetStatusResponse { Meta = Response(value.Meta), Value = new() { Connection = cloud.GetCenterStatus() } }
                : new CenterControlServiceGetStatusResponse { Meta = Response(value.Meta), Error = LinkStarting(value.Meta) },
            static (meta, error) => new() { Meta = meta, Error = error });

    public override Task<CenterControlServiceGetConnectFlowResponse> GetConnectFlow(
        CenterControlServiceGetConnectFlowRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta,
            value => IsRead(value.Meta) && Shapes.IsValid(value.FlowId) && Exact(value, CenterControlServiceGetConnectFlowRequest.Parser),
            (_, value, _) =>
            {
                var meta = Response(value.Meta);
                if (!_linkLoaded)
                    return new CenterControlServiceGetConnectFlowResponse { Meta = meta, Error = LinkStarting(value.Meta) };
                var flow = cloud.GetCenterFlow(value.FlowId);
                return flow is null
                    ? new CenterControlServiceGetConnectFlowResponse
                    {
                        Meta = meta,
                        Error = Error(value.Meta, ErrorCategory.State, "not_found", "center_flow_not_found")
                    }
                    : new CenterControlServiceGetConnectFlowResponse { Meta = meta, Value = new() { Flow = flow } };
            }, static (meta, error) => new() { Meta = meta, Error = error });

    public override Task<CenterControlServiceBeginConnectResponse> BeginConnect(
        CenterControlServiceBeginConnectRequest request, ServerCallContext context) =>
        Mutate(request, context, request.Meta, request.OwnerEpoch, nameof(BeginConnect),
            value => value.HasCenterOrigin && value.CenterOrigin.Length is > 0 and <= 1024
                && value.ServiceMode is "official" or "self_hosted" && value.FlowKind is "browser" or "device_code"
                && Exact(value, CenterControlServiceBeginConnectRequest.Parser),
            value => new CenterControlServiceBeginConnectRequest
            {
                CenterOrigin = value.CenterOrigin,
                ServiceMode = value.ServiceMode,
                FlowKind = value.FlowKind,
            }.ToByteArray(),
            async (value, token) =>
            {
                var (flow, error) = await cloud.BeginCenterConnectAsync(value.CenterOrigin, value.ServiceMode, value.FlowKind, token)
                    .ConfigureAwait(false);
                return new(error, flow);
            },
            static (meta, result) => new CenterControlServiceBeginConnectResponse
            {
                Meta = meta,
                Value = new() { Operation = result.Operation, Connection = result.Connection, FlowId = result.FlowId },
            }, static (meta, error) => new() { Meta = meta, Error = error });

    public override Task<CenterControlServiceCancelConnectResponse> CancelConnect(
        CenterControlServiceCancelConnectRequest request, ServerCallContext context) =>
        Mutate(request, context, request.Meta, request.OwnerEpoch, nameof(CancelConnect),
            value => Shapes.IsValid(value.FlowId) && Exact(value, CenterControlServiceCancelConnectRequest.Parser),
            value => value.FlowId.Value.ToByteArray(),
            async (value, token) => new(await cloud.CancelCenterConnectAsync(value.FlowId, token).ConfigureAwait(false)),
            static (meta, result) => new CenterControlServiceCancelConnectResponse
            {
                Meta = meta,
                Value = new() { Operation = result.Operation },
            }, static (meta, error) => new() { Meta = meta, Error = error });

    public override Task<CenterControlServiceDisconnectResponse> Disconnect(
        CenterControlServiceDisconnectRequest request, ServerCallContext context) =>
        Mutate(request, context, request.Meta, request.OwnerEpoch, nameof(Disconnect),
            value => Exact(value, CenterControlServiceDisconnectRequest.Parser), static _ => [],
            async (_, token) => new(await cloud.DisconnectCenterAsync(token).ConfigureAwait(false)),
            static (meta, result) => new CenterControlServiceDisconnectResponse
            {
                Meta = meta,
                Value = new() { Operation = result.Operation, Connection = result.Connection },
            }, static (meta, error) => new() { Meta = meta, Error = error });

    public override Task<CenterControlServiceSignOutResponse> SignOut(
        CenterControlServiceSignOutRequest request, ServerCallContext context) =>
        Mutate(request, context, request.Meta, request.OwnerEpoch, nameof(SignOut),
            value => Exact(value, CenterControlServiceSignOutRequest.Parser), static _ => [],
            async (_, token) =>
            {
                var (revocation, error) = await cloud.SignOutCenterAsync(token).ConfigureAwait(false);
                return new(error, RemoteRevocation: revocation);
            },
            static (meta, result) => new CenterControlServiceSignOutResponse
            {
                Meta = meta,
                Value = new() { Operation = result.Operation, Connection = result.Connection },
            }, static (meta, error) => new() { Meta = meta, Error = error });

    private async Task<TResponse> Mutate<TRequest, TResponse>(TRequest request, ServerCallContext context, RequestMeta meta, Id epoch,
        string method, Func<TRequest, bool> valid, Func<TRequest, byte[]> canonical, Func<TRequest, CancellationToken, Task<Effect>> effect,
        Func<ResponseMeta, Result, TResponse> success, Func<ResponseMeta, ArcError, TResponse> failure)
    {
        var authorized = await SandboxLocalCalls.Execute(node, context, request, meta,
            value => meta is { CommandId: not null, ExpectedRev: null, ExpectedNative: null }
                && Shapes.IsValid(meta) && Shapes.IsValid(meta.CorrelationId) && Shapes.IsValid(epoch) && valid(value),
            (manager, value, token) => ExecuteAsync(manager, meta, epoch, method, canonical(value),
                owned => effect(value, owned), success, failure, token),
            (response, error) => Task.FromResult(failure(response, error))).ConfigureAwait(false);
        return await authorized.ConfigureAwait(false);
    }

    private async Task<TResponse> ExecuteAsync<TResponse>(SandboxManager manager, RequestMeta meta, Id epoch, string method,
        byte[] canonical, Func<CancellationToken, Task<Effect>> action, Func<ResponseMeta, Result, TResponse> success,
        Func<ResponseMeta, ArcError, TResponse> failure, CancellationToken cancellationToken)
    {
        if (!_linkLoaded)
            return failure(Response(meta), LinkStarting(meta));
        if (!_recoveryReady)
            return failure(Response(meta), Error(meta, ErrorCategory.State, "busy", "center_control_recovery_unavailable"));

        await _mutations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var command = meta.CommandId.Value.ToByteArray();
            var intent = new DurableIntent(command, epoch.Value.ToByteArray(), Service + method, null, null, canonical);
            DurableAdmission admission;
            lock (manager.OwnershipGate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                admission = manager.Receipts.Admit(intent);
            }

            var rejected = Rejection(meta, admission);
            if (rejected is not null)
                return failure(Response(meta), rejected);

            var receipt = admission.Receipt;
            if (admission.Decision == DurableDecision.Execute)
                receipt = await ObserveAsync(manager, meta, command, method, action).ConfigureAwait(false);

            var observed = manager.GetOperation(new() { Meta = meta, OwnerEpoch = epoch, CommandId = meta.CommandId },
                CancellationToken.None);
            if (observed.Error is { } error)
                return failure(Response(meta), error);

            var operation = observed.Value.Operation;
            var (connection, flow) = Projection(receipt?.ResponseJson);
            if (method != nameof(CancelConnect) && connection is null)
            {
                return failure(Response(meta), operation.Error ?? Error(meta, ErrorCategory.Execution, "outcome_unknown",
                    "center_control_projection_unavailable", EffectCertainty.Unknown));
            }

            return success(Response(meta), new(operation, connection, flow));
        }
        catch (Exception error) when (StorageUnavailable(error))
        {
            Diagnose(meta, method, "receipt_unavailable", error);
            return failure(Response(meta), Error(meta, ErrorCategory.Internal, "store_corrupt",
                "center_control_metadata_unavailable", EffectCertainty.Unknown));
        }
        finally
        {
            _mutations.Release();
        }
    }

    private async Task<DurableReceipt> ObserveAsync(SandboxManager manager, RequestMeta meta, byte[] command, string method,
        Func<CancellationToken, Task<Effect>> action)
    {
        Effect observation;
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        try
        {
            observation = await action(budget.Token).ConfigureAwait(false);
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or HttpRequestException or UnauthorizedAccessException
            or CryptographicException or DurableStoreMaintenanceException)
        {
            Diagnose(meta, method, "effect_observation_unavailable", error);
            observation = new(Error(meta, ErrorCategory.Execution, "outcome_unknown", "center_control_observation_unavailable",
                EffectCertainty.Unknown));
        }

        var connection = method == nameof(CancelConnect) ? null : cloud.GetCenterStatus();
        var observed = observation.Error;
        if (connection is not null && observation.RemoteRevocation == "unknown")
        {
            connection.RemoteRevocation = "unknown";
            observed ??= Error(meta, ErrorCategory.Execution, "outcome_unknown", "center_remote_revocation_unconfirmed",
                EffectCertainty.Unknown);
        }

        string state = observed is null ? "SUCCEEDED" : observed.Effect == EffectCertainty.DidNotHappen ? "FAILED" : "UNKNOWN";
        var certainty = state switch
        {
            "SUCCEEDED" => EffectCertainty.Happened,
            "FAILED" => EffectCertainty.DidNotHappen,
            _ => EffectCertainty.Unknown,
        };
        var retained = new JsonObject
        {
            ["category"] = observed is null ? null : (int)observed.Category,
            ["code"] = observed?.Code,
            ["reason"] = observed?.Details?.State?.Reason,
            ["centerConnection"] = connection is null ? null : Convert.ToBase64String(connection.ToByteArray()),
            ["centerFlowId"] = observation.FlowId is null ? null : Convert.ToHexStringLower(observation.FlowId.Value.Span),
        };
        if (method == nameof(SignOut) && observation.RemoteRevocation is "unknown" or "confirmed" or "not_requested")
            retained["centerRemoteRevocation"] = observation.RemoteRevocation;

        DurableReceipt receipt;
        lock (manager.OwnershipGate)
        {
            receipt = manager.Receipts.SetResult(command, state, (int)certainty, retained.ToJsonString());
        }

        node.Log.Info("center.control", new LogField("operationId", Convert.ToHexStringLower(command)),
            new LogField("method", method), new LogField("phase", "settled_receipt"), new LogField("outcome", state));
        return receipt;
    }

    private static (CenterConnection? Connection, Id? FlowId) Projection(string? retained)
    {
        if (retained is null)
            return (null, null);

        using var document = JsonDocument.Parse(retained);
        var root = document.RootElement;
        var connection = root.TryGetProperty("centerConnection", out var value) && value.ValueKind == JsonValueKind.String
            ? CenterConnection.Parser.ParseFrom(value.GetBytesFromBase64()) : null;
        var flow = root.TryGetProperty("centerFlowId", out value) && value.ValueKind == JsonValueKind.String
            ? new Id { Value = ByteString.CopyFrom(Convert.FromHexString(value.GetString()!)) } : null;
        if (flow is not null && !Shapes.IsValid(flow))
            throw new InvalidDataException("Invalid stored Center flow identity.");
        return (connection, flow);
    }

    private static ArcError? Rejection(RequestMeta meta, DurableAdmission admission)
    {
        var refused = admission.Decision switch
        {
            DurableDecision.Conflict => Error(meta, ErrorCategory.Conflict, "command_id_reused", "command_intent_changed"),
            DurableDecision.EpochRetired => Error(meta, ErrorCategory.Conflict, "owner_epoch_retired", "owner_epoch_mismatch"),
            DurableDecision.Compacted => Error(meta, ErrorCategory.State, "receipt_compacted", "original_response_compacted",
                (EffectCertainty)(admission.Receipt?.Effect ?? (int)EffectCertainty.Unknown)),
            DurableDecision.Capacity => Error(meta, ErrorCategory.Resource, "disk_space", "durable_receipt_capacity"),
            DurableDecision.Maintenance => Error(meta, ErrorCategory.Internal, "store_corrupt", "center_control_metadata_unavailable",
                EffectCertainty.Unknown),
            _ => null,
        };
        if (admission.Decision == DurableDecision.Compacted && refused is not null)
            refused.Retry.ReconciliationOperation = "NodeService.GetOperation";
        return refused;
    }

    private void Diagnose(RequestMeta meta, string method, string reason, Exception error) =>
        node.Log.Warning("center.control", new LogField("operationId", Convert.ToHexStringLower(meta.CommandId.Value.Span)),
            new LogField("method", method), new LogField("reason", reason), new LogField("errorType", error.GetType().Name));

    private static bool IsRead(RequestMeta meta) =>
        meta is { CommandId: null, ExpectedRev: null, ExpectedNative: null }
        && Shapes.IsValid(meta) && Shapes.IsValid(meta.CorrelationId);

    private static bool Exact<T>(T request, MessageParser<T> parser) where T : IMessage<T> =>
        request.CalculateSize() <= 8192 && request.Equals(parser.WithDiscardUnknownFields(true).ParseFrom(request.ToByteArray()));

    private static bool StorageUnavailable(Exception exception) => exception is IOException or UnauthorizedAccessException
        or DurableStoreMaintenanceException or Microsoft.Data.Sqlite.SqliteException or JsonException or FormatException;

    private static ResponseMeta Response(RequestMeta meta) => new() { CorrelationId = meta.CorrelationId.Clone() };

    private static ArcError LinkStarting(RequestMeta meta) =>
        Error(meta, ErrorCategory.State, "busy", "center_link_initializing");

    private static ArcError Error(RequestMeta meta, ErrorCategory category, string code, string reason,
        EffectCertainty effect = EffectCertainty.DidNotHappen) => new()
        {
            Category = category,
            Code = code,
            Effect = effect,
            CorrelationId = meta.CorrelationId.Clone(),
            MessageKey = "center." + code,
            Details = new() { State = new() { Reason = reason } },
            Retry = effect == EffectCertainty.Unknown
            ? new() { Mode = RetryMode.Reconcile, ReconciliationOperation = "NodeService.GetOperation" }
            : new() { Mode = RetryMode.Never },
        };

    private sealed record Effect(ArcError? Error, Id? FlowId = null, string? RemoteRevocation = null);
    private sealed record Result(Operation Operation, CenterConnection? Connection, Id? FlowId);
}
