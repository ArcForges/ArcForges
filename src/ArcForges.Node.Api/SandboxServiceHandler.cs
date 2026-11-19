// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Sandboxes;
using Google.Protobuf;
using Grpc.Core;
using V2 = ArcForges.Contracts.Sandbox.V2;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

/// <summary>The owner's local V2 Sandbox management methods.</summary>
internal sealed class SandboxServiceHandler(NodeRuntime node) : V2.SandboxService.SandboxServiceBase
{
    public override Task<V2.SandboxServiceCreateResponse> Create(
        V2.SandboxServiceCreateRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, ValidLocalCreate,
            static (manager, value, cancellation) => manager.Create(value, cancellation),
            static (meta, error) => new V2.SandboxServiceCreateResponse { Meta = meta, Error = error });

    public override Task<V2.SandboxServiceConfigureResponse> Configure(
        V2.SandboxServiceConfigureRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.Configure(value, cancellation),
            static (meta, error) => new V2.SandboxServiceConfigureResponse { Meta = meta, Error = error });

    public override Task<V2.SandboxServiceListResponse> List(
        V2.SandboxServiceListRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.List(value, cancellation),
            static (meta, error) => new V2.SandboxServiceListResponse { Meta = meta, Error = error });

    public override Task<V2.SandboxServiceInspectResponse> Inspect(
        V2.SandboxServiceInspectRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.Inspect(value, cancellation),
            static (meta, error) => new V2.SandboxServiceInspectResponse { Meta = meta, Error = error });

    // The published whole-request validator requires TemplateRevision for routed provisioning.
    // Local creation uses the same field validators with the local contract's field presence.
    private static bool ValidLocalCreate(V2.SandboxServiceCreateRequest request) =>
        request.CalculateSize() <= 1_048_576
        && request.ProvisionGrantId is null
        && request.TemplateRevision is null
        && request.Meta is { CommandId: not null, ExpectedRev: null, ExpectedNative: null }
        && V2Shapes.IsValid(request.Meta)
        && V2Shapes.IsValid(request.OwnerEpoch)
        && V2Shapes.IsValid(request.Config)
        && request.HasDisplayName
        && ValidCreateName(request.DisplayName);

    private static bool ValidCreateName(string name)
    {
        var scalarCount = 0;
        for (var index = 0; index < name.Length;)
        {
            if (!Rune.TryGetRuneAt(name, index, out var scalar) || ++scalarCount > 80)
            {
                return false;
            }

            index += scalar.Utf16SequenceLength;
        }

        return scalarCount != 0;
    }
}

/// <summary>Negotiates the owner's V2 namespace, reads durable operations and manages local remote grants.</summary>
internal sealed class SandboxNodeServiceHandler(NodeRuntime node) : V2.NodeService.NodeServiceBase
{
    public override Task<V2.NodeServiceHandshakeResponse> Handshake(
        V2.NodeServiceHandshakeRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.Handshake(value, cancellation),
            static (meta, error) => new V2.NodeServiceHandshakeResponse { Meta = meta, Error = error });

    public override Task<V2.NodeServiceGetOperationResponse> GetOperation(
        V2.NodeServiceGetOperationRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, V2Shapes.IsValid,
            static (manager, value, cancellation) => manager.GetOperation(value, cancellation),
            static (meta, error) => new V2.NodeServiceGetOperationResponse { Meta = meta, Error = error });

    public override Task<V2.NodeServiceSetRemoteGrantResponse> SetRemoteGrant(
        V2.NodeServiceSetRemoteGrantRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta, ValidLocalGrantSet,
            static (manager, value, cancellation) => manager.SetRemoteGrant(value, cancellation),
            static (meta, error) => new V2.NodeServiceSetRemoteGrantResponse { Meta = meta, Error = error });

    public override Task<V2.NodeServiceListRemoteGrantsResponse> ListRemoteGrants(
        V2.NodeServiceListRemoteGrantsRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta,
            static value => V2Shapes.IsValid(value) && HasKnownFields(value, V2.NodeServiceListRemoteGrantsRequest.Parser),
            static (manager, value, cancellation) => manager.ListRemoteGrants(value, cancellation),
            static (meta, error) => new V2.NodeServiceListRemoteGrantsResponse { Meta = meta, Error = error });

    public override Task<V2.NodeServiceRevokeRemoteGrantResponse> RevokeRemoteGrant(
        V2.NodeServiceRevokeRemoteGrantRequest request, ServerCallContext context) =>
        SandboxLocalCalls.Execute(node, context, request, request.Meta,
            static value => V2Shapes.IsValid(value) && HasKnownFields(value, V2.NodeServiceRevokeRemoteGrantRequest.Parser),
            static (manager, value, cancellation) => manager.RevokeRemoteGrant(value, cancellation),
            static (meta, error) => new V2.NodeServiceRevokeRemoteGrantResponse { Meta = meta, Error = error });

    private static bool ValidLocalGrantSet(V2.NodeServiceSetRemoteGrantRequest request)
    {
        if (request.CalculateSize() > 1_048_576
            || request.Meta is not { CommandId: not null, ExpectedNative: null } meta
            || !V2Shapes.IsValid(meta) || !V2Shapes.IsValid(request.OwnerEpoch)
            || request.Grant is not { ParentGrantId: null } grant
            || (grant.HasState && grant.State != V2.GrantState.Active)
            || (grant.GrantId is not null && !V2Shapes.IsValid(grant.GrantId)))
        {
            return false;
        }

        var expected = meta.ExpectedRev;
        if (expected is not null && (expected is not { HasValue: true, Value: > 0 } || grant.GrantId is null))
        {
            return false;
        }

        var revision = expected?.Value ?? 1;
        if (grant.Revision is { } supplied && (!supplied.HasValue || supplied.Value != revision))
        {
            return false;
        }

        // The generated Set shape requires CAS and a complete grant projection. Grant creation
        // can omit those values, so validate a temporary projection and dispatch the original request.
        var shape = grant.Clone();
        shape.GrantId ??= request.OwnerEpoch;
        shape.Revision ??= new Revision { Value = revision };
        shape.State = V2.GrantState.Active;
        return V2Shapes.IsValid(shape) && HasKnownFields(request, V2.NodeServiceSetRemoteGrantRequest.Parser);
    }

    private static bool HasKnownFields<T>(T value, MessageParser<T> parser) where T : class, IMessage<T> =>
        value.Equals(parser.WithDiscardUnknownFields(true).ParseFrom(value.ToByteArray()));
}

internal static class SandboxLocalCalls
{
    internal static Task<TResponse> Execute<TRequest, TResponse>(
        NodeRuntime node,
        ServerCallContext context,
        TRequest request,
        RequestMeta? requestMeta,
        Func<TRequest, bool> isValid,
        Func<SandboxManager, TRequest, CancellationToken, TResponse> execute,
        Func<ResponseMeta, ArcError, TResponse> fail)
    {
        node.CountCall();
        var manager = node.Sandboxes;
        var owner = SandboxLocalOwner.ForPeer(context.GetLocalRpcPeer());
        if (owner is null || (manager is not null && !StringComparer.Ordinal.Equals(manager.OwnerId, owner)))
        {
            return Failure(NodeErrors.PermissionDenied("sandbox.local_owner"));
        }

        if (node.Lifecycle.IsStopping)
        {
            return Failure(NodeErrors.NodeStopping(node.Clock.GetUtcNow()));
        }

        if (manager is null)
        {
            throw new RpcException(new Status(StatusCode.Unavailable, "The local Sandbox store is unavailable."));
        }

        if (!isValid(request))
        {
            return Failure(NodeErrors.InvalidArgument("request: invalid Sandbox v2 request shape"));
        }

        context.CancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(execute(manager, request, context.CancellationToken));

        Task<TResponse> Failure(ArcError error)
        {
            var requested = requestMeta?.CorrelationId;
            var correlation = V2Shapes.IsValid(requested)
                ? requested.Clone()
                : new Id { Value = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(16)) };
            error.CorrelationId = correlation.Clone();
            if (error.Details?.State is { } state && !state.HasState)
            {
                state.State = "sandbox";
            }

            return Task.FromResult(fail(new ResponseMeta { CorrelationId = correlation }, error));
        }
    }
}

/// <summary>Uses the same local SID or effective UID as the transport's same-user resolver.</summary>
internal static class SandboxLocalOwner
{
    internal static string? Current()
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            return Windows(identity.User?.Value);
        }

        if (OperatingSystem.IsLinux())
        {
            var line = File.ReadLines("/proc/self/status")
                .FirstOrDefault(value => value.StartsWith("Uid:", StringComparison.Ordinal));
            if (line is not null)
            {
                var fields = line[4..].Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length == 4
                    && uint.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var effectiveUid))
                {
                    return Linux(effectiveUid);
                }
            }
        }

        return null;
    }

    internal static string? ForPeer(LocalRpcPeer? peer)
    {
        if (OperatingSystem.IsWindows())
        {
            return Windows(peer?.UserSid);
        }

        return OperatingSystem.IsLinux() && peer?.Uid is { } uid ? Linux(uid) : null;
    }

    private static string? Windows(string? sid) => string.IsNullOrEmpty(sid) ? null : "windows:" + sid;

    private static string Linux(uint uid) => string.Create(CultureInfo.InvariantCulture, $"linux:{uid}");
}
