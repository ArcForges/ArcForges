// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Platform.Shapes;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.LocalRpc;

/// <summary>The actual generated bootstrap service of one parent-owned registration; no discovery or product listener is created.</summary>
public sealed class LocalRpcBootstrapService : LocalBootstrapService.LocalBootstrapServiceBase
{
    private readonly LocalRpcRegistration _registration;
    private readonly EndpointManifest _server;

    /// <summary>Freezes the parent's actual manifest. Its instance is the registration's ParentInstanceId and its process is the launch's parent.</summary>
    public LocalRpcBootstrapService(LocalRpcRegistration registration, EndpointManifest server)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(server);
        var frozen = server.Clone();
        if (!ContractShapeValidation.IsValid(frozen)
            || BootstrapWire.FromId(frozen.InstanceId) != registration.ParentInstanceId
            || BootstrapWire.FromId(frozen.Endpoint.InstanceId) != registration.ParentInstanceId
            || frozen.ProcessId != (ulong)registration.Launch.Descriptor.Parent.ProcessId
            || Math.Abs(BootstrapWire.FromInstant(frozen.ProcessStartedAt).UtcTicks - registration.Launch.Descriptor.Parent.StartTimeUtcTicks)
                > LocalRpcProcessIdentity.StartTimeTolerance.Ticks)
        {
            throw new ArgumentException("The complete server manifest must describe this registration's actual parent.", nameof(server));
        }

        _registration = registration;
        _server = frozen;
    }

    public override Task<LocalBootstrapServiceChallengeResponse> Challenge(LocalBootstrapServiceChallengeRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var call = Call(context);
        if (!ContractShapeValidation.IsValid(request)
            || request.Caller.ContractMajors.Count != 1
            || BootstrapWire.FromId(request.Caller.InstanceId) != BootstrapWire.FromId(request.InstanceId)
            || BootstrapWire.FromId(request.Caller.Endpoint.InstanceId) != BootstrapWire.FromId(request.InstanceId))
        {
            throw BootstrapWire.Refused();
        }

        LocalRpcLaunchIdentity claimed;
        try
        {
            claimed = new LocalRpcLaunchIdentity(_registration.Launch.Descriptor.Identity.ChildKind,
                request.Caller.AppId, Convert.FromHexString(request.Caller.BuildHash),
                request.Caller.ContractMajors[0], Convert.FromHexString(request.Caller.ContractSetHash));
        }
        catch (ArgumentException)
        {
            throw BootstrapWire.Refused();
        }
        var result = call.TryChallenge(BootstrapWire.FromId(request.InstanceId), request.Challenge.Span, claimed, out var challenge);
        if (result != LocalRpcRegistrationRefusal.None || challenge is null) throw BootstrapWire.Refused();
        return Task.FromResult(new LocalBootstrapServiceChallengeResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId?.Clone() },
            Value = new LocalBootstrapServiceChallengeValue
            {
                ChallengeId = BootstrapWire.ToId(challenge.ChallengeId),
                ServerChallenge = ByteString.CopyFrom(challenge.ServerChallenge.Span),
                ExpiresAt = BootstrapWire.ToInstant(challenge.ExpiresAtUtc),
                Server = _server.Clone(),
            },
        });
    }

    public override Task<LocalBootstrapServiceConfirmResponse> Confirm(LocalBootstrapServiceConfirmRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var call = Call(context);
        if (!ContractShapeValidation.IsValid(request)) throw BootstrapWire.Refused();
        var result = call.TryConfirm(BootstrapWire.FromId(request.ChallengeId), request.Proof.Span, out var grant);
        if (result != LocalRpcRegistrationRefusal.None || grant is null) throw BootstrapWire.Refused();
        return Task.FromResult(new LocalBootstrapServiceConfirmResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId?.Clone() },
            Value = new LocalBootstrapServiceConfirmValue
            {
                PeerNonce = ByteString.CopyFrom(grant.PeerNonce.Span),
                ExpiresAt = BootstrapWire.ToInstant(grant.ExpiresAtUtc),
            },
        });
    }

    public override Task<LocalBootstrapServiceRenewResponse> Renew(LocalBootstrapServiceRenewRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        var call = Call(context);
        if (!ContractShapeValidation.IsValid(request) || request.Meta.CommandId?.Value.Length != 16) throw BootstrapWire.Refused();
        var result = call.TryRenew(request.Meta.CommandId.Value.Span, out var expiry);
        if (result != LocalRpcRegistrationRefusal.None) throw BootstrapWire.Refused();
        return Task.FromResult(new LocalBootstrapServiceRenewResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId?.Clone() },
            Value = new LocalBootstrapServiceRenewValue { ExpiresAt = BootstrapWire.ToInstant(expiry) },
        });
    }

    private LocalRpcBootstrapCall Call(ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.CancellationToken.ThrowIfCancellationRequested();
        var call = context.GetBootstrapCall();
        if (call is null || !ReferenceEquals(call.Registration, _registration)) throw BootstrapWire.Refused();
        return call;
    }
}

internal static class BootstrapWire
{
    internal static Guid FromId(Id? value) => value?.Value.Length == 16 ? new Guid(value.Value.Span, bigEndian: true) : Guid.Empty;
    internal static Id ToId(Guid value) => new() { Value = ByteString.CopyFrom(value.ToByteArray(bigEndian: true)) };
    internal static Instant ToInstant(DateTimeOffset value) => new()
    {
        UnixSeconds = value.ToUnixTimeSeconds(),
        Nanos = (uint)(value.UtcTicks % TimeSpan.TicksPerSecond * 100),
    };
    internal static DateTimeOffset FromInstant(Instant value) => DateTimeOffset.FromUnixTimeSeconds(value.UnixSeconds).AddTicks(value.Nanos / 100);
    internal static RpcException Refused() => new(new Status(StatusCode.Unauthenticated, "Registration refused."));
}
