// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Contracts;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using ArcForges.LocalRpc;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.ContentSandbox.Broker;

/// <summary>
/// The parent's generated LocalBootstrap service: the thin mapping between the generated messages and the three steps of the
/// registration the gate attached to each call. Every refusal is one <c>UNAUTHENTICATED</c> status that names no cause, so the stream
/// peer learns nothing about the secret, the nonce or the state.
/// </summary>
internal sealed class BootstrapService : LocalBootstrapService.LocalBootstrapServiceBase
{
    public override Task<LocalBootstrapServiceChallengeResponse> Challenge(LocalBootstrapServiceChallengeRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var call = context.GetBootstrapCall() ?? throw Refused();
        var expected = call.Registration.Launch.Descriptor.Identity;
        LocalRpcLaunchIdentity claimed;
        try
        {
            var manifest = request.Caller ?? throw Refused();
            claimed = new LocalRpcLaunchIdentity(
                expected.ChildKind,
                manifest.AppId,
                Convert.FromHexString(manifest.BuildHash),
                manifest.ContractMajors.Count == 1 ? manifest.ContractMajors[0] : 0,
                Convert.FromHexString(manifest.ContractSetHash));
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw Refused();
        }

        if (!SandboxRecords.TryReadId(request.InstanceId, out var instance))
        {
            throw Refused();
        }

        var refusal = call.TryChallenge(instance, request.Challenge.Span, claimed, out var challenge);
        if (refusal != LocalRpcRegistrationRefusal.None || challenge is null)
        {
            throw Refused();
        }

        return Task.FromResult(new LocalBootstrapServiceChallengeResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta?.CorrelationId },
            Value = new LocalBootstrapServiceChallengeValue
            {
                ChallengeId = SandboxRecords.ToWireId(challenge.ChallengeId),
                ServerChallenge = ByteString.CopyFrom(challenge.ServerChallenge.Span),
                ExpiresAt = SandboxRecords.ToInstant(challenge.ExpiresAtUtc),
                Server = new EndpointManifest { InstanceId = SandboxRecords.ToWireId(challenge.ServerInstanceId) },
            },
        });
    }

    public override Task<LocalBootstrapServiceConfirmResponse> Confirm(LocalBootstrapServiceConfirmRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var call = context.GetBootstrapCall() ?? throw Refused();
        if (!SandboxRecords.TryReadId(request.ChallengeId, out var challengeId))
        {
            throw Refused();
        }

        var refusal = call.TryConfirm(challengeId, request.Proof.Span, out var grant);
        if (refusal != LocalRpcRegistrationRefusal.None || grant is null)
        {
            throw Refused();
        }

        return Task.FromResult(new LocalBootstrapServiceConfirmResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta?.CorrelationId },
            Value = new LocalBootstrapServiceConfirmValue
            {
                PeerNonce = ByteString.CopyFrom(grant.PeerNonce.Span),
                ExpiresAt = SandboxRecords.ToInstant(grant.ExpiresAtUtc),
            },
        });
    }

    public override Task<LocalBootstrapServiceRenewResponse> Renew(LocalBootstrapServiceRenewRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var call = context.GetBootstrapCall() ?? throw Refused();
        var command = request.Meta?.CommandId?.Value ?? ByteString.Empty;
        var refusal = call.TryRenew(command.Span, out var expiry);
        if (refusal != LocalRpcRegistrationRefusal.None)
        {
            throw Refused();
        }

        return Task.FromResult(new LocalBootstrapServiceRenewResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta?.CorrelationId },
            Value = new LocalBootstrapServiceRenewValue { ExpiresAt = SandboxRecords.ToInstant(expiry) },
        });
    }

    private static RpcException Refused() => new(new Status(StatusCode.Unauthenticated, "Registration refused."));
}
