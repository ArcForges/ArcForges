// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;
using WireDecimal = ArcForges.Contracts.Foundation.V1.Decimal;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real local Fleet RPC and relay signature; the Center response is an isolated fixture.</summary>
public sealed class OptionalAvailableFleetProxyTests
{
    [Fact(Timeout = 60_000)]
    public async Task RealFleetProxyPreservesGenericAvailableAndRejectsInvalidProfile()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.ScriptedFleet = true;
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        byte[] publicKey;
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            publicKey = key.PublicKey;
            center.CommandKeys.Add(center.Channel.CommandPublicKey);
            center.Channel.RegisterNodeKey(credentials.AccessToken, publicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }
        await center.Channel.ProvedAsync();
        await Eventually.TrueAsync(() => node.Cloud.Status().Relay == RelayState.Connected, "the node channel is connected");
        await using var human = await node.ChannelAsync(Origin.Human);
        var fleet = new FleetService.FleetServiceClient(human.CallInvoker);
        var target = new Id { Value = ByteString.CopyFrom(nodeId) };
        var meta = CloudNode.Command();
        var request = new FileServicePlanRemovalRequest
        {
            Meta = meta.Clone(),
            WorkspacePath = new FilePath { WorkspaceId = CommandIds.New(), Path = "tree" },
        };
        var limit = new LimitFailure
        {
            LimitName = "removal_ownership_input_bytes",
            Maximum = new WireDecimal { Value = "67108864" },
            Available = new WireDecimal { Value = "1.00" },
        };
        var inner = new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Error = new ArcError
            {
                Category = ErrorCategory.Resource,
                Code = "too_large",
                MessageKey = "error.resource.too_large",
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Effect = EffectCertainty.DidNotHappen,
                CorrelationId = meta.CorrelationId.Clone(),
                Details = new ErrorDetails { Limit = limit },
            },
            Audit = new FileAuditMetadata
            {
                Observations =
                {
                    new FileAuditObservation
                    {
                        Kind = FileAuditKind.InputBytes, SizeBytes = 1, DigestInputBytes = 1,
                        Sha256 = ByteString.CopyFrom(SHA256.HashData("fixture-observation"u8)),
                    },
                },
            },
        };
        var outer = new FleetServicePlanNodeRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target.Clone() },
        };
        var fleetRequest = new FleetServicePlanNodeRemovalRequest
        {
            Meta = meta.Clone(),
            NodeId = target.Clone(),
            Request = request.ToByteString(),
        };
        async Task<FleetServicePlanNodeRemovalResponse> Invoke()
        {
            outer.Value.Response = inner.ToByteString();
            center.Script("PlanNodeRemoval", new FakeFault.Raw([.. FakeCenter.DataFrame(outer), .. FakeCenter.TrailerFrame(0, null)]));
            return await fleet.PlanNodeRemovalAsync(fleetRequest, cancellationToken: ct);
        }

        Assert.True(NodeShapes.IsValid(inner));
        var raw = inner.ToByteString();
        var reply = await Invoke();
        Assert.Null(reply.Error);
        Assert.NotNull(reply.Value);
        Assert.Equal(raw, reply.Value.Response);
        var forwarded = FleetServicePlanNodeRemovalRequest.Parser.ParseFrom(
            FakeCenter.Payload(Assert.Single(center.CallsOf("PlanNodeRemoval")).Body));
        var assertion = RelayAssertion.Parser.ParseFrom(forwarded.RelayAssertion);
        Assert.Equal(RoutedMethod.PlanNodeRemoval, assertion.Method);
        Assert.Equal(meta.CommandId, assertion.CommandId);
        Assert.Equal(request.ToByteString(), forwarded.Request);
        Assert.Equal(SHA256.HashData(forwarded.Request.Span), assertion.RequestSha256.ToByteArray());
        Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(assertion, center.Endpoint)!, assertion.Signature.ToByteArray()));

        limit.Available.Value = "01.0";
        Assert.False(NodeShapes.IsValid(inner));
        var badAvailable = await Invoke();
        Assert.Null(badAvailable.Value);
        Assert.Equal("internal", badAvailable.Error.Code);
        limit.Available.Value = "1.00";
        limit.Maximum.Value = "67108864.00";
        Assert.True(NodeShapes.IsValid(inner));
        var badMaximum = await Invoke();
        Assert.Null(badMaximum.Value);
        Assert.Equal("internal", badMaximum.Error.Code);
        Assert.Equal(3, center.CallsOf("PlanNodeRemoval").Count);
    }
}
