// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;
using WireDecimal = ArcForges.Contracts.Foundation.V1.Decimal;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Real selected Host and local Fleet RPC; the Center is an isolated scripted fixture.</summary>
[Trait("loop", "local")]
public sealed class OptionalAvailableFleetHostTests
{
    [Fact(Timeout = 90_000)]
    public async Task SelectedHostPreservesGenericAvailableWithoutRelaxingMaximum()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        center.ScriptedFleet = true;
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        using var host = await node.StartNodeAsync();
        Assert.False(host.HasExited);
        try
        {
            await using var human = await node.HumanChannelAsync();
            var info = await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: ct);
            Assert.Null(info.Error);
            var nodeId = info.Value.Node.Node.NodeId;
            var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest
            {
                Meta = Command(),
                Method = SignInMethod.DeviceCode,
            }, cancellationToken: ct);
            Assert.Null(begun.Error);
            center.ApproveDevice();
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(
                new AccountServiceGetAccountStatusRequest(), cancellationToken: ct)).Value.Status.Relay == RelayState.Connected,
                TimeSpan.FromSeconds(30), "the fixture Center channel is connected");
            var connection = await center.Channel.ProvedAsync();
            var publicKey = Assert.IsType<byte[]>(center.Channel.NodeKeyOf(connection.Installation));
            var fleet = new FleetService.FleetServiceClient(human.CallInvoker);
            var meta = Command();
            var request = new FileServicePlanRemovalRequest
            {
                Meta = meta.Clone(),
                WorkspacePath = new FilePath { WorkspaceId = CommandIds.New(), Path = "fixture" },
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
            };
            var outer = new FleetServicePlanNodeRemovalResponse
            {
                Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
                Value = new FleetServicePlanNodeRemovalValue { NodeId = nodeId.Clone() },
            };
            var sentRequest = new FleetServicePlanNodeRemovalRequest
            {
                Meta = meta.Clone(),
                NodeId = nodeId.Clone(),
                Request = request.ToByteString(),
            };
            async Task<FleetServicePlanNodeRemovalResponse> Invoke()
            {
                outer.Value.Response = inner.ToByteString();
                center.Script("PlanNodeRemoval", new FakeFault.Raw([.. FakeCenter.DataFrame(outer), .. FakeCenter.TrailerFrame(0, null)]));
                return await fleet.PlanNodeRemovalAsync(sentRequest, cancellationToken: ct);
            }

            Assert.True(NodeShapes.IsValid(inner));
            var original = inner.ToByteString();
            var result = await Invoke();
            Assert.Null(result.Error);
            Assert.NotNull(result.Value);
            Assert.Equal(original, result.Value.Response);
            var forwarded = FleetServicePlanNodeRemovalRequest.Parser.ParseFrom(
                FakeCenter.Payload(Assert.Single(center.CallsOf("PlanNodeRemoval")).Body));
            var assertion = RelayAssertion.Parser.ParseFrom(forwarded.RelayAssertion);
            Assert.Equal(RoutedMethod.PlanNodeRemoval, assertion.Method);
            Assert.Equal(meta.CommandId, assertion.CommandId);
            Assert.Equal(request.ToByteString(), forwarded.Request);
            Assert.Equal(SHA256.HashData(forwarded.Request.Span), assertion.RequestSha256.ToByteArray());
            Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(assertion, center.Endpoint)!, assertion.Signature.ToByteArray()));

            limit.Available.Value = "-0.0";
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
        }
        finally
        {
            if (node.Descriptor() is { } descriptor && descriptor.ProcessIsAlive())
            {
                await using var cleanup = await node.HumanChannelAsync();
                var signedOut = await cleanup.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() },
                    deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: CancellationToken.None);
                Assert.Null(signedOut.Error);
                await node.StopNodeAsync();
            }
        }
    }

    private static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
}
