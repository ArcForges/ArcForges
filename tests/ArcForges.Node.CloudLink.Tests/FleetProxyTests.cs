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
using Grpc.Core;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>REAL local endpoint, proxy, node signing and guarded HTTP transport; scripted center responses are MOCKED.</summary>
public sealed class FleetProxyTests
{
    [Fact(Timeout = 60000)]
    public async Task TheProxyUsesTheConnectionOriginAndSignsTheExactRequestWithFreshNonces()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
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

        var connection = await center.Channel.ProvedAsync();
        await Eventually.TrueAsync(() => node.Cloud.Status().Relay == RelayState.Connected, "the node channel is connected");
        await using var script = await node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        var listValue = new FleetServiceListNodesResponse { Meta = new ResponseMeta(), Value = new FleetServiceListNodesValue() };
        center.Script("ListNodes", Reply(listValue));
        center.Script("ListNodes", Reply(listValue));
        var forged = new RoutedCaller { Kind = CallerKind.NodeRelay, RelayingNodeId = CommandIds.New(), LocalOrigin = Origin.Human };
        var list = new FleetServiceListNodesRequest { Meta = CloudNode.Command(), Caller = forged, RelayAssertion = ByteString.CopyFrom([1, 2, 3]) };
        Assert.NotNull((await fleet.ListNodesAsync(list, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: TestContext.Current.CancellationToken)).Value);
        Assert.NotNull((await fleet.ListNodesAsync(list, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: TestContext.Current.CancellationToken)).Value);
        var captures = center.CallsOf("ListNodes");
        Assert.Equal(2, captures.Count);
        var first = FleetServiceListNodesRequest.Parser.ParseFrom(FakeCenter.Payload(captures[0].Body));
        var second = FleetServiceListNodesRequest.Parser.ParseFrom(FakeCenter.Payload(captures[1].Body));
        var firstAssertion = RelayAssertion.Parser.ParseFrom(first.RelayAssertion);
        var secondAssertion = RelayAssertion.Parser.ParseFrom(second.RelayAssertion);
        Assert.Equal(Origin.Script, first.Caller.LocalOrigin);
        Assert.Equal(nodeId, first.Caller.RelayingNodeId.Value.ToByteArray());
        Assert.Equal(Origin.Script, firstAssertion.LocalOrigin);
        Assert.Equal(nodeId, firstAssertion.RelayingNodeId.Value.ToByteArray());
        Assert.Equal(connection.Installation, firstAssertion.RelayingInstallationId.Value.ToByteArray());
        Assert.Equal(firstAssertion.LocalSessionId, secondAssertion.LocalSessionId);
        Assert.NotEqual(firstAssertion.RelayNonce, secondAssertion.RelayNonce);
        Assert.Null(firstAssertion.TargetNodeId);
        Assert.Null(firstAssertion.CommandId);
        var withoutAssertion = first.Clone();
        withoutAssertion.ClearRelayAssertion();
        Assert.Equal(SHA256.HashData(withoutAssertion.ToByteArray()), firstAssertion.RequestSha256.ToByteArray());
        Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(firstAssertion, center.Endpoint)!, firstAssertion.Signature.ToByteArray()));

        // A signed request can outlive a center switch. Never send its payload to the new center even if node/installation IDs match.
        Assert.True(CenterEndpoint.TryParse("http://localhost:9", out var differentCenter, out _));
        var sentToDifferentCenter = false;
        var mismatch = await node.Cloud.ForwardRelayAsync(new BoundRelayAssertion(firstAssertion, differentCenter),
            (client, options) =>
            {
                sentToDifferentCenter = true;
                return Task.FromResult(new FleetServiceListNodesResponse());
            }, TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(CenterOutcome.Unreachable, mismatch.Outcome);
        Assert.False(sentToDifferentCenter);

        var target = new Id { Value = ByteString.CopyFrom(nodeId) };
        var inner = new TaskServiceGetTaskRequest { Meta = CloudNode.Command(), TaskId = CommandIds.New() }.ToByteString();
        var nested = new TaskServiceGetTaskResponse { Meta = new ResponseMeta(), Value = new TaskServiceGetTaskValue() }.ToByteString();
        center.Script("GetNodeTask", Reply(new FleetServiceGetNodeTaskResponse
        {
            Meta = new ResponseMeta(), Value = new FleetServiceGetNodeTaskValue { NodeId = target, Response = nested },
        }));
        var result = await fleet.GetNodeTaskAsync(new FleetServiceGetNodeTaskRequest
        {
            Meta = CloudNode.Command(), NodeId = target, Caller = forged, Request = inner,
        }, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(nested, result.Value.Response);
        var sent = FleetServiceGetNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(center.CallsOf("GetNodeTask")).Body));
        var assertion = RelayAssertion.Parser.ParseFrom(sent.RelayAssertion);
        Assert.Equal(inner, sent.Request);
        Assert.Equal(SHA256.HashData(inner.Span), assertion.RequestSha256.ToByteArray());
        Assert.Equal(target, assertion.TargetNodeId);
        Assert.Null(assertion.CommandId);
        Assert.Equal(firstAssertion.LocalSessionId, assertion.LocalSessionId);
        Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(assertion, center.Endpoint)!, assertion.Signature.ToByteArray()));

        await using var agent = await node.ChannelAsync(Origin.Agent);
        var agentFleet = new FleetService.FleetServiceClient(agent.CallInvoker);
        var other = new Id { Value = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(16)) };
        var refused = await agentFleet.GetNodeTaskAsync(new FleetServiceGetNodeTaskRequest { Meta = CloudNode.Command(), NodeId = other, Request = inner }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("permission_denied", refused.Error.Code);
        Assert.Equal("relayed_agent_own_node_only", refused.Error.Details.State.Reason);
        Assert.Single(center.CallsOf("GetNodeTask"));

        var unsupported = await Assert.ThrowsAsync<RpcException>(async () =>
            await fleet.RenameNodeAsync(new FleetServiceRenameNodeRequest(), deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(StatusCode.Unimplemented, unsupported.StatusCode);
    }

    [Fact(Timeout = 60000)]
    public async Task ExpiredAssertionIsResignedWithTheSameMutationBytesAndCommand()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var center = await FakeCenter.StartAsync();
        center.ScriptedFleet = true;
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.CommandKeys.Add(center.Channel.CommandPublicKey);
            center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        await center.Channel.ProvedAsync();
        await Eventually.TrueAsync(() => node.Cloud.Status().Relay == RelayState.Connected, "the node channel is connected");
        await using var script = await node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        var target = new Id { Value = ByteString.CopyFrom(nodeId) };
        var meta = CloudNode.Command();
        var inner = new TaskServiceCancelTaskRequest { Meta = meta.Clone(), TaskId = CommandIds.New() }.ToByteString();
        var expired = new ArcError
        {
            Category = ErrorCategory.Authentication, Code = "unauthenticated", MessageKey = "error.authentication.unauthenticated",
            Effect = EffectCertainty.DidNotHappen, Retry = new RetryAdvice { Mode = RetryMode.SameCommand },
            Details = new ErrorDetails { State = new StateFailure { State = "relay_assertion", Reason = "expired" } },
        };
        center.Script("CancelNodeTask", Reply(new FleetServiceCancelNodeTaskResponse { Meta = new ResponseMeta(), Error = expired }));
        center.Script("CancelNodeTask", Reply(new FleetServiceCancelNodeTaskResponse
        {
            Meta = new ResponseMeta(), Value = new FleetServiceCancelNodeTaskValue { NodeId = target, Response = ByteString.CopyFrom([1]) },
        }));
        var answer = await fleet.CancelNodeTaskAsync(new FleetServiceCancelNodeTaskRequest { Meta = meta, NodeId = target, Request = inner },
            deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: TestContext.Current.CancellationToken);
        Assert.NotNull(answer.Value);
        var calls = center.CallsOf("CancelNodeTask").Select(call => FleetServiceCancelNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, calls.Count);
        var first = RelayAssertion.Parser.ParseFrom(calls[0].RelayAssertion);
        var second = RelayAssertion.Parser.ParseFrom(calls[1].RelayAssertion);
        Assert.Equal(inner, calls[0].Request);
        Assert.Equal(inner, calls[1].Request);
        Assert.Equal(meta.CommandId, calls[0].Meta.CommandId);
        Assert.Equal(meta.CommandId, calls[1].Meta.CommandId);
        Assert.Equal(meta.CommandId, first.CommandId);
        Assert.Equal(meta.CommandId, second.CommandId);
        Assert.Equal(first.RequestSha256, second.RequestSha256);
        Assert.NotEqual(first.RelayNonce, second.RelayNonce);
    }

    [Fact(Timeout = 60000)]
    public async Task UnsignedNodeRefusesWithoutContactingTheCenter()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var center = await FakeCenter.StartAsync();
        center.ScriptedFleet = true;
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        await using var local = await node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(local.CallInvoker);
        var response = await fleet.ListNodesAsync(new FleetServiceListNodesRequest { Meta = CloudNode.Command() }, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("not_signed_in", response.Error.Code);
        Assert.Empty(center.CallsOf("ListNodes"));
    }

    private static FakeFault.Raw Reply(IMessage response) => new([.. FakeCenter.DataFrame(response), .. FakeCenter.TrailerFrame(0, null)]);
}
