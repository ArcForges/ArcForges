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

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real local RPC and relay signing with a scripted center, not a native file effect or actual center.</summary>
public sealed class FleetMutationProxyTests
{
    [Fact(Timeout = 120_000)]
    public async Task MutationsSignExactInnerBytesAndValidateResponsesWithoutTrustingClaimedCaller()
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
        await using var script = await node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        var target = new Id { Value = ByteString.CopyFrom(nodeId) };
        var meta = CloudNode.Command();
        var request = new FileServiceWriteFileRequest
        {
            Meta = meta.Clone(),
            Path = new FilePath { WorkspaceId = CommandIds.New(), Path = "target" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFromUtf8("payload"),
        };
        // An unknown field is deliberately retained: the signed digest is over transmitted bytes, not a reserialization.
        var raw = ByteString.CopyFrom([.. request.ToByteArray(), 0xa0, 0x06, 0x01]);
        var hash = ByteString.CopyFrom(SHA256.HashData(request.Data.Span));
        var writeInner = new FileServiceWriteFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FileServiceWriteFileValue
            {
                Result = new FileMutationResult
                {
                    CommandId = meta.CommandId.Clone(),
                    SizeBytes = (ulong)request.Data.Length,
                    Sha256 = hash,
                }
            },
            Audit = new FileAuditMetadata
            {
                Observations = { new FileAuditObservation
            {
                Kind = FileAuditKind.WrittenBytes, SizeBytes = (ulong)request.Data.Length,
                DigestInputBytes = (ulong)request.Data.Length, Sha256 = hash,
            } }
            },
        };
        var outer = new FleetServiceWriteNodeFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = meta.CorrelationId.Clone() },
            Value = new FleetServiceWriteNodeFileValue { NodeId = target.Clone(), Response = writeInner.ToByteString() },
        };
        center.Script("WriteNodeFile", Reply(outer));
        var sentRequest = new FleetServiceWriteNodeFileRequest
        {
            Meta = meta.Clone(),
            NodeId = target.Clone(),
            Request = raw,
            Caller = new RoutedCaller { Kind = CallerKind.NodeRelay, RelayingNodeId = CommandIds.New(), LocalOrigin = Origin.Human },
            RelayAssertion = ByteString.CopyFrom([1, 2, 3]),
        };
        var response = await fleet.WriteNodeFileAsync(sentRequest, cancellationToken: ct);
        Assert.NotNull(response.Value);
        Assert.Equal(writeInner.ToByteString(), response.Value.Response);
        var forwarded = FleetServiceWriteNodeFileRequest.Parser.ParseFrom(
            FakeCenter.Payload(Assert.Single(center.CallsOf("WriteNodeFile")).Body));
        var assertion = RelayAssertion.Parser.ParseFrom(forwarded.RelayAssertion);
        Assert.Equal(Origin.Script, forwarded.Caller.LocalOrigin);
        Assert.Equal(target, forwarded.Caller.RelayingNodeId);
        Assert.Equal(RoutedMethod.WriteNodeFile, assertion.Method);
        Assert.Equal(target, assertion.TargetNodeId);
        Assert.Equal(meta.CommandId, assertion.CommandId);
        Assert.Equal(raw, forwarded.Request);
        Assert.Equal(SHA256.HashData(raw.Span), assertion.RequestSha256.ToByteArray());
        Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(assertion, center.Endpoint)!, assertion.Signature.ToByteArray()));

        var invalid = sentRequest.Clone();
        invalid.Meta.CommandId = CommandIds.New();
        Assert.Equal("invalid_argument", (await fleet.WriteNodeFileAsync(invalid, cancellationToken: ct)).Error.Code);
        Assert.Single(center.CallsOf("WriteNodeFile"));

        writeInner.Value.Result.CommandId = CommandIds.New();
        outer.Value.Response = writeInner.ToByteString();
        center.Script("WriteNodeFile", Reply(outer));
        var rejected = await fleet.WriteNodeFileAsync(sentRequest, cancellationToken: ct);
        Assert.Null(rejected.Value);
        Assert.Equal("internal", rejected.Error.Code);

        var editMeta = CloudNode.Command();
        var edit = new FileServiceEditFileRequest
        {
            Meta = editMeta.Clone(),
            Path = request.Path.Clone(),
            ExpectedSha256 = ByteString.CopyFrom(new byte[32]),
            OldText = "old",
            NewText = "new",
            ExpectedOccurrences = 1,
        };
        var editRaw = ByteString.CopyFrom([.. edit.ToByteArray(), 0xa0, 0x06, 0x01]);
        var unknown = new FileServiceEditFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = editMeta.CorrelationId.Clone() },
            Error = new ArcError
            {
                Category = ErrorCategory.Execution,
                Code = "operation_failed",
                MessageKey = "error.execution.operation_failed",
                Effect = EffectCertainty.Unknown,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                CorrelationId = editMeta.CorrelationId.Clone(),
                Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "file_outcome_unknown" } },
            },
        };
        center.Script("EditNodeFile", Reply(new FleetServiceEditNodeFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = editMeta.CorrelationId.Clone() },
            Value = new FleetServiceEditNodeFileValue { NodeId = target.Clone(), Response = unknown.ToByteString() },
        }));
        var editResult = await fleet.EditNodeFileAsync(new FleetServiceEditNodeFileRequest
        {
            Meta = editMeta.Clone(),
            NodeId = target.Clone(),
            Request = editRaw,
        }, cancellationToken: ct);
        Assert.Equal(unknown.ToByteString(), editResult.Value.Response);
        var forwardedEdit = FleetServiceEditNodeFileRequest.Parser.ParseFrom(
            FakeCenter.Payload(Assert.Single(center.CallsOf("EditNodeFile")).Body));
        var editAssertion = RelayAssertion.Parser.ParseFrom(forwardedEdit.RelayAssertion);
        Assert.Equal(RoutedMethod.EditNodeFile, editAssertion.Method);
        Assert.Equal(editMeta.CommandId, editAssertion.CommandId);
        Assert.Equal(editRaw, forwardedEdit.Request);
        Assert.Equal(SHA256.HashData(editRaw.Span), editAssertion.RequestSha256.ToByteArray());
        Assert.True(FakeChannelPeer.Verify(publicKey, RelaySignatures.AssertionInput(editAssertion, center.Endpoint)!, editAssertion.Signature.ToByteArray()));

        await using var agent = await node.ChannelAsync(Origin.Agent);
        var agentFleet = new FleetService.FleetServiceClient(agent.CallInvoker);
        var foreign = sentRequest.Clone();
        foreign.NodeId = CommandIds.New();
        Assert.Equal("permission_denied", (await agentFleet.WriteNodeFileAsync(foreign, cancellationToken: ct)).Error.Code);
        Assert.Equal(2, center.CallsOf("WriteNodeFile").Count);
    }

    private static FakeFault.Raw Reply(IMessage response) => new([.. FakeCenter.DataFrame(response), .. FakeCenter.TrailerFrame(0, null)]);
}
