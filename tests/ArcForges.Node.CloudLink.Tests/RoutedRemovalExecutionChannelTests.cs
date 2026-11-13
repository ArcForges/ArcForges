// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real Node, signed WebSocket, SQLite and native files with a mocked Center peer; not real Center acceptance.</summary>
public sealed class RoutedRemovalExecutionChannelTests
{
    [Fact(Timeout = 120_000)]
    public async Task SignedExecutionRefusalPreservesItsCallerAndRawReceiptWithoutMovingFiles()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
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

        var connection = await center.Channel.ProvedAsync();
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
            LocalOrigin = Origin.Human,
            LocalSessionId = CommandIds.New(),
        };
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "signed-removal-plan-root")).FullName;
        var tree = Directory.CreateDirectory(Path.Combine(root, "tree")).FullName;
        var marker = Path.Combine(tree, "marker");
        File.WriteAllText(marker, "signed-plan-only-private-body");
        var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = CloudNode.Command(), Path = root, Name = "plan" };
        var registration = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.RegisterNodeWorkspace,
            Payload = register.ToByteArray(),
            Caller = caller,
            CommandId = register.Meta.CommandId,
            Lifetime = TimeSpan.FromSeconds(30),
        }).Call;
        await connection.SendCallAsync(registration);
        var registeredFrame = await connection.ResultOfAsync(registration.CallId);
        await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(registration.CallId)), "verified registration");
        var registered = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(registeredFrame.Payload);
        Assert.Null(registered.Error);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = CloudNode.Command(),
            WorkspacePath = new NodeFilePath { WorkspaceId = registered.Value.Workspace.WorkspaceId, Path = "tree" },
        };
        var raw = request.ToByteArray();

        async Task<FileServicePlanRemovalResponse> Invoke(CenterCaller source)
        {
            ct.ThrowIfCancellationRequested();
            var built = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = RoutedMethod.PlanNodeRemoval,
                Payload = raw,
                Caller = source,
                CommandId = request.Meta.CommandId,
                Lifetime = TimeSpan.FromSeconds(30),
            });
            Assert.Equal(request.Meta.CommandId, built.Header!.CommandId);
            var call = built.Call;
            await connection.SendCallAsync(call);
            var frame = await connection.ResultOfAsync(call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(call.CallId)), "verified removal plan");
            Assert.Equal(RoutedOutcome.Executed, connection.VerifiedResults.Single(x => x.Header.CallId.Equals(call.CallId)).Header.Outcome);
            return FileServicePlanRemovalResponse.Parser.ParseFrom(frame.Payload);
        }

        var first = await Invoke(caller);
        Assert.True(NodeShapes.IsValid(first));
        Assert.Null(first.Error);
        Assert.Equal(2, first.Value.Plan.Items.Count);
        Assert.True(first.Value.Plan.RequiresApproval);
        Assert.True(first.Value.Plan.QuarantineAvailable);

        var execute = new FileServiceExecuteRemovalRequest
        {
            Meta = CloudNode.Command(),
            PlanId = first.Value.Plan.PlanId.Clone(),
            PlanDigest = first.Value.Plan.Digest,
            DeleteWithoutQuarantine = true,
        };
        var executionRaw = execute.ToByteArray();
        async Task<ByteString> Execute(CenterCaller source)
        {
            var built = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = RoutedMethod.ExecuteNodeRemoval,
                Payload = executionRaw,
                Caller = source,
                CommandId = execute.Meta.CommandId,
                Lifetime = TimeSpan.FromSeconds(30),
            });
            Assert.Equal(execute.Meta.CommandId, built.Header!.CommandId);
            await connection.SendCallAsync(built.Call);
            var frame = await connection.ResultOfAsync(built.Call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(built.Call.CallId)),
                "actual signed removal execution refusal");
            var signed = connection.VerifiedResults.Single(x => x.Header.CallId.Equals(built.Call.CallId));
            Assert.Equal(RoutedOutcome.Executed, signed.Header.Outcome);
            return frame.Payload;
        }
        var executionBytes = await Execute(caller);
        var response = FileServiceExecuteRemovalResponse.Parser.ParseFrom(executionBytes);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Null(response.Value);
        Assert.Equal("enforcement_unavailable", response.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(RetryMode.Never, response.Error.Retry.Mode);
        var targetId = new Id { Value = ByteString.CopyFrom(nodeId) };
        Assert.True(RoutedFileResponseValidation.ExecuteRemoval(new FleetServiceExecuteNodeRemovalResponse
        {
            Value = new FleetServiceExecuteNodeRemovalValue { NodeId = targetId.Clone(), Response = executionBytes },
        }, targetId, execute));
        Assert.Equal(executionBytes, await Execute(caller));
        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        Assert.Equal("command_id_reused", FileServiceExecuteRemovalResponse.Parser.ParseFrom(await Execute(foreign)).Error.Code);
        Assert.Equal("signed-plan-only-private-body", File.ReadAllText(marker));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan;")));
        Assert.Empty(connection.UnverifiedResults);
    }

    [Fact(Timeout = 30_000)]
    public async Task RemovalRelayAssertionSignsTheExactCommandAndRefusesItsAbsence()
    {
        var ct = TestContext.Current.CancellationToken;
        var (link, connection) = await ChannelTests.ConnectedAsync();
        await using (link)
        {
            var raw = "owned-removal-metadata-fixture"u8.ToArray();
            var command = CommandIds.New();
            var target = new Id { Value = ByteString.CopyFrom(link.NodeId) };
            var assertion = await link.Service.SignRelayAssertionAsync(Origin.Human, CommandIds.New(),
                RoutedMethod.ExecuteNodeRemoval, SHA256.HashData(raw), target, command, ct);
            Assert.NotNull(assertion);
            Assert.Equal(command, assertion.CommandId);
            Assert.Equal(RoutedMethod.ExecuteNodeRemoval, assertion.Method);
            Assert.Equal(SHA256.HashData(raw), assertion.RequestSha256.ToByteArray());
            Assert.Equal(1, connection.Received.Count(frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest));
            var input = RelaySignatures.AssertionInput(assertion, link.Center.Endpoint);
            Assert.NotNull(input);
            Assert.True(FakeChannelPeer.Verify(link.NodePublicKey, input, assertion.Signature.ToByteArray()));
            assertion.CommandId = null;
            Assert.Null(RelaySignatures.AssertionInput(assertion, link.Center.Endpoint));
        }
    }
}
