// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real Node, signed WebSocket, SQLite and native files with a mocked Center peer; not real Center acceptance.</summary>
public sealed class RoutedRemovalPlanChannelTests
{
    [Fact(Timeout = 120_000)]
    public async Task SignedPlanUsesActualCallerAndRawBytesAndReplaysWithoutRemovingFiles()
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
        Assert.False(first.Value.Plan.QuarantineAvailable);
        var replay = await Invoke(caller);
        Assert.Equal(first.ToByteString(), replay.ToByteString());
        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var denied = await Invoke(foreign);
        Assert.Equal("command_id_reused", denied.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, denied.Error.Effect);
        Assert.Equal("signed-plan-only-private-body", File.ReadAllText(marker));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(SHA256.HashData(raw), node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT request_sha256 FROM file_removal_plan WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        Assert.Empty(connection.UnverifiedResults);
    }
}
