// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Client;
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
        Assert.True(first.Value.Plan.QuarantineAvailable);
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
    // The real 985-entry size proof is timing-sensitive under concurrent project I/O; keep the file-operation budget unchanged.
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task SignedOversizedPlanReturnsAndReplaysTheCommittedInnerRefusal()
    {
        var ct = TestContext.Current.CancellationToken;
        var elapsed = Stopwatch.StartNew();
        var output = TestContext.Current.TestOutputHelper;
        void Observe(string phase) => output?.WriteLine($"oversized-plan elapsed-ms={elapsed.Elapsed.TotalMilliseconds:F0} {phase}");
        await using var center = await FakeCenter.StartAsync();
        var ownedNode = CloudNode.Create(center.Endpoint.Url);
        ownedNode.WrapRoutedDispatcher = inner => new TimingDispatcher(inner, Observe);
        await using var node = await ownedNode.StartAsync();
        Observe("node-ready");
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
        Observe("channel-proved");
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
            LocalOrigin = Origin.Human,
            LocalSessionId = CommandIds.New(),
        };
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "signed-budget-root")).FullName;
        var deep = Directory.CreateDirectory(Path.Combine(root, "tree")).FullName;
        for (var depth = 0; depth < 5; depth++)
            deep = Directory.CreateDirectory(Path.Combine(deep, new string((char)('a' + depth), 210))).FullName;
        for (var index = 0; index < 980; index++)
            File.WriteAllBytes(Path.Combine(deep, "f" + index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);
        Observe("native-985-entry-tree-created");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        Observe("workspace-registered");
        var request = new FileServicePlanRemovalRequest
        {
            Meta = CloudNode.Command(),
            WorkspacePath = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "tree" },
        };
        var raw = request.ToByteArray();
        async Task<ByteString> Invoke()
        {
            var built = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = RoutedMethod.PlanNodeRemoval,
                Payload = raw,
                Caller = caller,
                CommandId = request.Meta.CommandId,
                Lifetime = TimeSpan.FromSeconds(30),
            });
            Observe($"call-built declared-lifetime-ms=30000 deadline-ms={ProtoTime.ToDateTimeOffset(built.Header!.Deadline)?.ToUnixTimeMilliseconds()}");
            await connection.SendCallAsync(built.Call);
            Observe("call-sent");
            ChannelResult frame;
            try
            {
                frame = await connection.ResultOfAsync(built.Call.CallId);
                Observe("result-received");
            }
            finally
            {
                var receipt = node.Runtime.Store.Read(reader => reader.Scalar("SELECT outcome IS NOT NULL FROM command_dedup WHERE command_id = $id;",
                    ("$id", request.Meta.CommandId.Value.ToByteArray())));
                Observe($"result-wait-ended verified={connection.VerifiedResults.Count(x => x.Header.CallId.Equals(built.Call.CallId))} "
                    + $"unverified={connection.UnverifiedResults.Count} committed-receipt={receipt}");
            }
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(built.Call.CallId)), "verified size refusal");
            Assert.Equal(RoutedOutcome.Executed, connection.VerifiedResults.Single(x => x.Header.CallId.Equals(built.Call.CallId)).Header.Outcome);
            return frame.Payload;
        }
        var first = await Invoke();
        var refusal = FileServicePlanRemovalResponse.Parser.ParseFrom(first);
        Assert.True(NodeShapes.IsValid(refusal));
        Assert.Equal(ErrorCategory.Resource, refusal.Error.Category);
        Assert.Equal("too_large", refusal.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
        Assert.Equal(RetryMode.Never, refusal.Error.Retry.Mode);
        Assert.Equal("removal_plan_response_bytes", refusal.Error.Details.Limit.LimitName);
        Assert.Equal("1040384", refusal.Error.Details.Limit.Maximum.Value);
        Assert.Null(refusal.Value);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
        Assert.Equal(SHA256.HashData(raw), node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT payload_digest FROM command_dedup WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        for (var index = 980; index < 996; index++)
            File.WriteAllBytes(Path.Combine(deep, "f" + index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);
        Assert.Equal(first, await Invoke());
        Assert.Empty(connection.UnverifiedResults);
    }

    private sealed class TimingDispatcher(IRoutedDispatcher inner, Action<string> observe) : IRoutedDispatcher
    {
        public async Task<RoutedAnswer?> DispatchAsync(VerifiedCall call, IRoutedLink link, CancellationToken cancellationToken)
        {
            if (call.Header.Method != RoutedMethod.PlanNodeRemoval)
                return await inner.DispatchAsync(call, link, cancellationToken);
            observe("dispatch-entered");
            var handler = Assert.IsType<RoutedDispatcher>(inner).FileHandlerForTests;
            Assert.NotNull(handler);
            handler.AfterRemovalSizeRefusalForTests = _ => observe("size-refusal-before-commit");
            handler.AfterRemovalSizeCommitForTests = () => observe("size-refusal-after-commit");
            try
            {
                var answer = await inner.DispatchAsync(call, link, cancellationToken);
                observe("dispatch-returned " + (answer?.Outcome.ToString() ?? "dropped"));
                return answer;
            }
            catch (Exception failure)
            {
                observe("dispatch-threw " + failure.GetType().Name);
                throw;
            }
        }
    }
}
