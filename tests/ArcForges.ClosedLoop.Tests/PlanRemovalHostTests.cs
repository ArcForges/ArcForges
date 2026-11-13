// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Real local Host, native files, SQLite and signed channel; the center peer is synthetic.</summary>
[Trait("loop", "local")]
public sealed class PlanRemovalHostTests
{
    [Fact(Timeout = 180_000)]
    public async Task CompleteThousandEntryPlanAndOversizedRefusalSurviveTheRealHostRestart()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
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
            Assert.Contains("files.v1", info.Value.Node.Features);
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
                TimeSpan.FromSeconds(30), "the synthetic center channel is connected");
            var connection = await center.Channel.ProvedAsync();
            var caller = new CenterCaller
            {
                Kind = CenterCallerKind.NodeRelay,
                AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
                RelayingNodeId = nodeId.Clone(),
                LocalOrigin = Origin.Human,
                LocalSessionId = CommandIds.New(),
            };
            var root = Directory.CreateDirectory(Path.Combine(node.Root, "host-plan-budget-root")).FullName;
            var shortTree = Directory.CreateDirectory(Path.Combine(root, "short-tree")).FullName;
            for (var index = 0; index < 1000; index++)
                File.WriteAllBytes(Path.Combine(shortTree, index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);
            var deep = Directory.CreateDirectory(Path.Combine(root, "tree")).FullName;
            for (var depth = 0; depth < 5; depth++)
                deep = Directory.CreateDirectory(Path.Combine(deep, new string((char)('a' + depth), 210))).FullName;
            for (var index = 0; index < 980; index++)
                File.WriteAllBytes(Path.Combine(deep, "f" + index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);
            const string privateBody = "native-host-plan-budget-body-not-persisted-4028";
            var marker = Path.Combine(deep, "f0000");
            File.WriteAllText(marker, privateBody);

            async Task<byte[]> Invoke(RoutedMethod method, IMessage request, Id command)
            {
                var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec
                {
                    Method = method,
                    Payload = request.ToByteArray(),
                    Caller = caller,
                    CommandId = command,
                    Lifetime = TimeSpan.FromSeconds(30),
                });
                await connection.SendCallAsync(call);
                var frame = await connection.ResultOfAsync(call.CallId);
                await TestNode.WaitAsync(() => connection.VerifiedResults.Any(value => value.Header.CallId.Equals(call.CallId)),
                    TimeSpan.FromSeconds(15), "the real Host result signature verifies");
                Assert.Equal(RoutedOutcome.Executed, connection.VerifiedResults.Single(value => value.Header.CallId.Equals(call.CallId)).Header.Outcome);
                return frame.Payload.ToByteArray();
            }

            var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = Command(), Path = root, Name = "budget" };
            var registration = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(
                await Invoke(RoutedMethod.RegisterNodeWorkspace, register, register.Meta.CommandId));
            Assert.Null(registration.Error);
            var shortRequest = new FileServicePlanRemovalRequest
            {
                Meta = Command(),
                WorkspacePath = new NodeFilePath { WorkspaceId = registration.Value.Workspace.WorkspaceId.Clone(), Path = "short-tree" },
            };
            var shortRaw = shortRequest.ToByteArray();
            var shortBytes = await Invoke(RoutedMethod.PlanNodeRemoval, shortRequest, shortRequest.Meta.CommandId);
            var success = FileServicePlanRemovalResponse.Parser.ParseFrom(shortBytes);
            Assert.True(NodeShapes.IsValid(success));
            Assert.Null(success.Error);
            Assert.Equal(1001, success.Value.Plan.Items.Count);
            Assert.Equal(shortRequest.WorkspacePath, success.Value.Plan.WorkspacePath);
            Assert.True(success.CalculateSize() <= 1_040_384);
            Assert.True(success.Value.Plan.RequiresApproval);
            AssertSuccess(node.DataRoot, shortRequest.Meta.CommandId, shortRaw, shortBytes);
            var request = new FileServicePlanRemovalRequest
            {
                Meta = Command(),
                WorkspacePath = new NodeFilePath { WorkspaceId = registration.Value.Workspace.WorkspaceId.Clone(), Path = "tree" },
            };
            var raw = request.ToByteArray();
            var first = await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId);
            var refusal = FileServicePlanRemovalResponse.Parser.ParseFrom(first);
            Assert.True(NodeShapes.IsValid(refusal));
            Assert.Equal(ErrorCategory.Resource, refusal.Error.Category);
            Assert.Equal("too_large", refusal.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
            Assert.Equal(RetryMode.Never, refusal.Error.Retry.Mode);
            Assert.Equal("removal_plan_response_bytes", refusal.Error.Details.Limit.LimitName);
            Assert.Equal("1040384", refusal.Error.Details.Limit.Maximum.Value);
            Assert.Null(refusal.Value);
            AssertReceipt(node.DataRoot, request.Meta.CommandId, raw, first);

            for (var index = 980; index < 996; index++)
                File.WriteAllBytes(Path.Combine(deep, "f" + index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);
            Assert.Equal(first, await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId));
            await node.StopNodeAsync();
            await node.StartNodeAsync();
            connection = await center.Channel.ProvedAsync(2);
            Assert.Equal(first, await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId));
            AssertReceipt(node.DataRoot, request.Meta.CommandId, raw, first);
            AssertSuccess(node.DataRoot, shortRequest.Meta.CommandId, shortRaw, shortBytes);
            Assert.Equal(privateBody, File.ReadAllText(marker));
            Assert.Empty(connection.UnverifiedResults);
            foreach (var file in new[] { StorePaths.Database(node.DataRoot), StorePaths.Database(node.DataRoot) + "-wal", node.NodeLog })
            {
                if (CloudLinkHostTests.ReadAllShared(file) is not { } bytes) continue;
                Assert.Equal(-1, bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(privateBody)));
            }
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

    private static void AssertReceipt(string dataRoot, Id command, byte[] raw, byte[] response)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = StorePaths.Database(dataRoot), Mode = SqliteOpenMode.ReadOnly };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT d.payload_digest, d.outcome,
                   (SELECT count(*) FROM file_removal_plan),
                   (SELECT count(*) FROM cleanup_plan),
                   (SELECT count(*) FROM audit_log WHERE operation = 'cleanup.plan FileService.PlanRemoval'
                    AND outcome_summary = 'refused: too_large')
            FROM command_dedup d WHERE d.command_id = $id;
            """;
        query.Parameters.AddWithValue("$id", command.Value.ToByteArray());
        using var row = query.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(0));
        Assert.Equal(response, (byte[])row.GetValue(1));
        // The earlier short-tree plan remains; the oversized operation added no plan or cleanup item.
        Assert.Equal(1L, row.GetInt64(2));
        Assert.Equal(1L, row.GetInt64(3));
        Assert.True(row.GetInt64(4) >= 1);
    }
    private static void AssertSuccess(string dataRoot, Id command, byte[] raw, byte[] response)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = StorePaths.Database(dataRoot), Mode = SqliteOpenMode.ReadOnly };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT d.payload_digest, d.outcome,
                   (SELECT count(*) FROM file_removal_plan p WHERE p.command_id = d.command_id),
                   (SELECT count(*) FROM file_removal_plan_item i JOIN file_removal_plan p ON p.plan_id = i.plan_id
                    WHERE p.command_id = d.command_id),
                   (SELECT count(*) FROM audit_log WHERE operation = 'cleanup.plan FileService.PlanRemoval'
                    AND outcome_summary = 'planned')
            FROM command_dedup d WHERE d.command_id = $id;
            """;
        query.Parameters.AddWithValue("$id", command.Value.ToByteArray());
        using var row = query.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(0));
        Assert.Equal(response, (byte[])row.GetValue(1));
        Assert.Equal(1L, row.GetInt64(2));
        Assert.Equal(1001L, row.GetInt64(3));
        Assert.True(row.GetInt64(4) >= 1);
    }

}
