// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Real Host, native files, SQLite and signed channel. The Center peer and AGENT creation provenance are isolated
/// fixtures; they do not establish an actual AGENT create, real Center files route or strict cleanup acceptance.
/// </summary>
[Trait("loop", "local")]
public sealed class PlanRemovalInputAuditHostTests
{
    [Fact(Timeout = 180_000)]
    public async Task SignedRealHostReadsAndReplaysTheOriginalInputObservation()
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
            var channel = await center.Channel.ProvedAsync();
            var humanCaller = new CenterCaller
            {
                Kind = CenterCallerKind.NodeRelay,
                AccountId = new Id { Value = ByteString.CopyFrom(channel.AccountId) },
                RelayingNodeId = nodeId.Clone(),
                LocalOrigin = Origin.Human,
                LocalSessionId = CommandIds.New(),
            };
            var agentCaller = humanCaller.Clone();
            agentCaller.LocalOrigin = Origin.Agent;
            agentCaller.LocalSessionId = CommandIds.New();
            var rootName = Directory.CreateDirectory(Path.Combine(node.Root, "host-plan-input-root")).FullName;

            async Task<byte[]> Invoke(RoutedMethod method, IMessage request, Id command, CenterCaller caller)
            {
                ct.ThrowIfCancellationRequested();
                var built = center.Channel.BuildCall(channel, new FakeCallSpec
                {
                    Method = method,
                    Payload = request.ToByteArray(),
                    Caller = caller,
                    CommandId = command,
                    Lifetime = TimeSpan.FromSeconds(30),
                });
                await channel.SendCallAsync(built.Call);
                var frame = await channel.ResultOfAsync(built.Call.CallId);
                await TestNode.WaitAsync(() => channel.VerifiedResults.Any(value => value.Header.CallId.Equals(built.Call.CallId)),
                    TimeSpan.FromSeconds(15), "the real Host result signature verifies");
                Assert.Equal(RoutedOutcome.Executed, channel.VerifiedResults.Single(value => value.Header.CallId.Equals(built.Call.CallId)).Header.Outcome);
                return frame.Payload.ToByteArray();
            }

            var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = Command(), Path = rootName, Name = "input-audit" };
            var registered = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(
                await Invoke(RoutedMethod.RegisterNodeWorkspace, register, register.Meta.CommandId, humanCaller));
            Assert.Null(registered.Error);
            var workspace = registered.Value.Workspace.WorkspaceId.Value.ToByteArray();
            var path = Path.Combine(rootName, "input.txt");
            var body = "aot-host-plan-input-private-body-719c"u8.ToArray();
            byte[] marker;
            RegisteredWorkspaces.RootIdentity rootIdentity, objectIdentity;
            using (var root = WorkspacePath.OpenRoot(rootName))
            using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                file.Write(body);
                file.Flush(flushToDisk: true);
                marker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
                rootIdentity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
                objectIdentity = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file.SafeFileHandle), directory: false);
            }
            var key = Assert.IsType<byte[]>(FileCreationOwnership.StableKey(objectIdentity.Platform, objectIdentity.Bytes));
            SeedSyntheticProvenance(node.DataRoot, workspace, agentCaller, rootIdentity, objectIdentity, key, marker, body);

            var request = new FileServicePlanRemovalRequest
            {
                Meta = Command(),
                WorkspacePath = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = "input.txt" },
            };
            var raw = request.ToByteArray();
            var first = await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId, agentCaller);
            Assert.Equal(-1, first.AsSpan().IndexOf(body));
            Assert.Equal(-1, first.AsSpan().IndexOf(marker));
            var response = FileServicePlanRemovalResponse.Parser.ParseFrom(first);
            Assert.True(NodeShapes.IsValid(response));
            Assert.Null(response.Error);
            Assert.True(Assert.Single(response.Value.Plan.Items).OwnerVerified);
            var observation = Assert.Single(response.Audit.Observations);
            Assert.Equal(FileAuditKind.InputBytes, observation.Kind);
            Assert.Equal((ulong)body.Length, observation.SizeBytes);
            Assert.Equal((ulong)body.Length, observation.DigestInputBytes);
            Assert.False(observation.HasItemCount);
            Assert.Equal(SHA256.HashData(body), observation.Sha256.ToByteArray());
            AssertStored(node.DataRoot, request.Meta.CommandId, raw, first, body);

            File.WriteAllBytes(path, "changed-after-signed-plan"u8.ToArray());
            Assert.Equal(first, await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId, agentCaller));
            await node.StopNodeAsync();
            await node.StartNodeAsync();
            channel = await center.Channel.ProvedAsync(2);
            Assert.Equal(first, await Invoke(RoutedMethod.PlanNodeRemoval, request, request.Meta.CommandId, agentCaller));
            AssertStored(node.DataRoot, request.Meta.CommandId, raw, first, body);
            Assert.Empty(channel.UnverifiedResults);
            foreach (var file in new[] { StorePaths.Database(node.DataRoot), StorePaths.Database(node.DataRoot) + "-wal", node.NodeLog })
            {
                if (CloudLinkHostTests.ReadAllShared(file) is not { } bytes) continue;
                Assert.Equal(-1, bytes.AsSpan().IndexOf(body));
                if (file == node.NodeLog) Assert.Equal(-1, bytes.AsSpan().IndexOf(marker));
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

    private static void SeedSyntheticProvenance(string dataRoot, byte[] workspace, CenterCaller caller,
        RegisteredWorkspaces.RootIdentity root, RegisteredWorkspaces.RootIdentity file, byte[] key, byte[] marker, byte[] body)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = StorePaths.Database(dataRoot), Mode = SqliteOpenMode.ReadWrite };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;";
            pragma.ExecuteNonQuery();
        }
        using var transaction = connection.BeginTransaction();
        using (var generation = connection.CreateCommand())
        {
            generation.Transaction = transaction;
            generation.CommandText = "INSERT INTO file_ownership_object_generation (object_platform, object_key, generation) VALUES ($p, $key, 0);";
            generation.Parameters.AddWithValue("$p", file.Platform);
            generation.Parameters.AddWithValue("$key", key);
            generation.ExecuteNonQuery();
        }
        using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO file_creation_ownership
                  (workspace_id, relative_path, caller, creation_command_id, creation_request_sha256, root_platform, root_identity,
                   object_platform, object_identity, object_key, creation_marker, last_written_size, last_written_sha256,
                   global_generation, object_generation, recorded_at)
                VALUES ($ws, 'input.txt', $caller, $command, $request, $platform, $root, $platform, $object, $key,
                        $marker, $size, $hash, 0, 0, $now);
                """;
            insert.Parameters.AddWithValue("$ws", workspace);
            insert.Parameters.AddWithValue("$caller", caller.ToByteArray());
            insert.Parameters.AddWithValue("$command", CommandIds.New().Value.ToByteArray());
            insert.Parameters.AddWithValue("$request", SHA256.HashData("synthetic-owner-provenance"u8));
            insert.Parameters.AddWithValue("$platform", file.Platform);
            insert.Parameters.AddWithValue("$root", root.Bytes);
            insert.Parameters.AddWithValue("$object", file.Bytes);
            insert.Parameters.AddWithValue("$key", key);
            insert.Parameters.AddWithValue("$marker", marker);
            insert.Parameters.AddWithValue("$size", (long)body.Length);
            insert.Parameters.AddWithValue("$hash", SHA256.HashData(body));
            insert.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000);
            insert.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    private static void AssertStored(string dataRoot, Id command, byte[] raw, byte[] response, byte[] body)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = StorePaths.Database(dataRoot), Mode = SqliteOpenMode.ReadOnly };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT d.payload_digest, d.outcome, o.kind, o.size_bytes, o.digest_input_bytes, o.item_count, o.sha256
            FROM command_dedup d JOIN audit_log a ON a.remote_command_id = d.command_id
            JOIN file_workspace_audit_observation o ON o.audit_seq = a.seq
            WHERE d.command_id = $id AND a.operation = 'cleanup.plan FileService.PlanRemoval' AND a.outcome_summary = 'planned';
            """;
        query.Parameters.AddWithValue("$id", command.Value.ToByteArray());
        using var row = query.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(0));
        Assert.Equal(response, (byte[])row.GetValue(1));
        Assert.Equal((int)FileAuditKind.InputBytes, row.GetInt32(2));
        Assert.Equal((long)body.Length, row.GetInt64(3));
        Assert.Equal((long)body.Length, row.GetInt64(4));
        Assert.True(row.IsDBNull(5));
        Assert.Equal(SHA256.HashData(body), (byte[])row.GetValue(6));
        Assert.False(row.Read());
    }
}
