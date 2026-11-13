// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// Real Node, native filesystem, SQLite and ES256 WebSocket with a fixture Center peer. Agent creation provenance
/// is seeded metadata, not a successful AGENT create, a real Center route or strict cleanup acceptance.
/// </summary>
public sealed class RoutedRemovalPlanInputAuditChannelTests
{
    [Fact(Timeout = 120_000)]
    public async Task SignedActualReadAuditAndReceiptReplayOriginalBytes()
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
            LocalOrigin = Origin.Agent,
            LocalSessionId = CommandIds.New(),
        };
        var rootName = Directory.CreateDirectory(Path.Combine(node.Root, "signed-plan-input-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootName, cancellationToken: ct);
        var path = Path.Combine(rootName, "input.txt");
        var body = "signed-plan-input-private-body-3e91"u8.ToArray();
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
        var objectKey = Assert.IsType<byte[]>(FileCreationOwnership.StableKey(objectIdentity.Platform, objectIdentity.Bytes));
        node.Runtime.Store.Write(tx =>
        {
            tx.Execute("INSERT INTO file_ownership_object_generation (object_platform, object_key, generation) VALUES ($p, $key, 0);",
                ("$p", objectIdentity.Platform), ("$key", objectKey));
            return tx.Execute("""
                INSERT INTO file_creation_ownership
                  (workspace_id, relative_path, caller, creation_command_id, creation_request_sha256, root_platform, root_identity,
                   object_platform, object_identity, object_key, creation_marker, last_written_size, last_written_sha256,
                   global_generation, object_generation, recorded_at)
                VALUES ($ws, 'input.txt', $caller, $command, $request, $platform, $root, $platform, $object, $key,
                        $marker, $size, $hash, 0, 0, $now);
                """, ("$ws", workspace.Id), ("$caller", caller.ToByteArray()),
                ("$command", CommandIds.New().Value.ToByteArray()), ("$request", SHA256.HashData("synthetic-provenance"u8)),
                ("$platform", objectIdentity.Platform), ("$root", rootIdentity.Bytes), ("$object", objectIdentity.Bytes),
                ("$key", objectKey), ("$marker", marker), ("$size", (long)body.Length), ("$hash", SHA256.HashData(body)),
                ("$now", tx.NowMicroseconds));
        }, CommitDurability.Full);

        var request = new FileServicePlanRemovalRequest
        {
            Meta = CloudNode.Command(),
            WorkspacePath = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "input.txt" },
        };
        var raw = request.ToByteArray();
        async Task<ByteString> Invoke()
        {
            ct.ThrowIfCancellationRequested();
            var built = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = RoutedMethod.PlanNodeRemoval,
                Payload = raw,
                Caller = caller,
                CommandId = request.Meta.CommandId,
                Lifetime = TimeSpan.FromSeconds(30),
            });
            await connection.SendCallAsync(built.Call);
            var frame = await connection.ResultOfAsync(built.Call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(built.Call.CallId)),
                "verified PlanRemoval input audit");
            Assert.Equal(RoutedOutcome.Executed, connection.VerifiedResults.Single(x => x.Header.CallId.Equals(built.Call.CallId)).Header.Outcome);
            return frame.Payload;
        }

        var first = await Invoke();
        Assert.Equal(-1, first.Span.IndexOf(body));
        Assert.Equal(-1, first.Span.IndexOf(marker));
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
        node.Runtime.Store.Read(reader =>
        {
            using var sql = reader.CreateCommand("""
                SELECT o.kind, o.size_bytes, o.digest_input_bytes, o.item_count, o.sha256, d.payload_digest, d.outcome
                FROM audit_log a JOIN file_workspace_audit_observation o ON o.audit_seq = a.seq
                JOIN command_dedup d ON d.command_id = a.remote_command_id
                WHERE a.operation = 'cleanup.plan FileService.PlanRemoval' AND d.command_id = $id
                ORDER BY a.seq DESC LIMIT 1;
                """);
            sql.Parameters.AddWithValue("$id", request.Meta.CommandId.Value.ToByteArray());
            using var row = sql.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal((int)FileAuditKind.InputBytes, row.GetInt32(0));
            Assert.Equal((long)body.Length, row.GetInt64(1));
            Assert.Equal((long)body.Length, row.GetInt64(2));
            Assert.True(row.IsDBNull(3));
            Assert.Equal(SHA256.HashData(body), (byte[])row.GetValue(4));
            Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(5));
            Assert.Equal(first.ToByteArray(), (byte[])row.GetValue(6));
            return 0;
        });

        File.WriteAllBytes(path, "changed-after-plan"u8.ToArray()); // test-owned file, after the first result
        Assert.Equal(first, await Invoke()); // replay preserves the original audit without re-reading
        Assert.Empty(connection.UnverifiedResults);
        foreach (var database in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var stream = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(body));
        }
    }
}
