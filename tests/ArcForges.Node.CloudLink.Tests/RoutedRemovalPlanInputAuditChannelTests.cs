// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real Node, native file, SQLite and ES256 WebSocket; input observations and their response are pre-cutover fixtures.</summary>
public sealed class RoutedRemovalPlanInputAuditChannelTests
{
    // The fresh ownership/input-read producer check remains at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 120_000)]
    public async Task SignedRetainedInputAuditAndReceiptReplayOriginalBytesWithoutReadingTheChangedFile()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        await using var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
        var connection = await RoutedRemovalPlanFixture.ConnectAsync(center, node);
        var caller = RoutedRemovalPlanFixture.Caller(node, connection, Origin.Agent);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "signed-plan-input-root")).FullName;
        var path = Path.Combine(root, "input.txt");
        var body = "signed-plan-input-private-body-3e91"u8.ToArray();
        byte[] marker;
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            file.Write(body);
            file.Flush(flushToDisk: true);
            marker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
        }

        var request = RoutedRemovalPlanFixture.Request(node, root, "input.txt", ct);
        var raw = request.ToByteArray();
        var plan = RoutedRemovalPlanFixture.PriorPlan(node, request, requiresApproval: false,
            RoutedRemovalPlanFixture.Item("input.txt", FileEntryKind.File, (ulong)body.Length, ownerVerified: true));
        var audit = new FileAuditMetadata
        {
            Observations =
            {
                new FileAuditObservation
                {
                    Kind = FileAuditKind.InputBytes,
                    SizeBytes = (ulong)body.Length,
                    DigestInputBytes = (ulong)body.Length,
                    Sha256 = ByteString.CopyFrom(SHA256.HashData(body)),
                },
            },
        };
        var actor = RoutedRemovalPlanFixture.Actor(request, caller);
        var receipt = RoutedRemovalPlanFixture.OriginalBytes(new FileServicePlanRemovalResponse
        {
            Meta = RoutedRemovalPlanFixture.ReplyMeta(request),
            Value = new FileServicePlanRemovalValue { Plan = plan },
            Audit = audit,
        });
        node.Runtime.Store.Write(tx =>
        {
            RoutedRemovalPlanFixture.SeedReceipt(tx, request, raw, caller, receipt);
            RoutedRemovalPlanFixture.SeedPlan(tx, request, raw, caller, root, plan);
            AuditLog.AppendFileWorkspace(tx, actor, "cleanup.plan FileService.PlanRemoval",
                request.WorkspacePath.WorkspaceId.Value.ToByteArray(), null, request.WorkspacePath.Path,
                PermissionDecision.Allow, "planned", audit);
            return 0;
        }, CommitDurability.Full);

        Task<ByteString> Invoke() =>
            RoutedRemovalPlanFixture.InvokeAsync(center, connection, request.Meta.CommandId, caller, raw, ct);

        var first = await Invoke();
        Assert.Equal(ByteString.CopyFrom(receipt), first);
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

        var changed = "changed-after-plan"u8.ToArray();
        File.WriteAllBytes(path, changed);
        Assert.Equal(first, await Invoke());
        Assert.Equal(changed, File.ReadAllBytes(path));
        node.Runtime.Store.Read(reader =>
        {
            using var sql = reader.CreateCommand("""
                SELECT o.kind, o.size_bytes, o.digest_input_bytes, o.item_count, o.sha256, d.payload_digest, d.outcome,
                       a.actor, w.workspace_id, w.path
                FROM audit_log a JOIN file_workspace_audit_observation o ON o.audit_seq = a.seq
                JOIN file_workspace_audit w ON w.audit_seq = a.seq
                JOIN command_dedup d ON d.command_id = a.remote_command_id
                WHERE a.operation = 'cleanup.plan FileService.PlanRemoval' AND d.command_id = $id;
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
            Assert.Equal(receipt, (byte[])row.GetValue(6));
            Assert.Equal(actor, ActorRef.Parser.ParseFrom((byte[])row.GetValue(7)));
            Assert.Equal(request.WorkspacePath.WorkspaceId.Value.ToByteArray(), (byte[])row.GetValue(8));
            Assert.Equal(request.WorkspacePath.Path, row.GetString(9));
            Assert.False(row.Read());
            return 0;
        });
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
