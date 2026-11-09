// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Security;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Independently fixed workspace transcript vectors and real SQLite persistence; no workspace contents enter audit.</summary>
[Trait("feature", "workspace-audit")]
public sealed class WorkspaceAuditMetadataTests
{
    [Fact]
    public void EmptyAndOneRecordUseTheSpecifiedFramingAndFixedDigests()
    {
        var empty = Assert.Single(WorkspaceAuditMetadata.ForRecords([]).Observations);
        Assert.Equal((ulong)32, empty.SizeBytes);
        Assert.Equal((ulong)32, empty.DigestInputBytes);
        Assert.Equal(0U, empty.ItemCount);
        Assert.Equal("1de557e721f721d6eac4ba416d41ffac5139c3fcf98833301a375c39b5df0757", Convert.ToHexStringLower(empty.Sha256.Span));
        var record = new Workspace
        {
            WorkspaceId = new Id { Value = ByteString.CopyFrom(Enumerable.Range(0, 16).Select(index => (byte)index).ToArray()) },
            RootPath = "/x",
            Kind = WorkspaceKind.Registered,
            State = WorkspaceState.Active,
            Name = "demo",
        };
        var observed = Assert.Single(WorkspaceAuditMetadata.ForRecords([record]).Observations);
        Assert.Equal(FileAuditKind.WorkspaceMetadata, observed.Kind);
        Assert.Equal((ulong)70, observed.SizeBytes);
        Assert.Equal((ulong)70, observed.DigestInputBytes);
        Assert.Equal(1U, observed.ItemCount);
        Assert.Equal("17a3c78d08ab02f2c0b8a5454b4c313996a4fafac582e609af0ff5de5f578621", Convert.ToHexStringLower(observed.Sha256.Span));
    }

    [Fact(Timeout = 60_000)]
    public async Task RealAuditStoresScopeAndDigestAndDoesNotStoreWorkspaceFileBody()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var path = Directory.CreateDirectory(Path.Combine(node.Root, "root")).FullName;
        const string body = "sensitive-test-only-content-marker";
        File.WriteAllText(Path.Combine(path, "marker.txt"), body);
        var id = Enumerable.Repeat((byte)0x44, 16).ToArray();
        var workspace = new Workspace
        {
            WorkspaceId = new Id { Value = ByteString.CopyFrom(id) },
            RootPath = path,
            Kind = WorkspaceKind.Registered,
            State = WorkspaceState.Active,
            Name = "root",
        };
        var metadata = WorkspaceAuditMetadata.ForRecords([workspace]);
        node.Runtime.Store.Write(transaction => AuditLog.AppendFileWorkspace(transaction,
            new ActorRef { Origin = Origin.Human }, "workspace.read WorkspaceService.GetWorkspace", id, null, path,
            PermissionDecision.Allow, "success", metadata));
        var stored = node.Runtime.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("""
                SELECT a.path, o.kind, o.size_bytes, o.digest_input_bytes, o.item_count, o.sha256, l.outcome_summary
                FROM file_workspace_audit a JOIN file_workspace_audit_observation o ON o.audit_seq=a.audit_seq
                JOIN audit_log l ON l.seq=a.audit_seq WHERE a.workspace_id=$id;
                """);
            command.Parameters.AddWithValue("$id", id);
            using var rows = command.ExecuteReader();
            Assert.True(rows.Read());
            return (Path: rows.GetString(0), Kind: rows.GetInt32(1), Size: rows.GetInt64(2), Input: rows.GetInt64(3),
                Count: rows.GetInt64(4), Digest: (byte[])rows.GetValue(5), Outcome: rows.GetString(6));
        });
        var observation = Assert.Single(metadata.Observations);
        Assert.Equal(path, stored.Path);
        Assert.Equal((int)FileAuditKind.WorkspaceMetadata, stored.Kind);
        Assert.Equal((long)observation.SizeBytes, stored.Size);
        Assert.Equal((long)observation.DigestInputBytes, stored.Input);
        Assert.Equal(1L, stored.Count);
        Assert.Equal(observation.Sha256.ToByteArray(), stored.Digest);
        Assert.DoesNotContain(body, stored.Outcome, StringComparison.Ordinal);
        Assert.DoesNotContain(body, stored.Path, StringComparison.Ordinal);
        Assert.Equal(body, File.ReadAllText(Path.Combine(path, "marker.txt")));
    }
}
