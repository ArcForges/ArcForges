// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Windows native creation and SQLite through the existing in-process routed seam; caller fixture is synthetic.</summary>
public sealed class FileCreationOwnershipWindowsTests
{
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task CreatedEvidenceSurvivesRestartAndOnlyTheSameCallerCanAdvanceIt()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native exclusive-create settlement."); return; }
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var owner = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "owner-created")).FullName;
        var nestedRoot = Directory.CreateDirectory(Path.Combine(root, "nested")).FullName;
        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var workspace = manager.RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var nestedWorkspace = manager.RegisterFromVerifiedHuman(nestedRoot, cancellationToken: ct);
        var firstBody = Encoding.UTF8.GetBytes("new-created-owner-fixture-1aa1");
        var nextBody = Encoding.UTF8.GetBytes("same-owner-updated-fixture-2bb2");

        FileServiceWriteFileRequest Create(string path, byte[] body) => new()
        {
            Meta = Tasks.Meta(),
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = path },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
        };
        FileServiceWriteFileRequest Update(string path, byte[] expected, byte[] body, byte[]? selectedWorkspace = null) => new()
        {
            Meta = Tasks.Meta(),
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(selectedWorkspace ?? workspace.Id) }, Path = path },
            ExpectedSha256 = ByteString.CopyFrom(SHA256.HashData(expected)),
            Data = ByteString.CopyFrom(body),
        };
        async Task<FileServiceWriteFileResponse> Invoke(CenterCaller actor, FileServiceWriteFileRequest request)
        {
            var now = node.Runtime.Clock.GetUtcNow();
            var routed = new RoutedContext(calls.Link, node.Runtime.Lifecycle, now.AddSeconds(30), TimeSpan.FromSeconds(15),
                node.Runtime.Clock, node.Runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
            var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: actor.Clone())
            {
                CellsOrigin = CenterRouting.CellsOrigin(actor, node.Runtime.NodeId.Span),
                RemoteCommandId = request.Meta.CommandId.Clone(),
                RawRequest = request.ToByteArray(),
                Routed = routed,
            };
            var raw = await calls.Dispatcher.FileHandlerForTests!.WriteExistingCandidateAsync(caller, ct);
            return FileServiceWriteFileResponse.Parser.ParseFrom(raw);
        }
        (byte[] Marker, byte[] Hash, CenterCaller Caller, byte[] Command)? Record(string path) =>
            node.Runtime.Store.Read<(byte[] Marker, byte[] Hash, CenterCaller Caller, byte[] Command)?>(reader =>
            {
                using var sql = reader.CreateCommand("""
                    SELECT c.creation_marker, c.last_written_sha256, c.caller, c.creation_command_id
                    FROM file_creation_ownership c
                    JOIN file_ownership_generation g ON g.singleton = 1 AND g.generation = c.global_generation
                    JOIN file_ownership_object_generation o ON o.object_platform = c.object_platform AND o.object_key = c.object_key
                                                              AND o.generation = c.object_generation
                    WHERE c.workspace_id = $id AND c.relative_path = $path;
                    """);
                sql.Parameters.AddWithValue("$id", workspace.Id);
                sql.Parameters.AddWithValue("$path", path);
                using var row = sql.ExecuteReader();
                return !row.Read() ? null : ((byte[])row.GetValue(0), (byte[])row.GetValue(1),
                    CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2)), (byte[])row.GetValue(3));
            });

        var create = Create("nested/created.txt", firstBody);
        Assert.Null((await Invoke(owner, create)).Error);
        var initial = Assert.IsType<(byte[] Marker, byte[] Hash, CenterCaller Caller, byte[] Command)>(Record("nested/created.txt"));
        Assert.Equal(create.Meta.CommandId.Value.ToByteArray(), initial.Command);
        Assert.Equal(SHA256.HashData(firstBody), initial.Hash);
        Assert.True(CenterRouting.SameFileCaller(owner, initial.Caller));
        using (var anchor = WorkspacePath.OpenRoot(root))
        using (var opened = anchor.OpenReadForOwnership("nested/created.txt"))
            Assert.Equal(initial.Marker, WorkspaceCreationMarker.Read(opened));

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        Assert.Equal(initial.Marker, Record("nested/created.txt")!.Value.Marker);
        Assert.Null((await Invoke(owner, Update("nested/created.txt", firstBody, nextBody))).Error);
        var advanced = Record("nested/created.txt")!.Value;
        Assert.Equal(initial.Marker, advanced.Marker);
        Assert.Equal(initial.Command, advanced.Command);
        Assert.Equal(SHA256.HashData(nextBody), advanced.Hash);
        Assert.Equal(nextBody, File.ReadAllBytes(Path.Combine(nestedRoot, "created.txt")));

        var foreign = calls.Relay(Origin.Human);
        Assert.False(CenterRouting.SameFileCaller(owner, foreign));
        // The same native object is addressed via another registered root. An identical foreign write still
        // invalidates the original root's evidence; path-only invalidation would leave it falsely claimable.
        Assert.Null((await Invoke(foreign, Update("created.txt", nextBody, nextBody, nestedWorkspace.Id))).Error);
        Assert.Null(Record("nested/created.txt"));
        Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar(
            "SELECT count(*) FROM file_creation_ownership WHERE workspace_id = $id AND relative_path = 'nested/created.txt';",
            ("$id", workspace.Id)))); // stale row remains, but its object generation no longer matches

        var changed = Create("external.txt", firstBody);
        Assert.Null((await Invoke(owner, changed)).Error);
        Assert.NotNull(Record("external.txt"));
        var external = Encoding.UTF8.GetBytes("outside-owner-content-change");
        File.WriteAllBytes(Path.Combine(root, "external.txt"), external);
        Assert.Null((await Invoke(owner, Update("external.txt", external, nextBody))).Error);
        Assert.Null(Record("external.txt"));

        File.WriteAllBytes(Path.Combine(root, "occupied.txt"), firstBody);
        var collision = await Invoke(owner, Create("occupied.txt", nextBody));
        Assert.Equal("expected_absent_conflict", collision.Error.Details.State.Reason);
        Assert.Null(Record("occupied.txt"));
        Assert.Equal(firstBody, File.ReadAllBytes(Path.Combine(root, "occupied.txt")));
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public async Task RolledBackSettlementCannotLeaveClaimableCreationEvidence()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native exclusive-create settlement."); return; }
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "owner-rollback")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var body = Encoding.UTF8.GetBytes("rolled-back-owned-create-fixture-925d");
        var request = new FileServiceWriteFileRequest
        {
            Meta = Tasks.Meta(),
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "created.txt" },
            ExpectedAbsent = true,
            Data = ByteString.CopyFrom(body),
        };
        var now = node.Runtime.Clock.GetUtcNow();
        var routed = new RoutedContext(calls.Link, node.Runtime.Lifecycle, now.AddSeconds(30), TimeSpan.FromSeconds(15),
            node.Runtime.Clock, node.Runtime.Clock.GetTimestamp(), CommandIds.New(), fileWorkspace: true);
        var caller = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: actor.Clone())
        {
            CellsOrigin = CenterRouting.CellsOrigin(actor, node.Runtime.NodeId.Span),
            RemoteCommandId = request.Meta.CommandId.Clone(),
            RawRequest = request.ToByteArray(),
            Routed = routed,
        };
        var handler = calls.Dispatcher.FileHandlerForTests!;
        handler.AfterCreationSettlementForTests = () => throw new IOException("owned fixture rollback");
        try { await Assert.ThrowsAsync<IOException>(() => handler.WriteExistingCandidateAsync(caller, ct)); }
        finally { handler.AfterCreationSettlementForTests = null; }
        Assert.Equal(body, File.ReadAllBytes(Path.Combine(root, "created.txt")));
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_creation_ownership;")));
        var pending = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, request.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Prepared, pending!.State);
        Assert.True(pending.Held);

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var recovered = node.Runtime.Store.Read(r => FileMutationJournal.GetForCaller(r, request.Meta.CommandId.Value.Span, actor));
        Assert.Equal(FileOperationState.Unknown, recovered!.State);
        Assert.True(recovered.Held);
        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_creation_ownership;")));
        Assert.Equal(body, File.ReadAllBytes(Path.Combine(root, "created.txt")));
    }
}
