// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Cross-root ownership-generation test. The file and SQLite are real; the seeded caller and completed journal
/// are synthetic metadata and do not claim that the currently refused AGENT create was executed.
/// </summary>
public sealed class FileCreationOwnershipAliasTests
{
    [Fact(Timeout = 120_000)]
    public async Task SameOpenedObjectAcrossRegisteredRootsInvalidatesOldEvidenceWithoutScanningAliases()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var owner = calls.Relay(Origin.Agent);
        var foreign = calls.Relay(Origin.Agent);
        var rootName = Directory.CreateDirectory(Path.Combine(node.Root, "owner-alias")).FullName;
        var nestedName = Directory.CreateDirectory(Path.Combine(rootName, "nested")).FullName;
        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var outer = manager.RegisterFromVerifiedHuman(rootName, cancellationToken: ct);
        var nested = manager.RegisterFromVerifiedHuman(nestedName, cancellationToken: ct);
        var path = Path.Combine(nestedName, "one.txt");
        var body = Encoding.UTF8.GetBytes("owned-alias-fixture-761c");
        byte[] marker;
        RegisteredWorkspaces.RootIdentity rootId, nestedId, objectId;
        using (var root = WorkspacePath.OpenRoot(rootName))
        using (var child = WorkspacePath.OpenRoot(nestedName))
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            file.Write(body);
            file.Flush(flushToDisk: true);
            marker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
            rootId = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            nestedId = RegisteredWorkspaces.RootIdentity.Encode(child.RootIdentity);
            objectId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file.SafeFileHandle), directory: false);
        }
        var key = Assert.IsType<byte[]>(FileCreationOwnership.StableKey(objectId.Platform, objectId.Bytes));
        node.Runtime.Store.Write(tx =>
        {
            tx.Execute("INSERT INTO file_ownership_object_generation (object_platform, object_key, generation) VALUES ($p, $key, 0);",
                ("$p", objectId.Platform), ("$key", key));
            return tx.Execute("""
                INSERT INTO file_creation_ownership
                  (workspace_id, relative_path, caller, creation_command_id, creation_request_sha256, root_platform, root_identity,
                   object_platform, object_identity, object_key, creation_marker, last_written_size, last_written_sha256,
                   global_generation, object_generation, recorded_at)
                VALUES ($ws, 'nested/one.txt', $owner, $creation, $request, $platform, $root, $platform, $object, $key,
                        $marker, $size, $hash, 0, 0, $now);
                """, ("$ws", outer.Id), ("$owner", owner.ToByteArray()), ("$creation", CommandIds.New().Value.ToByteArray()),
                ("$request", SHA256.HashData("synthetic-alias-request"u8)), ("$platform", objectId.Platform),
                ("$root", rootId.Bytes), ("$object", objectId.Bytes), ("$key", key), ("$marker", marker),
                ("$size", (long)body.Length), ("$hash", SHA256.HashData(body)), ("$now", tx.NowMicroseconds));
        }, CommitDurability.Full);

        bool ObservedOwned()
        {
            using var root = WorkspacePath.OpenRoot(rootName);
            var entry = Assert.Single(WorkspaceRemovalPlan.Capture(root, "nested/one.txt", ct).Entries);
            return node.Runtime.Store.Read(reader => FileCreationOwnership.IsVerifiedAgent(reader, owner, outer.Id, root, entry, ct));
        }
        Assert.True(ObservedOwned());

        // This is an explicitly synthetic completed-journal row for a different caller and nested root. The
        // object ID comes from the actual file; its stored birth-time bytes are varied to verify stable-key matching.
        var target = objectId.Bytes.ToArray();
        target[objectId.Platform == 1 ? 25 : 9] ^= 1;
        Assert.Equal(key, FileCreationOwnership.StableKey(objectId.Platform, target));
        var commandId = CommandIds.New().Value.ToByteArray();
        var digest = SHA256.HashData("synthetic-alias-write"u8);
        node.Runtime.Store.Write(tx =>
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, commandId,
                "arcforges.node.v1.FileService/WriteFile", digest, Origin.Remote).Status);
            tx.Execute("""
                INSERT INTO file_operation_journal
                  (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
                   identity_platform, root_identity, parent_identity, target_identity, expected_absent,
                   original_size, original_sha256, original_stage_identity, intended_size, intended_sha256,
                   intended_stage_identity, created_at, updated_at, held, acknowledged)
                VALUES ($id, 1, 2, $digest, $caller, $correlation, $ws, 'one.txt',
                        $platform, $root, $root, $object, 0, $size, $hash, $root, $size, $hash, $root, $now, $now, 0, 0);
                """, ("$id", commandId), ("$digest", digest), ("$caller", foreign.ToByteArray()),
                ("$correlation", CommandIds.New().Value.ToByteArray()), ("$ws", nested.Id), ("$platform", objectId.Platform),
                ("$root", nestedId.Bytes), ("$object", target), ("$size", (long)body.Length),
                ("$hash", SHA256.HashData(body)), ("$now", tx.NowMicroseconds));
            var generation = FileCreationOwnership.InvalidateAffected(tx, commandId, created: null);
            FileCreationOwnership.ForgetPath(tx, nested.Id, "one.txt");
            return generation;
        }, CommitDurability.Full);

        Assert.Equal(0L, node.Runtime.Store.Read(r => r.Scalar("SELECT generation FROM file_ownership_generation WHERE singleton = 1;")));
        Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("SELECT generation FROM file_ownership_object_generation;")));
        Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_creation_ownership;")));
        Assert.False(ObservedOwned());
        Assert.Equal(body, File.ReadAllBytes(path));
    }
}
