// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Synthetic agent provenance is seeded only to exercise the planning consumer. The fixture does not claim that the
/// currently refused AGENT expected-absent API created this file. Native files, hashing, SQLite and planning are real.
/// </summary>
public sealed class FileCreationOwnershipPlanTests
{
    [Fact(Timeout = 120_000)]
    public async Task PlanningChecksExactCallerMarkerIdentityAndContentButKeepsStrictApproval()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Agent);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "owner-plan")).FullName;
        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var workspace = manager.RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var target = Path.Combine(root, "fixture.txt");
        var body = Encoding.UTF8.GetBytes("creation-ownership-fixture-body-6a61");
        byte[] marker;
        RegisteredWorkspaces.RootIdentity rootIdentity, fileIdentity;
        using (var anchor = WorkspacePath.OpenRoot(root))
        using (var created = new FileStream(target, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            created.Write(body);
            created.Flush(flushToDisk: true);
            marker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(created.SafeFileHandle));
            rootIdentity = RegisteredWorkspaces.RootIdentity.Encode(anchor.RootIdentity);
            fileIdentity = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(created.SafeFileHandle), directory: false);
        }

        // Synthetic completed journal metadata exercises the actual record transaction. It is deliberately
        // not presented as a successful caller/API creation.
        var syntheticCommand = CommandIds.New().Value.ToByteArray();
        var syntheticCorrelation = CommandIds.New();
        var requestHash = SHA256.HashData("synthetic-request"u8);
        node.Runtime.Store.Write(tx =>
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, syntheticCommand,
                "arcforges.node.v1.FileService/WriteFile", requestHash, Origin.Remote).Status);
            tx.Execute("""
                INSERT INTO file_operation_journal
                  (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
                   identity_platform, root_identity, parent_identity, target_identity, expected_absent,
                   original_size, original_sha256, original_stage_identity, intended_size, intended_sha256,
                   intended_stage_identity, created_at, updated_at, held, acknowledged)
                VALUES ($id, 1, 2, $request, $caller, $correlation, $workspace, 'fixture.txt',
                        $platform, $root, $root, NULL, 1, NULL, NULL, NULL, $size, $hash, $root, $now, $now, 0, 0);
                """, ("$id", syntheticCommand), ("$request", requestHash), ("$caller", actor.ToByteArray()),
                ("$correlation", syntheticCorrelation.Value.ToByteArray()), ("$workspace", workspace.Id),
                ("$platform", fileIdentity.Platform), ("$root", rootIdentity.Bytes), ("$size", (long)body.Length),
                ("$hash", SHA256.HashData(body)), ("$now", tx.NowMicroseconds));
            var receipt = new FileServiceWriteFileResponse
            {
                Meta = new ResponseMeta { CorrelationId = syntheticCorrelation },
                Value = new FileServiceWriteFileValue
                {
                    Result = new FileMutationResult
                    {
                        CommandId = new Id { Value = ByteString.CopyFrom(syntheticCommand) },
                        SizeBytes = (ulong)body.Length,
                        Sha256 = ByteString.CopyFrom(SHA256.HashData(body)),
                    },
                },
                Audit = new FileAuditMetadata
                {
                    Observations = { new FileAuditObservation
                    {
                        Kind = FileAuditKind.WrittenBytes, SizeBytes = (ulong)body.Length,
                        DigestInputBytes = (ulong)body.Length, Sha256 = ByteString.CopyFrom(SHA256.HashData(body)),
                    } },
                },
            };
            CommandDeduplication.Complete(tx, syntheticCommand, receipt.ToByteArray());
            var evidence = new WorkspaceCreatedOwnership(fileIdentity, marker);
            _ = FileCreationOwnership.InvalidateAffected(tx, syntheticCommand, evidence);
            FileCreationOwnership.RecordCompleted(tx, syntheticCommand, evidence, body.Length, SHA256.HashData(body));
            return 0;
        }, CommitDurability.Full);

        async Task<FileRemovalPlan> Plan(CenterCaller caller)
        {
            var request = new FileServicePlanRemovalRequest
            {
                Meta = Tasks.Meta(),
                WorkspacePath = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "fixture.txt" },
            };
            var answer = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId,
                cancellationToken: ct);
            var response = FileServicePlanRemovalResponse.Parser.ParseFrom(answer.Answer!.Response);
            Assert.Null(response.Error);
            var plan = response.Value.Plan;
            Assert.Single(plan.Items);
            Assert.True(plan.RequiresApproval);
            Assert.False(plan.QuarantineAvailable);
            Assert.NotEqual(RiskClass.Low, plan.Risk);
            return plan;
        }

        Assert.True((await Plan(actor)).Items[0].OwnerVerified);
        Assert.False((await Plan(calls.Relay(Origin.Agent))).Items[0].OwnerVerified); // another verified relay session
        Assert.False((await Plan(calls.Relay(Origin.Human))).Items[0].OwnerVerified);
        Assert.Equal(body, File.ReadAllBytes(target));

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        Assert.True((await Plan(actor)).Items[0].OwnerVerified);

        var wrong = RandomNumberGenerator.GetBytes(32);
        node.Runtime.Store.Write(tx => tx.Execute(
            "UPDATE file_creation_ownership SET creation_marker = $marker WHERE workspace_id = $id AND relative_path = 'fixture.txt';",
            ("$marker", wrong), ("$id", workspace.Id)), CommitDurability.Full);
        Assert.False((await Plan(actor)).Items[0].OwnerVerified);
        node.Runtime.Store.Write(tx => tx.Execute(
            "UPDATE file_creation_ownership SET creation_marker = $marker WHERE workspace_id = $id AND relative_path = 'fixture.txt';",
            ("$marker", marker), ("$id", workspace.Id)), CommitDurability.Full);

        File.WriteAllBytes(target, Encoding.UTF8.GetBytes("external-content-change"));
        Assert.False((await Plan(actor)).Items[0].OwnerVerified);
        File.Delete(target); // only the test-owned object
        File.WriteAllBytes(target, body); // a new same-name object is not adopted
        Assert.False((await Plan(actor)).Items[0].OwnerVerified);
        Assert.Equal(body, File.ReadAllBytes(target));

        foreach (var database in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var stream = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(body));
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task UnknownUnidentifiedCreateInvalidatesGenerationAndCannotReviveAnOldProof()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(Origin.Agent);
        var rootName = Directory.CreateDirectory(Path.Combine(node.Root, "owner-epoch")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootName, cancellationToken: ct);
        var path = Path.Combine(rootName, "observed.txt");
        var body = Encoding.UTF8.GetBytes("synthetic-provenance-epoch-fixture");
        byte[] marker;
        RegisteredWorkspaces.RootIdentity rootIdentity, fileIdentity;
        using (var root = WorkspacePath.OpenRoot(rootName))
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            file.Write(body);
            file.Flush(flushToDisk: true);
            marker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
            rootIdentity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            fileIdentity = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file.SafeFileHandle), directory: false);
        }
        var key = Assert.IsType<byte[]>(FileCreationOwnership.StableKey(fileIdentity.Platform, fileIdentity.Bytes));
        node.Runtime.Store.Write(tx =>
        {
            tx.Execute("INSERT INTO file_ownership_object_generation (object_platform, object_key, generation) VALUES ($p, $k, 0);",
                ("$p", fileIdentity.Platform), ("$k", key));
            return tx.Execute("""
                INSERT INTO file_creation_ownership
                  (workspace_id, relative_path, caller, creation_command_id, creation_request_sha256, root_platform, root_identity,
                   object_platform, object_identity, object_key, creation_marker, last_written_size, last_written_sha256,
                   global_generation, object_generation, recorded_at)
                VALUES ($ws, 'observed.txt', $caller, $command, $request, $platform, $root, $platform, $object, $key,
                        $marker, $size, $hash, 0, 0, $now);
                """, ("$ws", workspace.Id), ("$caller", actor.ToByteArray()), ("$command", CommandIds.New().Value.ToByteArray()),
                ("$request", SHA256.HashData("synthetic-only"u8)), ("$platform", fileIdentity.Platform),
                ("$root", rootIdentity.Bytes), ("$object", fileIdentity.Bytes), ("$key", key), ("$marker", marker),
                ("$size", (long)body.Length), ("$hash", SHA256.HashData(body)), ("$now", tx.NowMicroseconds));
        }, CommitDurability.Full);

        FileCreationOwnership.UpdateProof proof;
        using (var root = WorkspacePath.OpenRoot(rootName))
        using (var guard = root.OpenExistingWriteGuard("observed.txt"))
        {
            proof = Assert.IsType<FileCreationOwnership.UpdateProof>(node.Runtime.Store.Read(reader =>
                FileCreationOwnership.PrepareUpdate(reader, actor, workspace.Id, root, "observed.txt", guard, SHA256.HashData(body), ct)));
        }
        bool ObservedOwned()
        {
            using var root = WorkspacePath.OpenRoot(rootName);
            var entry = Assert.Single(WorkspaceRemovalPlan.Capture(root, "observed.txt", ct).Entries);
            return node.Runtime.Store.Read(reader => FileCreationOwnership.IsVerifiedAgent(reader, actor, workspace.Id, root, entry, ct));
        }
        Assert.True(ObservedOwned());

        // Synthetic journal metadata exercises recovery only; it does not claim a real create or private-stage effect.
        var uncertainId = CommandIds.New().Value.ToByteArray();
        var uncertainCorrelation = CommandIds.New().Value.ToByteArray();
        var digest = SHA256.HashData("synthetic-unknown-request"u8);
        node.Runtime.Store.Write(tx =>
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, uncertainId,
                "arcforges.node.v1.FileService/WriteFile", digest, Origin.Remote).Status);
            return tx.Execute("""
                INSERT INTO file_operation_journal
                  (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
                   identity_platform, root_identity, parent_identity, target_identity, expected_absent,
                   original_size, original_sha256, original_stage_identity, intended_size, intended_sha256,
                   intended_stage_identity, created_at, updated_at, held, acknowledged)
                VALUES ($id, 1, 1, $digest, $caller, $correlation, $ws, 'unobserved.txt',
                        $platform, $root, $root, NULL, 1, NULL, NULL, NULL, 0, $empty_hash, $root, $now, $now, 1, 0);
                """, ("$id", uncertainId), ("$digest", digest), ("$caller", actor.ToByteArray()),
                ("$correlation", uncertainCorrelation), ("$ws", workspace.Id), ("$platform", rootIdentity.Platform),
                ("$root", rootIdentity.Bytes), ("$empty_hash", SHA256.HashData(ReadOnlySpan<byte>.Empty)), ("$now", tx.NowMicroseconds));
        }, CommitDurability.Full);
        Assert.False(ObservedOwned()); // a PREPARED create lacks an observed object identity
        node.Runtime.Store.Write(tx => FileMutationJournal.MarkUnknown(tx, uncertainId), CommitDurability.Full);
        Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("SELECT generation FROM file_ownership_generation WHERE singleton = 1;")));
        Assert.Equal(1L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_creation_ownership;"))); // stale row, no table scan/delete

        var human = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
        Assert.Equal(FileJournalAcknowledgment.Acknowledged, node.Runtime.Store.Write(
            tx => FileMutationJournal.AcknowledgeFromVerifiedHuman(tx, uncertainId, digest, human), CommitDurability.Full));
        Assert.False(ObservedOwned());

        // An old in-memory proof cannot revalidate a row after the global generation changed.
        var completedId = CommandIds.New().Value.ToByteArray();
        Assert.False(node.Runtime.Store.Write(tx =>
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, completedId,
                "arcforges.node.v1.FileService/WriteFile", digest, Origin.Remote).Status);
            tx.Execute("""
                INSERT INTO file_operation_journal
                  (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
                   identity_platform, root_identity, parent_identity, target_identity, expected_absent,
                   original_size, original_sha256, original_stage_identity, intended_size, intended_sha256,
                   intended_stage_identity, created_at, updated_at, held, acknowledged)
                VALUES ($id, 1, 2, $digest, $caller, $correlation, $ws, 'observed.txt',
                        $platform, $root, $root, $object, 0, $size, $hash, $root, $size, $hash, $root, $now, $now, 0, 0);
                """, ("$id", completedId), ("$digest", digest), ("$caller", actor.ToByteArray()),
                ("$correlation", CommandIds.New().Value.ToByteArray()), ("$ws", workspace.Id), ("$platform", fileIdentity.Platform),
                ("$root", rootIdentity.Bytes), ("$object", fileIdentity.Bytes), ("$size", (long)body.Length),
                ("$hash", SHA256.HashData(body)), ("$now", tx.NowMicroseconds));
            var objectGeneration = FileCreationOwnership.InvalidateAffected(tx, completedId, created: null);
            Assert.Equal(1L, objectGeneration);
            return FileCreationOwnership.Advance(tx, proof, completedId, workspace.Id, "observed.txt", actor,
                body.Length, SHA256.HashData(body), objectGeneration!.Value);
        }, CommitDurability.Full));
        Assert.False(ObservedOwned());
        Assert.Equal(body, File.ReadAllBytes(path));
    }
}
