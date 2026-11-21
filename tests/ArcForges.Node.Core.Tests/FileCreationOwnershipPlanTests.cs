// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Durable legacy creation ownership with synthetic native observations and no filesystem effects.</summary>
public sealed class FileCreationOwnershipPlanTests
{
    private const string ExistingPath = "observed.txt";

    [Fact]
    public Task CompletedCreationOwnershipStaysBoundToItsOriginalReceiptAndObservedObject() =>
        LegacyPlannerHistoryFixture.WithStoreAsync(store =>
        {
            var owner = LegacyPlannerHistoryFixture.Owner(store);
            var evidence = CreationEvidence();
            var original = store.Write(transaction =>
            {
                var workspace = LegacyPlannerHistoryFixture.SeedWorkspace(transaction, Path.Combine(store.DataRoot, "workspace"));
                return SeedCreation(transaction, workspace, owner, evidence);
            }, CommitDurability.Full);

            Assert.True(store.Read(reader =>
            {
                using var command = reader.CreateCommand("""
                    SELECT caller, creation_command_id, root_identity, object_identity, creation_marker,
                           last_written_size, last_written_sha256
                    FROM file_creation_ownership WHERE workspace_id = $workspace AND relative_path = $path;
                    """);
                command.Parameters.AddWithValue("$workspace", original.Workspace);
                command.Parameters.AddWithValue("$path", ExistingPath);
                using var row = command.ExecuteReader();
                Assert.True(row.Read());
                Assert.Equal(original.CallerBytes, (byte[])row.GetValue(0));
                Assert.Equal(original.Command, (byte[])row.GetValue(1));
                Assert.Equal(original.RootIdentity, (byte[])row.GetValue(2));
                Assert.Equal(original.ObjectIdentity, (byte[])row.GetValue(3));
                Assert.Equal(original.Marker, (byte[])row.GetValue(4));
                Assert.Equal(original.Size, row.GetInt64(5));
                Assert.Equal(original.Hash, (byte[])row.GetValue(6));
                return !row.Read();
            }));
            Assert.False(Directory.Exists(Path.Combine(store.DataRoot, "workspace")));
            return Task.CompletedTask;
        });

    [Fact]
    public Task UnknownUnidentifiedCreateInvalidatesGenerationAndCannotReviveAnOldProof() =>
        LegacyPlannerHistoryFixture.WithStoreAsync(store =>
        {
            var actor = LegacyPlannerHistoryFixture.Owner(store);
            var evidence = CreationEvidence();
            var root = RootIdentity();
            var (workspace, original) = store.Write(transaction =>
            {
                var registered = LegacyPlannerHistoryFixture.SeedWorkspace(transaction, Path.Combine(store.DataRoot, "workspace"));
                return (registered, SeedCreation(transaction, registered, actor, evidence));
            }, CommitDurability.Full);
            var oldProof = new FileCreationOwnership.UpdateProof(original.Workspace, ExistingPath, actor,
                original.CallerBytes, root.Platform, original.RootIdentity, evidence.Identity.Platform,
                original.ObjectIdentity, original.Marker, original.Size, original.Hash,
                GlobalGeneration: 0, original.ObjectGeneration);
            var uncertain = store.Write(transaction =>
                SeedIntent(transaction, workspace, actor, root, "unobserved.txt", phase: 1,
                    target: null, size: 0, SHA256.HashData(ReadOnlySpan<byte>.Empty)), CommitDurability.Full);
            store.Write(transaction => FileMutationJournal.MarkUnknown(transaction, uncertain.Command), CommitDurability.Full);
            Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT generation FROM file_ownership_generation WHERE singleton = 1;")));
            Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM file_creation_ownership;")));
            Assert.Equal(FileJournalAcknowledgment.Acknowledged, store.Write(transaction =>
                FileMutationJournal.AcknowledgeFromVerifiedHuman(transaction, uncertain.Command, uncertain.RequestHash,
                    new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli }), CommitDurability.Full));
            Assert.Equal(FileOperationState.Unknown, store.Read(reader =>
                FileMutationJournal.GetForCaller(reader, uncertain.Command, actor))!.State);

            var laterHash = SHA256.HashData("subsequent write"u8);
            Assert.False(store.Write(transaction =>
            {
                var later = SeedIntent(transaction, workspace, actor, root, ExistingPath, phase: 2,
                    evidence.Identity.Bytes, original.Size, laterHash);
                var generation = FileCreationOwnership.InvalidateAffected(transaction, later.Command, created: null);
                Assert.Equal(original.ObjectGeneration + 1, generation);
                return FileCreationOwnership.Advance(transaction, oldProof, later.Command, original.Workspace, ExistingPath,
                    actor, original.Size, laterHash, generation!.Value);
            }, CommitDurability.Full));

            Assert.Equal(0L, store.Read(reader => reader.Scalar("""
                SELECT count(*) FROM file_creation_ownership c JOIN file_ownership_generation g ON c.global_generation = g.generation;
                """)));
            Assert.Equal(original.Hash, (byte[]?)store.Read(reader => reader.Scalar("SELECT last_written_sha256 FROM file_creation_ownership;")));
            Assert.False(Directory.Exists(Path.Combine(store.DataRoot, "workspace")));
            return Task.CompletedTask;
        });

    private sealed record Creation(byte[] Workspace, byte[] CallerBytes, byte[] Command, byte[] RootIdentity, byte[] ObjectIdentity,
        byte[] Marker, long Size, byte[] Hash, long ObjectGeneration);

    private static WorkspaceCreatedOwnership CreationEvidence() =>
        new(new RegisteredWorkspaces.RootIdentity(1, [1, 29, .. new byte[31]]), SHA256.HashData("fixture marker"u8));

    private static RegisteredWorkspaces.RootIdentity RootIdentity() => new(1, [1, 17, .. new byte[31]]);

    private static Creation SeedCreation(StoreTransaction transaction, Id workspace, CenterCaller owner, WorkspaceCreatedOwnership evidence)
    {
        const int size = 25;
        var hash = SHA256.HashData("historical body"u8);
        var root = RootIdentity();
        var intent = SeedIntent(transaction, workspace, owner, root, ExistingPath, phase: 2, target: null, size, hash);
        var receipt = new FileServiceWriteFileResponse
        {
            Meta = new() { CorrelationId = intent.Correlation },
            Value = new()
            {
                Result = new()
                {
                    CommandId = new Id { Value = ByteString.CopyFrom(intent.Command) },
                    SizeBytes = size,
                    Sha256 = ByteString.CopyFrom(hash),
                },
            },
            Audit = new()
            {
                Observations = { new FileAuditObservation
                {
                    Kind = FileAuditKind.WrittenBytes, SizeBytes = size, DigestInputBytes = size, Sha256 = ByteString.CopyFrom(hash),
                } },
            },
        };
        CommandDeduplication.Complete(transaction, intent.Command, receipt.ToByteArray());
        var generation = FileCreationOwnership.InvalidateAffected(transaction, intent.Command, evidence);
        Assert.Equal(1L, generation);
        FileCreationOwnership.RecordCompleted(transaction, intent.Command, evidence, size, hash);
        return new Creation(workspace.Value.ToByteArray(), owner.ToByteArray(), intent.Command, root.Bytes, evidence.Identity.Bytes,
            evidence.Marker!, size, hash, generation!.Value);
    }

    private static (byte[] Command, Id Correlation, byte[] RequestHash) SeedIntent(StoreTransaction transaction, Id workspace,
        CenterCaller actor, RegisteredWorkspaces.RootIdentity root, string path, int phase, byte[]? target, long size, byte[] hash)
    {
        var id = CommandIds.New().Value.ToByteArray();
        var correlation = CommandIds.New();
        var digest = SHA256.HashData(id);
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id,
            "arcforges.node.v1.FileService/WriteFile", digest, Origin.Remote).Status);
        Assert.Equal(1, transaction.Execute("""
            INSERT INTO file_operation_journal
              (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
               identity_platform, root_identity, parent_identity, target_identity, expected_absent,
               original_size, original_sha256, original_stage_identity, intended_size, intended_sha256,
               intended_stage_identity, created_at, updated_at, held, acknowledged)
            VALUES ($id, 1, $phase, $digest, $caller, $correlation, $workspace, $path,
                    $platform, $root, $root, $target, $absent, $originalSize, $originalHash, $originalStage,
                    $size, $hash, $root, $now, $now, $held, 0);
            """, ("$id", id), ("$phase", phase), ("$digest", digest), ("$caller", actor.ToByteArray()),
            ("$correlation", correlation.Value.ToByteArray()), ("$workspace", workspace.Value.ToByteArray()), ("$path", path),
            ("$platform", root.Platform), ("$root", root.Bytes), ("$target", target), ("$absent", target is null ? 1 : 0),
            ("$originalSize", target is null ? null : size), ("$originalHash", target is null ? null : hash),
            ("$originalStage", target is null ? null : root.Bytes), ("$size", size), ("$hash", hash),
            ("$now", transaction.NowMicroseconds), ("$held", phase == 1 ? 1 : 0)));
        return (id, correlation, digest);
    }
}
