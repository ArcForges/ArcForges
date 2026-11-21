// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Migrations;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

public sealed partial class DurableCommandStoreTests
{
    [Fact]
    public void SqlOnlyRetirementIsRejectedBeforeItCouldDisappearBehindADatabaseRollback()
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var destination = new TemporaryDataRoot();
        var clock = new ManualClock();
        var backupSecrets = NodeSecretStores.ForTestDataRoot(backup.Path);
        DurableIntent original;
        using (var store = source.Open(clock, StoreMigrations.Released))
        using (var commands = Commands(store, source.Path))
        {
            original = Intent(commands);
            commands.Admit(original);
            commands.SetResult(original.CommandId, "FAILED", 1, "{\"synthetic_effect\":\"did_not_happen\"}");
            commands.CreateBackup(backup.Path, backupSecrets);
            Assert.Throws<SqliteException>(() => store.Write(tx => tx.Execute(
                "UPDATE owner_epoch SET state='RETIRED',retired_utc='2026-10-15T12:00:00.0000000Z';"), CommitDurability.Full));
            Assert.Equal("ACTIVE", store.Read(reader => reader.Scalar("SELECT state FROM owner_epoch;")));
            Assert.Equal(DurableDecision.Replay, commands.Admit(original).Decision);
        }
        // A rejected retirement is not an acknowledged authority change. The unchanged
        // backup remains coherent and must retain the original known replay identity.
        File.Copy(backup.Database, source.Database, overwrite: true);
        DurableCommandStore.RestoreBackup(backup.Path, backupSecrets, source.Path, NodeSecretStores.ForTestDataRoot(source.Path),
            destination.Path, NodeSecretStores.ForTestDataRoot(destination.Path));
        using var restored = destination.Open(clock, StoreMigrations.Released);
        using var owner = Commands(restored, destination.Path);
        Assert.Equal(DurableDecision.Replay, owner.Admit(original).Decision);
        Assert.Equal(1, owner.Inspect(original.CommandId)!.Effect);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CompleteBackupPreservesEveryOwnerAndProtectedEpochKey(bool contracted)
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var destination = new TemporaryDataRoot();
        var clock = new ManualClock();
        var plan = contracted ? StoreMigrations.Released : StoreMigrations.Expanded;
        var backupSecrets = NodeSecretStores.ForTestDataRoot(backup.Path);
        DurableIntent first;
        DurableIntent second;
        using (var store = source.Open(clock, plan))
        using (var owner = Commands(store, source.Path))
        {
            first = Intent(owner);
            owner.Admit(first);
            owner.SetResult(first.CommandId, "SUCCEEDED", 2, "{\"synthetic_observation\":1}");
            using (var other = new DurableCommandStore(store, "second-owner", NodeSecretStores.ForTestDataRoot(source.Path), Capacity))
            {
                second = Intent(other);
                other.Admit(second);
                other.SetResult(second.CommandId, "UNKNOWN", 3, "{\"fixture\":\"uncertain_second_owner\"}");
                // A full snapshot cannot silently omit another currently owned namespace.
                Assert.Throws<DurableStoreMaintenanceException>(() => owner.CreateBackup(backup.Path, backupSecrets));
            }
            Assert.False(Directory.Exists(backup.Path));
            owner.CreateBackup(backup.Path, backupSecrets);
        }
        DurableCommandStore.RestoreBackup(backup.Path, backupSecrets, source.Path, NodeSecretStores.ForTestDataRoot(source.Path),
            destination.Path, NodeSecretStores.ForTestDataRoot(destination.Path));
        using var restored = destination.Open(clock, plan);
        Assert.Equal(plan.LatestVersion, restored.Metadata.SchemaVersion);
        Assert.Equal(plan.LatestVersion, restored.Metadata.MinReaderVersion);
        using var restoredFirst = Commands(restored, destination.Path);
        using var restoredSecond = new DurableCommandStore(restored, "second-owner", NodeSecretStores.ForTestDataRoot(destination.Path), Capacity);
        Assert.Equal(DurableDecision.Replay, restoredFirst.Admit(first).Decision);
        Assert.Equal(DurableDecision.InProgress, restoredSecond.Admit(second).Decision);
        Assert.Contains("uncertain_second_owner", restoredSecond.Inspect(second.CommandId)!.ResponseJson, StringComparison.Ordinal);
        Assert.Equal(2, new TestDataRootSecretStore(destination.Path).Names().Count);
    }

    [Fact]
    public void AuthorizedRestorePreservesExpandedLegacyCustodyAndOriginalOwnerReceipts()
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var destination = new TemporaryDataRoot();
        var clock = new ManualClock();
        var sourceSecrets = NodeSecretStores.ForTestDataRoot(source.Path);
        var backupSecrets = NodeSecretStores.ForTestDataRoot(backup.Path);
        var destinationSecrets = NodeSecretStores.ForTestDataRoot(destination.Path);
        var oldPlan = new MigrationPlan(StoreMigrations.Expanded.Steps.Take(15));
        const string retryMethod = "arcforges.node.v1.TaskService/RetryTask";
        const string fileMethod = "arcforges.node.v1.FileService/WriteFile";
        Id NewId() => new() { Value = ByteString.CopyFrom(StoreIds.NewUuid7(clock)) };
        var legacyRetry = new TaskServiceRetryTaskRequest
        {
            Meta = new() { CommandId = NewId(), CorrelationId = NewId() },
            TaskId = NewId(),
        };
        var knownLegacy = legacyRetry.Meta.CommandId.Value.ToByteArray();
        var knownDigest = PayloadDigest.Compute(legacyRetry);
        var originalReply = new TaskServiceRetryTaskResponse
        {
            Meta = new() { CorrelationId = legacyRetry.Meta.CorrelationId },
            Error = StoreErrors.SecretsUnavailable(StoreTime.ToMicroseconds(clock.GetUtcNow())),
        }.ToByteArray();
        var unresolvedFile = NewId().Value.ToByteArray();
        var workspace = NewId().Value.ToByteArray();
        var fileDigest = new byte[32];
        // Supplied history metadata. Native ownership and owned-path restore are separate evidence.
        byte[] historicalIdentity = [1, .. new byte[32]];
        var initialPolicy = DefaultPolicy.Create();
        var revisedPolicy = initialPolicy.Clone();
        revisedPolicy.Resources.GlobalMaxRunning = 2;
        var policyAuthor = new ActorRef { Origin = Origin.Human, SessionId = NewId() };
        const string policyComment = "Set the local concurrency limit before expansion.";
        var initialPolicyAt = StoreTime.ToMicroseconds(clock.GetUtcNow());
        long revisedPolicyAt;
        using (var legacy = source.Open(clock, oldPlan))
        {
            clock.Advance(TimeSpan.FromSeconds(1));
            revisedPolicyAt = StoreTime.ToMicroseconds(clock.GetUtcNow());
            legacy.Write(tx =>
            {
                tx.Execute("UPDATE policy_document SET is_current = 0 WHERE revision = 1 AND is_current = 1;");
                tx.Execute("""
                    INSERT INTO policy_document (revision, document, digest, created_at, actor, comment, is_current)
                    VALUES (2, $document, $digest, $at, $actor, $comment, 1);
                    """, ("$document", revisedPolicy.ToByteArray()), ("$digest", PolicyDocuments.Digest(revisedPolicy)),
                    ("$at", revisedPolicyAt), ("$actor", policyAuthor.ToByteArray()), ("$comment", policyComment));
                Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, knownLegacy, retryMethod, knownDigest, Origin.Human).Status);
                CommandDeduplication.Complete(tx, knownLegacy, originalReply);
                tx.Execute("INSERT INTO workspace(workspace_id,kind,state,name,root_path,created_at,last_used_at,rev) VALUES($w,1,2,'historical','/fixture',0,0,0);",
                    ("$w", workspace));
                tx.Execute("INSERT INTO command_dedup(command_id,method,payload_digest,origin,created_at,expires_at) VALUES($id,$method,$digest,4,0,1);",
                    ("$id", unresolvedFile), ("$method", fileMethod), ("$digest", fileDigest));
                tx.Execute("""
                    INSERT INTO file_operation_journal(command_id,kind,phase,request_sha256,caller,correlation_id,workspace_id,relative_path,
                      identity_platform,root_identity,parent_identity,expected_absent,intended_size,intended_sha256,intended_stage_identity,
                      created_at,updated_at,held,acknowledged)
                    VALUES($id,1,3,$digest,x'01',$id,$w,'fixture',1,$identity,$identity,1,0,zeroblob(32),$identity,0,0,1,0);
                    """, ("$id", unresolvedFile), ("$digest", fileDigest), ("$w", workspace), ("$identity", historicalIdentity));
            }, CommitDurability.Full);
        }

        void AssertPolicyLineage(StoreReader reader)
        {
            var revisions = new (long Revision, PolicyDocument Document, long At, ActorRef Actor, string Comment, long Current)[]
            {
                (1, initialPolicy, initialPolicyAt, new ActorRef { Origin = Origin.Node }, PolicyDocuments.DefaultComment, 0),
                (2, revisedPolicy, revisedPolicyAt, policyAuthor, policyComment, 1),
            };
            using var query = reader.CreateCommand("""
                SELECT revision, document, digest, created_at, actor, comment, is_current
                FROM policy_document ORDER BY revision;
                """);
            using var row = query.ExecuteReader();
            foreach (var revision in revisions)
            {
                Assert.True(row.Read());
                Assert.Equal(revision.Revision, row.GetInt64(0));
                Assert.Equal(revision.Document.ToByteArray(), (byte[])row.GetValue(1));
                Assert.Equal(PolicyDocuments.Digest(revision.Document), (byte[])row.GetValue(2));
                Assert.Equal(revision.At, row.GetInt64(3));
                Assert.Equal(revision.Actor.ToByteArray(), (byte[])row.GetValue(4));
                Assert.Equal(revision.Comment, row.GetString(5));
                Assert.Equal(revision.Current, row.GetInt64(6));
            }

            Assert.False(row.Read());
        }

        void AssertLegacyHistory(StoreReader reader)
        {
            var legacyOutcome = CommandDeduplication.ReadRetained(reader, knownLegacy, retryMethod, knownDigest, reader.NowMicroseconds);
            Assert.NotNull(legacyOutcome);
            Assert.Equal(DedupStatus.Replay, legacyOutcome.Status);
            Assert.Equal(originalReply, legacyOutcome.Outcome!.Value.ToArray());
            Assert.Equal((long)Origin.Human, reader.Scalar("SELECT origin FROM command_dedup WHERE command_id = $id;", ("$id", knownLegacy)));
            Assert.Equal(1L, reader.Scalar("""
                SELECT count(*) FROM command_dedup AS d JOIN routed_file_command_retention AS r USING (command_id)
                WHERE d.command_id = $id AND d.method = $method AND d.payload_digest = $digest AND d.outcome IS NULL
                  AND r.delete_permitted = 0;
                """, ("$id", unresolvedFile), ("$method", fileMethod), ("$digest", fileDigest)));
            Assert.Equal(historicalIdentity, reader.Scalar("""
                SELECT intended_stage_identity FROM file_operation_journal
                WHERE command_id = $id AND workspace_id = $w AND phase = 3 AND held = 1 AND acknowledged = 0;
                """, ("$id", unresolvedFile), ("$w", workspace)) as byte[]);
            Assert.Equal(2L, reader.Scalar("SELECT count(*) FROM command_dedup;"));
        }

        string frozenBackup;
        byte[] frozenBytes;
        DurableIntent known;
        DurableIntent uncertain;
        DurableReceipt knownReceipt;
        DurableReceipt uncertainReceipt;
        using (var expanded = source.Open(clock, StoreMigrations.Expanded))
        using (var owner = Commands(expanded, source.Path))
        {
            Assert.Equal(15, expanded.Opening.MigratedFrom);
            Assert.Equal(19, expanded.Metadata.SchemaVersion);
            Assert.Equal(19, expanded.Metadata.MinReaderVersion);
            frozenBackup = Assert.IsType<string>(expanded.Opening.BackupPath);
            frozenBytes = File.ReadAllBytes(frozenBackup);
            using (var snapshot = StoreCreationTests.Open(frozenBackup))
            {
                var reader = new StoreReader(snapshot, null, clock);
                Assert.Equal("ok", reader.Scalar("PRAGMA integrity_check;"));
                Assert.Equal(15L, reader.Scalar("SELECT schema_version FROM store_meta WHERE singleton = 1;"));
                Assert.Equal(15L, reader.Scalar("SELECT min_reader_version FROM store_meta WHERE singleton = 1;"));
                Assert.Equal(0L, reader.Scalar("""
                    SELECT count(*) FROM sqlite_schema WHERE name IN ('sandbox', 'owner_epoch', 'command_receipt', 'migration_checkpoint');
                    """));
                AssertPolicyLineage(reader);
                AssertLegacyHistory(reader);
            }

            var frozenDigest = Convert.ToHexStringLower(SHA256.HashData(frozenBytes));
            Assert.Equal(1L, expanded.Read(reader => reader.Scalar("""
                SELECT count(*) FROM migration_checkpoint
                WHERE migration_id = 'AFV2-DATA-01/schema16' AND source_schema = 15 AND target_schema = 16
                  AND backup_identity = $digest AND unresolved_count = 1;
                """, ("$digest", frozenDigest))));
            known = Intent(owner, body: "fixture-known");
            uncertain = Intent(owner, body: "fixture-uncertain");
            Assert.Equal(DurableDecision.Execute, owner.Admit(known).Decision);
            Assert.Equal(DurableDecision.Execute, owner.Admit(uncertain).Decision);
            knownReceipt = owner.SetResult(known.CommandId, "SUCCEEDED", 2, "{\"fixture\":\"observed\"}");
            uncertainReceipt = owner.SetResult(uncertain.CommandId, "UNKNOWN", 3, "{\"fixture\":\"uncertain\"}");
            owner.CreateBackup(backup.Path, backupSecrets);
        }

        var sourceBytes = File.ReadAllBytes(source.Database);
        var backupBytes = File.ReadAllBytes(backup.Database);
        DurableCommandStore.RestoreBackup(backup.Path, backupSecrets, source.Path, sourceSecrets, destination.Path, destinationSecrets);
        Assert.Equal(sourceBytes, File.ReadAllBytes(source.Database));
        Assert.Equal(frozenBytes, File.ReadAllBytes(frozenBackup));
        Assert.Equal(backupBytes, File.ReadAllBytes(backup.Database));
        Assert.Equal(backupBytes, File.ReadAllBytes(destination.Database));

        foreach (string root in new[] { source.Path, destination.Path })
        {
            var originalFiles = Directory.GetFiles(root, "*", SearchOption.AllDirectories)
                .ToDictionary(file => file, file => SHA256.HashData(File.ReadAllBytes(file)), StringComparer.Ordinal);
            var refusal = Assert.Throws<StoreIncompatibleException>(() => NodeStore.OpenForV2Runtime(
                new NodeStoreOptions { DataRoot = root, BootIdentity = "successor" }));
            Assert.Contains("legacy_store_requires_offline_cutover", refusal.Message, StringComparison.Ordinal);
            Assert.Equal(originalFiles.Keys.Order(StringComparer.Ordinal),
                Directory.GetFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal));
            foreach (var (file, digest) in originalFiles)
                Assert.Equal(digest, SHA256.HashData(File.ReadAllBytes(file)));
        }

        using var restored = destination.Open(clock, StoreMigrations.Expanded);
        Assert.Equal(19, restored.Metadata.SchemaVersion);
        Assert.Equal(19, restored.Metadata.MinReaderVersion);
        using var restoredOwner = Commands(restored, destination.Path);
        Assert.Equal(known.OwnerEpoch, restoredOwner.OwnerEpoch.ToArray());
        Assert.Equal(new DurableAdmission(DurableDecision.Replay, knownReceipt), restoredOwner.Admit(known));
        Assert.Equal(new DurableAdmission(DurableDecision.InProgress, uncertainReceipt), restoredOwner.Admit(uncertain));
        restored.Read(reader =>
        {
            AssertPolicyLineage(reader);
            AssertLegacyHistory(reader);
            Assert.True(RoutedFileRetention.IsHeld(reader, unresolvedFile));
            Assert.Equal(DedupStatus.InProgress, CommandDeduplication.ReadRetained(reader, unresolvedFile, fileMethod, fileDigest, reader.NowMicroseconds)?.Status);
            Assert.Equal(2L, reader.Scalar("SELECT count(*) FROM command_receipt;"));
            return 0;
        });
    }

    [Fact]
    public void ANewOwnerAdmittedAfterBackupCannotDisappearFromRestoreChecks()
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var destination = new TemporaryDataRoot();
        var clock = new ManualClock();
        var backupSecrets = NodeSecretStores.ForTestDataRoot(backup.Path);
        using (var store = source.Open(clock, StoreMigrations.Released))
        {
            using (var owner = Commands(store, source.Path))
            {
                var intent = Intent(owner);
                owner.Admit(intent);
                owner.SetResult(intent.CommandId, "FAILED", 1, "{\"synthetic_effect\":\"did_not_happen\"}");
                owner.CreateBackup(backup.Path, backupSecrets);
            }
            using var later = new DurableCommandStore(store, "second-owner", NodeSecretStores.ForTestDataRoot(source.Path), Capacity);
            Assert.Equal(DurableDecision.Execute, later.Admit(Intent(later)).Decision);
        }
        Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.RestoreBackup(backup.Path, backupSecrets,
            source.Path, NodeSecretStores.ForTestDataRoot(source.Path), destination.Path, NodeSecretStores.ForTestDataRoot(destination.Path)));
        Assert.False(File.Exists(destination.Database));
    }

    [Fact]
    public void RolledBackLatestDatabaseCannotEraseItsNewerIndependentFence()
    {
        using var source = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var destination = new TemporaryDataRoot();
        var clock = new ManualClock();
        var backupSecrets = NodeSecretStores.ForTestDataRoot(backup.Path);
        using (var store = source.Open(clock, StoreMigrations.Released))
        using (var commands = Commands(store, source.Path))
        {
            var intent = Intent(commands);
            commands.Admit(intent);
            commands.CreateBackup(backup.Path, backupSecrets);
            commands.SetResult(intent.CommandId, "SUCCEEDED", 2, "{\"synthetic_observation\":1}");
        }
        // A controlled old-DB restore input, leaving the independently retained newest fence untouched.
        File.Copy(backup.Database, source.Database, overwrite: true);
        Assert.Throws<DurableStoreMaintenanceException>(() => DurableCommandStore.RestoreBackup(backup.Path, backupSecrets,
            source.Path, NodeSecretStores.ForTestDataRoot(source.Path), destination.Path, NodeSecretStores.ForTestDataRoot(destination.Path)));
        Assert.False(File.Exists(destination.Database));
    }
}
