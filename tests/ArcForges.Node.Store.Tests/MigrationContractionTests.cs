// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Migrations;
using Google.Protobuf;

namespace ArcForges.Node.Store.Tests;

[Collection(nameof(MigrationOwnershipFixture))]
public sealed class MigrationContractionTests
{
    private const string Owner = "migration-fixture-owner";
    private const string FileMethod = "arcforges.node.v1.FileService/WriteFile";
    private const string Checkpoint = "AFV2-MIG-02/schema20";
    private const string SandboxJson = """{"migration":"original config bytes"}""";
    private const string SuccessJson = """{"ok":"original observation"}""";
    private const string UnknownJson = """{"state":"original uncertain observation"}""";

    [Fact]
    public void FreshNodeUsesTheContractedLayoutAndRefusesTheOldReader()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        byte[] node;
        using (var store = OpenRuntime(root, clock))
        {
            Assert.True(store.Opening.Created);
            node = store.Metadata.NodeId.ToArray();
            AssertContracted(store);
            store.Read(reader =>
            {
                Assert.Equal(1L, reader.Scalar("""
                    SELECT count(*) FROM migration_checkpoint
                    WHERE migration_id=$id AND source_schema=0 AND target_schema=20 AND unresolved_count=0
                      AND state='CONTRACTED_FRESH' AND backup_identity='fresh:no-predecessor'
                      AND source_database_sha256 IS NULL AND history_archive_sha256 IS NULL
                      AND restore_database_sha256 IS NULL AND scope_receipt_sha256 IS NULL;
                    """, ("$id", Checkpoint)));
                return 0;
            });
        }

        AssertOldReaderRefuses(root, clock);
        using var reopened = OpenRuntime(root, clock);
        Assert.Equal(node, reopened.Metadata.NodeId.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("env", "windows-real")]
    public void StoreInspectionCanReadPastAnExistingWindowsWriteHandle(bool includeWal)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows requires compatible file sharing for all open handles.");
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        byte[] node;
        using (var initial = OpenRuntime(root, clock))
            node = initial.Metadata.NodeId.ToArray();

        using var writer = new FileStream(root.Database, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
        if (includeWal)
        {
            using var sqlite = new Microsoft.Data.Sqlite.SqliteConnection(
                StorePaths.ConnectionString(root.Database, Microsoft.Data.Sqlite.SqliteOpenMode.ReadWrite));
            sqlite.Open();
            using var command = sqlite.CreateCommand();
            command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; UPDATE store_meta SET clean_shutdown_at=clean_shutdown_at+1;";
            command.ExecuteNonQuery();
            Assert.True(File.Exists(root.Database + "-wal"));
            using var reopened = root.Open(clock, StoreMigrations.Released);
            Assert.Equal(node, reopened.Metadata.NodeId.ToArray());
        }
        else
        {
            Assert.False(File.Exists(root.Database + "-wal"));
            using var reopened = root.Open(clock, StoreMigrations.Released);
            Assert.Equal(node, reopened.Metadata.NodeId.ToArray());
        }
    }

    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void Schema15HistoryAndV2AuthoritySurviveContractionAndRestore()
    {
        AssertNativePlatform();
        using var source = new TemporaryDataRoot();
        using var history = new TemporaryDataRoot();
        using var staged = new TemporaryDataRoot();
        using var currentBackup = new TemporaryDataRoot();
        using var restored = new TemporaryDataRoot();
        var clock = new ManualClock();
        string boot = NodeContractionScope.ReadCurrentBootIdentity();
        var legacy = SeedLegacy(source, clock, boot);
        CurrentRecords current;
        string expansionBackup;
        using (var expanded = source.Open(clock, StoreMigrations.Expanded, boot))
        {
            Assert.Equal(15, expanded.Opening.MigratedFrom);
            Assert.Equal(19, expanded.Metadata.SchemaVersion);
            Assert.Equal(19, expanded.Metadata.MinReaderVersion);
            expansionBackup = Assert.IsType<string>(expanded.Opening.BackupPath);
            AssertLegacy(expanded, legacy);
            current = SeedCurrent(expanded, source, history);
        }

        PrepareOfflineScope(source);
        string originalDigest = HashFile(source.Database);
        string historyDigest = HashFile(history.Database);
        string expansionDigest = HashFile(expansionBackup);
        string manifestDigest = HashFile(Path.Combine(history.Path, "v2-backup.manifest"));
        string scopeDigest;
        using (var scope = NodeContractionScope.Acquire(source.Path))
        {
            scopeDigest = scope.ReceiptSha256;
            var archive = RestoreArchive(scope, source, history, staged);
            Assert.Equal(historyDigest, HashFile(staged.Database));

            // Stop immediately before the SQLite commit, after the actual DDL and checkpoint were written.
            var interrupted = new InvalidOperationException("fixture interrupted before commit");
            Assert.Same(interrupted, Assert.Throws<InvalidOperationException>(() =>
                NodeStore.ContractVerifiedCopy(archive, clock, beforeCommit: () => throw interrupted)));
            Assert.Equal(historyDigest, HashFile(staged.Database));
            using (var rolledBack = StoreCreationTests.Open(staged.Database))
            {
                Assert.Equal(["19|19"], StoreCreationTests.Query(rolledBack, "SELECT schema_version || '|' || min_reader_version FROM store_meta;"));
                Assert.Equal(["task"], StoreCreationTests.Query(rolledBack, "SELECT name FROM sqlite_schema WHERE name='task';"));
                Assert.Empty(StoreCreationTests.Query(rolledBack, "SELECT migration_id FROM migration_checkpoint WHERE target_schema=20;"));
                Assert.Equal(["ok"], StoreCreationTests.Query(rolledBack, "PRAGMA integrity_check;"));
            }

            string verifiedFile = staged.Database + ".verified";
            File.Move(staged.Database, verifiedFile);
            try
            {
                File.Copy(verifiedFile, staged.Database);
                Assert.Equal(historyDigest, HashFile(staged.Database));
                var replacement = Assert.Throws<StoreIncompatibleException>(() => NodeStore.ContractVerifiedCopy(archive, clock));
                Assert.Contains("staged database file identity changed", replacement.Message, StringComparison.Ordinal);
            }
            finally
            {
                File.Move(verifiedFile, staged.Database, overwrite: true);
            }

            NodeStore.ContractVerifiedCopy(archive, clock);
            Assert.Equal(originalDigest, HashFile(source.Database));
            Assert.Equal(historyDigest, HashFile(history.Database));
        }

        Assert.Equal(expansionDigest, HashFile(expansionBackup));
        Assert.Equal(manifestDigest, HashFile(Path.Combine(history.Path, "v2-backup.manifest")));
        AssertOldReaderRefuses(staged, clock);
        using (var frozen = StoreCreationTests.Open(expansionBackup))
        {
            Assert.Equal(["15|15"], StoreCreationTests.Query(frozen, "SELECT schema_version || '|' || min_reader_version FROM store_meta;"));
            AssertLegacy(new StoreReader(frozen, null, clock), legacy);
        }
        using (var archived = StoreCreationTests.Open(history.Database))
        {
            Assert.Equal(["19|19"], StoreCreationTests.Query(archived, "SELECT schema_version || '|' || min_reader_version FROM store_meta;"));
            AssertLegacy(new StoreReader(archived, null, clock), legacy);
        }

        using (var contracted = OpenRuntime(staged, clock))
        using (var owner = Commands(contracted, staged))
        {
            AssertContracted(contracted);
            AssertCurrent(contracted, owner, current);
            contracted.Read(reader =>
            {
                Assert.Equal(1L, reader.Scalar("""
                    SELECT count(*) FROM migration_checkpoint
                    WHERE migration_id=$id AND source_schema=19 AND target_schema=20 AND unresolved_count=0
                      AND state='CONTRACTED_VERIFIED_ARCHIVE' AND backup_identity=$manifest
                      AND source_database_sha256=$original AND history_archive_sha256=$history
                      AND restore_database_sha256=$history AND scope_receipt_sha256=$scope;
                    """, ("$id", Checkpoint), ("$manifest", manifestDigest), ("$original", originalDigest),
                    ("$history", historyDigest), ("$scope", scopeDigest)));
                Assert.Equal(legacy.FileReply, reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id=$id;",
                    ("$id", legacy.FileCommand)) as byte[]);
                Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM contracted_command_hold WHERE command_id=$id;",
                    ("$id", legacy.FileCommand)));
                return 0;
            });
            owner.CreateBackup(currentBackup.Path, Secrets(currentBackup));
        }

        DurableCommandStore.RestoreBackup(
            currentBackup.Path, Secrets(currentBackup), staged.Path, Secrets(staged), restored.Path, Secrets(restored));
        Assert.Equal(HashFile(currentBackup.Database), HashFile(restored.Database));
        AssertOldReaderRefuses(restored, clock);
        using var final = OpenRuntime(restored, clock);
        using var finalOwner = Commands(final, restored);
        AssertContracted(final);
        AssertCurrent(final, finalOwner, current);
        Assert.Equal(originalDigest, HashFile(source.Database));
        Assert.Equal(historyDigest, HashFile(history.Database));
    }

    [Theory(DisableParallelization = true)]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("isolation", "exclusive")]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void ChangedArchiveOrChangedOriginalCannotProduceAServingStore(bool tamperWithArchive)
    {
        AssertNativePlatform();
        using var source = new TemporaryDataRoot();
        using var history = new TemporaryDataRoot();
        using var staged = new TemporaryDataRoot();
        var clock = new ManualClock();
        string boot = NodeContractionScope.ReadCurrentBootIdentity();
        var legacy = SeedLegacy(source, clock, boot);
        using (var expanded = source.Open(clock, StoreMigrations.Expanded, boot))
        {
            SeedCurrent(expanded, source, history);
            if (!tamperWithArchive)
            {
                expanded.Write(tx => tx.Execute("""
                    INSERT INTO node_setting(name,value_json,updated_at,rev) VALUES('after_backup','42',0,0);
                    """), CommitDurability.Full);
            }
        }

        PrepareOfflineScope(source);
        if (tamperWithArchive)
        {
            string manifest = Path.Combine(history.Path, "v2-backup.manifest");
            byte[] bytes = File.ReadAllBytes(manifest);
            bytes[^1] ^= 1;
            File.WriteAllBytes(manifest, bytes);
        }
        string sourceDigest = HashFile(source.Database);
        string archiveDigest = HashFile(history.Database);
        using (var scope = NodeContractionScope.Acquire(source.Path))
        {
            if (tamperWithArchive)
            {
                Assert.Throws<DurableStoreMaintenanceException>(() => RestoreArchive(scope, source, history, staged));
                Assert.False(Directory.Exists(staged.Path));
            }
            else
            {
                var refusal = Assert.Throws<StoreIncompatibleException>(() => RestoreArchive(scope, source, history, staged));
                Assert.Contains("missing original rows", refusal.Message, StringComparison.Ordinal);
                AssertRuntimeRefuses(staged, clock);
            }
        }
        Assert.Equal(sourceDigest, HashFile(source.Database));
        Assert.Equal(archiveDigest, HashFile(history.Database));
        AssertRuntimeRefuses(source, clock);
        using var original = StoreCreationTests.Open(source.Database);
        AssertLegacy(new StoreReader(original, null, clock), legacy);
    }

    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void UnknownHistoricalFileEffectKeepsTheExpandedStoreInMaintenance()
    {
        AssertNativePlatform();
        using var source = new TemporaryDataRoot();
        using var history = new TemporaryDataRoot();
        using var staged = new TemporaryDataRoot();
        var clock = new ManualClock();
        string boot = NodeContractionScope.ReadCurrentBootIdentity();
        var legacy = SeedLegacy(source, clock, boot, unknownEffect: true);
        using (var expanded = source.Open(clock, StoreMigrations.Expanded, boot))
        {
            SeedCurrent(expanded, source, history);
        }

        PrepareOfflineScope(source);
        string originalDigest = HashFile(source.Database);
        string historyDigest = HashFile(history.Database);
        using (var scope = NodeContractionScope.Acquire(source.Path))
        {
            var archive = RestoreArchive(scope, source, history, staged);
            var refusal = Assert.Throws<StoreIncompatibleException>(() => NodeStore.ContractVerifiedCopy(archive, clock));
            Assert.Contains("Unresolved legacy custody", refusal.Message, StringComparison.Ordinal);
        }

        Assert.Equal(originalDigest, HashFile(source.Database));
        Assert.Equal(historyDigest, HashFile(history.Database));
        Assert.Equal(historyDigest, HashFile(staged.Database));
        AssertRuntimeRefuses(staged, clock);
        using var checkpoint = StoreCreationTests.Open(staged.Database);
        var reader = new StoreReader(checkpoint, null, clock);
        Assert.Equal(1L, reader.Scalar("""
            SELECT count(*) FROM file_operation_journal j JOIN command_dedup d USING (command_id)
            WHERE j.command_id=$id AND j.phase=3 AND j.held=1 AND d.outcome IS NULL;
            """, ("$id", legacy.FileCommand)));
    }

    private static LegacyRecords SeedLegacy(TemporaryDataRoot source, ManualClock clock, string boot, bool unknownEffect = false)
    {
        var original = new FileServiceWriteFileResponse
        {
            Meta = new() { CorrelationId = new Id { Value = ByteString.CopyFrom(StoreIds.NewUuid7(clock)) } },
            Error = StoreErrors.SecretsUnavailable(StoreTime.ToMicroseconds(clock.Now)),
        };
        byte[] command = StoreIds.NewUuid7(clock);
        byte[] workspace = StoreIds.NewUuid7(clock);
        byte[] attempt = StoreIds.NewUuid7(clock);
        byte[] digest = SHA256.HashData("original historical request bytes"u8);
        byte[] reply = original.ToByteArray();
        byte[] objectIdentity = [1, 19, .. new byte[31]];
        var oldPlan = new MigrationPlan(StoreMigrations.Expanded.Steps.Take(15));
        using var store = source.Open(clock, oldPlan, boot);
        Assert.Equal(15, store.Metadata.SchemaVersion);
        var node = store.Metadata.NodeId.ToArray();
        byte[] task = store.Write(tx =>
        {
            byte[] taskId = Rows.InsertTask(tx, spec: new TaskSpec { Title = "original task" });
            tx.Execute("UPDATE task SET state=7 WHERE task_id=$id;", ("$id", taskId));
            tx.Execute("""
                INSERT INTO attempt(attempt_id,task_id,number,kind,state,executor_node_id,
                    request_cpu_millicores,request_mem_expected_bytes,request_mem_ceiling_bytes,request_source,
                    accounted_mem_bytes,created_at,finished_at,termination_reason,effect,rev)
                VALUES($id,$task,1,1,9,$node,25,1024,2048,1,1024,0,1,1,2,0);
                """, ("$id", attempt), ("$task", taskId), ("$node", node));
            tx.Execute("""
                INSERT INTO workspace(workspace_id,kind,state,name,root_path,created_at,last_used_at,rev)
                VALUES($id,1,2,'historical','/fixture',0,0,0);
                """, ("$id", workspace));
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, command, FileMethod, digest, Origin.Human).Status);
            if (!unknownEffect)
                CommandDeduplication.Complete(tx, command, reply);
            tx.Execute("""
                INSERT INTO file_operation_journal(command_id,kind,phase,request_sha256,caller,correlation_id,workspace_id,
                    relative_path,identity_platform,root_identity,parent_identity,expected_absent,intended_size,
                    intended_sha256,intended_stage_identity,created_at,updated_at,held,acknowledged)
                VALUES($id,1,$phase,$digest,$caller,$correlation,$workspace,'fixture',1,$object,$object,1,0,$digest,$object,0,0,$held,0);
                """, ("$id", command), ("$digest", digest), ("$caller", new ActorRef { Origin = Origin.Human }.ToByteArray()),
                ("$correlation", original.Meta.CorrelationId.Value.ToByteArray()), ("$workspace", workspace), ("$object", objectIdentity),
                ("$phase", unknownEffect ? 3 : 2), ("$held", unknownEffect ? 1 : 0));
            return taskId;
        }, CommitDurability.Full);

        return new(task, attempt, workspace, command, digest, reply, objectIdentity);
    }

    private static CurrentRecords SeedCurrent(NodeStore store, TemporaryDataRoot root, TemporaryDataRoot backup)
    {
        string id = Convert.ToHexStringLower(StoreIds.NewUuid7(store.Clock));
        var config = new StoredSandboxConfig("fixture-profile", "1", SandboxJson,
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(SandboxJson))));
        DateTimeOffset now = store.Clock.GetUtcNow();
        var sandbox = new StoredSandbox(id, Owner, "Original name", "original name", 1, StoredSandboxState.Creating,
            "sandboxes/" + id, SandboxRecords.PendingRootIdentity, 1, now, now, config);
        using var commands = Commands(store, root);
        var success = new DurableIntent(StoreIds.NewUuid7(store.Clock), commands.OwnerEpoch.ToArray(), "FixtureService.Configure",
            "sandbox", id, "original mutation"u8.ToArray());
        var unknown = success with { CommandId = StoreIds.NewUuid7(store.Clock), CanonicalBody = "uncertain mutation"u8.ToArray() };
        Assert.Equal(DurableDecision.Execute, commands.Admit(success).Decision);
        store.Write(tx => SandboxRecords.Reserve(tx, sandbox), CommitDurability.Full);
        var succeeded = commands.SetResult(success.CommandId, "SUCCEEDED", 2, SuccessJson);
        Assert.Equal(DurableDecision.Execute, commands.Admit(unknown).Decision);
        var uncertain = commands.SetResult(unknown.CommandId, "UNKNOWN", 3, UnknownJson);
        byte[] policy = store.Read(reader => Assert.IsType<byte[]>(reader.Scalar("SELECT document FROM policy_document WHERE is_current=1;")));
        commands.CreateBackup(backup.Path, Secrets(backup));
        return new(store.Metadata.NodeId.ToArray(), sandbox, success, unknown, succeeded, uncertain, policy);
    }

    private static void AssertLegacy(NodeStore store, LegacyRecords expected) => store.Read(reader =>
    {
        AssertLegacy(reader, expected);
        return 0;
    });

    private static void AssertLegacy(StoreReader reader, LegacyRecords expected)
    {
        Assert.Equal(expected.Task, reader.Scalar("SELECT task_id FROM attempt WHERE attempt_id=$id AND state=9;",
            ("$id", expected.Attempt)) as byte[]);
        Assert.Equal(expected.Workspace, reader.Scalar("SELECT workspace_id FROM file_operation_journal WHERE command_id=$id AND phase=2;",
            ("$id", expected.FileCommand)) as byte[]);
        Assert.Equal(expected.FileIdentity, reader.Scalar("SELECT intended_stage_identity FROM file_operation_journal WHERE command_id=$id;",
            ("$id", expected.FileCommand)) as byte[]);
        Assert.Equal(expected.FileDigest, reader.Scalar("SELECT payload_digest FROM command_dedup WHERE command_id=$id AND method=$method;",
            ("$id", expected.FileCommand), ("$method", FileMethod)) as byte[]);
        Assert.Equal(expected.FileReply, reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id=$id;",
            ("$id", expected.FileCommand)) as byte[]);
    }

    private static void AssertCurrent(NodeStore store, DurableCommandStore owner, CurrentRecords current)
    {
        Assert.Equal(current.Node, store.Metadata.NodeId.ToArray());
        Assert.Equal(current.Known.OwnerEpoch, owner.OwnerEpoch.ToArray());
        Assert.Equal(new DurableAdmission(DurableDecision.Replay, current.Succeeded), owner.Admit(current.Known));
        Assert.Equal(new DurableAdmission(DurableDecision.InProgress, current.Uncertain), owner.Admit(current.Unknown));
        store.Read(reader =>
        {
            Assert.Equal(current.Sandbox, SandboxRecords.Get(reader, Owner, current.Sandbox.SandboxId));
            Assert.Equal(current.Policy, reader.Scalar("SELECT document FROM policy_document WHERE is_current=1;") as byte[]);
            Assert.Equal(2L, reader.Scalar("SELECT count(*) FROM command_receipt;"));
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM event WHERE kind='sandbox' AND aggregate_id=$id AND owner_id=$owner;",
                ("$id", current.Sandbox.SandboxId), ("$owner", Owner)));
            return 0;
        });
    }

    private static void AssertContracted(NodeStore store)
    {
        Assert.Equal(20, store.Metadata.SchemaVersion);
        Assert.Equal(20, store.Metadata.MinReaderVersion);
        store.Read(reader =>
        {
            Assert.Equal("20|20", reader.Scalar("SELECT version || '|' || min_reader FROM schema_version WHERE singleton=1;"));
            Assert.Equal(0L, reader.Scalar("""
                SELECT count(*) FROM sqlite_schema WHERE name IN ('task','attempt','workspace','file_operation_journal',
                    'routed_file_command_retention','offer','cache_instance','toolchain','peer','phone_pairing');
                """));
            Assert.Equal(8L, reader.Scalar("""
                SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('sandbox','run','policy_document',
                    'owner_epoch','command_receipt','remote_grant','transfer','migration_checkpoint');
                """));
            Assert.Equal("ok", reader.Scalar("PRAGMA integrity_check;"));
            Assert.Null(reader.Scalar("SELECT rowid FROM pragma_foreign_key_check LIMIT 1;"));
            return 0;
        });
    }

    private static void AssertRuntimeRefuses(TemporaryDataRoot root, ManualClock clock)
    {
        string originalDigest = HashFile(root.Database);
        var refusal = Assert.Throws<StoreIncompatibleException>(() => OpenRuntime(root, clock));
        Assert.Contains("legacy_store_requires_offline_cutover", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(originalDigest, HashFile(root.Database));
    }

    private static void AssertOldReaderRefuses(TemporaryDataRoot root, ManualClock clock)
    {
        string originalDigest = HashFile(root.Database);
        var refusal = Assert.Throws<StoreIncompatibleException>(() => NodeStore.OpenForV2Runtime(
            new NodeStoreOptions { DataRoot = root.Path, BootIdentity = NodeContractionScope.ReadCurrentBootIdentity(), Clock = clock },
            StoreMigrations.Expanded));
        Assert.Contains("schema version 20", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(originalDigest, HashFile(root.Database));
        Assert.False(File.Exists(root.Database + "-wal"));
        Assert.False(File.Exists(root.Database + "-journal"));
    }

    private static void PrepareOfflineScope(TemporaryDataRoot root)
    {
        if (OperatingSystem.IsLinux())
        {
            using var lease = new FileStream(Path.Combine(root.Path, "node.lock"), new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
        }
    }

    private static void AssertNativePlatform() =>
        Assert.SkipUnless(OperatingSystem.IsWindows() || OperatingSystem.IsLinux(), "The native contraction scope uses Windows or Linux.");

    private static NodeStore OpenRuntime(TemporaryDataRoot root, ManualClock clock) =>
        NodeStore.OpenForV2Runtime(new NodeStoreOptions { DataRoot = root.Path, BootIdentity = "fixture-reopen", Clock = clock });

    private static VerifiedNodeContractionArchive RestoreArchive(NodeContractionScope scope, TemporaryDataRoot source,
        TemporaryDataRoot history, TemporaryDataRoot staged) =>
        VerifiedNodeContractionArchive.Restore(scope, Secrets(source), history.Path, Secrets(history), staged.Path, Secrets(staged));

    private static NodeSecretStore Secrets(TemporaryDataRoot root) => NodeSecretStores.ForTestDataRoot(root.Path);

    private static DurableCommandStore Commands(NodeStore store, TemporaryDataRoot root) => new(store, Owner, Secrets(root), new DurableCapacity());

    private static string HashFile(string path)
    {
        using var input = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(input));
    }

    private sealed record LegacyRecords(byte[] Task, byte[] Attempt, byte[] Workspace, byte[] FileCommand,
        byte[] FileDigest, byte[] FileReply, byte[] FileIdentity);

    private sealed record CurrentRecords(byte[] Node, StoredSandbox Sandbox, DurableIntent Known, DurableIntent Unknown,
        DurableReceipt Succeeded, DurableReceipt Uncertain, byte[] Policy);
}

[CollectionDefinition(nameof(MigrationOwnershipFixture))]
public sealed class MigrationOwnershipFixture;
