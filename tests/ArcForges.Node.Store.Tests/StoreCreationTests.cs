// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Migrations;
using ArcForges.Node.Store.Policy;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Schema version 1 (every table of node-store.sql), the store file settings, store_meta and default policy revision 1.</summary>
public sealed partial class StoreCreationTests
{
    [Fact]
    public void ANewStoreHasEveryTableOfEveryReleasedStep()
    {
        using var root = new TemporaryDataRoot();
        using (var store = root.Open(new ManualClock()))
        {
            Assert.True(store.Opening.Created);
            Assert.Equal(StoreMigrations.SupportedSchemaVersion, store.Opening.SchemaVersion);
        }

        var expected = StoreMigrations.Released.Steps.SelectMany(step => CreateTable().Matches(step.Sql)).Select(match => match.Groups[1].Value)
            .Order(StringComparer.Ordinal).ToList();
        using var connection = Open(root.Database);
        var tables = Query(connection, "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name;");

        Assert.True(expected.Count >= 60, $"node-store.sql defines {expected.Count} tables");
        Assert.Equal(expected, tables);
        Assert.Equal(["ok"], Query(connection, "PRAGMA integrity_check;"));
        Assert.Empty(Query(connection, "PRAGMA foreign_key_check;"));
        Assert.Equal(["1"], Query(connection, "SELECT count(*) FROM store_meta;"));
    }

    [Fact]
    public void TheStoreIsWalWithForeignKeysNormalSyncAndBusyTimeout()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());

        Assert.Equal(StorePaths.Database(root.Path), store.DatabasePath);
        store.Write(transaction =>
        {
            Assert.Equal("wal", transaction.Scalar("PRAGMA journal_mode;"));
            Assert.Equal(1L, transaction.Scalar("PRAGMA foreign_keys;"));
            Assert.Equal(1L, transaction.Scalar("PRAGMA synchronous;")); // NORMAL
            Assert.Equal(5000L, transaction.Scalar("PRAGMA busy_timeout;"));
            Assert.Equal(1L, transaction.Scalar("PRAGMA secure_delete;"));
        });
        store.Read(reader =>
        {
            Assert.Throws<SqliteException>(() => reader.Execute("INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ('x', '1', 0, 0);"));
            return 0;
        });
    }

    [Fact]
    public void StoreMetaRecordsIdentityVersionsAndBootAcrossRuns()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        byte[] nodeId;
        using (var store = root.Open(clock, boot: "boot-a"))
        {
            nodeId = store.Metadata.NodeId.ToArray();
            Assert.Equal(16, nodeId.Length);
            Assert.Equal(0x70, nodeId[6] & 0xF0); // UUIDv7
            Assert.Equal(NodeRole.Host, store.Metadata.Role);
            Assert.Equal(StoreMigrations.SupportedSchemaVersion, store.Metadata.SchemaVersion);
            Assert.Equal(StoreMigrations.SupportedSchemaVersion, store.Metadata.MinReaderVersion);
            Assert.Equal(StoreTime.ToMicroseconds(clock.Now), store.Metadata.CreatedAt);
            Assert.True(store.Metadata.PreviousShutdownClean);
            Assert.Equal(1, store.Metadata.JournalGeneration);
        }

        clock.Advance(TimeSpan.FromMinutes(5));
        using (var store = root.Open(clock, boot: "boot-b"))
        {
            Assert.Equal(nodeId, store.Metadata.NodeId.ToArray());
            Assert.False(store.Opening.Created);
            Assert.Equal("boot-a", store.Metadata.PreviousBootIdentity);
            Assert.Equal("boot-b", store.Metadata.BootIdentity);
            Assert.True(store.Metadata.PreviousShutdownClean);

            // While the store is open the marker is cleared; a killed node leaves it cleared (CrashConsistencyTests).
            Assert.Null(store.Read(reader => reader.Scalar("SELECT clean_shutdown_at FROM store_meta;")));
        }
    }

    [Fact]
    public void V2RuntimeCreatesAndReopensAnIsolatedStore()
    {
        using var root = new TemporaryDataRoot();
        var options = new NodeStoreOptions { DataRoot = root.Path, BootIdentity = "first" };
        byte[] nodeId;
        using (var created = NodeStore.OpenForV2Runtime(options))
        {
            Assert.True(created.Opening.Created);
            nodeId = created.Metadata.NodeId.ToArray();
        }

        using var reopened = NodeStore.OpenForV2Runtime(new NodeStoreOptions { DataRoot = root.Path, BootIdentity = "second" });
        Assert.False(reopened.Opening.Created);
        Assert.Equal(nodeId, reopened.Metadata.NodeId.ToArray());
        Assert.Equal("first", reopened.Metadata.PreviousBootIdentity);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void V2RuntimeRefusesOriginalStoresBeforeChangingDatabaseBytes(bool expanded)
    {
        using var root = new TemporaryDataRoot();
        var plan = expanded ? StoreMigrations.Released : new MigrationPlan(StoreMigrations.Released.Steps.Take(15));
        using (var original = root.Open(new ManualClock(), plan))
        {
            if (expanded)
            {
                original.Write(transaction => transaction.Execute("""
                    INSERT INTO task(task_id,state,kind,title,command_summary,spec,spec_digest,owner,owner_origin,pool,
                        priority,effective_priority,side_effect,side_effect_source,command_fingerprint,command_digest,created_at,rev)
                    VALUES(randomblob(16),7,1,'original','original',x'',zeroblob(32),x'00',1,'fixture',1,1,1,1,
                        'fixture',zeroblob(32),1,0);
                    """));
            }
        }

        byte[] before = File.ReadAllBytes(root.Database);
        var refusal = Assert.Throws<StoreIncompatibleException>(() => NodeStore.OpenForV2Runtime(
            new NodeStoreOptions { DataRoot = root.Path, BootIdentity = "after" }));
        Assert.Contains("legacy_store_requires_offline_cutover", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(before, File.ReadAllBytes(root.Database));
    }

    [Fact]
    public void V2RuntimeInspectsTheLiteralDataRootPath()
    {
        using var fixture = new TemporaryDataRoot();
        var original = new NodeStoreOptions { DataRoot = Path.Combine(fixture.Path, "100%61 # 私有"), BootIdentity = "original" };
        var sibling = new NodeStoreOptions { DataRoot = Path.Combine(fixture.Path, "100a # 私有"), BootIdentity = "sibling" };
        using (var legacy = NodeStore.Open(original, new MigrationPlan(StoreMigrations.Released.Steps.Take(15))))
        using (var current = NodeStore.OpenForV2Runtime(sibling))
        {
            Assert.Equal(15, legacy.Opening.SchemaVersion);
            Assert.Equal(StoreMigrations.SupportedSchemaVersion, current.Opening.SchemaVersion);
        }

        string database = StorePaths.Database(original.DataRoot);
        byte[] before = File.ReadAllBytes(database);
        var refusal = Assert.Throws<StoreIncompatibleException>(() => NodeStore.OpenForV2Runtime(original));
        Assert.Contains("legacy_store_requires_offline_cutover", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(before, File.ReadAllBytes(database));
    }

    [Fact]
    public void V2RuntimeRefusesUnsettledLegacyApprovalWithoutCreatingAnOutcome()
    {
        using var root = new TemporaryDataRoot();
        using (var original = root.Open(new ManualClock()))
        {
            original.Write(transaction => transaction.Execute("""
                INSERT INTO approval(approval_id,state,operation,summary,details_json,risk,requester,command_id,request,
                    request_digest,created_at,expires_at,rev)
                VALUES(randomblob(16),2,'TaskService.RetryTask','original','{}',1,x'01',randomblob(16),x'01',
                    zeroblob(32),0,1,0);
                """));
        }

        byte[] before = File.ReadAllBytes(root.Database);
        var refusal = Assert.Throws<StoreIncompatibleException>(() => NodeStore.OpenForV2Runtime(
            new NodeStoreOptions { DataRoot = root.Path, BootIdentity = "after" }));
        Assert.Contains("legacy_store_requires_offline_cutover", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(before, File.ReadAllBytes(root.Database));
    }

    [Fact]
    public void V2RuntimeRefusesRetiredTaskCommittedOnlyInWalWithoutChangingOriginalFiles()
    {
        using var crashed = new TemporaryDataRoot();
        CopyCommittedWal(crashed, transaction => { _ = Rows.InsertTask(transaction); });
        var files = Directory.GetFiles(crashed.Path, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal([crashed.Database, crashed.Database + "-wal"], files);
        var before = files.ToDictionary(path => path, File.ReadAllBytes, StringComparer.Ordinal);

        var refusal = Assert.Throws<StoreIncompatibleException>(() =>
        {
            using var opened = NodeStore.OpenForV2Runtime(new NodeStoreOptions { DataRoot = crashed.Path, BootIdentity = "v2-restart" });
        });

        Assert.Contains("legacy_store_requires_offline_cutover", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(files, Directory.GetFiles(crashed.Path, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal));
        foreach (var (path, original) in before)
            Assert.Equal(original, File.ReadAllBytes(path));
    }

    [Fact]
    public void V2RuntimeRecoversASharedSettingCommittedOnlyInWal()
    {
        const string displayNameJson = "\"wal-only display name\"";
        using var crashed = new TemporaryDataRoot();
        CopyCommittedWal(crashed, transaction =>
        {
            Assert.Equal(1, transaction.Execute("""
                INSERT INTO node_setting(name, value_json, updated_at, rev) VALUES ('node.name', $name, 17, 0);
                """, ("$name", displayNameJson)));
        });

        using var opened = NodeStore.OpenForV2Runtime(new NodeStoreOptions { DataRoot = crashed.Path, BootIdentity = "v2-restart" });

        Assert.False(opened.Opening.Created);
        Assert.Equal("wal-writer", opened.Metadata.PreviousBootIdentity);
        Assert.False(opened.Metadata.PreviousShutdownClean);
        Assert.Equal(displayNameJson, opened.Read(reader => reader.Scalar("SELECT value_json FROM node_setting WHERE name='node.name';")));
        Assert.Equal(17L, opened.Read(reader => reader.Scalar("SELECT updated_at FROM node_setting WHERE name='node.name';")));
    }

    private static void CopyCommittedWal(TemporaryDataRoot crashed, Action<StoreTransaction> write)
    {
        using var seed = new TemporaryDataRoot();
        var clock = new ManualClock();
        using (var initialized = seed.Open(clock))
        {
            Assert.Equal(0L, initialized.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
            Assert.Null(initialized.Read(reader => reader.Scalar("SELECT value_json FROM node_setting WHERE name='node.name';")));
        }

        var checkpointed = File.ReadAllBytes(seed.Database);
        using var writer = seed.Open(clock, boot: "wal-writer");
        writer.Write(transaction => Assert.Equal(0L, transaction.Scalar("PRAGMA wal_autocheckpoint=0;")));
        writer.Write(write, CommitDurability.Full);

        // Copy the main file and its committed WAL before the last connection can checkpoint them.
        var main = ReadSharedBytes(seed.Database);
        var wal = ReadSharedBytes(seed.Database + "-wal");
        Assert.Equal(checkpointed, main);
        Assert.True(wal.Length > 32);
        StorePaths.CreatePrivateDirectory(Path.GetDirectoryName(crashed.Database)!);
        File.WriteAllBytes(crashed.Database, main);
        File.WriteAllBytes(crashed.Database + "-wal", wal);
        Assert.False(File.Exists(crashed.Database + "-shm"));
    }

    private static byte[] ReadSharedBytes(string path)
    {
        using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var bytes = new MemoryStream();
        source.CopyTo(bytes);
        return bytes.ToArray();
    }

    [Fact]
    public void V2RuntimeDoesNotInitializeAnEmptyDatabaseBesideExistingAuthority()
    {
        using var root = new TemporaryDataRoot();
        string directory = Path.GetDirectoryName(root.Database)!;
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(root.Database, []);
        string authority = Path.Combine(directory, "v2-owner-original.fence");
        byte[] original = [1, 2, 3];
        File.WriteAllBytes(authority, original);

        Assert.Throws<StoreIncompatibleException>(() => NodeStore.OpenForV2Runtime(
            new NodeStoreOptions { DataRoot = root.Path, BootIdentity = "after" }));
        Assert.Empty(File.ReadAllBytes(root.Database));
        Assert.Equal(original, File.ReadAllBytes(authority));
    }

    [Fact]
    public void AGuestNodeStoreIsRefused()
    {
        // WSL guest nodes are retired (ArcForges-Design AD-0018): every node is a HOST, and the store refuses any other role.
        using var root = new TemporaryDataRoot();

        var refused = Assert.Throws<ArgumentException>(() => NodeStore.Open(
            new NodeStoreOptions { DataRoot = root.Path, BootIdentity = "boot", Role = NodeRole.Guest, Clock = new ManualClock() }));

        Assert.Contains("HOST", refused.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(StorePaths.Database(root.Path)));
    }

    [Fact]
    public void TheDefaultPolicyIsRevision1()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);

        var policy = store.Policies.Current();

        Assert.Equal(1, policy.Revision);
        Assert.Equal(DefaultPolicy.Create(), policy.Document);
        Assert.Equal(PolicyDocuments.Digest(policy.Document), policy.Digest.ToArray());
        Assert.Equal(StoreTime.ToMicroseconds(clock.Now), policy.CreatedAt);
        Assert.Equal(Origin.Node, policy.Actor.Origin);
        Assert.Equal(PolicyDocuments.DefaultComment, policy.Comment);
        Assert.Equal(24u, policy.Document.Storage.SecretRetentionHours);
        Assert.Equal(90u, policy.Document.Storage.RecordRetentionDays);
        Assert.Equal(DefaultPolicy.SecretNamePatterns, policy.Document.Privacy.SecretNamePatterns);
        Assert.Equal(DefaultPolicy.BuiltInPools, policy.Document.Pools.Select(pool => pool.Name));
        Assert.Equal(RoutingMode.Observe, policy.Document.Routing.DefaultMode);
        Assert.Equal(ResultCacheMode.Off, policy.Document.ResultCache.DefaultMode);
        Assert.False(policy.Document.RetrySafety.AcceptAgentAssertions);
        Assert.False(policy.Document.Remote.Enabled);
        Assert.False(policy.Document.Lan.Enabled);
        Assert.Equal([".*"], policy.Document.Agents.AllowedCommandPatterns);
    }

    [Fact]
    public void WritesDoNotNestAndRollBackOnFailure()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());

        Assert.Throws<InvalidOperationException>(() => store.Write(_ => store.Write(_ => 0)));
        Assert.Throws<InvalidDataException>(() => store.Write(transaction =>
        {
            transaction.Execute("INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ('rolled-back', '1', 0, 0);");
            throw new InvalidDataException("abort");
        }));
        Assert.Null(store.Read(reader => reader.Scalar("SELECT name FROM node_setting WHERE name = 'rolled-back';")));
    }

    [Fact]
    public void OnLinuxTheDataRootAndStoreDirectoryAreOwnerOnly()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Unix directory modes apply on Linux.");
            return;
        }

        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());

        Assert.Equal(StorePaths.PrivateDirectoryMode, File.GetUnixFileMode(root.Path));
        Assert.Equal(StorePaths.PrivateDirectoryMode, File.GetUnixFileMode(Path.GetDirectoryName(root.Database)!));
    }

    internal static SqliteConnection Open(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        return connection;
    }

    internal static List<string> Query(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        using var reader = command.ExecuteReader();
        var values = new List<string>();
        while (reader.Read())
        {
            values.Add(Convert.ToString(reader.GetValue(0), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
        }

        return values;
    }

    [GeneratedRegex(@"^CREATE TABLE (\w+) \(", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex CreateTable();
}
