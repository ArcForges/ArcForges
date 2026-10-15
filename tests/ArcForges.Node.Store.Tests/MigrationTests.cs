// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// Forward-only migrations, min_reader enforcement and pre-migration backups (13-distribution-updates section 6). Later
/// schema versions are test inputs: plans that extend the released version 1 with expand steps.
/// </summary>
public sealed class MigrationTests
{
    [Fact]
    public void ReleasedMigrationsEndAtTheSupportedSchemaVersion()
    {
        Assert.Equal(StoreMigrations.SupportedSchemaVersion, StoreMigrations.Released.LatestVersion);
        Assert.Equal(1, StoreMigrations.Released.Steps[^1].MinReaderVersion);
    }

    [Fact]
    public void AnOlderStoreIsBackedUpThenMigratedForward()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        byte[] nodeId;
        using (var store = root.Open(clock))
        {
            nodeId = store.Metadata.NodeId.ToArray();
            store.Write(transaction => transaction.Execute("INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ('kept', '42', 0, 0);"));
        }

        clock.Advance(TimeSpan.FromDays(1));
        using (var store = root.Open(clock, Plan(2)))
        {
            Assert.Equal(1, store.Opening.MigratedFrom);
            Assert.Equal(2, store.Opening.SchemaVersion);
            Assert.Equal(2, store.Metadata.SchemaVersion);
            Assert.Equal(1, store.Metadata.MinReaderVersion);
            Assert.Equal(nodeId, store.Metadata.NodeId.ToArray());
            Assert.Equal("42", store.Read(reader => reader.Scalar("SELECT value_json FROM node_setting WHERE name = 'kept';")));
            Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM test_expansion_2;")));

            var backup = Assert.Single(StoreBackups.List(root.Path));
            Assert.Equal(backup, store.Opening.BackupPath);
            Assert.Matches(@"store-1-2-20261016T120000000Z\.db$", backup);
            using var copy = StoreCreationTests.Open(backup);
            Assert.Equal(["ok"], StoreCreationTests.Query(copy, "PRAGMA integrity_check;"));
            Assert.Equal(["1"], StoreCreationTests.Query(copy, "SELECT schema_version FROM store_meta;"));
            Assert.Equal(["42"], StoreCreationTests.Query(copy, "SELECT value_json FROM node_setting WHERE name = 'kept';"));
        }

        // A current store is opened without another backup.
        using (var store = root.Open(clock, Plan(2)))
        {
            Assert.Null(store.Opening.MigratedFrom);
            Assert.Single(StoreBackups.List(root.Path));
        }
    }

    [Fact]
    public void OnlyTheLastThreeBackupsAreKept()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        root.Open(clock).Dispose();
        for (var version = 2; version <= 5; version++)
        {
            clock.Advance(TimeSpan.FromMinutes(1));
            root.Open(clock, Plan(version)).Dispose();
        }

        var names = StoreBackups.List(root.Path).Select(Path.GetFileName).ToList();
        Assert.Equal(["store-2-3-20261015T120200000Z.db", "store-3-4-20261015T120300000Z.db", "store-4-5-20261015T120400000Z.db"], names);
    }

    [Fact]
    public void AStoreFromANewerExpandOnlyReleaseStillOpens()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        root.Open(clock, Plan(3)).Dispose();

        // A rolled-back binary (schema 1) reads a store a newer node expanded while min_reader stays 1.
        using var store = root.Open(clock);

        Assert.Equal(3, store.Opening.SchemaVersion);
        Assert.Null(store.Opening.MigratedFrom);
        Assert.Equal(3, store.Metadata.SchemaVersion);
        Assert.Empty(StoreBackups.List(root.Path));
    }

    [Fact]
    public void AStoreWithAHigherMinReaderIsRefusedAndLeftUnchanged()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using (var store = root.Open(clock))
        {
            store.Write(transaction => transaction.Execute("UPDATE store_meta SET schema_version = 3, min_reader_version = 2;"));
        }

        var before = SHA256.HashData(File.ReadAllBytes(root.Database));
        var refused = Assert.Throws<StoreIncompatibleException>(() => root.Open(clock));

        Assert.Contains("schema version 2", refused.Message, StringComparison.Ordinal);
        SqliteConnection.ClearAllPools();
        Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(root.Database)));
        Assert.Empty(StoreBackups.List(root.Path));

        // A binary that reads schema 2 opens it.
        using var newer = root.Open(clock, Plan(2));
        Assert.Equal(3, newer.Metadata.SchemaVersion);
        Assert.Equal(2, newer.Metadata.MinReaderVersion);
    }

    [Fact]
    public void AFailedMigrationStepLeavesTheStoreAtItsVersionWithItsBackup()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        root.Open(clock).Dispose();
        var failing = new MigrationPlan([.. StoreMigrations.Released.Steps,
            new StoreMigration(2, 1, "0002-failing.sql", "CREATE TABLE half_done (id INTEGER PRIMARY KEY); INSERT INTO no_such_table VALUES (1);")]);

        Assert.Throws<SqliteException>(() => root.Open(clock, failing));

        using (var connection = StoreCreationTests.Open(root.Database))
        {
            Assert.Equal(["1"], StoreCreationTests.Query(connection, "SELECT schema_version FROM store_meta;"));
            Assert.Empty(StoreCreationTests.Query(connection, "SELECT name FROM sqlite_schema WHERE name = 'half_done';"));
            Assert.Equal(["ok"], StoreCreationTests.Query(connection, "PRAGMA integrity_check;"));
        }

        Assert.Single(StoreBackups.List(root.Path));
        using var store = root.Open(clock, Plan(2));
        Assert.Equal(2, store.Metadata.SchemaVersion);
    }

    [Fact]
    public void ADatabaseThatIsNotANodeStoreIsRefused()
    {
        using var root = new TemporaryDataRoot();
        Directory.CreateDirectory(Path.GetDirectoryName(root.Database)!);
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = root.Database, Pooling = false }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE unrelated (id INTEGER PRIMARY KEY);";
            command.ExecuteNonQuery();
        }

        Assert.Throws<StoreIncompatibleException>(() => root.Open(new ManualClock()));
    }

    [Fact]
    public void MigrationPlansAreConsecutiveAndMinReaderNeverDecreases()
    {
        var one = StoreMigrations.Released.Steps[0];
        Assert.Throws<ArgumentException>(() => new MigrationPlan([one, new StoreMigration(3, 1, "x.sql", "SELECT 1;")]));
        Assert.Throws<ArgumentException>(() => new MigrationPlan([one, new StoreMigration(2, 2, "a.sql", "SELECT 1;"), new StoreMigration(3, 1, "b.sql", "SELECT 1;")]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new StoreMigration(2, 3, "c.sql", "SELECT 1;"));
    }

    /// <summary>The released steps plus expand steps up to <paramref name="latest"/> (min_reader stays 1).</summary>
    internal static MigrationPlan Plan(int latest) => new([
        .. StoreMigrations.Released.Steps,
        .. Enumerable.Range(2, latest - 1).Select(version => new StoreMigration(version, 1, $"000{version}-test.sql",
            $"CREATE TABLE test_expansion_{version} (id BLOB NOT NULL PRIMARY KEY, note TEXT) STRICT; ALTER TABLE node_setting ADD COLUMN note_{version} TEXT;")),
    ]);
}
