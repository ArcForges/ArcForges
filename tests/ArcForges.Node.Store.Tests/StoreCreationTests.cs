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
    public void ANewStoreHasEveryTableOfSchemaVersion1()
    {
        using var root = new TemporaryDataRoot();
        using (var store = root.Open(new ManualClock()))
        {
            Assert.True(store.Opening.Created);
            Assert.Equal(1, store.Opening.SchemaVersion);
        }

        var expected = CreateTable().Matches(StoreMigrations.Released.Steps[0].Sql).Select(match => match.Groups[1].Value).Order(StringComparer.Ordinal).ToList();
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
            Assert.Equal(1, store.Metadata.SchemaVersion);
            Assert.Equal(1, store.Metadata.MinReaderVersion);
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
    public void AGuestNodeStoreRecordsItsRole()
    {
        using var root = new TemporaryDataRoot();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = root.Path, BootIdentity = "boot", Role = NodeRole.Guest, Clock = new ManualClock() });

        Assert.Equal(NodeRole.Guest, store.Metadata.Role);
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
