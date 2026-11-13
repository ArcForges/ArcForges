// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Actual SQLite upgrade from the delivered AF-CTR-05 schemas; no claim about an unpublished old14 binary.</summary>
public sealed class SupportedStoreUpgradeTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void DeliveredStoreMigratesForwardWithItsRecordsAndBackup(int oldVersion)
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var prior = new MigrationPlan(StoreMigrations.Released.Steps.Take(oldVersion));
        var commandId = StoreIds.NewUuid7(clock);
        var digest = SHA256.HashData("legacy fixture request"u8);
        var outcome = Encoding.UTF8.GetBytes("legacy fixture receipt");
        byte[] nodeId;
        using (var old = root.Open(clock, prior))
        {
            nodeId = old.Metadata.NodeId.ToArray();
            old.Write(tx =>
            {
                tx.Execute("INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ('upgrade-kept', '42', 0, 0);");
                Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, commandId,
                    "arcforges.node.v1.TaskService/SubmitTask", digest, Origin.Script).Status);
                CommandDeduplication.Complete(tx, commandId, outcome);
            }, CommitDurability.Full);
        }
        using (var current = root.Open(clock))
        {
            Assert.Equal(oldVersion, current.Opening.MigratedFrom);
            Assert.Equal(StoreMigrations.SupportedSchemaVersion, current.Metadata.SchemaVersion);
            Assert.Equal(StoreMigrations.SupportedSchemaVersion, current.Metadata.MinReaderVersion);
            Assert.Equal(nodeId, current.Metadata.NodeId.ToArray());
            Assert.Equal("42", current.Read(r => r.Scalar("SELECT value_json FROM node_setting WHERE name = 'upgrade-kept';")));
            Assert.Equal(outcome, current.Read(r => (byte[])r.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", commandId))!));
            Assert.Equal(digest, current.Read(r => (byte[])r.Scalar("SELECT payload_digest FROM command_dedup WHERE command_id = $id;", ("$id", commandId))!));
            Assert.Equal(4L, current.Read(r => r.Scalar("""
                SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name IN
                  ('file_stage_production', 'file_private_stage_object', 'file_creation_ownership', 'file_removal_plan');
                """)));
            var backup = Assert.Single(StoreBackups.List(root.Path));
            Assert.Equal(backup, current.Opening.BackupPath);
            using var copy = StoreCreationTests.Open(backup);
            Assert.Equal(["ok"], StoreCreationTests.Query(copy, "PRAGMA integrity_check;"));
            Assert.Equal([oldVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)],
                StoreCreationTests.Query(copy, "SELECT schema_version FROM store_meta;"));
            Assert.Equal(["42"], StoreCreationTests.Query(copy, "SELECT value_json FROM node_setting WHERE name = 'upgrade-kept';"));
            Assert.Equal([Convert.ToHexString(nodeId)], StoreCreationTests.Query(copy, "SELECT hex(node_id) FROM store_meta;"));
            Assert.Equal([Convert.ToHexString(outcome)], StoreCreationTests.Query(copy, "SELECT hex(outcome) FROM command_dedup;"));
        }
        var beforeRefusal = SHA256.HashData(File.ReadAllBytes(root.Database));
        Assert.Throws<StoreIncompatibleException>(() => root.Open(clock, prior));
        Assert.Equal(beforeRefusal, SHA256.HashData(File.ReadAllBytes(root.Database)));
        using var reopened = root.Open(clock);
        Assert.Null(reopened.Opening.MigratedFrom);
        Assert.Single(StoreBackups.List(root.Path));
        Assert.Equal(nodeId, reopened.Metadata.NodeId.ToArray());
        Assert.Equal("42", reopened.Read(r => r.Scalar("SELECT value_json FROM node_setting WHERE name = 'upgrade-kept';")));
    }

    [Fact]
    public void InterruptedDeliveredUpgradeRemainsAtItsOriginalSchemaAndCanRetry()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var prior = new MigrationPlan(StoreMigrations.Released.Steps.Take(2));
        byte[] nodeId;
        using (var old = root.Open(clock, prior))
        {
            nodeId = old.Metadata.NodeId.ToArray();
            old.Write(tx => tx.Execute("INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ('upgrade-kept', '43', 0, 0);"));
        }
        var last = StoreMigrations.Released.Steps[^1];
        var failing = new MigrationPlan([.. StoreMigrations.Released.Steps.SkipLast(1),
            new StoreMigration(last.Version, last.MinReaderVersion, last.Name,
                last.Sql + "\nINSERT INTO missing_upgrade_fixture_table VALUES (1);\n")]);
        var failure = Assert.Throws<SqliteException>(() => root.Open(clock, failing));
        Assert.Equal(1, failure.SqliteErrorCode);
        using (var preserved = root.Open(clock, prior))
        {
            Assert.Equal(2, preserved.Metadata.SchemaVersion);
            Assert.Equal(nodeId, preserved.Metadata.NodeId.ToArray());
            Assert.Equal("43", preserved.Read(r => r.Scalar("SELECT value_json FROM node_setting WHERE name = 'upgrade-kept';")));
            Assert.Equal(0L, preserved.Read(r => r.Scalar("""
                SELECT count(*) FROM sqlite_schema WHERE name IN
                  ('file_stage_production', 'file_creation_ownership', 'file_removal_plan');
                """)));
        }
        var backup = Assert.Single(StoreBackups.List(root.Path));
        using (var copy = StoreCreationTests.Open(backup))
        {
            Assert.Equal(["2"], StoreCreationTests.Query(copy, "SELECT schema_version FROM store_meta;"));
            Assert.Equal(["43"], StoreCreationTests.Query(copy, "SELECT value_json FROM node_setting WHERE name = 'upgrade-kept';"));
            Assert.Equal(["ok"], StoreCreationTests.Query(copy, "PRAGMA integrity_check;"));
        }
        using var retried = root.Open(clock);
        Assert.Equal(2, retried.Opening.MigratedFrom);
        Assert.Equal(StoreMigrations.SupportedSchemaVersion, retried.Metadata.SchemaVersion);
        Assert.Equal(nodeId, retried.Metadata.NodeId.ToArray());
        Assert.Equal("43", retried.Read(r => r.Scalar("SELECT value_json FROM node_setting WHERE name = 'upgrade-kept';")));
    }
}
