// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store.Tests;

/// <summary>Reader admission cannot fence a version-13 instance which has already opened the store.</summary>
[Trait("feature", "workspace-store")]
[Trait("check", "schema")]
public sealed class CreationOwnershipMigrationTests
{
    [Fact]
    public void FreshVersion14RefusesAnOlderReader()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using (var current = root.Open(clock))
        {
            Assert.Equal(14, current.Metadata.SchemaVersion);
            Assert.Equal(14, current.Metadata.MinReaderVersion);
            Assert.Equal(1L, current.Read(reader => reader.Scalar(
                "SELECT count(*) FROM sqlite_schema WHERE name = 'file_creation_ownership';")));
        }
        var older = new MigrationPlan(StoreMigrations.Released.Steps.Take(13));
        var refusal = Assert.Throws<StoreIncompatibleException>(() => root.Open(clock, older));
        Assert.Contains("schema version 14", refusal.Message, StringComparison.Ordinal);
        using var reopened = root.Open(clock);
        Assert.Equal(14, reopened.Metadata.SchemaVersion);
    }

    [Fact]
    public void AlreadyOpenVersion13PreventsUpgradeAndRemainsUsable()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var prior = new MigrationPlan(StoreMigrations.Released.Steps.Take(13));
        using (var old = root.Open(clock, prior))
        {
            old.Write(tx => tx.Execute("INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ('retained', '42', 0, 0);"));
            var refusal = Assert.Throws<StoreIncompatibleException>(() => root.Open(clock));
            Assert.Contains("prior node-instance exclusion", refusal.Message, StringComparison.Ordinal);
            Assert.Equal(13, old.Metadata.SchemaVersion);
            Assert.Equal("42", old.Read(reader => reader.Scalar("SELECT value_json FROM node_setting WHERE name = 'retained';")));
            old.Write(tx => tx.Execute("UPDATE node_setting SET value_json = '43' WHERE name = 'retained';"));
            Assert.Equal(0L, old.Read(reader => reader.Scalar(
                "SELECT count(*) FROM sqlite_schema WHERE name = 'file_creation_ownership';")));
        }

        // Closing this one fixture connection is not proof that every earlier node instance has ended.
        Assert.Throws<StoreIncompatibleException>(() => root.Open(clock));
        using var stillOld = root.Open(clock, prior);
        Assert.Equal("43", stillOld.Read(reader => reader.Scalar("SELECT value_json FROM node_setting WHERE name = 'retained';")));
    }
}
