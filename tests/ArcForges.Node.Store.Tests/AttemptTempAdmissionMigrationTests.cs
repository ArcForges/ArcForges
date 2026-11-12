// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store.Tests;

/// <summary>Version admission and draft-layout checks do not by themselves fence a writer that was already open.</summary>
[Trait("feature", "workspace-store")]
[Trait("check", "schema")]
public sealed class AttemptTempAdmissionMigrationTests
{
    [Fact]
    public void AnOlderReaderCannotOpenANewVersion13Store()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using (var current = root.Open(clock))
        {
            Assert.Equal(13, current.Metadata.SchemaVersion);
            Assert.Equal(13, current.Metadata.MinReaderVersion);
            current.Write(transaction => transaction.Execute("INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ('preserved', '7', 0, 0);"));
        }

        var older = new MigrationPlan(StoreMigrations.Released.Steps.Take(12));
        var refusal = Assert.Throws<StoreIncompatibleException>(() => root.Open(clock, older));
        Assert.Contains("schema version 13", refusal.Message, StringComparison.Ordinal);
        using var reopened = root.Open(clock);
        Assert.Equal("7", reopened.Read(reader => reader.Scalar("SELECT value_json FROM node_setting WHERE name = 'preserved';")));
    }

    [Fact]
    public void AClosedMatchingStep12StoreIsRetainedUntilTheUpgradeCanExcludeOlderInstances()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var prior = new MigrationPlan(StoreMigrations.Released.Steps.Take(12));
        using (var old = root.Open(clock, prior))
        {
            old.Write(transaction => transaction.Execute("INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ('kept', '42', 0, 0);"));
        }

        // Closing this fixture's connection alone cannot establish that no other older node is still running.
        var refusal = Assert.Throws<StoreIncompatibleException>(() => root.Open(clock));
        Assert.Contains("prior node-instance exclusion", refusal.Message, StringComparison.Ordinal);
        using var readOnly = StoreCreationTests.Open(root.Database);
        Assert.Equal(["12"], StoreCreationTests.Query(readOnly, "SELECT schema_version FROM store_meta;"));
        Assert.Equal(["1"], StoreCreationTests.Query(readOnly, "SELECT min_reader_version FROM store_meta;"));
        Assert.Equal(["42"], StoreCreationTests.Query(readOnly, "SELECT value_json FROM node_setting WHERE name = 'kept';"));
        Assert.Empty(StoreCreationTests.Query(readOnly, "SELECT name FROM sqlite_schema WHERE name = 'file_attempt_temp_identity';"));
    }

    [Fact]
    public void AConflictingStep12DraftIsRefusedBeforeMigrationAndLeftIntact()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var conflicting = new MigrationPlan([.. StoreMigrations.Released.Steps.Take(11),
            new StoreMigration(12, 1, "different-step-12.sql", "CREATE TABLE other_draft (value INTEGER NOT NULL) STRICT;")]);
        using (var old = root.Open(clock, conflicting))
        {
            old.Write(transaction => transaction.Execute("INSERT INTO other_draft (value) VALUES (41);"));
            Assert.Equal(12, old.Metadata.SchemaVersion);
        }

        var refusal = Assert.Throws<StoreIncompatibleException>(() => root.Open(clock));
        Assert.Contains("unrecognized removal-plan draft layout", refusal.Message, StringComparison.Ordinal);
        using var readOnly = StoreCreationTests.Open(root.Database);
        Assert.Equal(["12"], StoreCreationTests.Query(readOnly, "SELECT schema_version FROM store_meta;"));
        Assert.Equal(["1"], StoreCreationTests.Query(readOnly, "SELECT min_reader_version FROM store_meta;"));
        Assert.Equal(["41"], StoreCreationTests.Query(readOnly, "SELECT value FROM other_draft;"));
        Assert.Empty(StoreCreationTests.Query(readOnly, "SELECT name FROM sqlite_schema WHERE name = 'file_attempt_temp_identity';"));
    }
}
