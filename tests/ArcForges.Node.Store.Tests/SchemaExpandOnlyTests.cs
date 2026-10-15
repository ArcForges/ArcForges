// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// The expand-only schema diff check (13-distribution-updates sections 6 and 9), run in CI as the step "Check the node store
/// schema is expand-only" (suite store-schema): released migrations are immutable, and each one only expands the schema.
/// </summary>
[Trait("check", "schema")]
public sealed class SchemaExpandOnlyTests
{
    /// <summary>ArcForges-Design docs/data/node-store.sql at 78f0f5a (schema version 1).</summary>
    private const string DesignSchemaV1Sha256 = "8f56a161a3c73c18a455dc01d6061fa34bde6341a6eb130900daac336205a649";

    [Fact]
    public void Version1IsTheDesignSchemaVerbatim()
    {
        Assert.Equal(DesignSchemaV1Sha256, StoreMigrations.Released.Steps[0].Sha256);
    }

    [Fact]
    public void ReleasedMigrationsMatchTheirRecordedHistory()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Repository.PathOf("src/ArcForges.Node.Store/Schema/schema-history.json")));
        var recorded = document.RootElement.GetProperty("steps").EnumerateArray()
            .Select(step => (
                Version: step.GetProperty("version").GetInt32(),
                MinReader: step.GetProperty("minReaderVersion").GetInt32(),
                File: step.GetProperty("file").GetString(),
                Sha256: step.GetProperty("sha256").GetString()))
            .ToList();
        var released = StoreMigrations.Released.Steps.Select(step => (step.Version, step.MinReaderVersion, (string?)step.Name, (string?)step.Sha256)).ToList();

        // Every recorded step is still released unchanged; new steps are recorded in the same change.
        Assert.Equal(recorded, released);
        foreach (var step in StoreMigrations.Released.Steps)
        {
            var file = File.ReadAllText(Repository.PathOf("src/ArcForges.Node.Store/Schema/" + step.Name));
            Assert.Equal(step.Sql, file);
        }
    }

    [Fact]
    public void EveryReleasedMigrationIsExpandOnly()
    {
        var steps = StoreMigrations.Released.Steps;
        var previous = Snapshot([]);
        for (var count = 1; count <= steps.Count; count++)
        {
            var current = Snapshot(steps.Take(count));
            if (count > 1)
            {
                Assert.Empty(SchemaDiff.ContractStatements(steps[count - 1].Sql));
                Assert.Empty(SchemaDiff.ExpandOnlyViolations(previous, current));
            }

            previous = current;
        }

        Assert.True(previous.Tables.Count >= 60);
    }

    [Theory]
    [InlineData("DROP TABLE notification;", "table notification was dropped or renamed")]
    [InlineData("ALTER TABLE notification RENAME TO notice;", "table notification was dropped or renamed")]
    [InlineData("ALTER TABLE notification DROP COLUMN link;", "column notification.link was dropped, renamed or moved")]
    [InlineData("ALTER TABLE notification RENAME COLUMN link TO href;", "column notification.link was dropped, renamed or moved")]
    [InlineData("DROP INDEX ix_notification__created;", "index ix_notification__created was dropped or renamed")]
    [InlineData(
        "CREATE TABLE n2 (notification_id BLOB NOT NULL PRIMARY KEY CHECK (length(notification_id) = 16), kind TEXT NOT NULL, severity INTEGER NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, link TEXT, created_at INTEGER NOT NULL, read_at INTEGER) STRICT; INSERT INTO n2 SELECT * FROM notification; DROP TABLE notification; ALTER TABLE n2 RENAME TO notification; CREATE INDEX ix_notification__created ON notification (created_at);",
        "table notification changed its definition beyond added columns")]
    public void ContractStepsAreViolations(string sql, string violation)
    {
        var before = Snapshot(StoreMigrations.Released.Steps);
        var after = Snapshot([.. StoreMigrations.Released.Steps, new StoreMigration(2, 1, "0002-contract.sql", sql)]);

        Assert.Contains(violation, SchemaDiff.ExpandOnlyViolations(before, after));
        Assert.NotEmpty(SchemaDiff.ContractStatements(sql));
    }

    [Fact]
    public void ExpandStepsAreAllowed()
    {
        const string sql = """
            -- A new table, a nullable column, a defaulted NOT NULL column and an index: all expand-only.
            CREATE TABLE fleet_cache (id BLOB NOT NULL PRIMARY KEY, note TEXT) STRICT;
            ALTER TABLE notification ADD COLUMN category TEXT;
            ALTER TABLE guest_grant ADD COLUMN weight INTEGER NOT NULL DEFAULT 1;
            CREATE INDEX ix_notification__read ON notification (read_at) WHERE read_at IS NULL;
            UPDATE node_setting SET rev = rev WHERE name = 'never "DROP" here';
            """;
        var before = Snapshot(StoreMigrations.Released.Steps);
        var after = Snapshot([.. StoreMigrations.Released.Steps, new StoreMigration(2, 1, "0002-expand.sql", sql)]);

        Assert.Empty(SchemaDiff.ExpandOnlyViolations(before, after));
        Assert.Empty(SchemaDiff.ContractStatements(sql));
        Assert.Contains("fleet_cache", after.Tables.Keys);
    }

    [Fact]
    public void ANotNullColumnWithoutDefaultIsAViolation()
    {
        var before = Snapshot(StoreMigrations.Released.Steps);
        var rebuilt = Snapshot([.. StoreMigrations.Released.Steps, new StoreMigration(2, 1, "0002-x.sql",
            "CREATE TABLE t2 (a INTEGER) STRICT; DROP TABLE toolchain; CREATE TABLE toolchain (kind TEXT NOT NULL, path TEXT NOT NULL, version TEXT NOT NULL, identity_json TEXT NOT NULL CHECK (json_valid(identity_json)), detected_at INTEGER NOT NULL, missing INTEGER NOT NULL DEFAULT 0 CHECK (missing IN (0, 1)), owner TEXT NOT NULL, PRIMARY KEY (kind, path)) STRICT, WITHOUT ROWID;")]);

        Assert.Contains("column toolchain.owner was added NOT NULL without a default", SchemaDiff.ExpandOnlyViolations(before, rebuilt));
    }

    private static SchemaSnapshot Snapshot(IEnumerable<StoreMigration> steps)
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        foreach (var step in steps)
        {
            using var command = connection.CreateCommand();
            command.CommandText = step.Sql;
            command.ExecuteNonQuery();
        }

        return SchemaSnapshot.Capture(connection);
    }
}
