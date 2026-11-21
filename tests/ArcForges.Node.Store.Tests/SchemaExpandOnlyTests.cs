// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// Checks the immutable expansion through schema 19 and the separately qualified schema 20 contraction.
/// </summary>
[Trait("check", "schema")]
public sealed class SchemaExpandOnlyTests
{
    /// <summary>ArcForges-Design docs/data/node-store.sql at 78f0f5a (schema version 1).</summary>
    private const string DesignSchemaV1Sha256 = "8f56a161a3c73c18a455dc01d6061fa34bde6341a6eb130900daac336205a649";

    internal static IReadOnlyList<string> ExpectedContractedTables { get; } =
    [
        "approval", "audit", "audit_log", "command_dedup", "command_receipt", "contracted_command_hold",
        "deletion_journal", "event", "event_eviction", "event_journal", "finding", "job", "limit_application",
        "migration_checkpoint", "node_setting", "notification", "output_segment", "owner_epoch", "owner_epoch_capacity",
        "policy_document", "remote_command_binding", "remote_grant", "resource_policy", "run", "run_recovery",
        "run_stop_intent", "sandbox", "sandbox_config", "schema_version", "store_meta", "supervisor_identity", "transfer",
        "v2_resource_sample",
    ];

    [Fact]
    public void Version1IsTheDesignSchemaVerbatim()
    {
        Assert.Equal(DesignSchemaV1Sha256, StoreMigrations.Released.Steps[0].Sha256);
    }

    /// <summary>ArcForges-Design docs/data/node-store.sql at 611dda6, its "schema step 2" block (node-store.md section 2a).</summary>
    private const string DesignSchemaStep2Sha256 = "5540abe3d93b59cdf4c3bb0669306224623fc6d6c79e076ca027950437ed1137";

    [Fact]
    public void Version2IsTheDesignStep2Verbatim()
    {
        Assert.Equal(DesignSchemaStep2Sha256, StoreMigrations.Released.Steps[1].Sha256);
        Assert.StartsWith("-- ------------------------------------------------------------------ schema step 2\n", StoreMigrations.Released.Steps[1].Sql, StringComparison.Ordinal);
        Assert.Contains("CREATE UNIQUE INDEX ux_routed_call_log__call ON routed_call_log (call_id) WHERE call_id IS NOT NULL;", StoreMigrations.Released.Steps[1].Sql,
            StringComparison.Ordinal);
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
        var expansionHistory = string.Join("\n", StoreMigrations.Expanded.Steps.Select(step => step.Sha256));
        Assert.Equal("a266ad2d89fa5bb91eb77b80ef570e4f795fc1569d9f0f436a5c6786f985dd4c",
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(expansionHistory))));
        foreach (var step in StoreMigrations.Released.Steps)
        {
            var file = File.ReadAllText(Repository.PathOf("src/ArcForges.Node.Store/Schema/" + step.Name));
            Assert.Equal(step.Sql, file);
        }
    }

    [Fact]
    public void EveryOriginalExpansionStepIsExpandOnly()
    {
        var steps = StoreMigrations.Expanded.Steps;
        Assert.Equal(19, steps.Count);
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

    [Fact]
    public void Schema20ContractsOnlyTheReviewedInventoryAndRaisesTheReaderFloor()
    {
        var contraction = StoreMigrations.Released.Steps[^1];
        Assert.Equal(20, contraction.Version);
        Assert.Equal(20, contraction.MinReaderVersion);
        Assert.Equal("0020-v2-contract.sql", contraction.Name);
        Assert.Equal("58fd86eb6a31fc6e9dc6027ab3d4d2bd28323e16ac9b18bb11076f060aee7dd6", contraction.Sha256);
        Assert.Equal(94, SchemaDiff.ContractStatements(contraction.Sql).Count);

        var expanded = Snapshot(StoreMigrations.Expanded.Steps);
        var contracted = Snapshot(StoreMigrations.Released.Steps);
        Assert.Equal(ExpectedContractedTables, contracted.Tables.Keys);
        Assert.Equal(81, expanded.Tables.Keys.Except(contracted.Tables.Keys, StringComparer.Ordinal).Count());

        foreach (var name in ExpectedContractedTables.Where(name => name != "contracted_command_hold"))
        {
            var before = expanded.Tables[name];
            var after = contracted.Tables[name];
            if (name == "migration_checkpoint")
            {
                Assert.True(SchemaDiff.IsAppendOnly(before, after));
                Assert.Equal(before.Columns, after.Columns.Take(before.Columns.Count));
                Assert.Equal(
                    ["source_database_sha256", "history_archive_sha256", "restore_database_sha256", "scope_receipt_sha256"],
                    after.Columns.Skip(before.Columns.Count).Select(column => column.Name));
            }
            else
            {
                Assert.Equal(before.Sql, after.Sql);
                Assert.Equal(before.Columns, after.Columns);
            }
        }

        string[] retiredSharedTriggers =
        [
            "trigger:tr_file_audit_retention_guard_delete",
            "trigger:tr_file_audit_retention_release",
            "trigger:tr_file_command_retention_guard_delete",
            "trigger:tr_file_command_retention_guard_insert",
            "trigger:tr_file_command_retention_guard_update",
            "trigger:tr_file_command_retention_insert",
            "trigger:tr_file_command_retention_release",
            "trigger:tr_file_operation_journal__guard_command_delete",
            "trigger:tr_file_owner_audit_retention_insert",
            "trigger:tr_file_private_stage_guard_command_delete",
        ];
        Assert.Equal(retiredSharedTriggers, expanded.Indexes
            .Where(objectEntry => contracted.Tables.ContainsKey(objectEntry.Value.Table) && !contracted.Indexes.ContainsKey(objectEntry.Key))
            .Select(objectEntry => objectEntry.Key));
        foreach (var (name, definition) in contracted.Indexes)
        {
            if (expanded.Indexes.TryGetValue(name, out var original))
                Assert.Equal(original, definition);
        }

        Assert.Equal(
            ["trigger:contracted_command_hold_command_update", "trigger:contracted_command_hold_immutable_delete", "trigger:contracted_command_hold_immutable_update"],
            contracted.Indexes.Keys.Except(expanded.Indexes.Keys, StringComparer.Ordinal));
        Assert.Equal(
            ["view:file_stage_capacity_totals", "view:file_stage_capacity_totals_v15", "view:file_stage_reserved_identity"],
            expanded.Indexes.Keys.Where(name => name.StartsWith("view:", StringComparison.Ordinal)));
        Assert.DoesNotContain(contracted.Indexes.Keys, name => name.StartsWith("view:", StringComparison.Ordinal));
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
        var before = Snapshot(StoreMigrations.Expanded.Steps);
        var after = Snapshot([.. StoreMigrations.Expanded.Steps, new StoreMigration(StoreMigrations.ExpandedSchemaVersion + 1, 1, "0003-contract.sql", sql)]);

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
        var before = Snapshot(StoreMigrations.Expanded.Steps);
        var after = Snapshot([.. StoreMigrations.Expanded.Steps, new StoreMigration(StoreMigrations.ExpandedSchemaVersion + 1, 1, "0003-expand.sql", sql)]);

        Assert.Empty(SchemaDiff.ExpandOnlyViolations(before, after));
        Assert.Empty(SchemaDiff.ContractStatements(sql));
        Assert.Contains("fleet_cache", after.Tables.Keys);
    }

    [Fact]
    public void AColumnAddedBeforeATableConstraintIsExpandOnly()
    {
        // SQLite inserts an added column after the last column definition, before the table constraints (the task table of step 2).
        var before = Snapshot([new StoreMigration(1, 1, "0001-t.sql", "CREATE TABLE t (a INTEGER NOT NULL, b INTEGER, CHECK (a > 0 OR b IS NULL)) STRICT;")]);
        var after = Snapshot([new StoreMigration(1, 1, "0001-t.sql", "CREATE TABLE t (a INTEGER NOT NULL, b INTEGER, CHECK (a > 0 OR b IS NULL)) STRICT;"),
            new StoreMigration(2, 1, "0002-t.sql", "ALTER TABLE t ADD COLUMN c INTEGER NOT NULL DEFAULT 0 CHECK (c IN (0, 1));")]);
        Assert.Empty(SchemaDiff.ExpandOnlyViolations(before, after));

        // A rebuilt table whose constraint changed is still refused, also when it gains a column.
        var rebuilt = Snapshot([new StoreMigration(1, 1, "0001-t.sql", "CREATE TABLE t (a INTEGER NOT NULL, b INTEGER, c INTEGER, CHECK (a > 1 OR b IS NULL)) STRICT;")]);
        Assert.Contains("table t changed its definition beyond added columns", SchemaDiff.ExpandOnlyViolations(before, rebuilt));
    }

    [Fact]
    public void AnInsertionOutsideTheTopLevelOfTheColumnListIsNotAnAppend()
    {
        // Review B N-6: the position of an insertion is at the top level of the column list only, never inside a constraint, a quoted
        // default or a comment; and the rest of the text must be unchanged byte for byte.
        const string Sql = "CREATE TABLE t (a INTEGER CHECK (a > 0), b TEXT DEFAULT '(,)' -- (note)\n, c INTEGER)";
        Assert.True(SchemaDiff.TopLevelOfColumns(Sql, Sql.IndexOf(", b", StringComparison.Ordinal)));
        Assert.True(SchemaDiff.TopLevelOfColumns(Sql, Sql.LastIndexOf(')', StringComparison.Ordinal)));
        Assert.False(SchemaDiff.TopLevelOfColumns(Sql, Sql.IndexOf("> 0", StringComparison.Ordinal)));
        Assert.False(SchemaDiff.TopLevelOfColumns(Sql, Sql.IndexOf("(,)", StringComparison.Ordinal) + 2));
        Assert.False(SchemaDiff.TopLevelOfColumns(Sql, Sql.IndexOf("(note", StringComparison.Ordinal) + 2));
        Assert.False(SchemaDiff.TopLevelOfColumns(Sql, Sql.IndexOf('(')));

        var a = new ColumnSchema("a", "INTEGER", false, null, 0);
        var b = new ColumnSchema("b", "INTEGER", false, null, 0);
        var c = new ColumnSchema("c", "INTEGER", false, null, 0);
        var before = new TableSchema("t", [a, b], "CREATE TABLE t (a INTEGER, b INTEGER CHECK (b IN (1, 2)))");
        Assert.True(SchemaDiff.IsAppendOnly(before, new TableSchema("t", [a, b, c], "CREATE TABLE t (a INTEGER, b INTEGER CHECK (b IN (1, 2)), c INTEGER)")));
        Assert.False(SchemaDiff.IsAppendOnly(before, new TableSchema("t", [a, b, c], "CREATE TABLE t (a INTEGER, b INTEGER CHECK (b IN (1, 2), c INTEGER))")));
        Assert.False(SchemaDiff.IsAppendOnly(before, new TableSchema("t", [a, b, c], "CREATE TABLE t (a INTEGER, b INTEGER CHECK (b IN (1, 3)), c INTEGER)")));
        Assert.False(SchemaDiff.IsAppendOnly(before, new TableSchema("t", [a, b, c], "CREATE TABLE t (a INTEGER, b INTEGER CHECK (b IN (1, 2)) c INTEGER)")));
    }

    [Fact]
    public void ANotNullColumnWithoutDefaultIsAViolation()
    {
        var before = Snapshot(StoreMigrations.Expanded.Steps);
        var rebuilt = Snapshot([.. StoreMigrations.Expanded.Steps, new StoreMigration(StoreMigrations.ExpandedSchemaVersion + 1, 1, "0003-x.sql",
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
