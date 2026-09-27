// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;
using ArcForges.Foundation.Versions;
using ArcForges.Persistence.Sqlite;
using ArcForges.Persistence.Sqlite.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Tests.PersistenceTests;

public sealed class MigrationsTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "arcforges-migrations-" + Guid.NewGuid().ToString("N"));
    private readonly Guid _storeId = Guid.NewGuid();

    public MigrationsTests() => Directory.CreateDirectory(_directory);
    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Xunit.Fact]
    public void MigrationDefinitionsCannotChangeAfterAdmission()
    {
        string[] statements = ["CREATE TABLE example(value TEXT NOT NULL)"];
        var step = new MigrationStep(new(1), "initial", statements);
        var checksum = step.Checksum;
        statements[0] = "DROP TABLE example";
        Xunit.Assert.Equal("CREATE TABLE example(value TEXT NOT NULL)", step.Statements[0]);
        Xunit.Assert.Equal(checksum, step.Checksum);
        Xunit.Assert.NotEqual(checksum, new MigrationStep(new(1), "initial", statements).Checksum);
        Xunit.Assert.NotEqual(checksum, new MigrationStep(new(2), "initial", step.Statements).Checksum);
        Xunit.Assert.NotEqual(checksum, new MigrationStep(new(1), "renamed", step.Statements).Checksum);
        Xunit.Assert.Throws<NotSupportedException>(() => ((IList<string>)step.Statements)[0] = "changed");
    }

    [Xunit.Fact]
    public void CompletePlanOrdersNumbersAndRejectsAmbiguousHistory()
    {
        var first = new MigrationStep(new(1), "initial", ["CREATE TABLE example(value TEXT)"]);
        var third = new MigrationStep(new(3), "index", ["CREATE INDEX ix ON example(value)"]);
        MigrationStep[] input = [third, first];
        var plan = new MigrationPlan(input);
        input[0] = first;
        Xunit.Assert.Equal(new uint[] { 1, 3 }, plan.Steps.Select(step => step.Version.Number));
        Xunit.Assert.Equal(new StorageSchemaVersion(3), plan.LatestVersion);
        Xunit.Assert.Throws<ArgumentException>(() => new MigrationPlan([first, first]));
        Xunit.Assert.Throws<ArgumentException>(() => new MigrationPlan([
            first, new MigrationStep(new(2), "initial", ["SELECT 1"])]));
        Xunit.Assert.Throws<ArgumentException>(() => new MigrationStep(default, "bad", ["SELECT 1"]));
        Xunit.Assert.Throws<ArgumentException>(() => new MigrationStep(new(0), "bad", ["SELECT 1"]));
        Xunit.Assert.Throws<ArgumentException>(() => new MigrationStep(new(1), "empty", []));
        Xunit.Assert.Throws<ArgumentException>(() => new MigrationStep(new(1), "empty", [" "]));
        Xunit.Assert.Equal(new StorageSchemaVersion(0), new MigrationPlan([]).LatestVersion);
    }

    [Xunit.Theory]
    [Xunit.InlineData(1u)]
    [Xunit.InlineData(2u)]
    [Xunit.InlineData(3u)]
    public void EveryHistoricalDatabaseReopensAndPreservesGoldenMeaning(uint historicalVersion)
    {
        var plan = FixturePlan();
        var path = Path.Combine(_directory, "history.db");
        using (var historical = new StoreDatabase(path, _storeId))
            new MigrationRunner(historical).MigrateTo(plan, new(historicalVersion));
        using var current = new StoreDatabase(path, _storeId);
        var runner = new MigrationRunner(current);
        Xunit.Assert.Equal(new StorageSchemaVersion(historicalVersion), runner.CurrentVersion);
        Xunit.Assert.Equal(new StorageSchemaVersion(3), runner.MigrateTo(plan, new(3)));
        var rows = current.Read(context =>
        {
            using var command = context.CreateCommand("SELECT id, body, origin FROM migration_fixture_notes ORDER BY id");
            using var reader = command.ExecuteReader();
            List<(long Id, string Body, string Origin)> output = [];
            while (reader.Read()) output.Add((reader.GetInt64(0), reader.GetString(1), reader.GetString(2)));
            return output;
        });
        using var fixture = JsonDocument.Parse(File.ReadAllText(FixturePath()));
        var expected = fixture.RootElement.GetProperty("semanticGolden").EnumerateArray()
            .Select(row => (row.GetProperty("id").GetInt64(), row.GetProperty("body").GetString()!, row.GetProperty("origin").GetString()!));
        Xunit.Assert.Equal(expected, rows);
        // A repeat must not execute the initial INSERTs or CREATE statements again.
        runner.MigrateTo(plan, new(3));
        Xunit.Assert.Equal(3L, Scalar(current, "SELECT COUNT(*) FROM __arcforges_migration_history"));
        Xunit.Assert.Equal("3", current.Read(context =>
        {
            using var query = context.CreateCommand("SELECT value FROM sys_meta WHERE key='storageSchemaVersion'");
            return (string)query.ExecuteScalar()!;
        }));
    }

    [Xunit.Fact]
    public void FailedStepRollsBackItsDataAndHistoryThenReopenResumes()
    {
        var first = new MigrationStep(new(1), "initial", ["CREATE TABLE resume_fixture (id INTEGER PRIMARY KEY)"]);
        var failing = new MigrationStep(new(2), "second", ["INSERT INTO resume_fixture VALUES (1)", "INSERT INTO missing_table VALUES (2)"]);
        var path = Path.Combine(_directory, "resume.db");
        using (var database = new StoreDatabase(path, _storeId))
        {
            var runner = new MigrationRunner(database);
            Xunit.Assert.Throws<SqliteException>(() => runner.MigrateTo(new([first, failing]), new(2)));
            Xunit.Assert.Equal(new StorageSchemaVersion(1), runner.CurrentVersion);
            Xunit.Assert.Equal(0L, Scalar(database, "SELECT COUNT(*) FROM resume_fixture"));
            Xunit.Assert.Equal(1L, Scalar(database, "SELECT COUNT(*) FROM __arcforges_migration_history"));
        }
        using var reopened = new StoreDatabase(path, _storeId);
        var repaired = new MigrationStep(new(2), "second", ["INSERT INTO resume_fixture VALUES (1)"]);
        new MigrationRunner(reopened).MigrateTo(new([first, repaired]), new(2));
        Xunit.Assert.Equal(1L, Scalar(reopened, "SELECT COUNT(*) FROM resume_fixture"));
        Xunit.Assert.Equal(2L, Scalar(reopened, "SELECT COUNT(*) FROM __arcforges_migration_history"));
    }

    [Xunit.Fact]
    public void DowngradeAndChangedAppliedStepRefuseBeforeMutation()
    {
        using var database = new StoreDatabase(Path.Combine(_directory, "refusal.db"), _storeId);
        var runner = new MigrationRunner(database);
        var plan = FixturePlan();
        runner.MigrateTo(plan, new(3));
        Xunit.Assert.Contains("downgrade", Xunit.Assert.Throws<InvalidOperationException>(() => runner.MigrateTo(plan, new(1))).Message);
        var changed = new MigrationStep(new(1), "notes-initial", ["DROP TABLE migration_fixture_notes"]);
        Xunit.Assert.Throws<InvalidOperationException>(() => runner.MigrateTo(new([changed, .. plan.Steps.Skip(1)]), new(3)));
        Xunit.Assert.Equal(new StorageSchemaVersion(3), runner.CurrentVersion);
        Xunit.Assert.Equal(2L, Scalar(database, "SELECT COUNT(*) FROM migration_fixture_notes"));
    }

    [Xunit.Fact]
    public void ConflictingMetadataPreservesEvidenceAndRefusesResume()
    {
        using var database = new StoreDatabase(Path.Combine(_directory, "corrupt.db"), _storeId);
        var runner = new MigrationRunner(database);
        var plan = FixturePlan();
        runner.MigrateTo(plan, new(1));
        database.RunSchemaExclusive(session => session.WithTransaction(context =>
        {
            using var corrupt = context.CreateCommand("UPDATE sys_meta SET value='02' WHERE key='storageSchemaVersion'");
            return corrupt.ExecuteNonQuery();
        }));
        Xunit.Assert.Throws<InvalidOperationException>(() => runner.MigrateTo(plan, new(3)));
        Xunit.Assert.Throws<InvalidOperationException>(() => runner.CurrentVersion);
        Xunit.Assert.Equal(1L, Scalar(database, "SELECT COUNT(*) FROM __arcforges_migration_history"));
        Xunit.Assert.Equal(2L, Scalar(database, "SELECT COUNT(*) FROM migration_fixture_notes"));
    }

    [Xunit.Theory]
    [Xunit.InlineData("COMMIT")]
    [Xunit.InlineData("ROLLBACK")]
    [Xunit.InlineData("SAVEPOINT escape")]
    [Xunit.InlineData("DELETE FROM sys_meta")]
    [Xunit.InlineData("DROP TABLE __arcforges_migration_history")]
    public void OwnerSqlCannotEscapeTransactionOrRewriteMechanismHistory(string forbidden)
    {
        using var database = new StoreDatabase(Path.Combine(_directory, "control.db"), _storeId);
        var step = new MigrationStep(new(1), "control", ["CREATE TABLE control_fixture (id INTEGER)", forbidden]);
        Xunit.Assert.Throws<SqliteException>(() => new MigrationRunner(database).MigrateTo(new([step]), new(1)));
        Xunit.Assert.Null(new MigrationRunner(database).CurrentVersion);
        Xunit.Assert.Equal(0L, Scalar(database, "SELECT COUNT(*) FROM sqlite_master WHERE name='control_fixture'"));
    }

    private static long Scalar(StoreDatabase database, string sql) => database.Read(context =>
    {
        using var command = context.CreateCommand(sql);
        return (long)command.ExecuteScalar()!;
    });

    private static MigrationPlan FixturePlan()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(FixturePath()));
        return new(document.RootElement.GetProperty("steps").EnumerateArray().Select(step => new MigrationStep(
            new(step.GetProperty("version").GetUInt32()), step.GetProperty("id").GetString()!,
            step.GetProperty("statements").EnumerateArray().Select(sql => sql.GetString()!))));
    }

    private static string FixturePath()
    {
        for (var directory = new DirectoryInfo(Directory.GetCurrentDirectory()); directory is not null; directory = directory.Parent)
        {
            var path = Path.Combine(directory.FullName, "fixtures", "formats", "migrations", "history.json");
            if (File.Exists(path)) return path;
        }
        throw new FileNotFoundException("Migration semantic history fixture is missing.");
    }
}
