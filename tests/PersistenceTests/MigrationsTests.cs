// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Foundation.Versions;
using ArcForges.Persistence.Sqlite.Migrations;

namespace ArcForges.Tests.PersistenceTests;

public sealed class MigrationsTests
{
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
}
