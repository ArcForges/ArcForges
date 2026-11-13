// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// Actual SQLite/NodeStore admission logic on owned data. Missing/future reader capabilities are controlled inputs;
/// these cases do not replace the coordinator's unmodified old-binary/process-exclusion evidence.
/// </summary>
public sealed class StageProducerAdmissionTests
{
    [Fact]
    public void FreshStageSchemaStartsWithTheActualWriterCapabilityButMissingStartFunctionIsRejected()
    {
        var directory = Directory.CreateTempSubdirectory("af-stage-admission-");
        try
        {
            using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = directory.FullName, BootIdentity = "stage-test-boot" });
            Assert.Equal(15, store.Metadata.SchemaVersion);
            Assert.Equal(15, store.Metadata.MinReaderVersion);
            Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM file_stage_production;")));
            using var missing = Raw(store.DatabasePath);
            using var command = missing.CreateCommand();
            command.CommandText = "UPDATE store_meta SET boot_identity = 'unadmitted-reader' WHERE singleton = 1;";
            var failure = Assert.Throws<SqliteException>(() => command.ExecuteNonQuery());
            Assert.Contains("arcforges_store_reader_version", failure.Message, StringComparison.Ordinal);
            Assert.Equal("stage-test-boot", store.Read(reader => reader.Scalar("SELECT boot_identity FROM store_meta WHERE singleton = 1;")));
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    public void AWriterRechecksTheCurrentFloorBeforeRunningTheCommandAction()
    {
        var directory = Directory.CreateTempSubdirectory("af-stage-floor-");
        try
        {
            using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = directory.FullName, BootIdentity = "stage-floor-boot" });
            using var future = Raw(store.DatabasePath);
            // A hypothetical later reader is an explicit test input, not a claimed future binary or migration.
            future.CreateFunction<long>("arcforges_store_reader_version", () => 16);
            void SetVersion(int version)
            {
                using var set = future.CreateCommand();
                set.CommandText = "UPDATE store_meta SET schema_version = $version, min_reader_version = $version WHERE singleton = 1;";
                set.Parameters.AddWithValue("$version", version);
                _ = set.ExecuteNonQuery();
            }
            SetVersion(16);
            try
            {
                var entered = false;
                Assert.Throws<StoreIncompatibleException>(() => store.Write(_ => { entered = true; return 0; }));
                Assert.False(entered);
            }
            finally { SetVersion(15); }
            Assert.Equal(1, store.Write(_ => 1));
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    public void ExistingFourteenStillRefusesUpgradeUntilRealProcessExclusionIsAdmitted()
    {
        var directory = Directory.CreateTempSubdirectory("af-stage-legacy-");
        try
        {
            var options = new NodeStoreOptions { DataRoot = directory.FullName, BootIdentity = "legacy-stage-boot" };
            using (var old = NodeStore.Open(options, new MigrationPlan(StoreMigrations.Released.Steps.Take(14))))
                Assert.Equal(14, old.Metadata.SchemaVersion);
            var bytes = File.ReadAllBytes(StorePaths.Database(directory.FullName));
            var failure = Assert.Throws<StoreIncompatibleException>(() => NodeStore.Open(options));
            Assert.Contains("schema 15", failure.Message, StringComparison.Ordinal);
            Assert.Equal(bytes, File.ReadAllBytes(StorePaths.Database(directory.FullName)));
        }
        finally { directory.Delete(recursive: true); }
    }

    private static SqliteConnection Raw(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString());
        connection.Open();
        return connection;
    }
}
