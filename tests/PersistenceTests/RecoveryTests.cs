// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Versions;
using ArcForges.Persistence.Sqlite;
using ArcForges.Persistence.Sqlite.Migrations;
using Microsoft.Data.Sqlite;
using Xunit;

namespace ArcForges.Tests.PersistenceTests;

public sealed class RecoveryTests
{
    [Fact]
    public void PolicySnapshotIsSelfDescribingTruncatesOnlyVerifiedPrefixAndReopensCleanly()
    {
        using var file = new SnapshotFixture();
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        using (var store = CreateStore(file, new JournalSnapshotPolicy(1, 1024 * 1024, 3600)))
        {
            var receipt = store.Write(command);
            var snapshot = store.LastSnapshot;
            Assert.NotNull(snapshot);
            Assert.Equal(receipt.Sequence.Value, snapshot!.ThroughSequence);
            Assert.Equal(new StorageSchemaVersion(0), snapshot.SchemaVersion);
            Assert.Null(store.LastSnapshotFailure);
            Assert.Single(Directory.GetFiles(file.SnapshotDirectory, "*.afsnap"));
            Assert.Equal(receipt.Sequence.Value, file.ReadWatermarks().Floor);
        }

        using var reopened = new SqliteStore(file.Path, file.Id, new Allow());
        Assert.Equal(StoreRecoveryOutcome.Clean, reopened.Recovery.Outcome);
        Assert.Equal(command.Content.Version, reopened.Read(command.AggregateKind, command.AggregateId)!.Version);
        Assert.Empty(reopened.ReadJournal(new JournalSequence(file.Id, 1), 10));
    }

    [Fact]
    public void CorruptJournalTailReplaysVerifiedPrefixPreservesEvidenceAndEntersSafeStart()
    {
        using var file = new SnapshotFixture();
        var first = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        var second = Command(StoreVersion.Native(new(1)), StoreVersion.Native(new(2)), first.AggregateId);
        var third = Command(StoreVersion.Native(new(2)), StoreVersion.Native(new(3)), first.AggregateId);
        using (var store = new SqliteStore(file.Path, file.Id, new Allow()))
        {
            store.Write(first);
            var snapshot = store.CreateSnapshot();
            Assert.NotNull(snapshot);
            Assert.Equal(1, snapshot!.ThroughSequence);
            store.Write(second);
            store.Write(third);
        }
        file.CorruptJournalTail();

        using var recovered = new SqliteStore(file.Path, file.Id, new Allow());
        Assert.Equal(StoreRecoveryOutcome.RecoveredWithLossOfUncommittedWork, recovered.Recovery.Outcome);
        Assert.True(recovered.Recovery.RequiresSafeStart);
        Assert.Equal(1, recovered.Recovery.VerifiedThrough);
        Assert.Equal(2, recovered.Recovery.RecoveredThrough);
        Assert.NotNull(recovered.Recovery.EvidencePath);
        Assert.True(File.Exists(Path.Combine(recovered.Recovery.EvidencePath!, Path.GetFileName(file.Path))));
        Assert.Equal(second.Content.Version, recovered.Read(first.AggregateKind, first.AggregateId)!.Version);
        Assert.Throws<InvalidOperationException>(() => recovered.Write(
            Command(StoreVersion.Native(new(2)), StoreVersion.Native(new(3)), first.AggregateId)));
    }

    [Fact]
    public void CorruptSnapshotIsIgnoredWhenTheCanonicalDatabaseAndJournalAreClean()
    {
        using var file = new SnapshotFixture();
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        using (var store = new SqliteStore(file.Path, file.Id, new Allow()))
        {
            store.Write(command);
            Assert.NotNull(store.CreateSnapshot());
        }
        var snapshot = Assert.Single(Directory.GetFiles(file.SnapshotDirectory, "*.afsnap"));
        File.WriteAllBytes(snapshot, "corrupt snapshot"u8.ToArray());

        using var reopened = new SqliteStore(file.Path, file.Id, new Allow());
        Assert.Equal(StoreRecoveryOutcome.Clean, reopened.Recovery.Outcome);
        Assert.Equal(command.Content.Version, reopened.Read(command.AggregateKind, command.AggregateId)!.Version);
    }

    [Fact]
    public void InitializedDatabaseWithMissingOwnerIdentityTableIsRecoveredFromSnapshot()
    {
        using var file = new SnapshotFixture();
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        using (var store = new SqliteStore(file.Path, file.Id, new Allow()))
        {
            store.Write(command);
            Assert.NotNull(store.CreateSnapshot());
        }
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = file.Path,
            Pooling = false
        }.ToString()))
        {
            connection.Open();
            using var corrupt = connection.CreateCommand();
            corrupt.CommandText = "DROP TABLE store_identity";
            corrupt.ExecuteNonQuery();
        }

        using var reopened = new SqliteStore(file.Path, file.Id, new Allow());

        Assert.Equal(StoreRecoveryOutcome.Clean, reopened.Recovery.Outcome);
        Assert.NotNull(reopened.Recovery.EvidencePath);
        Assert.Equal(command.Content.Version, reopened.Read(command.AggregateKind, command.AggregateId)!.Version);
    }

    [Fact]
    public void InitializedDatabaseWithMissingOwnerIdentityRowIsRecoveredFromSnapshot()
    {
        using var file = new SnapshotFixture();
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        using (var store = new SqliteStore(file.Path, file.Id, new Allow()))
        {
            store.Write(command);
            Assert.NotNull(store.CreateSnapshot());
        }
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = file.Path,
            Pooling = false
        }.ToString()))
        {
            connection.Open();
            using var corrupt = connection.CreateCommand();
            corrupt.CommandText = "DELETE FROM store_identity";
            corrupt.ExecuteNonQuery();
        }

        using var reopened = new SqliteStore(file.Path, file.Id, new Allow());

        Assert.Equal(StoreRecoveryOutcome.Clean, reopened.Recovery.Outcome);
        Assert.NotNull(reopened.Recovery.EvidencePath);
        Assert.Equal(command.Content.Version, reopened.Read(command.AggregateKind, command.AggregateId)!.Version);
    }

    [Fact]
    public void MissingDatabaseRestoresVerifiedSnapshotAndPreservesOrphanedSqliteSidecars()
    {
        using var file = new SnapshotFixture();
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        using (var store = new SqliteStore(file.Path, file.Id, new Allow()))
        {
            store.Write(command);
            Assert.NotNull(store.CreateSnapshot());
        }

        File.Delete(file.Path);
        var orphanedWal = "orphaned WAL evidence"u8.ToArray();
        File.WriteAllBytes(file.Path + "-wal", orphanedWal);

        using var reopened = new SqliteStore(file.Path, file.Id, new Allow());

        Assert.Equal(StoreRecoveryOutcome.RecoveredWithLossOfUncommittedWork, reopened.Recovery.Outcome);
        Assert.True(reopened.Recovery.RequiresSafeStart);
        Assert.NotNull(reopened.Recovery.EvidencePath);
        Assert.Equal(orphanedWal, File.ReadAllBytes(Path.Combine(reopened.Recovery.EvidencePath!, Path.GetFileName(file.Path) + "-wal")));
        Assert.False(File.Exists(file.Path + "-wal"));
        Assert.Equal(command.Content.Version, reopened.Read(command.AggregateKind, command.AggregateId)!.Version);
    }

    [Fact]
    public void MissingDatabaseWithOrphanedSidecarsAndNoSnapshotIsNotSilentlyInitialized()
    {
        using var file = new SnapshotFixture();
        using (new SqliteStore(file.Path, file.Id, new Allow())) { }
        File.Delete(file.Path);
        var orphanedWal = "possibly committed content"u8.ToArray();
        File.WriteAllBytes(file.Path + "-wal", orphanedWal);

        var exception = Assert.Throws<StoreRecoveryException>(() => new SqliteStore(file.Path, file.Id, new Allow()));

        Assert.Equal(StoreRecoveryOutcome.UnrecoverableWithPreservedEvidence, exception.Report.Outcome);
        Assert.NotNull(exception.Report.EvidencePath);
        Assert.Equal(orphanedWal, File.ReadAllBytes(Path.Combine(exception.Report.EvidencePath!, Path.GetFileName(file.Path) + "-wal")));
        Assert.False(File.Exists(file.Path));
        Assert.Equal(orphanedWal, File.ReadAllBytes(file.Path + "-wal"));
    }

    [Fact]
    public void NoVerifiedSnapshotLeavesCorruptDatabaseUntouchedAndReportsEvidence()
    {
        using var file = new SnapshotFixture();
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        using (var store = new SqliteStore(file.Path, file.Id, new Allow()))
        {
            store.Write(command);
            Assert.NotNull(store.CreateSnapshot());
        }
        foreach (var snapshot in Directory.GetFiles(file.SnapshotDirectory, "*.afsnap"))
            File.WriteAllBytes(snapshot, "not a verified snapshot"u8.ToArray());
        File.WriteAllBytes(file.Path, "corrupt sqlite evidence"u8.ToArray());
        var original = File.ReadAllBytes(file.Path);

        var exception = Assert.Throws<StoreRecoveryException>(() => new SqliteStore(file.Path, file.Id, new Allow()));
        Assert.Equal(StoreRecoveryOutcome.UnrecoverableWithPreservedEvidence, exception.Report.Outcome);
        Assert.Equal(file.Path, exception.Report.EvidencePath);
        Assert.Equal(original, File.ReadAllBytes(file.Path));
    }

    [Fact]
    public void SnapshotDiskFailureDoesNotMisreportOrRollbackTheCommittedWrite()
    {
        using var file = new SnapshotFixture();
        File.WriteAllText(file.SnapshotDirectory, "blocks snapshot directory");
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        using var store = CreateStore(file, new JournalSnapshotPolicy(1, 1024 * 1024, 3600));

        var receipt = store.Write(command);

        Assert.Equal(command.Content.Version, store.Read(command.AggregateKind, command.AggregateId)!.Version);
        Assert.Equal(receipt.Sequence.Value, store.ReadJournal(null, 10).Single().Sequence.Value);
        Assert.NotNull(store.LastSnapshotFailure);
        Assert.Null(store.LastSnapshot);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void SnapshotInterruptionAtEachDurabilityBoundaryReopensCleanly(int interruptionValue)
    {
        var interruption = (SnapshotStage)interruptionValue;
        using var file = new SnapshotFixture();
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        using (var store = new SqliteStore(file.Path, file.Id, new Allow(), null,
            new JournalSnapshotPolicy(1, 1024 * 1024, 3600), performRecovery: true, runSnapshotPolicy: true,
            snapshotFault: stage =>
            {
                if (stage == interruption) throw new IOException("Injected interruption during snapshot publication.");
            }))
        {
            store.Write(command);
            Assert.NotNull(store.LastSnapshotFailure);
            Assert.Equal(command.Content.Version, store.Read(command.AggregateKind, command.AggregateId)!.Version);
        }

        using var reopened = new SqliteStore(file.Path, file.Id, new Allow());
        Assert.Equal(StoreRecoveryOutcome.Clean, reopened.Recovery.Outcome);
        Assert.Equal(command.Content.Version, reopened.Read(command.AggregateKind, command.AggregateId)!.Version);
        var floor = file.ReadWatermarks().Floor;
        Assert.Equal(interruption == SnapshotStage.JournalTruncated ? 1 : 0, floor);
        if (floor == 0) Assert.Single(reopened.ReadJournal(null, 10));
        else Assert.Empty(reopened.ReadJournal(new JournalSequence(file.Id, 1), 10));
        Assert.Equal(interruption == SnapshotStage.EnvelopeFlushed ? 0 : 1,
            Directory.GetFiles(file.SnapshotDirectory, "*.afsnap").Length);
    }

    [Fact]
    public void SqliteFullDuringWriteRollsBackAndReopensAtThePriorBoundary()
    {
        using var file = new SnapshotFixture();
        using (new SqliteStore(file.Path, file.Id, new Allow())) { }
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)), payloadSize: 1024 * 1024);

        using (var store = new SqliteStore(file.Path, file.Id, new Allow(), stage =>
        {
            if (stage == CommitStage.Applied) throw new SqliteException("Injected SQLITE_FULL during owner write.", 13);
        }))
        {
            var exception = Assert.Throws<SqliteException>(() => store.Write(command));
            Assert.Equal(13, exception.SqliteErrorCode);
        }

        using var reopened = new SqliteStore(file.Path, file.Id, new Allow());
        Assert.Equal(StoreRecoveryOutcome.Clean, reopened.Recovery.Outcome);
        Assert.Null(reopened.Read(command.AggregateKind, command.AggregateId));
        Assert.Empty(reopened.ReadJournal(null, 10));
    }

    [Fact]
    public void InterruptedMigrationKeepsLastCommittedStepAndReopensCleanly()
    {
        using var file = new SnapshotFixture();
        var first = new MigrationStep(new(1), "recovery-first", [
            "CREATE TABLE recovery_migration(value TEXT NOT NULL)",
            "INSERT INTO recovery_migration(value) VALUES('committed')"]);
        var interrupted = new MigrationStep(new(2), "recovery-second", [
            "INSERT INTO recovery_migration(value) VALUES('not committed')",
            "INSERT INTO missing_recovery_table(value) VALUES('failure')"]);
        var plan = new MigrationPlan([first, interrupted]);
        using (var store = new SqliteStore(file.Path, file.Id, new Allow()))
        {
            Assert.Throws<SqliteException>(() => store.Migrations.MigrateTo(plan, new StorageSchemaVersion(2)));
            Assert.Equal(new StorageSchemaVersion(1), store.Migrations.CurrentVersion);
            store.Write(Command(StoreVersion.NewRoot, StoreVersion.Native(new(1))));
            var snapshot = store.CreateSnapshot();
            Assert.NotNull(snapshot);
            Assert.Equal(new StorageSchemaVersion(1), snapshot!.SchemaVersion);
        }

        using var reopened = new SqliteStore(file.Path, file.Id, new Allow());
        Assert.Equal(StoreRecoveryOutcome.Clean, reopened.Recovery.Outcome);
        Assert.Equal(new StorageSchemaVersion(1), reopened.Migrations.CurrentVersion);
        Assert.Equal(1L, file.CountMigrationRows());
    }

    [Fact]
    public async Task NativeProcessKillInsideTransactionRollsBackAndReopensCleanly()
    {
        if (Environment.GetEnvironmentVariable("ARCFORGES_RUN_NATIVE_RECOVERY_CRASH") != "1") return;

        using var file = new SnapshotFixture();
        var command = Command(StoreVersion.NewRoot, StoreVersion.Native(new(1)));
        using (var store = new SqliteStore(file.Path, file.Id, new Allow()))
        {
            store.Write(command);
            Assert.NotNull(store.CreateSnapshot());
        }

        var marker = System.IO.Path.Combine(file.DirectoryPath, "native-crash-ready");
        var childPath = System.IO.Path.Combine(AppContext.BaseDirectory,
            OperatingSystem.IsWindows() ? "ArcForges.Tests.PersistenceTests.exe" : "ArcForges.Tests.PersistenceTests");
        Assert.True(File.Exists(childPath), "The local opt-in process-kill test requires the test apphost.");
        using var child = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = childPath,
                WorkingDirectory = Environment.CurrentDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };
        child.StartInfo.ArgumentList.Add("-method");
        child.StartInfo.ArgumentList.Add("ArcForges.Tests.PersistenceTests.RecoveryTests.NativeCrashChildWaitsInsideUncommittedTransaction");
        child.StartInfo.Environment["ARCFORGES_RECOVERY_CRASH_CHILD"] = "1";
        child.StartInfo.Environment["ARCFORGES_RECOVERY_CRASH_DATABASE"] = file.Path;
        child.StartInfo.Environment["ARCFORGES_RECOVERY_CRASH_AGGREGATE"] = command.AggregateId.ToString("D");
        child.StartInfo.Environment["ARCFORGES_RECOVERY_CRASH_MARKER"] = marker;
        Assert.True(child.Start(), "The opt-in native crash child did not start.");
        var standardOutput = child.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var standardError = child.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (!File.Exists(marker) && !child.HasExited && DateTime.UtcNow < deadline)
            await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.Current.CancellationToken).ConfigureAwait(true);

        var reachedTransaction = File.Exists(marker);
        if (!child.HasExited) child.Kill(entireProcessTree: true);
        await child.WaitForExitAsync(TestContext.Current.CancellationToken).ConfigureAwait(true);
        var output = await standardOutput.ConfigureAwait(true);
        var error = await standardError.ConfigureAwait(true);
        Assert.True(reachedTransaction, $"The crash child did not reach its open transaction. stdout={output} stderr={error}");
        Assert.NotEqual(0, child.ExitCode);

        using var reopened = new SqliteStore(file.Path, file.Id, new Allow());
        Assert.Equal(StoreRecoveryOutcome.Clean, reopened.Recovery.Outcome);
        Assert.Equal(command.Content.Version, reopened.Read(command.AggregateKind, command.AggregateId)!.Version);
        Assert.Equal(command.Content.Payload.ToArray(), reopened.Read(command.AggregateKind, command.AggregateId)!.Payload.ToArray());
    }

    [Fact]
    public void NativeCrashChildWaitsInsideUncommittedTransaction()
    {
        if (Environment.GetEnvironmentVariable("ARCFORGES_RECOVERY_CRASH_CHILD") != "1") return;

        var database = Environment.GetEnvironmentVariable("ARCFORGES_RECOVERY_CRASH_DATABASE")
            ?? throw new InvalidOperationException("The crash-child database path is missing.");
        var aggregate = Environment.GetEnvironmentVariable("ARCFORGES_RECOVERY_CRASH_AGGREGATE")
            ?? throw new InvalidOperationException("The crash-child aggregate identity is missing.");
        var marker = Environment.GetEnvironmentVariable("ARCFORGES_RECOVERY_CRASH_MARKER")
            ?? throw new InvalidOperationException("The crash-child marker path is missing.");
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = database,
            Pooling = false
        }.ToString());
        connection.Open();
        using var transaction = connection.BeginTransaction();
        using (var mutation = connection.CreateCommand())
        {
            mutation.Transaction = transaction;
            mutation.CommandText = "UPDATE store_content SET payload=$payload WHERE kind='recovery-test' AND id=$aggregate";
            mutation.Parameters.AddWithValue("$payload", "uncommitted native process-kill mutation"u8.ToArray());
            mutation.Parameters.AddWithValue("$aggregate", aggregate);
            Assert.Equal(1, mutation.ExecuteNonQuery());
        }
        using (var ready = new FileStream(marker, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            ready.WriteByte(1);
            ready.Flush(flushToDisk: true);
        }
        Thread.Sleep(Timeout.Infinite);
    }

    private static SqliteStore CreateStore(SnapshotFixture file, JournalSnapshotPolicy policy) =>
        new(file.Path, file.Id, new Allow(), null, policy, performRecovery: true, runSnapshotPolicy: true);

    private static WriteCommand Command(StoreVersion expected, StoreVersion next, Guid? aggregateId = null,
        int payloadSize = 0)
    {
        var payload = Encoding.UTF8.GetBytes(payloadSize == 0
            ? "recovery-body-" + next.CanonicalText
            : new string('x', payloadSize));
        var origin = new ContentOrigin
        {
            Profile = "arcforges.content-origin.v1",
            OriginId = new ContentOriginId(Guid.NewGuid()).ToWire(),
            ContentUnitId = new ContentUnitId(Guid.NewGuid()).ToWire(),
            PayloadSha256 = Convert.ToHexStringLower(SHA256.HashData(payload)),
            ProducerKind = "human",
            OmittedParentCount = 0
        };
        origin.Kinds.Add("nonAi");
        return new(new(Guid.NewGuid()), "recovery-test", aggregateId ?? Guid.NewGuid(), expected,
            new(next, payload, origin), "recovery.replace", new(Guid.Parse("00000000-0000-4000-8000-000000000001")),
            Guid.NewGuid(), ArcForges.Foundation.Instant.FromDateTimeOffset(DateTimeOffset.UtcNow));
    }

    private sealed class Allow : IStoreAuthorization
    {
        public bool CanWrite(WriteCommand command) => true;
    }

    private sealed class SnapshotFixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "arcforges-recovery-" + Guid.NewGuid().ToString("N"));

        internal SnapshotFixture()
        {
            Directory.CreateDirectory(directory);
            Path = System.IO.Path.Combine(directory, "owner.db");
            Id = Guid.NewGuid();
        }

        internal string Path { get; }
        internal string DirectoryPath => directory;
        internal Guid Id { get; }
        internal string SnapshotDirectory => Path + ".snapshots";

        internal (long Head, long Floor) ReadWatermarks()
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT last_sequence,truncated_through FROM journal_state WHERE store_id=$store";
            command.Parameters.AddWithValue("$store", Id.ToString("D"));
            using var row = command.ExecuteReader();
            Assert.True(row.Read());
            return (row.GetInt64(0), row.GetInt64(1));
        }

        internal void CorruptJournalTail()
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE journal SET operation='corrupt-tail' WHERE sequence=3";
            command.ExecuteNonQuery();
        }

        internal long CountMigrationRows()
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM recovery_migration";
            return (long)command.ExecuteScalar()!;
        }

        private SqliteConnection Open()
        {
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = Path,
                Pooling = false
            }.ToString());
            connection.Open();
            return connection;
        }

        public void Dispose()
        {
            var actual = System.IO.Path.GetFullPath(directory);
            var parent = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(System.IO.Path.GetTempPath()));
            if (!string.Equals(System.IO.Path.GetDirectoryName(actual), parent, StringComparison.OrdinalIgnoreCase) ||
                !System.IO.Path.GetFileName(actual).StartsWith("arcforges-recovery-", StringComparison.Ordinal) ||
                new DirectoryInfo(actual).LinkTarget is not null)
                throw new InvalidOperationException("Refusing cleanup outside the isolated recovery fixture.");
            Directory.Delete(actual, recursive: true);
        }
    }
}
