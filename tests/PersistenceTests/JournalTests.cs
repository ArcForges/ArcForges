// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Persistence.Sqlite;
using Microsoft.Data.Sqlite;
using Xunit;

namespace ArcForges.Tests.PersistenceTests;

public sealed class JournalTests
{
    [Fact]
    public void LocalEditIdentitySurvivesReplayAndShadowAcknowledgementWithoutUsingJournalOrder()
    {
        using var fixture = new JournalFixture();
        var journal = new SqliteJournal();
        var template = fixture.Entry(new JournalSequence(fixture.StoreId, 1), 1);
        JournalEntry Local(long journalOrder, StoreVersion previous, StoreVersion next, long? localSequence) =>
            JournalEntry.Create(new JournalSequence(fixture.StoreId, journalOrder), "local", template.AggregateId,
                previous, next, new CommandId(Guid.NewGuid()), "edit-or-shadow", 1, "body"u8, null,
                template.ActorId, template.CorrelationId, null, template.CommittedAt, localSequence);
        // Another aggregate uses the first journal position; local edits still begin at one.
        fixture.Append(journal, template);
        fixture.Append(journal, Local(2, StoreVersion.NewRoot, StoreVersion.Local(null, 1), 1));
        fixture.Append(journal, Local(3, StoreVersion.Local(null, 1), StoreVersion.Local(null, 2), 2));
        fixture.Append(journal, Local(4, StoreVersion.Local(null, 2), StoreVersion.Local(new CloudRevision(7), 2), null));
        fixture.Append(journal, Local(5, StoreVersion.Local(new CloudRevision(7), 2), StoreVersion.Local(new CloudRevision(7), 3), 3));
        using var connection = fixture.Open();
        using var transaction = connection.BeginTransaction(deferred: true);
        var entries = journal.Read(new SqliteReadContext(fixture.StoreId, connection, transaction), null, 10);
        Assert.Equal(new long?[] { null, 1, 2, null, 3 }, entries.Select(entry => entry.LocalSequence));
        Assert.Equal(new long[] { 1, 2, 3, 4, 5 }, entries.Select(entry => entry.Sequence.Value));
        Assert.Throws<ArgumentException>(() => Local(6, StoreVersion.Local(new CloudRevision(7), 3),
            StoreVersion.Local(new CloudRevision(7), 4), 6));
        Assert.Throws<ArgumentException>(() => Local(6, StoreVersion.Local(new CloudRevision(7), 3),
            StoreVersion.Local(new CloudRevision(8), 3), 3));
        Assert.Throws<ArgumentException>(() => Local(6, StoreVersion.Local(new CloudRevision(7), 3),
            StoreVersion.Local(new CloudRevision(7), 4), null));
    }

    [Fact]
    public void NativeSyncEditIdentityIsIndependentOfNativeRevision()
    {
        using var fixture = new JournalFixture();
        var template = fixture.Entry(new JournalSequence(fixture.StoreId, 1), 1);
        var entry = JournalEntry.Create(template.Sequence, "native", template.AggregateId,
            StoreVersion.Native(new NativeRevision(20)), StoreVersion.Native(new NativeRevision(21)),
            template.CommandId, template.Operation, 1, template.Payload.Span, null, template.ActorId,
            template.CorrelationId, null, template.CommittedAt, 3);
        var journal = new SqliteJournal();
        fixture.Append(journal, entry);
        using var connection = fixture.Open();
        using var transaction = connection.BeginTransaction(deferred: true);
        var restored = Assert.Single(journal.Read(new SqliteReadContext(fixture.StoreId, connection, transaction), null, 10));
        Assert.Equal(3, restored.LocalSequence);
        Assert.Equal(entry.Next, restored.Next);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StoreTransactionAcknowledgesOnlyAtomicBodyAndJournal(bool interrupt)
    {
        using var fixture = new JournalFixture();
        var journal = new SqliteJournal();
        using (var store = new StoreDatabase(fixture.DatabasePath, fixture.StoreId))
        {
            bool Commit() => store.WithTransaction(context =>
            {
                using var body = context.CreateCommand("INSERT INTO replay_state(value) VALUES('owner body')");
                body.ExecuteNonQuery();
                journal.Append(context, fixture.Entry(journal.GetNextSequence(context), 1));
                if (interrupt) throw new IOException("Injected interruption after journal append before owner commit.");
                return true;
            });
            if (interrupt) Assert.Throws<IOException>(() => Commit());
            else Assert.True(Commit());
        }
        using var reopened = new StoreDatabase(fixture.DatabasePath, fixture.StoreId);
        reopened.Read(context =>
        {
            var entries = journal.Read(context, null, 10);
            using var body = context.CreateCommand("SELECT COUNT(*) FROM replay_state");
            Assert.Equal(interrupt ? 0L : 1L, (long)body.ExecuteScalar()!);
            Assert.Equal(interrupt ? 0 : 1, entries.Count);
            return 0;
        });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void InterruptedCommitRecoversOnlyTheDurableBoundary(int interruption)
    {
        using var fixture = new JournalFixture();
        var journal = new SqliteJournal();
        using (var connection = fixture.Open())
        using (var transaction = connection.BeginTransaction())
        {
            var context = new SqliteCommitContext(fixture.StoreId, connection, transaction);
            using var state = context.CreateCommand("INSERT INTO replay_state(value) VALUES('committed body')");
            state.ExecuteNonQuery();
            if (interruption > 0) journal.Append(context, fixture.Entry(journal.GetNextSequence(context), 1));
            if (interruption == 2) transaction.Commit();
            // Disposing a unit before commit models loss before acknowledgement, not an OS crash.
        }
        using var reopened = fixture.Open();
        using var snapshot = reopened.BeginTransaction(deferred: true);
        var read = new SqliteReadContext(fixture.StoreId, reopened, snapshot);
        var entries = journal.Read(read, null, 10);
        using var count = read.CreateCommand("SELECT COUNT(*) FROM replay_state");
        Assert.Equal(interruption == 2 ? 1L : 0L, (long)count.ExecuteScalar()!);
        Assert.Equal(interruption == 2 ? 1 : 0, entries.Count);
        if (entries.Count == 1) Assert.Equal("body-1"u8.ToArray(), entries[0].Payload.ToArray());
    }

    [Fact]
    public void ReplayPreservesEveryMetadataFieldAndDefensivelyOwnsPayloadBytes()
    {
        using var fixture = new JournalFixture();
        var journal = new SqliteJournal();
        var payload = "body-1"u8.ToArray();
        var entry = fixture.Entry(new JournalSequence(fixture.StoreId, 1), 1, payload);
        payload[0] ^= 1;
        var returned = entry.Payload.ToArray();
        returned[0] ^= 1;
        fixture.Append(journal, entry);
        fixture.Append(journal, fixture.Entry(new JournalSequence(fixture.StoreId, 2), 2));
        using var connection = fixture.Open();
        using var transaction = connection.BeginTransaction(deferred: true);
        var context = new SqliteReadContext(fixture.StoreId, connection, transaction);
        var first = Assert.Single(journal.Read(context, null, 1));
        var second = Assert.Single(journal.Read(context, first.Sequence, 1));
        Assert.Equal(entry.Checksum.ToArray(), first.Checksum.ToArray());
        Assert.Equal(entry.CommandId, first.CommandId);
        Assert.Equal(entry.AggregateId, first.AggregateId);
        Assert.Equal(entry.ActorId, first.ActorId);
        Assert.Equal(entry.CorrelationId, first.CorrelationId);
        Assert.Equal(entry.CausationId, first.CausationId);
        Assert.Equal(entry.CommittedAt, first.CommittedAt);
        Assert.Equal("body-1"u8.ToArray(), first.Payload.ToArray());
        Assert.Equal(first.Next, second.Previous);
        Assert.Empty(journal.Read(context, second.Sequence, 1));
    }

    [Theory]
    [InlineData("UPDATE journal SET operation='modified' WHERE sequence=2")]
    [InlineData("DELETE FROM journal WHERE sequence=1")]
    [InlineData("DELETE FROM journal WHERE sequence=2")]
    [InlineData("UPDATE journal SET local_seq=1 WHERE sequence=2")]
    public void ReplayRefusesChangedMetadataMissingMiddleAndMissingTail(string corruption)
    {
        using var fixture = new JournalFixture();
        var journal = new SqliteJournal();
        fixture.Append(journal, fixture.Entry(new JournalSequence(fixture.StoreId, 1), 1));
        fixture.Append(journal, fixture.Entry(new JournalSequence(fixture.StoreId, 2), 2));
        using var connection = fixture.Open();
        using (var mutate = connection.CreateCommand())
        {
            switch (corruption)
            {
                case "UPDATE journal SET operation='modified' WHERE sequence=2":
                    mutate.CommandText = "UPDATE journal SET operation='modified' WHERE sequence=2";
                    break;
                case "DELETE FROM journal WHERE sequence=1":
                    mutate.CommandText = "DELETE FROM journal WHERE sequence=1";
                    break;
                case "DELETE FROM journal WHERE sequence=2":
                    mutate.CommandText = "DELETE FROM journal WHERE sequence=2";
                    break;
                case "UPDATE journal SET local_seq=1 WHERE sequence=2":
                    mutate.CommandText = "UPDATE journal SET local_seq=1 WHERE sequence=2";
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(corruption));
            }
            mutate.ExecuteNonQuery();
        }
        using var transaction = connection.BeginTransaction(deferred: true);
        Assert.Throws<InvalidDataException>(() => journal.Read(new SqliteReadContext(fixture.StoreId, connection, transaction), null, 10));
    }

    [Fact]
    public void TruncationKeepsAnExistingReadSnapshotAndNeverReusesSequenceNumbers()
    {
        using var fixture = new JournalFixture();
        var first = fixture.Entry(new JournalSequence(fixture.StoreId, 1), 1);
        var second = fixture.Entry(new JournalSequence(fixture.StoreId, 2), 2);
        var boundary = new VerifiedSnapshotBoundary(second.Sequence, second.Checksum.Span, new byte[32]);
        var journal = new SqliteJournal(new NamedSnapshotFixture(boundary));
        fixture.Append(journal, first);
        fixture.Append(journal, second);
        using var readerConnection = fixture.Open();
        using var readTransaction = readerConnection.BeginTransaction(deferred: true);
        var reader = new SqliteReadContext(fixture.StoreId, readerConnection, readTransaction);
        Assert.Single(journal.Read(reader, null, 1));
        using var writerConnection = fixture.Open();
        using var writeTransaction = writerConnection.BeginTransaction();
        var writer = new SqliteCommitContext(fixture.StoreId, writerConnection, writeTransaction);
        journal.Truncate(writer, boundary);
        Assert.Equal(second.Sequence, Assert.Single(journal.Read(reader, first.Sequence, 1)).Sequence);
        readTransaction.Dispose();
        writeTransaction.Commit();
        using var nextTransaction = writerConnection.BeginTransaction();
        var nextContext = new SqliteCommitContext(fixture.StoreId, writerConnection, nextTransaction);
        Assert.Equal(3, journal.GetNextSequence(nextContext).Value);
        nextTransaction.Rollback();
        using var finalTransaction = writerConnection.BeginTransaction(deferred: true);
        var finalRead = new SqliteReadContext(fixture.StoreId, writerConnection, finalTransaction);
        Assert.Empty(journal.Read(finalRead, boundary.Through, 10));
        Assert.Throws<InvalidOperationException>(() => journal.Read(finalRead, first.Sequence, 10));
        Assert.Throws<InvalidOperationException>(() => journal.Read(finalRead, null, 10));
    }

    [Fact]
    public void TruncationRefusesMissingSnapshotProofAndWrongBoundaryWithoutDeletingEntries()
    {
        using var fixture = new JournalFixture();
        var entry = fixture.Entry(new JournalSequence(fixture.StoreId, 1), 1);
        fixture.Append(new SqliteJournal(), entry);
        var wrong = new VerifiedSnapshotBoundary(entry.Sequence, new byte[32], new byte[32]);
        using var connection = fixture.Open();
        using var transaction = connection.BeginTransaction();
        var context = new SqliteCommitContext(fixture.StoreId, connection, transaction);
        Assert.Throws<InvalidOperationException>(() => new SqliteJournal().Truncate(context, wrong));
        Assert.Throws<InvalidDataException>(() => new SqliteJournal(new NamedSnapshotFixture(wrong)).Truncate(context, wrong));
        using var count = context.CreateCommand("SELECT COUNT(*) FROM journal");
        Assert.Equal(1L, (long)count.ExecuteScalar()!);
    }

    [Fact]
    public void CountSizeAndTimePressureAreBoundedAndDoNotAdvanceTheHeadOnRefusal()
    {
        using var fixture = new JournalFixture();
        var entry = fixture.Entry(new JournalSequence(fixture.StoreId, 1), 1);
        var journal = new SqliteJournal(snapshotPolicy: new JournalSnapshotPolicy(1, 1024 * 1024, 10));
        fixture.Append(journal, entry);
        using var connection = fixture.Open();
        using (var transaction = connection.BeginTransaction())
        {
            var context = new SqliteCommitContext(fixture.StoreId, connection, transaction);
            Assert.Throws<JournalCapacityException>(() => journal.Append(context, fixture.Entry(new JournalSequence(fixture.StoreId, 2), 2)));
            Assert.Equal(2, journal.GetNextSequence(context).Value);
        }
        using var readTransaction = connection.BeginTransaction(deferred: true);
        var read = new SqliteReadContext(fixture.StoreId, connection, readTransaction);
        Assert.True(journal.RequiresSnapshot(read, entry.CommittedAt));
        Assert.True(new SqliteJournal(snapshotPolicy: new JournalSnapshotPolicy(100, 1024 * 1024, 10))
            .RequiresSnapshot(read, new Instant(entry.CommittedAt.UnixSeconds + 10, 0)));
        Assert.False(new SqliteJournal().RequiresSnapshot(read, entry.CommittedAt));
    }

    [Fact]
    public void WrongStoreBackwardVersionsAndOversizedEntriesAreRejected()
    {
        using var fixture = new JournalFixture();
        var journal = new SqliteJournal(snapshotPolicy: new JournalSnapshotPolicy(10, 1, 10));
        using var connection = fixture.Open();
        using var transaction = connection.BeginTransaction();
        var context = new SqliteCommitContext(fixture.StoreId, connection, transaction);
        var entry = fixture.Entry(new JournalSequence(fixture.StoreId, 1), 1);
        Assert.Throws<JournalCapacityException>(() => journal.Append(context, entry));
        Assert.Equal(1, journal.GetNextSequence(context).Value);
        Assert.Throws<ArgumentException>(() => journal.Append(context, fixture.Entry(new JournalSequence(Guid.NewGuid(), 1), 1)));
        Assert.Throws<ArgumentException>(() => JournalEntry.Create(entry.Sequence, entry.AggregateKind, entry.AggregateId,
            StoreVersion.Cloud(new CloudRevision(2)), StoreVersion.Cloud(new CloudRevision(1)), entry.CommandId,
            entry.Operation, entry.OperationVersion, entry.Payload.Span, null, entry.ActorId,
            entry.CorrelationId, entry.CausationId, entry.CommittedAt));
    }

    // This names the PLT03 seam only; it does not claim that a real snapshot was created or verified.
    private sealed class NamedSnapshotFixture(VerifiedSnapshotBoundary expected) : IJournalSnapshotVerifier
    {
        public bool IsVerified(VerifiedSnapshotBoundary boundary) => ReferenceEquals(expected, boundary);
    }

    private sealed class JournalFixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "arcforges-journal-" + Guid.NewGuid().ToString("N"));
        private readonly Guid aggregateId = Guid.NewGuid();
        internal Guid StoreId { get; } = Guid.NewGuid();
        internal string DatabasePath => Path.Combine(directory, "journal.db");

        internal JournalFixture()
        {
            Directory.CreateDirectory(directory);
            using var connection = Open();
            using (var settings = connection.CreateCommand())
            {
                settings.CommandText = "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;";
                settings.ExecuteNonQuery();
            }
            using var transaction = connection.BeginTransaction();
            var context = new SqliteCommitContext(StoreId, connection, transaction);
            new SqliteJournal().Initialize(context);
            using var state = context.CreateCommand("CREATE TABLE replay_state(value TEXT NOT NULL)");
            state.ExecuteNonQuery();
            transaction.Commit();
        }

        internal SqliteConnection Open()
        {
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = DatabasePath,
                Pooling = false,
                DefaultTimeout = 1,
            }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA synchronous=FULL";
            command.ExecuteNonQuery();
            return connection;
        }

        internal JournalEntry Entry(JournalSequence sequence, long revision, byte[]? payload = null) => JournalEntry.Create(
            sequence, "fixture", aggregateId, revision == 1 ? StoreVersion.NewRoot : StoreVersion.Cloud(new CloudRevision(revision - 1)),
            StoreVersion.Cloud(new CloudRevision(revision)), new CommandId(Guid.NewGuid()), "replace", 1,
            payload ?? System.Text.Encoding.UTF8.GetBytes("body-" + revision.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            null, new UserId(Guid.NewGuid()), Guid.NewGuid(), Guid.NewGuid(), new Instant(100, 123));

        internal void Append(SqliteJournal journal, JournalEntry entry)
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction();
            journal.Append(new SqliteCommitContext(StoreId, connection, transaction), entry);
            transaction.Commit();
        }

        public void Dispose()
        {
            var actual = Path.GetFullPath(directory);
            var parent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
            if (!string.Equals(Path.GetDirectoryName(actual), parent, StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(actual).StartsWith("arcforges-journal-", StringComparison.Ordinal) ||
                new DirectoryInfo(actual).LinkTarget is not null)
                throw new InvalidOperationException("Refusing cleanup outside the isolated journal fixture.");
            Directory.Delete(actual, recursive: true);
        }
    }
}
