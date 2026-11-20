// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store.Tests;

public sealed class ScopedSandboxEventTests
{
    [Fact]
    public void SandboxAndRunEventsShareTheSourceTransactionAndKeepScopedRetention()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using (var prior = root.Open(clock, new MigrationPlan(StoreMigrations.Released.Steps.Take(18))))
        {
            Assert.Equal(18, prior.Metadata.SchemaVersion);
        }

        using var store = root.Open(clock);
        const string owner = "fixture-owner";
        const string foreign = "other-owner";
        const string epoch = "7";
        string sandbox = Guid.NewGuid().ToString("N");
        string other = Guid.NewGuid().ToString("N");
        string unrelated = Guid.NewGuid().ToString("N");
        store.Write(transaction =>
        {
            transaction.Execute("UPDATE store_meta SET journal_generation=7 WHERE singleton=1;");
            Reserve(transaction, owner, sandbox);
            Reserve(transaction, owner, other);
            Reserve(transaction, foreign, unrelated);
        }, CommitDurability.Full);

        var first = store.Read(reader => SandboxEventRecords.ReadNext(reader, owner, sandbox, epoch, 0));
        var another = store.Read(reader => SandboxEventRecords.ReadNext(reader, owner, other, epoch, 0));
        Assert.Equal(sandbox, first.Next?.SandboxId);
        Assert.Equal("sandbox", first.Next?.Kind);
        Assert.Equal(1L, first.Next?.Revision);
        Assert.Equal(other, another.Next?.SandboxId);
        Assert.Equal(0L, another.EvictedThrough);
        Assert.Null(store.Read(reader => SandboxEventRecords.ReadNext(reader, owner, unrelated, epoch, 0)).Next);

        string runId = Guid.NewGuid().ToString("N");
        var run = new StoredRun(runId, other, 1, 1, StoredRunState.Starting, Guid.NewGuid().ToString("N"),
            new string('0', 64), "{}", StoredPayloadStart.Unknown, clock.GetUtcNow());
        store.Write(transaction =>
        {
            Assert.True(SandboxRecords.SettleCreation(transaction, owner, other, "fixture-root", StoredSandboxState.Ready));
            Assert.True(RunRecords.InsertStarting(transaction, owner, run));
        }, CommitDurability.Full);
        var ready = store.Read(reader => SandboxEventRecords.ReadNext(reader, owner, other, epoch, another.LastRetained));
        var started = store.Read(reader => SandboxEventRecords.ReadNext(reader, owner, other, epoch, ready.Next!.Value.Sequence));
        Assert.Equal("sandbox", ready.Next?.Kind);
        Assert.Equal("run", started.Next?.Kind);
        Assert.Equal(runId, started.Next?.AggregateId);

        Assert.Throws<InvalidOperationException>(() => store.Write(transaction =>
        {
            Assert.True(SandboxRecords.SettleCreation(transaction, owner, sandbox, "fixture-root", StoredSandboxState.Ready));
            throw new InvalidOperationException("rollback");
        }, CommitDurability.Full));
        Assert.Null(store.Read(reader => SandboxEventRecords.ReadNext(reader, owner, sandbox, epoch, first.LastRetained)).Next);

        // Advance the database's event sequence to exercise the real bounded trigger without allocating 100,000 test rows.
        store.Write(transaction =>
        {
            transaction.Execute("UPDATE sqlite_sequence SET seq=100000 WHERE name='event';");
            Assert.True(RunRecords.TryAdvance(transaction, owner, runId, run.Epoch, 1, StoredRunState.Starting,
                new(StoredRunState.Stopping, StoredPayloadStart.Unknown, 3)));
        }, CommitDurability.Full);
        var evicted = store.Read(reader => SandboxEventRecords.ReadNext(reader, owner, sandbox, epoch, 0));
        var retained = store.Read(reader => SandboxEventRecords.ReadNext(reader, owner, other, epoch, started.LastRetained));
        Assert.Equal(first.LastRetained, evicted.EvictedThrough);
        Assert.Null(evicted.Next);
        Assert.Equal(0L, retained.EvictedThrough);
        Assert.Equal(100_001L, retained.Next?.Sequence);
        Assert.Equal(2L, retained.Next?.Revision);
        Assert.Equal(5L, store.Read(reader => reader.Scalar("SELECT count(*) FROM event WHERE body_json='{}';")));
    }

    private static void Reserve(StoreTransaction transaction, string owner, string id)
    {
        var config = new StoredSandboxConfig("fixture", "1", "{}", new string('0', 64));
        SandboxRecords.Reserve(transaction, new(id, owner, id, id, 1, StoredSandboxState.Creating, "data/" + id,
            SandboxRecords.PendingRootIdentity, 1, transaction.Clock.GetUtcNow(), transaction.Clock.GetUtcNow(), config));
    }
}
