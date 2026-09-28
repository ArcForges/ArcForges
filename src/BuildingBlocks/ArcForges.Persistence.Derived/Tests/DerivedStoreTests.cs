// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Persistence.Derived.Tests;

using System.Runtime.CompilerServices;
using Xunit;

public sealed class DerivedStoreTests
{
    private static readonly string[] ExpectedEvictionOrder = ["cheap-cold", "cheap-warm"];

    [Theory]
    [InlineData("local-search-index")]
    [InlineData("local-retrieval-index")]
    [InlineData("waveform_cache")]
    [InlineData("thumbnail_cache")]
    [InlineData("analysis_result")]
    [InlineData("decoded_event_index")]
    [InlineData("task_projection")]
    [InlineData("capability_registry_cache")]
    public async Task EachDefinedLocalKindCanBeDeletedAndRebuiltFromItsCanonicalSnapshot(string kind)
    {
        var canonicalRecords = new[]
        {
            new CanonicalSourceRecord<string>(new CanonicalSourceIdentity(kind, "source-1", "revision-7"), "alpha"),
            new CanonicalSourceRecord<string>(new CanonicalSourceIdentity(kind, "source-2", "revision-9"), "beta"),
        };
        var source = new MemoryCanonicalSource(canonicalRecords);
        var store = new MemoryDerivedStore(Descriptor($"store-{kind}", kind, DerivedRebuildCost.Cheap, 12, Utc(2026, 9, 28)), source);
        store.Seed(new DerivedRecord<string>(canonicalRecords[0].Identity, "stale-pipeline", "stale"));
        var canonicalBefore = source.Records.ToArray();
        var cancellationToken = TestContext.Current.CancellationToken;

        await store.DeleteAllAsync(cancellationToken).ConfigureAwait(true);

        Assert.Empty(store.Records);
        await store.RebuildAsync(cancellationToken).ConfigureAwait(true);

        Assert.Collection(
            store.Records,
            first =>
            {
                Assert.Equal(canonicalRecords[0].Identity, first.Source);
                Assert.Equal("pipeline-v1", first.PipelineVersion);
                Assert.Equal("alpha-derived", first.Value);
            },
            second =>
            {
                Assert.Equal(canonicalRecords[1].Identity, second.Source);
                Assert.Equal("pipeline-v1", second.PipelineVersion);
                Assert.Equal("beta-derived", second.Value);
            });
        Assert.Equal(canonicalBefore, source.Records);
        Assert.Equal(1, source.OpenCount);
        Assert.Equal(1, source.DisposedSnapshotCount);
    }

    [Fact]
    public async Task FailedProjectionKeepsThePreviousDerivedSnapshot()
    {
        var source = new MemoryCanonicalSource(
        [
            new CanonicalSourceRecord<string>(new CanonicalSourceIdentity("local-search-index", "source-1", "revision-1"), "throw"),
        ]);
        var store = new MemoryDerivedStore(Descriptor("search", "local-search-index", DerivedRebuildCost.Cheap, 1, Utc(2026, 9, 28)), source)
        {
            FailProjection = true,
        };
        store.Seed(new DerivedRecord<string>(new CanonicalSourceIdentity("local-search-index", "source-old", "revision-0"), "pipeline-v0", "previous"));

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await store.RebuildAsync(TestContext.Current.CancellationToken).ConfigureAwait(true)).ConfigureAwait(true);

        Assert.Collection(store.Records, record => Assert.Equal("previous", record.Value));
    }

    [Fact]
    public async Task EvictionUsesRebuildCostThenLastUseAndNeverChangesCanonicalData()
    {
        var canonicalRecords = new[]
        {
            new CanonicalSourceRecord<string>(new CanonicalSourceIdentity("local-search-index", "source-1", "revision-1"), "canonical"),
        };
        var canonicalSource = new MemoryCanonicalSource(canonicalRecords);
        var cheapCold = Store("cheap-cold", "thumbnail_cache", DerivedRebuildCost.Cheap, 600, Utc(2025, 1, 1), canonicalSource);
        var cheapWarm = Store("cheap-warm", "task_projection", DerivedRebuildCost.Cheap, 500, Utc(2026, 1, 1), canonicalSource);
        var moderate = Store("moderate", "analysis_result", DerivedRebuildCost.Moderate, 800, Utc(2024, 1, 1), canonicalSource);
        var expensive = Store("expensive", "waveform_cache", DerivedRebuildCost.Expensive, 1_200, Utc(2020, 1, 1), canonicalSource);
        var stores = new DerivedStore[] { expensive, moderate, cheapWarm, cheapCold };
        foreach (var store in stores.Cast<MemoryDerivedStore>())
        {
            store.Seed(new DerivedRecord<string>(canonicalRecords[0].Identity, "pipeline-v1", store.Descriptor.StoreId));
        }

        var canonicalBefore = canonicalSource.Records.ToArray();
        var state = new StoragePressureState(
            StoragePressureLevel.Critical,
            availableBytes: 100,
            durabilityReserveBytes: 1_000,
            canonicalBytes: 4_096,
            stores.Select(static store => store.Descriptor));
        var plan = StoragePressureEvictionPolicy.CreatePlan(state, stores);

        Assert.Equal(ExpectedEvictionOrder, plan.StoreIds);
        Assert.Equal(900, plan.BytesBelowDurabilityReserve);
        Assert.Equal(1_100, plan.EstimatedBytesReclaimed);
        Assert.True(plan.ReserveRestoredByEstimate);
        Assert.Equal(4_096, state.CanonicalBytes);
        Assert.Equal(3_100, state.ReclaimableDerivedBytes);

        var result = await StoragePressureEvictionPolicy.ExecuteAsync(plan, TestContext.Current.CancellationToken).ConfigureAwait(true);

        Assert.Equal(plan.StoreIds, result.EvictedStoreIds);
        Assert.Equal(1_100, result.EstimatedBytesReclaimed);
        Assert.Empty(cheapCold.Records);
        Assert.Empty(cheapWarm.Records);
        Assert.NotEmpty(moderate.Records);
        Assert.NotEmpty(expensive.Records);
        Assert.Equal(canonicalBefore, canonicalSource.Records);
    }

    [Fact]
    public async Task PolicyDoesNotEvictWhenFreeSpaceAlreadyMeetsTheDurabilityReserve()
    {
        var source = new MemoryCanonicalSource(
        [
            new CanonicalSourceRecord<string>(new CanonicalSourceIdentity("local-search-index", "source-1", "revision-1"), "canonical"),
        ]);
        var store = Store("search", "local-search-index", DerivedRebuildCost.Cheap, 100, Utc(2025, 1, 1), source);
        store.Seed(new DerivedRecord<string>(source.Records[0].Identity, "pipeline-v1", "cached"));
        var state = new StoragePressureState(StoragePressureLevel.Warning, 500, 400, 100, [store.Descriptor]);

        var plan = StoragePressureEvictionPolicy.CreatePlan(state, [store]);
        var result = await StoragePressureEvictionPolicy.ExecuteAsync(plan, TestContext.Current.CancellationToken).ConfigureAwait(true);

        Assert.Empty(plan.StoreIds);
        Assert.Empty(result.EvictedStoreIds);
        Assert.Single(store.Records);
        Assert.Equal(0, state.BytesBelowDurabilityReserve);
    }

    [Fact]
    public void PolicyRejectsAnIncompleteStoreSnapshot()
    {
        var source = new MemoryCanonicalSource(
        [
            new CanonicalSourceRecord<string>(new CanonicalSourceIdentity("local-search-index", "source-1", "revision-1"), "canonical"),
        ]);
        var first = Store("first", "local-search-index", DerivedRebuildCost.Cheap, 100, Utc(2025, 1, 1), source);
        var second = Store("second", "task_projection", DerivedRebuildCost.Cheap, 200, Utc(2025, 1, 1), source);
        var state = new StoragePressureState(StoragePressureLevel.Critical, 0, 500, 100, [first.Descriptor, second.Descriptor]);

        Assert.Throws<ArgumentException>(() => StoragePressureEvictionPolicy.CreatePlan(state, [first]));
    }

    [Fact]
    public async Task PolicyRejectsAPlanAfterStoreUsageChanges()
    {
        var source = new MemoryCanonicalSource(
        [
            new CanonicalSourceRecord<string>(new CanonicalSourceIdentity("local-search-index", "source-1", "revision-1"), "canonical"),
        ]);
        var store = Store("search", "local-search-index", DerivedRebuildCost.Cheap, 100, Utc(2025, 1, 1), source);
        store.Seed(new DerivedRecord<string>(source.Records[0].Identity, "pipeline-v1", "cached"));
        var state = new StoragePressureState(StoragePressureLevel.Critical, 0, 50, 100, [store.Descriptor]);
        var plan = StoragePressureEvictionPolicy.CreatePlan(state, [store]);
        store.UpdateUsageForTest(200, Utc(2026, 1, 1));

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await StoragePressureEvictionPolicy.ExecuteAsync(plan, TestContext.Current.CancellationToken).ConfigureAwait(true)).ConfigureAwait(true);

        Assert.Single(store.Records);
    }

    private static MemoryDerivedStore Store(
        string id,
        string kind,
        DerivedRebuildCost cost,
        long bytes,
        DateTimeOffset lastUsedUtc,
        MemoryCanonicalSource source) =>
        new(Descriptor(id, kind, cost, bytes, lastUsedUtc), source);

    private static DerivedStoreDescriptor Descriptor(
        string id,
        string kind,
        DerivedRebuildCost cost,
        long bytes,
        DateTimeOffset lastUsedUtc) =>
        new(id, kind, "pipeline-v1", cost, bytes, lastUsedUtc);

    private static DateTimeOffset Utc(int year, int month, int day) =>
        new(year, month, day, 0, 0, 0, TimeSpan.Zero);

    private sealed class MemoryCanonicalSource(IReadOnlyList<CanonicalSourceRecord<string>> records)
        : ICanonicalSnapshotSource<string>
    {
        public CanonicalSourceRecord<string>[] Records { get; } = records.ToArray();

        public int OpenCount { get; private set; }

        public int DisposedSnapshotCount { get; private set; }

        public ValueTask<ICanonicalSnapshot<string>> OpenSnapshotAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            OpenCount++;
            return ValueTask.FromResult<ICanonicalSnapshot<string>>(CreateSnapshot());
        }

        private MemoryCanonicalSnapshot CreateSnapshot() =>
            new MemoryCanonicalSnapshot(Records.ToArray(), () => DisposedSnapshotCount++);
    }

    private sealed class MemoryCanonicalSnapshot(
        IReadOnlyList<CanonicalSourceRecord<string>> records,
        Action onDispose) : ICanonicalSnapshot<string>
    {
        public async IAsyncEnumerable<CanonicalSourceRecord<string>> ReadAllAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            foreach (var record in records)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await Task.Yield();
                yield return record;
            }
        }

        public ValueTask DisposeAsync()
        {
            onDispose();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class MemoryDerivedStore(
        DerivedStoreDescriptor descriptor,
        MemoryCanonicalSource source) : DerivedStore<string, string>(descriptor, source)
    {
        private IReadOnlyList<DerivedRecord<string>> records = [];

        public IReadOnlyList<DerivedRecord<string>> Records => records;

        public bool FailProjection { get; init; }

        public void Seed(DerivedRecord<string> record) => records = [.. records, record];

        public void UpdateUsageForTest(long estimatedBytes, DateTimeOffset lastUsedUtc) => UpdateUsage(estimatedBytes, lastUsedUtc);

        protected override ValueTask DeleteDerivedContentsAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            records = [];
            return ValueTask.CompletedTask;
        }

        protected override async ValueTask ReplaceDerivedSnapshotAsync(
            IAsyncEnumerable<DerivedRecord<string>> replacement,
            CancellationToken cancellationToken)
        {
            var staged = new List<DerivedRecord<string>>();
            await foreach (var record in replacement.WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                staged.Add(record);
            }

            records = Array.AsReadOnly(staged.ToArray());
        }

        protected override async IAsyncEnumerable<string> ProjectAsync(
            CanonicalSourceRecord<string> canonicalRecord,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (FailProjection)
            {
                throw new InvalidOperationException("Injected projection failure.");
            }

            await Task.Yield();
            yield return $"{canonicalRecord.Value}-derived";
        }
    }
}
