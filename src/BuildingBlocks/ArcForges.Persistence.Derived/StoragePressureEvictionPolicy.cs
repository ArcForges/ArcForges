// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Persistence.Derived;

/// <summary>A non-mutating eviction plan containing only registered derived stores.</summary>
public sealed class DerivedEvictionPlan
{
    internal DerivedEvictionPlan(long bytesBelowDurabilityReserve, IReadOnlyList<DerivedEvictionEntry> entries)
    {
        BytesBelowDurabilityReserve = bytesBelowDurabilityReserve;
        Entries = Array.AsReadOnly(entries.ToArray());
        StoreIds = Array.AsReadOnly(entries.Select(static entry => entry.Descriptor.StoreId).ToArray());
        EstimatedBytesReclaimed = entries.Aggregate(0L, static (total, entry) => checked(total + entry.Descriptor.EstimatedBytes));
    }

    public long BytesBelowDurabilityReserve { get; }

    public IReadOnlyList<string> StoreIds { get; }

    public long EstimatedBytesReclaimed { get; }

    public bool ReserveRestoredByEstimate => EstimatedBytesReclaimed >= BytesBelowDurabilityReserve;

    internal IReadOnlyList<DerivedEvictionEntry> Entries { get; }
}

/// <summary>The stores actually cleared and their estimated, not measured, reclaimed bytes.</summary>
public sealed class DerivedEvictionResult
{
    internal DerivedEvictionResult(IReadOnlyList<string> evictedStoreIds, long estimatedBytesReclaimed)
    {
        EvictedStoreIds = Array.AsReadOnly(evictedStoreIds.ToArray());
        EstimatedBytesReclaimed = estimatedBytesReclaimed;
    }

    public IReadOnlyList<string> EvictedStoreIds { get; }

    public long EstimatedBytesReclaimed { get; }
}

internal sealed record DerivedEvictionEntry(DerivedStore Store, DerivedStoreDescriptor Descriptor);

/// <summary>
/// Plans eviction by rebuild cost (cheapest first), then oldest use, and finally stable store ID.
/// It accepts only <see cref="DerivedStore"/> instances and can never call a canonical-store API.
/// </summary>
public static class StoragePressureEvictionPolicy
{
    public static DerivedEvictionPlan CreatePlan(StoragePressureState state, IEnumerable<DerivedStore> derivedStores)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(derivedStores);

        var stores = derivedStores.ToArray();
        if (stores.Any(static store => store is null))
        {
            throw new ArgumentException("Derived store registrations cannot contain null entries.", nameof(derivedStores));
        }

        var byId = stores.ToDictionary(static store => store.Descriptor.StoreId, StringComparer.Ordinal);
        if (byId.Count != state.DerivedStores.Count || state.DerivedStores.Any(descriptor =>
            !byId.TryGetValue(descriptor.StoreId, out var store) || store.Descriptor != descriptor))
        {
            throw new ArgumentException("The pressure snapshot must describe exactly the supplied derived stores.", nameof(derivedStores));
        }

        var requiredBytes = state.BytesBelowDurabilityReserve;
        var selected = new List<DerivedEvictionEntry>();
        var estimatedBytes = 0L;
        foreach (var descriptor in state.DerivedStores
            .OrderBy(static descriptor => descriptor.RebuildCost)
            .ThenBy(static descriptor => descriptor.LastUsedUtc)
            .ThenBy(static descriptor => descriptor.StoreId, StringComparer.Ordinal))
        {
            if (requiredBytes == 0)
            {
                break;
            }

            if (descriptor.EstimatedBytes == 0)
            {
                continue;
            }

            selected.Add(new DerivedEvictionEntry(byId[descriptor.StoreId], descriptor));
            estimatedBytes = checked(estimatedBytes + descriptor.EstimatedBytes);
            if (estimatedBytes >= requiredBytes)
            {
                break;
            }
        }

        return new DerivedEvictionPlan(requiredBytes, selected);
    }

    public static async ValueTask<DerivedEvictionResult> ExecuteAsync(
        DerivedEvictionPlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);

        foreach (var entry in plan.Entries)
        {
            if (entry.Store.Descriptor != entry.Descriptor)
            {
                throw new InvalidOperationException("The derived-store snapshot changed after eviction was planned; create a new plan.");
            }
        }

        foreach (var entry in plan.Entries)
        {
            await entry.Store.DeleteAllAsync(cancellationToken).ConfigureAwait(false);
        }

        return new DerivedEvictionResult(plan.StoreIds, plan.EstimatedBytesReclaimed);
    }
}
