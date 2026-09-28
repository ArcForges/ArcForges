// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Persistence.Derived;

/// <summary>A caller-classified, user-visible storage pressure state; no threshold is implied here.</summary>
public enum StoragePressureLevel
{
    Normal = 0,
    Warning = 1,
    Critical = 2,
}

/// <summary>
/// A snapshot of available space, the durability reserve, canonical usage, and independently
/// reclaimable derived stores. Pressure classification is supplied by the owner; this model does
/// not invent product-specific thresholds.
/// </summary>
public sealed class StoragePressureState
{
    public StoragePressureState(
        StoragePressureLevel level,
        long availableBytes,
        long durabilityReserveBytes,
        long canonicalBytes,
        IEnumerable<DerivedStoreDescriptor> derivedStores)
    {
        if (!Enum.IsDefined(level))
        {
            throw new ArgumentOutOfRangeException(nameof(level));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(availableBytes);
        ArgumentOutOfRangeException.ThrowIfNegative(durabilityReserveBytes);
        ArgumentOutOfRangeException.ThrowIfNegative(canonicalBytes);
        ArgumentNullException.ThrowIfNull(derivedStores);

        var stores = derivedStores.ToArray();
        if (stores.Any(static store => store is null))
        {
            throw new ArgumentException("Derived store descriptors cannot contain null entries.", nameof(derivedStores));
        }

        if (stores.Select(static store => store.StoreId).Distinct(StringComparer.Ordinal).Count() != stores.Length)
        {
            throw new ArgumentException("Derived store IDs must be unique in a pressure snapshot.", nameof(derivedStores));
        }

        Level = level;
        AvailableBytes = availableBytes;
        DurabilityReserveBytes = durabilityReserveBytes;
        CanonicalBytes = canonicalBytes;
        DerivedStores = Array.AsReadOnly(stores.OrderBy(static store => store.StoreId, StringComparer.Ordinal).ToArray());
        ReclaimableDerivedBytes = stores.Aggregate(0L, static (total, store) => checked(total + store.EstimatedBytes));
    }

    public StoragePressureLevel Level { get; }

    public long AvailableBytes { get; }

    public long DurabilityReserveBytes { get; }

    public long CanonicalBytes { get; }

    public IReadOnlyList<DerivedStoreDescriptor> DerivedStores { get; }

    public long ReclaimableDerivedBytes { get; }

    /// <summary>The estimated bytes needed to bring free space back to the declared durability reserve.</summary>
    public long BytesBelowDurabilityReserve => Math.Max(0, DurabilityReserveBytes - AvailableBytes);
}
