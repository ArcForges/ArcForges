// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Persistence.Sqlite;

/// <summary>A durable journal position within one store, not a transport sequence.</summary>
public readonly record struct JournalSequence
{
    public JournalSequence(Guid storeId, long value)
    {
        if (storeId == Guid.Empty) throw new ArgumentException("A store identity is required.", nameof(storeId));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
        StoreId = storeId;
        Value = value;
    }

    public Guid StoreId { get; }
    public long Value { get; }

    internal void RequireStore(Guid storeId)
    {
        if (StoreId == Guid.Empty || StoreId != storeId || Value <= 0)
            throw new ArgumentException("The journal position belongs to another or an invalid store.");
    }
}
