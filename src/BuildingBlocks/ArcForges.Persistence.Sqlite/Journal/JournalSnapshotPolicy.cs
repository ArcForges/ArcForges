// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Persistence.Sqlite;

/// <summary>Bounded journal retention; the snapshot owner responds to count, size or elapsed-time pressure.</summary>
internal sealed class JournalSnapshotPolicy
{
    internal JournalSnapshotPolicy(long maximumEntries = 10000, long maximumBytes = 67108864,
        long maximumAgeSeconds = 300)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumEntries);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumAgeSeconds);
        MaximumEntries = maximumEntries;
        MaximumBytes = maximumBytes;
        MaximumAgeSeconds = maximumAgeSeconds;
    }

    internal long MaximumEntries { get; }
    internal long MaximumBytes { get; }
    internal long MaximumAgeSeconds { get; }
}
