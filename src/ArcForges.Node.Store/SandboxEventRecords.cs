// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Node.Store;

internal readonly record struct StoredSandboxEvent(long Sequence, string Kind, string SandboxId, string AggregateId,
    long Revision, DateTimeOffset ObservedAt);

internal readonly record struct SandboxEventRead(long EvictedThrough, long FirstRetained, long LastRetained, StoredSandboxEvent? Next);

internal static class SandboxEventRecords
{
    internal static SandboxEventRead ReadNext(StoreReader reader, string owner, string? sandboxId, string epoch, long after)
    {
        // Select a fixed predicate so SQLite can seek by its owner or Sandbox cursor index.
        string scope = sandboxId is null ? "" : " AND sandbox_id=$sandbox";
        (string Name, object? Value)[] keys = sandboxId is null ? [("$owner", owner), ("$epoch", epoch)]
            : [("$owner", owner), ("$epoch", epoch), ("$sandbox", sandboxId)];
        long evictedThrough;
        long firstRetained;
        long lastRetained;
        using (var bounds = reader.CreateCommand($"""
            SELECT coalesce((SELECT max(through_sequence) FROM event_eviction WHERE owner_id=$owner AND epoch=$epoch{scope}),0),
                   coalesce((SELECT sequence FROM event WHERE owner_id=$owner AND epoch=$epoch{scope} ORDER BY sequence LIMIT 1),0),
                   coalesce((SELECT sequence FROM event WHERE owner_id=$owner AND epoch=$epoch{scope} ORDER BY sequence DESC LIMIT 1),0);
            """))
        {
            StoreReader.Bind(bounds, keys);
            using var row = bounds.ExecuteReader();
            if (!row.Read())
            {
                throw new InvalidDataException("The Sandbox event cursor bounds are unavailable.");
            }

            evictedThrough = row.GetInt64(0);
            firstRetained = row.GetInt64(1);
            lastRetained = row.GetInt64(2);
        }

        using var next = reader.CreateCommand($"""
            SELECT sequence,kind,sandbox_id,aggregate_id,revision,created_utc FROM event
            WHERE owner_id=$owner AND epoch=$epoch{scope} AND sequence>$after ORDER BY sequence LIMIT 1;
            """);
        StoreReader.Bind(next, [.. keys, ("$after", after)]);
        using var record = next.ExecuteReader();
        return new(evictedThrough, firstRetained, lastRetained,
            record.Read() ? new StoredSandboxEvent(record.GetInt64(0), record.GetString(1), record.GetString(2), record.GetString(3),
                record.GetInt64(4), DateTimeOffset.Parse(record.GetString(5), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)) : null);
    }
}
