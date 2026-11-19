// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Node.Store;

internal sealed record StoredDurableOperation(string Method, string? AggregateId, string State, int Effect,
    string? ResponseJson, bool Compacted, DateTimeOffset UpdatedAt);

/// <summary>Projects a retained receipt at its original identity without opening mutation authority.</summary>
internal static class DurableOperationReads
{
    internal static StoredDurableOperation? Find(StoreReader reader, string ownerId,
        ReadOnlySpan<byte> ownerEpoch, ReadOnlySpan<byte> commandId)
    {
        StoreIds.Validate(ownerEpoch, nameof(ownerEpoch));
        StoreIds.Validate(commandId, nameof(commandId));
        using var command = reader.CreateCommand("""
            SELECT method,aggregate_id,state,effect_certainty,response_json,response_compacted_utc,updated_utc
            FROM command_receipt
            WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$id;
            """);
        StoreReader.Bind(command, [("$owner", ownerId), ("$epoch", ownerEpoch.ToArray()), ("$id", StoreIds.ToHex(commandId))]);
        using var row = command.ExecuteReader();
        return row.Read()
            ? new(row.GetString(0), row.IsDBNull(1) ? null : row.GetString(1), row.GetString(2), row.GetInt32(3),
                row.IsDBNull(4) ? null : row.GetString(4), !row.IsDBNull(5),
                DateTimeOffset.Parse(row.GetString(6), CultureInfo.InvariantCulture))
            : null;
    }
}
