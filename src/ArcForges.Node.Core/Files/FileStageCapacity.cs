// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Files;

/// <summary>Durable capacity facts for initial producers, retained named stages and held file-effect journals.</summary>
internal static class FileStageCapacity
{
    internal static (int Active, long Bytes) Durable(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        if (!PrivateStageRegistry.HasSchema(reader)) return (0, 0);
        using var query = reader.CreateCommand(FileStageProduction.HasSchema(reader)
            ? "SELECT active_mutations, reserved_bytes FROM file_stage_capacity_totals_v15;"
            : "SELECT active_mutations, reserved_bytes FROM file_stage_capacity_totals;");
        using var row = query.ExecuteReader();
        if (!row.Read()) throw new InvalidDataException("The durable file stage capacity is unavailable.");
        var active = row.GetInt64(0);
        var bytes = row.GetInt64(1);
        if (active is < 0 or > FileStageBudget.MaximumMutations || bytes is < 0 or > FileStageBudget.MaximumBytes)
            throw new InvalidDataException("The durable file stage capacity is inconsistent.");
        return (checked((int)active), bytes);
    }

    internal static bool HasActiveCommand(StoreReader reader, ReadOnlySpan<byte> commandId)
    {
        var id = commandId.ToArray();
        if (reader.Scalar("""
            SELECT 1 WHERE EXISTS (SELECT 1 FROM file_private_stage_reservation WHERE command_id = $id AND active = 1)
                        OR EXISTS (SELECT 1 FROM file_operation_journal WHERE command_id = $id AND held = 1);
            """, ("$id", id)) is not null) return true;
        return FileStageProduction.HasSchema(reader) && reader.Scalar("""
            SELECT 1 FROM file_stage_production WHERE command_id = $id AND active = 1;
            """, ("$id", id)) is not null;
    }

    internal static bool HasExactStage(StoreReader reader, ReadOnlySpan<byte> commandId, int slot,
        RegisteredWorkspaces.RootIdentity identity, long bytes)
    {
        var id = commandId.ToArray();
        if (reader.Scalar("""
            SELECT 1 WHERE EXISTS
              (SELECT 1 FROM file_private_stage_object WHERE command_id = $id AND slot = $slot
               AND identity_platform = $platform AND native_identity = $identity AND expected_size = $size)
            OR EXISTS
              (SELECT 1 FROM file_operation_journal WHERE command_id = $id AND held = 1 AND identity_platform = $platform
               AND (($slot = 1 AND original_stage_identity = $identity AND original_size = $size) OR
                    ($slot = 2 AND intended_stage_identity = $identity AND intended_size = $size)));
            """, ("$id", id), ("$slot", slot), ("$platform", identity.Platform),
            ("$identity", identity.Bytes), ("$size", bytes)) is not null) return true;
        return FileStageProduction.HasSchema(reader) && reader.Scalar("""
            SELECT 1 FROM file_stage_produced_object o JOIN file_stage_production p ON p.command_id = o.command_id
            WHERE o.command_id = $id AND o.slot = $slot AND o.identity_platform = $platform
              AND o.native_identity = $identity AND o.expected_size = $size AND p.storage_kind = 1 AND p.released = 0;
            """, ("$id", id), ("$slot", slot), ("$platform", identity.Platform),
            ("$identity", identity.Bytes), ("$size", bytes)) is not null;
    }
}
