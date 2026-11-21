// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Files;

/// <summary>Preserves workspace holds and observes worker exit for durable pre-target stage records.</summary>
internal static class FileStageProduction
{
    internal static bool HasSchema(StoreReader reader) =>
        reader.Scalar("SELECT schema_version FROM store_meta WHERE singleton = 1;") is long version && version >= 15;

    internal static bool HasWorkspaceHold(StoreReader reader, ReadOnlySpan<byte> workspaceId) =>
        HasSchema(reader) && reader.Scalar("""
            SELECT 1 FROM file_stage_production WHERE workspace_id = $id AND active = 1 LIMIT 1;
            """, ("$id", workspaceId.ToArray())) is not null;

    /// <summary>Only actual native exit permits a no-target-effect settlement. An unknown observation keeps all holds.</summary>
    internal static bool TryFinishFailedNamed(StoreTransaction transaction, ReadOnlySpan<byte> commandId)
    {
        RequireFull(transaction);
        if (!HasSchema(transaction) || transaction.Scalar("""
            SELECT 1 FROM file_stage_production WHERE command_id = $id AND storage_kind = 2;
            """, ("$id", commandId.ToArray())) is null) return true;
        if (!ObserveEndedWorkers(transaction, commandId)) return false;
        transaction.Execute("UPDATE file_stage_production SET active = 0 WHERE command_id = $id AND active = 1 AND storage_kind = 2;",
            ("$id", commandId.ToArray()));
        return true;
    }

    /// <summary>A new reader floor is not an old-worker retirement proof. Unknown process observations retain the fence.</summary>
    internal static bool ObserveEndedWorkers(StoreTransaction transaction, ReadOnlySpan<byte> commandId)
    {
        RequireFull(transaction);
        if (!HasSchema(transaction)) return true;
        var id = commandId.ToArray();
        var workers = new List<(int Slot, int Platform, string Boot, string? Namespace, int Pid, long Start)>();
        using (var query = transaction.CreateCommand("""
            SELECT slot, identity_platform, boot_identity, pid_namespace, process_id, start_ticks
            FROM file_stage_worker WHERE command_id = $id AND ended = 0;
            """))
        {
            query.Parameters.AddWithValue("$id", id);
            using var row = query.ExecuteReader();
            while (row.Read()) workers.Add((row.GetInt32(0), row.GetInt32(1), row.GetString(2),
                row.IsDBNull(3) ? null : row.GetString(3), row.GetInt32(4), row.GetInt64(5)));
        }
        var allEnded = true;
        foreach (var worker in workers)
        {
            var ended = OperatingSystem.IsLinux() && worker.Platform == 2 && worker.Namespace is not null &&
                Guid.TryParseExact(worker.Boot, "D", out var boot) &&
                new LinuxOwnedProcessIdentity(boot, worker.Namespace, worker.Pid, worker.Start).Observe() == LinuxProcessObservation.Ended;
            if (OperatingSystem.IsWindows() && worker.Platform == 1 && worker.Namespace is null)
                ended = new WindowsOwnedStageIdentity(worker.Boot, worker.Pid, worker.Start).Observe() == WindowsStageProcessObservation.Ended;
            if (!ended) { allEnded = false; continue; }
            transaction.Execute("UPDATE file_stage_worker SET ended = 1 WHERE command_id = $id AND slot = $slot AND ended = 0;",
                ("$id", id), ("$slot", worker.Slot));
        }
        return allEnded;
    }

    private static void RequireFull(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.Durability != CommitDurability.Full)
            throw new InvalidOperationException("The stage production fence requires FULL durability.");
    }
}
