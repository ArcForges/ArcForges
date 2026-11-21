// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Files;

/// <summary>Checks the persisted lifetime fence for an original Linux file-effect worker.</summary>
internal static class FileEffectWorker
{
    /// <summary>Releases the worker fence only when its original process identity is actually no longer present.</summary>
    internal static bool MarkEndedIfObserved(StoreTransaction transaction, ReadOnlySpan<byte> commandId)
    {
        RequireFull(transaction);
        StoreIds.Validate(commandId, nameof(commandId));
        if (!HasSchema(transaction)) return true; // Earlier schemas could not launch this worker.
        var id = commandId.ToArray();
        string boot;
        string pidNamespace;
        int pid;
        long start;
        using (var query = transaction.CreateCommand("""
            SELECT boot_id, pid_namespace, process_id, start_ticks, ended FROM file_effect_worker WHERE command_id = $id;
            """))
        {
            query.Parameters.AddWithValue("$id", id);
            using var row = query.ExecuteReader();
            if (!row.Read()) return true;
            if (row.GetInt32(4) == 1) return true;
            boot = row.GetString(0);
            pidNamespace = row.GetString(1);
            pid = row.GetInt32(2);
            start = row.GetInt64(3);
        }
        if (!OperatingSystem.IsLinux() || !Guid.TryParseExact(boot, "D", out var bootId) ||
            new LinuxOwnedProcessIdentity(bootId, pidNamespace, pid, start).Observe() != LinuxProcessObservation.Ended)
            return false;
        return transaction.Execute("UPDATE file_effect_worker SET ended = 1 WHERE command_id = $id AND ended = 0;", ("$id", id)) == 1;
    }

    private static bool HasSchema(StoreReader reader) =>
        reader.Scalar("SELECT schema_version FROM store_meta WHERE singleton = 1;") is long version && version >= 10;

    private static void RequireFull(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.Durability != CommitDurability.Full)
            throw new InvalidOperationException("The effect-worker fence requires FULL durability.");
    }
}
