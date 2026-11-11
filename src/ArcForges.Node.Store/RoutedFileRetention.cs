// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;

namespace ArcForges.Node.Store;

/// <summary>Per-open evidence based on the host monotonic counter, independent of the node wall clock.</summary>
internal sealed class RoutedFileRetentionProcess
{
    internal RoutedFileRetentionProcess(TimeProvider clock)
    {
        StartedAt = Stopwatch.GetTimestamp();
        StartedWall = StoreTime.NowMicroseconds(clock);
    }

    internal byte[] Epoch { get; } = RandomNumberGenerator.GetBytes(16);

    internal long StartedAt { get; }

    internal long StartedWall { get; }
}

/// <summary>
/// Identifies AF-CTR-06 receipts protected from premature wall-clock pruning. A protected row is live even when the
/// wall-clock expiry has passed. Older compatible binaries are stopped by the schema triggers as well.
/// </summary>
public static class RoutedFileRetention
{
    /// <summary>True while the durable elapsed-retention hold for this command exists.</summary>
    public static bool IsHeld(StoreReader reader, ReadOnlySpan<byte> commandId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return reader.FileRetention is not null &&
            reader.Scalar("SELECT 1 FROM routed_file_command_retention WHERE command_id = $id;", ("$id", commandId.ToArray())) is not null;
    }

    internal static void MarkCommand(StoreTransaction transaction, ReadOnlySpan<byte> commandId)
    {
        if (transaction.FileRetention is not { } process || !IsHeld(transaction, commandId))
        {
            return;
        }

        if (transaction.Execute("""
            UPDATE routed_file_command_retention SET process_epoch = $epoch, monotonic_start = $start
            WHERE command_id = $id AND process_epoch IS NULL AND monotonic_start IS NULL AND delete_permitted = 0;
            """, ("$epoch", process.Epoch), ("$start", Stopwatch.GetTimestamp()), ("$id", commandId.ToArray())) != 1)
        {
            throw new InvalidOperationException("The file command retention hold was not recorded.");
        }
    }

    /// <summary>Associates a new content-free file/workspace audit with this process's actual monotonic start.</summary>
    public static void MarkAudit(StoreTransaction transaction, long auditSequence)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.FileRetention is not { } process)
        {
            return;
        }

        if (transaction.Execute("""
            UPDATE routed_file_audit_retention SET process_epoch = $epoch, monotonic_start = $start
            WHERE audit_seq = $id AND process_epoch IS NULL AND monotonic_start IS NULL AND delete_permitted = 0;
            """, ("$epoch", process.Epoch), ("$start", Stopwatch.GetTimestamp()), ("$id", auditSequence)) != 1)
        {
            throw new InvalidOperationException("The file audit retention hold was not recorded.");
        }
    }

    /// <summary>
    /// Releases only elapsed workspace receipts, verified-call logs and file audit whose persisted validation floor and
    /// real elapsed time both establish expiry. Other file commands remain held until their journal recovery is available.
    /// </summary>
    public static int Prune(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.FileRetention is not { } process)
        {
            return 0;
        }

        var sample = RoutedFileValidationTime.Advance(transaction);
        if (!sample.Healthy)
        {
            return 0;
        }

        var currentTick = Stopwatch.GetTimestamp();
        var removed = 0;
        bool Elapsed(byte[]? epoch, long? start, TimeSpan minimum)
        {
            var since = epoch is not null && epoch.AsSpan().SequenceEqual(process.Epoch) && start.HasValue
                ? start.Value : process.StartedAt;
            return since >= process.StartedAt && currentTick >= since && Stopwatch.GetElapsedTime(since, currentTick) >= minimum;
        }

        var commands = new List<(byte[] Id, byte[]? Epoch, long? Start)>();
        using (var command = transaction.CreateCommand("""
            SELECT d.command_id, h.process_epoch, h.monotonic_start FROM command_dedup d
            JOIN routed_file_command_retention h ON h.command_id = d.command_id
            WHERE d.expires_at <= $now AND d.outcome IS NOT NULL AND h.delete_permitted = 0 AND d.method IN
              ('arcforges.node.v1.WorkspaceService/RegisterWorkspace', 'arcforges.node.v1.WorkspaceService/UnregisterWorkspace')
            ORDER BY d.expires_at LIMIT 256;
            """))
        {
            command.Parameters.AddWithValue("$now", sample.BoundaryMicroseconds);
            using var row = command.ExecuteReader();
            while (row.Read()) commands.Add(((byte[])row.GetValue(0), row.IsDBNull(1) ? null : (byte[])row.GetValue(1), row.IsDBNull(2) ? null : row.GetInt64(2)));
        }

        foreach (var (id, epoch, start) in commands)
        {
            if (!Elapsed(epoch, start, CommandDeduplication.Window)) continue;
            transaction.Execute("UPDATE routed_file_command_retention SET delete_permitted = 1 WHERE command_id = $id;", ("$id", id));
            if (transaction.Execute("DELETE FROM command_dedup WHERE command_id = $id;", ("$id", id)) != 1)
                throw new InvalidOperationException("The elapsed workspace receipt could not be removed safely.");
            removed++;
        }

        const long Day = 24L * 60 * 60 * 1_000_000;
        var calls = new List<(long Id, byte[]? Epoch, long? Start, bool Read)>();
        using (var command = transaction.CreateCommand("""
            SELECT l.log_id, h.process_epoch, h.monotonic_start,
              (l.decision = 1 AND l.method IN (9, 12, 13, 16, 19, 20)) AS is_read
            FROM routed_file_call_log l JOIN routed_file_call_retention h ON h.log_id = l.log_id
            WHERE h.delete_permitted = 0 AND
              ((l.decision = 1 AND l.method IN (9, 12, 13, 16, 19, 20) AND l.received_at < $read_cutoff)
               OR l.received_at < $year_cutoff)
            ORDER BY l.received_at LIMIT 256;
            """))
        {
            command.Parameters.AddWithValue("$read_cutoff", checked(sample.BoundaryMicroseconds - 7 * Day));
            command.Parameters.AddWithValue("$year_cutoff", checked(sample.BoundaryMicroseconds - 365 * Day));
            using var row = command.ExecuteReader();
            while (row.Read()) calls.Add((row.GetInt64(0), row.IsDBNull(1) ? null : (byte[])row.GetValue(1),
                row.IsDBNull(2) ? null : row.GetInt64(2), row.GetInt32(3) != 0));
        }

        foreach (var (id, epoch, start, read) in calls)
        {
            if (!Elapsed(epoch, start, TimeSpan.FromDays(read ? 7 : 365))) continue;
            transaction.Execute("UPDATE routed_file_call_retention SET delete_permitted = 1 WHERE log_id = $id;", ("$id", id));
            if (transaction.Execute("DELETE FROM routed_file_call_log WHERE log_id = $id;", ("$id", id)) != 1)
                throw new InvalidOperationException("The elapsed file call log could not be removed safely.");
            removed++;
        }

        var audits = new List<(long Id, byte[]? Epoch, long? Start)>();
        using (var command = transaction.CreateCommand("""
            SELECT a.seq, h.process_epoch, h.monotonic_start FROM audit_log a
            JOIN routed_file_audit_retention h ON h.audit_seq = a.seq
            WHERE a.at < $cutoff AND h.delete_permitted = 0 AND NOT EXISTS
              (SELECT 1 FROM routed_file_command_retention c WHERE c.command_id = a.remote_command_id)
            ORDER BY a.at LIMIT 256;
            """))
        {
            command.Parameters.AddWithValue("$cutoff", checked(sample.BoundaryMicroseconds - 365 * Day));
            using var row = command.ExecuteReader();
            while (row.Read()) audits.Add((row.GetInt64(0), row.IsDBNull(1) ? null : (byte[])row.GetValue(1), row.IsDBNull(2) ? null : row.GetInt64(2)));
        }

        foreach (var (id, epoch, start) in audits)
        {
            if (!Elapsed(epoch, start, TimeSpan.FromDays(365))) continue;
            transaction.Execute("UPDATE routed_file_audit_retention SET delete_permitted = 1 WHERE audit_seq = $id;", ("$id", id));
            if (transaction.Execute("DELETE FROM audit_log WHERE seq = $id;", ("$id", id)) != 1)
                throw new InvalidOperationException("The elapsed file audit could not be removed safely.");
            removed++;
        }

        return removed;
    }

    /// <summary>Associates a newly verified file/workspace call with this actual node process's monotonic start.</summary>
    public static void MarkCall(StoreTransaction transaction, long logId)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.FileRetention is not { } process)
        {
            return;
        }

        if (transaction.Execute("""
            UPDATE routed_file_call_retention SET process_epoch = $epoch, monotonic_start = $start
            WHERE log_id = $id AND process_epoch IS NULL AND monotonic_start IS NULL AND delete_permitted = 0;
            """, ("$epoch", process.Epoch), ("$start", Stopwatch.GetTimestamp()), ("$id", logId)) != 1)
        {
            throw new InvalidOperationException("The verified file call retention hold was not recorded.");
        }
    }
}
