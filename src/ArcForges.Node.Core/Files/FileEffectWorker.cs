// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Files;

/// <summary>
/// Metadata-only lifetime fence for a Linux effect worker. It does not authorize a worker or perform an effect:
/// the caller must complete peer/capability binding and commit PREPARED before any effect can be permitted.
/// </summary>
internal static class FileEffectWorker
{
    /// <summary>
    /// Records a challenge-sealed live child against the exact PREPARED intent, in the same FULL transaction in which
    /// the coordinator rechecks current authority. This metadata fence alone does not grant a file effect.
    /// </summary>
    internal static void RecordPreparedChild(StoreTransaction transaction, FileJournalIntent intent,
        ReadOnlySpan<byte> transmitted, LinuxOwnedPidfd worker)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(worker);
        if (!OperatingSystem.IsLinux() || !HasSchema(transaction))
            throw new InvalidOperationException("The Linux worker lifetime fence is unavailable.");
        FileMutationJournal.ValidateIntent(intent, transmitted);
        if (FileMutationJournal.FindExisting(transaction, intent.Kind, intent.CommandId, intent.Caller, transmitted) !=
            FileJournalPreparation.Existing || transaction.Scalar("""
                SELECT 1 FROM file_operation_journal j JOIN command_dedup d ON d.command_id = j.command_id
                WHERE j.command_id = $id AND j.kind = $kind AND j.phase = 1 AND j.held = 1 AND j.acknowledged = 0
                  AND d.outcome IS NULL AND j.caller = $caller AND j.correlation_id = $correlation AND j.workspace_id = $workspace
                  AND j.relative_path = $path AND j.identity_platform = $platform AND j.root_identity = $root
                  AND j.parent_identity = $parent AND j.target_identity IS $target AND j.expected_absent = $absent
                  AND j.original_size IS $original_size AND j.original_sha256 IS $original_hash
                  AND j.original_stage_identity IS $original_stage AND j.intended_size = $intended_size
                  AND j.intended_sha256 = $intended_hash AND j.intended_stage_identity = $intended_stage;
                """, ("$id", intent.CommandId), ("$kind", (int)intent.Kind),
                ("$caller", FileMutationJournal.Sanitize(intent.Caller).ToByteArray()), ("$correlation", intent.CorrelationId),
                ("$workspace", intent.WorkspaceId), ("$path", intent.RelativePath), ("$platform", intent.IdentityPlatform),
                ("$root", intent.RootIdentity), ("$parent", intent.ParentIdentity), ("$target", intent.TargetIdentity),
                ("$absent", intent.TargetIdentity is null ? 1 : 0), ("$original_size", intent.OriginalSize),
                ("$original_hash", intent.OriginalSha256), ("$original_stage", intent.OriginalStageIdentity),
                ("$intended_size", intent.IntendedSize), ("$intended_hash", intent.IntendedSha256),
                ("$intended_stage", intent.IntendedStageIdentity)) is null)
            throw new InvalidOperationException("The worker does not match the prepared file intent.");
        var identity = worker.SealedIdentity();
        transaction.Execute("""
            INSERT INTO file_effect_worker (command_id, boot_id, pid_namespace, process_id, start_ticks, ended)
            VALUES ($id, $boot, $namespace, $pid, $start, 0);
            """, ("$id", intent.CommandId), ("$boot", identity.BootId.ToString("D")),
            ("$namespace", identity.PidNamespace), ("$pid", identity.ProcessId), ("$start", identity.StartTicks));
    }

    /// <summary>
    /// Produces the immutable worker payload only after registering the exact prepared intent. The caller must commit
    /// this FULL transaction and independently recheck live authority before sending any effect permission.
    /// </summary>
    internal static LinuxFileEffectBinding BindPreparedChild(StoreTransaction transaction, FileJournalIntent intent,
        ReadOnlySpan<byte> transmitted, LinuxOwnedPidfd worker, long deadline, long expiryMicroseconds)
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("The Linux worker is unavailable.");
        RecordPreparedChild(transaction, intent, transmitted, worker);
        return LinuxFileEffectBinding.FromPrepared(intent, transmitted, deadline, expiryMicroseconds);
    }

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
