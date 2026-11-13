// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Execution;

/// <summary>
/// Records evidence from a native exclusive create of an attempt directory. A record does not authorize removal;
/// planning and any eventual effect must independently recheck caller, liveness, native identity and protection.
/// </summary>
internal static class AttemptTempProvenance
{
    internal static void Record(StoreTransaction transaction, WorkspacePath root, SafeFileHandle directory,
        string name, byte[] attemptId, byte[] taskId)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(directory);
        if (transaction.Durability != CommitDurability.Full || !OperatingSystem.IsWindows() ||
            attemptId.Length != 16 || taskId.Length != 16 || !string.Equals(name, IdText.Format(attemptId), StringComparison.Ordinal))
            throw new InvalidOperationException("Exact attempt directory provenance requires a FULL native-create transaction.");

        var rootId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(root.RootHandle));
        var directoryId = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(directory));
        using (var namedRoot = WorkspacePath.OpenRoot(root.RootPath, root.RootIdentity))
        {
            var named = namedRoot.InspectEntry(name);
            var held = WorkspacePath.Identity(directory);
            if (named.Kind != WorkspaceEntryType.Directory || !held.SameObject(named.Identity) ||
                !root.RootIdentity.SameObject(WorkspacePath.Identity(root.RootHandle)) || held.Volume != root.RootIdentity.Volume)
                throw new InvalidOperationException("The newly created attempt directory changed before it could be recorded.");
        }

        byte[] owner;
        using (var query = transaction.CreateCommand("""
            SELECT t.owner, a.state, t.state, t.current_attempt_id
            FROM attempt a JOIN task t ON t.task_id = a.task_id
            WHERE a.attempt_id = $attempt AND a.task_id = $task;
            """))
        {
            query.Parameters.AddWithValue("$attempt", attemptId);
            query.Parameters.AddWithValue("$task", taskId);
            using var row = query.ExecuteReader();
            if (!row.Read() || row.GetInt32(1) != 3 || row.GetInt32(2) != 4 || row.IsDBNull(3) ||
                !((byte[])row.GetValue(3)).AsSpan().SequenceEqual(attemptId))
                throw new InvalidOperationException("The attempt is no longer the admitted task's current starting attempt.");
            owner = (byte[])row.GetValue(0);
            if (owner.Length is < 1 or > 4096 || row.Read())
                throw new InvalidOperationException("The task owner is unavailable.");
        }
        try { _ = ActorRef.Parser.ParseFrom(owner); }
        catch (InvalidProtocolBufferException exception) { throw new InvalidOperationException("The task owner is invalid.", exception); }

        transaction.Execute("INSERT INTO root_location (root_class, path) VALUES ('tmp', $path) ON CONFLICT(root_class) DO NOTHING;",
            ("$path", root.RootPath));
        if (transaction.Scalar("SELECT path FROM root_location WHERE root_class = 'tmp';") is not string saved ||
            !string.Equals(saved, root.RootPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The temporary root does not match its persisted location.");

        var record = StoreIds.NewUuid7(transaction.Clock);
        var now = transaction.NowMicroseconds;
        transaction.Execute("""
            INSERT INTO managed_directory
              (directory_id, owner_kind, owner_id, root_class, relative_path, created_at, last_used_at, pinned, state, rev)
            VALUES ($directory, 1, $attempt, 'tmp', $name, $now, $now, 0, 1, 0);
            """, ("$directory", record), ("$attempt", attemptId), ("$name", name), ("$now", now));
        transaction.Execute("""
            INSERT INTO file_attempt_temp_identity
              (attempt_id, directory_id, task_id, owner, root_platform, root_identity, directory_identity, recorded_at)
            VALUES ($attempt, $directory, $task, $owner, $platform, $root, $identity, $now);
            """, ("$attempt", attemptId), ("$directory", record), ("$task", taskId), ("$owner", owner),
            ("$platform", rootId.Platform), ("$root", rootId.Bytes), ("$identity", directoryId.Bytes), ("$now", now));
    }

    /// <summary>Records an ordinary terminal transition, not a proof that external uses or leases have ended.</summary>
    internal static void MarkIdle(StoreTransaction transaction, byte[] attemptId)
    {
        transaction.Execute("""
            UPDATE managed_directory SET state = 2, last_used_at = $now, rev = rev + 1
            WHERE directory_id = (SELECT directory_id FROM file_attempt_temp_identity WHERE attempt_id = $attempt)
              AND state = 1;
            """, ("$attempt", attemptId), ("$now", transaction.NowMicroseconds));
    }
}
