// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Files;

/// <summary>Private producer metadata, not a target PREPARED record or a grant of filesystem authority.</summary>
internal sealed record FileStageProductionReservation(byte[] CommandId, byte[] ProducerNonce, byte[] RequestSha256,
    byte[] CallerDigest, byte[] WorkspaceId, byte[] CorrelationId, int Kind, int Platform, byte[] RootIdentity,
    byte[] ParentIdentity, long DeadlineTicks, long ExpiryMicroseconds);

/// <summary>
/// FULL reservations and actual-child fences for pre-target staging. Bytes and live handle capabilities stay outside
/// SQLite. The coordinator must independently bind the verified caller, policy, native references and original deadline.
/// </summary>
internal static class FileStageProduction
{
    internal static bool HasSchema(StoreReader reader) =>
        reader.Scalar("SELECT schema_version FROM store_meta WHERE singleton = 1;") is long version && version >= 15;

    internal static bool HasWorkspaceHold(StoreReader reader, ReadOnlySpan<byte> workspaceId) =>
        HasSchema(reader) && reader.Scalar("""
            SELECT 1 FROM file_stage_production WHERE workspace_id = $id AND active = 1 LIMIT 1;
            """, ("$id", workspaceId.ToArray())) is not null;

    /// <summary>Rebinds only the already FULL-reserved named request, without manufacturing a file operation.</summary>
    internal static FileStageProductionReservation ReserveNamed(StoreTransaction transaction, ReadOnlySpan<byte> commandId,
        CenterCaller caller, ReadOnlySpan<byte> transmitted, WorkspacePath root, WorkspacePath stageDirectory,
        WorkspaceObjectIdentity? target, long deadlineTicks, long expiryMicroseconds)
    {
        RequireFull(transaction);
        StoreIds.Validate(commandId, nameof(commandId));
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(stageDirectory);
        if (!HasSchema(transaction) || CenterRouting.Shape(caller) is not null ||
            transmitted.Length is < 1 or > 245_760 || deadlineTicks <= 0 || expiryMicroseconds <= 0)
            throw new InvalidOperationException("The stage producer reservation is unavailable.");
        var id = commandId.ToArray();
        var digest = SHA256.HashData(transmitted);
        var stableCaller = FileMutationJournal.Sanitize(caller).ToByteArray();
        var rootId = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var parentId = RegisteredWorkspaces.RootIdentity.Encode(stageDirectory.RootIdentity);
        var targetId = target is { } value ? RegisteredWorkspaces.RootIdentity.Encode(value, directory: false) : null;
        using var query = transaction.CreateCommand("""
            SELECT r.workspace_id, r.kind, r.correlation_id, r.relative_path, r.expected_absent, r.expected_sha256,
                   r.expected_occurrences, r.reserved_bytes, r.request_sha256, r.caller, d.method, d.payload_digest,
                   d.outcome, w.platform, w.native_identity,
                   (SELECT count(*) FROM file_private_stage_object o WHERE o.command_id = r.command_id),
                   (SELECT count(*) FROM file_private_stage_object o WHERE o.command_id = r.command_id AND o.phase = 1),
                   d.origin
            FROM file_private_stage_reservation r JOIN command_dedup d ON d.command_id = r.command_id
            JOIN workspace_root_identity w ON w.workspace_id = r.workspace_id AND w.released_at IS NULL
            WHERE r.command_id = $id AND r.active = 1;
            """);
        query.Parameters.AddWithValue("$id", id);
        using var row = query.ExecuteReader();
        if (!row.Read()) throw new InvalidOperationException("The named stage reservation is unavailable.");
        var kind = row.GetInt32(1);
        var method = kind == 1 ? "arcforges.node.v1.FileService/WriteFile" :
            kind == 2 ? "arcforges.node.v1.FileService/EditFile" :
            throw new InvalidDataException("Unknown staged operation.");
        var absent = row.GetInt32(4);
        if (!CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(8), digest) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(11), digest) ||
            !CenterRouting.SameFileCaller(CenterCaller.Parser.ParseFrom((byte[])row.GetValue(9)), caller) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(9), stableCaller) ||
            row.GetString(10) != method || !row.IsDBNull(12) || row.GetInt32(13) != rootId.Platform ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(14), rootId.Bytes) ||
            parentId.Platform != rootId.Platform || targetId is not null && targetId.Platform != rootId.Platform ||
            absent != (targetId is null ? 1 : 0) || row.GetInt32(15) != (absent == 1 ? 1 : 2) ||
            row.GetInt32(16) != row.GetInt32(15) || row.GetInt32(17) != (int)Origin.Remote)
            throw new InvalidOperationException("The producer does not bind the original reserved caller and request.");
        var workspace = (byte[])row.GetValue(0);
        var correlation = (byte[])row.GetValue(2);
        var path = row.GetString(3);
        var expected = row.IsDBNull(5) ? null : (byte[])row.GetValue(5);
        var occurrences = row.IsDBNull(6) ? (long?)null : row.GetInt64(6);
        var bytes = row.GetInt64(7);
        row.Close();
        var nonce = RandomNumberGenerator.GetBytes(16);
        transaction.Execute("""
            INSERT INTO file_stage_production
              (command_id, producer_nonce, storage_kind, workspace_id, operation_kind, correlation_id, relative_path,
               expected_absent, expected_sha256, expected_occurrences, target_identity, request_sha256, caller,
               identity_platform, root_identity, parent_identity, object_count, reserved_bytes, deadline_clock,
               deadline_ticks, expiry_microseconds, created_at)
            VALUES ($id, $nonce, 2, $workspace, $kind, $correlation, $path, $absent, $expected, $occurrences, $target,
                    $digest, $caller, $platform, $root, $parent, $count, $bytes, $clock, $deadline, $expiry, $now);
            """, ("$id", id), ("$nonce", nonce), ("$workspace", workspace), ("$kind", kind),
            ("$correlation", correlation), ("$path", path), ("$absent", absent), ("$expected", expected),
            ("$occurrences", occurrences), ("$target", targetId?.Bytes), ("$digest", digest), ("$caller", stableCaller),
            ("$platform", rootId.Platform), ("$root", rootId.Bytes), ("$parent", parentId.Bytes),
            ("$count", absent == 1 ? 1 : 2), ("$bytes", bytes), ("$clock", OperatingSystem.IsLinux() ? 1 : 2),
            ("$deadline", deadlineTicks), ("$expiry", expiryMicroseconds), ("$now", transaction.NowMicroseconds));
        var boundCount = transaction.Execute("""
            INSERT INTO file_stage_produced_object
              (command_id, slot, stage_path, expected_size, expected_sha256, identity_platform, parent_identity)
            SELECT o.command_id, o.slot, o.stage_path, o.expected_size, o.expected_sha256, $platform, $parent
            FROM file_private_stage_object o WHERE o.command_id = $id AND o.phase = 1;
            """, ("$id", id), ("$platform", rootId.Platform), ("$parent", parentId.Bytes));
        if (boundCount != (absent == 1 ? 1 : 2))
            throw new InvalidOperationException("The producer did not reserve the complete original object set.");
        return new FileStageProductionReservation(id, nonce, digest, SHA256.HashData(stableCaller), workspace, correlation,
            kind, rootId.Platform, rootId.Bytes, parentId.Bytes, deadlineTicks, expiryMicroseconds);
    }

    /// <summary>Seals the actual live child in FULL before it receives any creation descriptor or body permission.</summary>
    internal static LinuxPrivateStageBinding RecordLinuxChild(StoreTransaction transaction,
        FileStageProductionReservation reservation, int slot, LinuxOwnedPidfd worker)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(worker);
        if (!OperatingSystem.IsLinux() || reservation.Platform != 2 || slot is not (1 or 2))
            throw new InvalidOperationException("The Linux stage producer is unavailable.");
        using var query = transaction.CreateCommand("""
            SELECT o.stage_path, o.expected_size, o.expected_sha256, p.producer_nonce, p.request_sha256, p.caller,
                   p.workspace_id, p.correlation_id, p.root_identity, p.parent_identity, p.deadline_ticks,
                   p.expiry_microseconds
            FROM file_stage_production p JOIN file_stage_produced_object o ON o.command_id = p.command_id
            WHERE p.command_id = $id AND o.slot = $slot AND p.storage_kind = 2 AND p.identity_platform = 2
              AND p.active = 1 AND p.released = 0 AND p.deadline_clock = 1 AND o.phase = 0;
            """);
        query.Parameters.AddWithValue("$id", reservation.CommandId);
        query.Parameters.AddWithValue("$slot", slot);
        using var row = query.ExecuteReader();
        if (!row.Read() || row.IsDBNull(0) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(3), reservation.ProducerNonce) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(4), reservation.RequestSha256) ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData((byte[])row.GetValue(5)), reservation.CallerDigest) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(6), reservation.WorkspaceId) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(7), reservation.CorrelationId) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(8), reservation.RootIdentity) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(9), reservation.ParentIdentity) ||
            row.GetInt64(10) != reservation.DeadlineTicks || row.GetInt64(11) != reservation.ExpiryMicroseconds)
            throw new InvalidOperationException("The private producer does not bind this original operation.");
        var name = Path.GetFileName(row.GetString(0));
        var size = row.GetInt64(1);
        var hash = (byte[])row.GetValue(2);
        row.Close();
        var nonce = RandomNumberGenerator.GetBytes(16);
        var identity = worker.SealedIdentity();
        var binding = new LinuxPrivateStageBinding(reservation.CommandId, reservation.ProducerNonce, nonce,
            reservation.RequestSha256, reservation.CallerDigest, reservation.WorkspaceId, reservation.CorrelationId,
            slot, reservation.RootIdentity, reservation.ParentIdentity, name, size, hash,
            reservation.DeadlineTicks, reservation.ExpiryMicroseconds, identity);
        binding.Validate();
        if (LinuxFatalDeadline.MonotonicNanoseconds() >= binding.Deadline)
            throw new OperationCanceledException();
        transaction.Execute("""
            INSERT INTO file_stage_worker
              (command_id, slot, worker_nonce, producer_nonce, identity_platform, boot_identity, pid_namespace,
               process_id, start_ticks, ended)
            VALUES ($id, $slot, $nonce, $producer, 2, $boot, $namespace, $pid, $start, 0);
            """, ("$id", reservation.CommandId), ("$slot", slot), ("$nonce", nonce),
            ("$producer", reservation.ProducerNonce), ("$boot", identity.BootId.ToString("D")),
            ("$namespace", identity.PidNamespace), ("$pid", identity.ProcessId), ("$start", identity.StartTicks));
        return binding;
    }

    /// <summary>Seals the actual live child in FULL before it receives any creation descriptor or body permission.</summary>
    internal static WindowsPrivateStageBinding RecordWindowsChild(StoreTransaction transaction,
        FileStageProductionReservation reservation, int slot, WindowsOwnedStageProcess worker)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(worker);
        if (!OperatingSystem.IsWindows() || reservation.Platform != 1 || slot is not (1 or 2))
            throw new InvalidOperationException("The Windows stage producer is unavailable.");
        using var query = transaction.CreateCommand("""
            SELECT o.stage_path, o.expected_size, o.expected_sha256, p.producer_nonce, p.request_sha256, p.caller,
                   p.workspace_id, p.correlation_id, p.root_identity, p.parent_identity, p.deadline_ticks,
                   p.expiry_microseconds
            FROM file_stage_production p JOIN file_stage_produced_object o ON o.command_id = p.command_id
            WHERE p.command_id = $id AND o.slot = $slot AND p.storage_kind = 2 AND p.identity_platform = 1
              AND p.active = 1 AND p.released = 0 AND p.deadline_clock = 2 AND o.phase = 0;
            """);
        query.Parameters.AddWithValue("$id", reservation.CommandId);
        query.Parameters.AddWithValue("$slot", slot);
        using var row = query.ExecuteReader();
        if (!row.Read() || row.IsDBNull(0) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(3), reservation.ProducerNonce) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(4), reservation.RequestSha256) ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData((byte[])row.GetValue(5)), reservation.CallerDigest) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(6), reservation.WorkspaceId) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(7), reservation.CorrelationId) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(8), reservation.RootIdentity) ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(9), reservation.ParentIdentity) ||
            row.GetInt64(10) != reservation.DeadlineTicks || row.GetInt64(11) != reservation.ExpiryMicroseconds)
            throw new InvalidOperationException("The private producer does not bind this original operation.");
        var name = Path.GetFileName(row.GetString(0));
        var size = row.GetInt64(1);
        var hash = (byte[])row.GetValue(2);
        row.Close();
        var nonce = RandomNumberGenerator.GetBytes(16);
        var identity = worker.SealedIdentity();
        var binding = new WindowsPrivateStageBinding(reservation.CommandId, reservation.ProducerNonce, nonce,
            reservation.RequestSha256, reservation.CallerDigest, reservation.WorkspaceId, reservation.CorrelationId,
            slot, reservation.RootIdentity, reservation.ParentIdentity, name, size, hash,
            reservation.DeadlineTicks, reservation.ExpiryMicroseconds, identity);
        binding.Validate();
        if (System.Diagnostics.Stopwatch.GetTimestamp() >= binding.Deadline)
            throw new OperationCanceledException();
        transaction.Execute("""
            INSERT INTO file_stage_worker
              (command_id, slot, worker_nonce, producer_nonce, identity_platform, boot_identity, pid_namespace,
               process_id, start_ticks, ended)
            VALUES ($id, $slot, $nonce, $producer, 1, $boot, NULL, $pid, $start, 0);
            """, ("$id", reservation.CommandId), ("$slot", slot), ("$nonce", nonce),
            ("$producer", reservation.ProducerNonce), ("$boot", identity.BootIdentity),
            ("$pid", identity.ProcessId), ("$start", identity.CreationTime));
        return binding;
    }

    /// <summary>Records only the native identity returned while the already bound producer is live; no body is allowed yet.</summary>
    internal static void BindEmptyObject(StoreTransaction transaction, FileStageProductionReservation reservation, int slot,
        RegisteredWorkspaces.RootIdentity identity)
    {
        RequireFull(transaction);
        if (slot is not (1 or 2) || identity.Platform != reservation.Platform)
            throw new ArgumentException("The stage identity does not match its reservation.");
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(identity.Platform, identity.Bytes);
        if (transaction.Execute("""
            UPDATE file_stage_produced_object SET native_identity = $identity, phase = 1
            WHERE command_id = $id AND slot = $slot AND phase = 0 AND native_identity IS NULL
              AND identity_platform = $platform AND EXISTS
                (SELECT 1 FROM file_stage_production p WHERE p.command_id = $id AND p.producer_nonce = $nonce
                 AND p.request_sha256 = $digest AND p.active = 1 AND p.released = 0)
              AND EXISTS (SELECT 1 FROM file_stage_worker w WHERE w.command_id = $id AND w.slot = $slot
                          AND w.producer_nonce = $nonce AND w.identity_platform = $platform AND w.ended = 0);
            """, ("$id", reservation.CommandId), ("$slot", slot), ("$identity", identity.Bytes),
            ("$platform", identity.Platform), ("$nonce", reservation.ProducerNonce), ("$digest", reservation.RequestSha256)) != 1)
            throw new InvalidOperationException("The producer object could not be identity bound.");
    }

    /// <summary>READY is metadata-only and follows actual producer exit plus the coordinator's held-FD rehash.</summary>
    internal static void CompleteNamedObject(StoreTransaction transaction, FileStageProductionReservation reservation,
        int slot, RegisteredWorkspaces.RootIdentity identity, long size, ReadOnlySpan<byte> sha256)
    {
        RequireFull(transaction);
        if (identity.Platform != reservation.Platform || sha256.Length != 32 ||
            !ObserveEndedWorkers(transaction, reservation.CommandId))
            throw new InvalidOperationException("The stage worker has not actually ended.");
        if (transaction.Execute("""
            UPDATE file_stage_produced_object SET phase = 2
            WHERE command_id = $id AND slot = $slot AND phase = 1 AND identity_platform = $platform
              AND native_identity = $identity AND expected_size = $size AND expected_sha256 = $hash
              AND EXISTS (SELECT 1 FROM file_stage_production p WHERE p.command_id = $id
                          AND p.producer_nonce = $nonce AND p.request_sha256 = $request AND p.active = 1 AND p.released = 0);
            """, ("$id", reservation.CommandId), ("$slot", slot), ("$platform", identity.Platform),
            ("$identity", identity.Bytes), ("$size", size), ("$hash", sha256.ToArray()),
            ("$nonce", reservation.ProducerNonce), ("$request", reservation.RequestSha256)) != 1)
            throw new InvalidOperationException("The produced stage differs from its exact reserved object.");
        if (transaction.Execute("""
            UPDATE file_private_stage_object SET phase = 3 WHERE command_id = $id AND slot = $slot AND phase = 2
              AND identity_platform = $platform AND native_identity = $identity AND expected_size = $size AND expected_sha256 = $hash;
            """, ("$id", reservation.CommandId), ("$slot", slot), ("$platform", identity.Platform),
            ("$identity", identity.Bytes), ("$size", size), ("$hash", sha256.ToArray())) != 1)
            throw new InvalidOperationException("The private named stage differs from its producer binding.");
    }

    /// <summary>The named reservation keeps its privacy and byte charge after the producer's active slot ends.</summary>
    internal static void FinishNamed(StoreTransaction transaction, FileStageProductionReservation reservation)
    {
        RequireFull(transaction);
        if (!ObserveEndedWorkers(transaction, reservation.CommandId) || transaction.Execute("""
            UPDATE file_stage_production SET active = 0
            WHERE command_id = $id AND producer_nonce = $nonce AND request_sha256 = $digest
              AND storage_kind = 2 AND active = 1 AND released = 0
              AND object_count = (SELECT count(*) FROM file_stage_produced_object o
                                  WHERE o.command_id = $id AND o.phase = 2);
            """, ("$id", reservation.CommandId), ("$nonce", reservation.ProducerNonce), ("$digest", reservation.RequestSha256)) != 1)
            throw new InvalidOperationException("The complete named producer has not actually finished.");
    }

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
