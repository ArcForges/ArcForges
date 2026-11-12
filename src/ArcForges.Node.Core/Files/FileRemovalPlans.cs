// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;
using Id = ArcForges.Contracts.Foundation.V1.Id;

namespace ArcForges.Node.Core.Files;

/// <summary>
/// Persists one checked metadata-only plan with its exact caller and request binding in the caller's FULL transaction.
/// The caller owns authorization, the receipt and audit. This class neither grants cleanup authority nor changes files.
/// </summary>
internal static class FileRemovalPlans
{
    internal const long LifetimeMicroseconds = 60L * 60 * 1_000_000;

    internal sealed record PreparedWorkspacePlan(FileRemovalPlan Plan, byte[] CommandId, byte[] RawSha256,
        byte[] CallerBytes, byte[] ActorBytes, FilePath Target, string RootPath, WorkspaceRemovalSnapshot Snapshot,
        long ObservedTime, long ExpiresAt);

    internal static PreparedWorkspacePlan PrepareWorkspace(StoreTransaction transaction, ReadOnlySpan<byte> commandId,
        ReadOnlySpan<byte> rawSha256, CenterCaller caller, ActorRef actor, FilePath target, string rootPath,
        WorkspaceRemovalSnapshot snapshot, long observedTime, IReadOnlySet<string>? verifiedOwnedPaths = null)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(snapshot);
        if (transaction.Durability != CommitDurability.Full || rawSha256.Length != 32 ||
            commandId.Length != 16 || target.WorkspaceId?.Value.Length != 16 || !target.HasPath ||
            snapshot.Entries.Count is < 1 or > WorkspaceRemovalPlan.MaximumDescendants + 1 ||
            snapshot.TotalBytes > WorkspaceRemovalPlan.MaximumTotalBytes)
            throw new InvalidOperationException("A checked removal plan requires a FULL transaction and bounded identity.");

        var planId = StoreIds.NewUuid7(transaction.Clock);
        var expires = checked(observedTime + LifetimeMicroseconds);
        var plan = new FileRemovalPlan
        {
            PlanId = new Id { Value = ByteString.CopyFrom(planId) },
            ExpiresAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(expires)),
            WorkspacePath = target.Clone(),
            TotalBytes = snapshot.TotalBytes,
            // Ownership observations do not prove strict cleanup protection or a usable quarantine.
            // This candidate therefore keeps the plan high-risk and requires approval.
            RequiresApproval = true,
            QuarantineAvailable = false,
            Risk = RiskClass.High,
        };
        foreach (var entry in snapshot.Entries)
        {
            plan.Items.Add(new FileRemovalItem
            {
                Path = entry.Path,
                Kind = (FileEntryKind)entry.Kind,
                SizeBytes = entry.Size,
                IdentitySha256 = ByteString.CopyFrom(entry.IdentitySha256),
                OwnerVerified = verifiedOwnedPaths?.Contains(entry.Path) == true,
            });
        }

        var callerBytes = caller.ToByteArray();
        var digest = Digest(plan, rawSha256, callerBytes, snapshot);
        plan.Digest = ByteString.CopyFrom(digest);
        return new PreparedWorkspacePlan(plan, commandId.ToArray(), rawSha256.ToArray(), callerBytes, actor.ToByteArray(),
            target.Clone(), rootPath, snapshot, observedTime, expires);
    }

    internal static void RecordWorkspace(StoreTransaction transaction, PreparedWorkspacePlan prepared)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(prepared);
        if (transaction.Durability != CommitDurability.Full)
            throw new InvalidOperationException("A removal plan requires a FULL transaction.");
        var plan = prepared.Plan;
        var unsigned = plan.Clone();
        unsigned.ClearDigest();
        var digest = Digest(unsigned, prepared.RawSha256, prepared.CallerBytes, prepared.Snapshot);
        if (plan.PlanId?.Value.Length != 16 || !plan.HasDigest ||
            !CryptographicOperations.FixedTimeEquals(plan.Digest.Span, digest))
            throw new InvalidOperationException("The checked removal plan changed before persistence.");
        var planId = plan.PlanId.Value.ToByteArray();
        var commandId = prepared.CommandId;
        var rawSha256 = prepared.RawSha256;
        var callerBytes = prepared.CallerBytes;
        var target = prepared.Target;
        var rootPath = prepared.RootPath;
        var snapshot = prepared.Snapshot;
        var observedTime = prepared.ObservedTime;
        var expires = prepared.ExpiresAt;
        transaction.Execute("""
            INSERT INTO cleanup_plan
              (plan_id, state, digest, planned_by, total_bytes, item_count, created_at, expires_at, rev)
            VALUES ($plan, 1, $digest, $actor, $total, $count, $created, $expires, 0);
            """, ("$plan", planId), ("$digest", digest), ("$actor", prepared.ActorBytes),
            ("$total", checked((long)snapshot.TotalBytes)), ("$count", snapshot.Entries.Count),
            ("$created", observedTime), ("$expires", expires));
        transaction.Execute("""
            INSERT INTO file_removal_plan
              (plan_id, command_id, request_sha256, caller, target_kind, workspace_id, workspace_path,
               root_platform, root_identity, requires_approval, quarantine_available)
            VALUES ($plan, $command, $request, $caller, 1, $workspace, $path, $platform, $root, 1, 0);
            """, ("$plan", planId), ("$command", commandId), ("$request", rawSha256),
            ("$caller", callerBytes), ("$workspace", target.WorkspaceId.Value.ToByteArray()), ("$path", target.Path),
            ("$platform", snapshot.RootIdentity.Platform), ("$root", snapshot.RootIdentity.Bytes));

        for (var index = 0; index < snapshot.Entries.Count; index++)
        {
            var entry = snapshot.Entries[index];
            var ownerVerified = plan.Items[index].OwnerVerified;
            var itemId = StoreIds.NewUuid7(transaction.Clock);
            // Display-only path for the existing cleanup ledger; all future authority must use the recorded native root and IDs.
            var displayPath = Path.Combine(rootPath, entry.Path.Replace('/', Path.DirectorySeparatorChar));
            transaction.Execute("""
                INSERT INTO cleanup_item
                  (plan_id, item_id, path, size_bytes, item_class, reason, risk, action,
                   fp_mtime, fp_size, fp_owner_state, external)
                VALUES ($plan, $item, $path, $size, 10, $reason, 3, 1,
                        $mtime, $size, $owner, 1);
                """, ("$plan", planId), ("$item", itemId), ("$path", displayPath), ("$size", checked((long)entry.Size)),
                ("$mtime", entry.Stamp.Modification), ("$reason", ownerVerified ? "ownership_verified" : "ownership_unverified"),
                ("$owner", ownerVerified ? "verified" : "unverified"));
            transaction.Execute("""
                INSERT INTO file_removal_plan_item
                  (plan_id, item_id, ordinal, relative_path, entry_kind, native_platform, native_identity,
                   identity_sha256, fingerprint_sha256, stamp_size, stamp_mtime, stamp_mtime_nsec,
                   stamp_change, stamp_change_nsec, mode, link_count, owner_verified)
                VALUES ($plan, $item, $ordinal, $path, $kind, $platform, $identity,
                        $identity_sha, $fingerprint, $size, $mtime, $mtime_nsec, $change, $change_nsec, $mode, $links, $owner);
                """, ("$plan", planId), ("$item", itemId), ("$ordinal", index), ("$path", entry.Path),
                ("$kind", (int)entry.Kind), ("$platform", entry.NativeIdentity.Platform), ("$identity", entry.NativeIdentity.Bytes),
                ("$identity_sha", entry.IdentitySha256), ("$fingerprint", entry.FingerprintSha256), ("$size", entry.Stamp.Size),
                ("$mtime", entry.Stamp.Modification), ("$mtime_nsec", (long)entry.Stamp.ModificationNanoseconds),
                ("$change", entry.Stamp.Change), ("$change_nsec", (long)entry.Stamp.ChangeNanoseconds),
                ("$mode", (long)entry.Mode), ("$links", (long)entry.Links), ("$owner", ownerVerified ? 1 : 0));
        }

    }

    internal sealed record PreparedAttemptPlan(FileRemovalPlan Plan, byte[] CommandId, byte[] RawSha256,
        byte[] CallerBytes, byte[] ActorBytes, Id AttemptId, string AttemptRootPath, WorkspaceRemovalSnapshot Snapshot,
        long ObservedTime, long ExpiresAt);

    /// <summary>Prepares metadata for the exact verified task-temp tree; it does not grant cleanup authority.</summary>
    internal static PreparedAttemptPlan PrepareAttempt(StoreTransaction transaction, ReadOnlySpan<byte> commandId,
        ReadOnlySpan<byte> rawSha256, CenterCaller caller, ActorRef actor, Id attemptId, string attemptRootPath,
        WorkspaceRemovalSnapshot snapshot, long observedTime)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(attemptId);
        ArgumentNullException.ThrowIfNull(snapshot);
        if (transaction.Durability != CommitDurability.Full || rawSha256.Length != 32 || commandId.Length != 16 ||
            attemptId.Value.Length != 16 || snapshot.Entries.Count is < 1 or > WorkspaceRemovalPlan.MaximumDescendants + 1 ||
            snapshot.TotalBytes > WorkspaceRemovalPlan.MaximumTotalBytes || snapshot.Entries[0].Path.Length != 0 ||
            snapshot.Entries[0].Kind != ArcForges.Node.Core.Platform.WorkspaceEntryType.Directory)
            throw new InvalidOperationException("A checked attempt removal plan requires a FULL transaction and bounded identity.");

        var planId = StoreIds.NewUuid7(transaction.Clock);
        var expires = checked(observedTime + LifetimeMicroseconds);
        var plan = new FileRemovalPlan
        {
            PlanId = new Id { Value = ByteString.CopyFrom(planId) },
            ExpiresAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(expires)),
            AttemptId = attemptId.Clone(),
            TotalBytes = snapshot.TotalBytes,
            // The exact task-temp provenance is not a strict cleanup guard or a usable quarantine.
            RequiresApproval = true,
            QuarantineAvailable = false,
            Risk = RiskClass.High,
        };
        foreach (var entry in snapshot.Entries)
        {
            plan.Items.Add(new FileRemovalItem
            {
                Path = entry.Path,
                Kind = (FileEntryKind)entry.Kind,
                SizeBytes = entry.Size,
                IdentitySha256 = ByteString.CopyFrom(entry.IdentitySha256),
                // Only the root has recorded native-create provenance; descendants need independent proof.
                OwnerVerified = entry.Path.Length == 0,
            });
        }

        var callerBytes = caller.ToByteArray();
        plan.Digest = ByteString.CopyFrom(Digest(plan, rawSha256, callerBytes, snapshot));
        return new PreparedAttemptPlan(plan, commandId.ToArray(), rawSha256.ToArray(), callerBytes, actor.ToByteArray(),
            attemptId.Clone(), attemptRootPath, snapshot, observedTime, expires);
    }

    /// <summary>Records the checked attempt target and every fingerprint alongside the caller's receipt transaction.</summary>
    internal static void RecordAttempt(StoreTransaction transaction, PreparedAttemptPlan prepared)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(prepared);
        if (transaction.Durability != CommitDurability.Full)
            throw new InvalidOperationException("A removal plan requires a FULL transaction.");
        var plan = prepared.Plan;
        var unsigned = plan.Clone();
        unsigned.ClearDigest();
        var digest = Digest(unsigned, prepared.RawSha256, prepared.CallerBytes, prepared.Snapshot);
        if (plan.PlanId?.Value.Length != 16 || !plan.HasDigest ||
            !CryptographicOperations.FixedTimeEquals(plan.Digest.Span, digest))
            throw new InvalidOperationException("The checked removal plan changed before persistence.");

        var planId = plan.PlanId.Value.ToByteArray();
        var snapshot = prepared.Snapshot;
        transaction.Execute("""
            INSERT INTO cleanup_plan
              (plan_id, state, digest, planned_by, total_bytes, item_count, created_at, expires_at, rev)
            VALUES ($plan, 1, $digest, $actor, $total, $count, $created, $expires, 0);
            """, ("$plan", planId), ("$digest", digest), ("$actor", prepared.ActorBytes),
            ("$total", checked((long)snapshot.TotalBytes)), ("$count", snapshot.Entries.Count),
            ("$created", prepared.ObservedTime), ("$expires", prepared.ExpiresAt));
        transaction.Execute("""
            INSERT INTO file_removal_plan
              (plan_id, command_id, request_sha256, caller, target_kind, attempt_id,
               root_platform, root_identity, requires_approval, quarantine_available)
            VALUES ($plan, $command, $request, $caller, 2, $attempt, $platform, $root, 1, 0);
            """, ("$plan", planId), ("$command", prepared.CommandId), ("$request", prepared.RawSha256),
            ("$caller", prepared.CallerBytes), ("$attempt", prepared.AttemptId.Value.ToByteArray()),
            ("$platform", snapshot.RootIdentity.Platform), ("$root", snapshot.RootIdentity.Bytes));

        for (var index = 0; index < snapshot.Entries.Count; index++)
        {
            var entry = snapshot.Entries[index];
            var itemId = StoreIds.NewUuid7(transaction.Clock);
            // Display-only; future authority must re-derive the attempt root and compare the persisted native identities.
            // The tracked attempt root is per-owner USAGE; descendants without independent provenance are UNTRACKED.
            // These descriptive classes do not authorize an effect or establish a quarantine.
            var displayPath = Path.Combine(prepared.AttemptRootPath, entry.Path.Replace('/', Path.DirectorySeparatorChar));
            transaction.Execute("""
                INSERT INTO cleanup_item
                  (plan_id, item_id, path, size_bytes, item_class, reason, risk, action,
                   fp_mtime, fp_size, fp_owner_state, external)
                VALUES ($plan, $item, $path, $size, $class, $reason, 3, 1,
                        $mtime, $size, $owner, 0);
                """, ("$plan", planId), ("$item", itemId), ("$path", displayPath), ("$size", checked((long)entry.Size)),
                ("$class", index == 0 ? 1 : 10), ("$mtime", entry.Stamp.Modification),
                ("$reason", index == 0 ? "attempt_temp_verified" : "ownership_unverified"),
                ("$owner", index == 0 ? "verified" : "unverified"));
            transaction.Execute("""
                INSERT INTO file_removal_plan_item
                  (plan_id, item_id, ordinal, relative_path, entry_kind, native_platform, native_identity,
                   identity_sha256, fingerprint_sha256, stamp_size, stamp_mtime, stamp_mtime_nsec,
                   stamp_change, stamp_change_nsec, mode, link_count, owner_verified)
                VALUES ($plan, $item, $ordinal, $path, $kind, $platform, $identity,
                        $identity_sha, $fingerprint, $size, $mtime, $mtime_nsec, $change, $change_nsec, $mode, $links, $owner);
                """, ("$plan", planId), ("$item", itemId), ("$ordinal", index), ("$path", entry.Path),
                ("$kind", (int)entry.Kind), ("$platform", entry.NativeIdentity.Platform), ("$identity", entry.NativeIdentity.Bytes),
                ("$identity_sha", entry.IdentitySha256), ("$fingerprint", entry.FingerprintSha256), ("$size", entry.Stamp.Size),
                ("$mtime", entry.Stamp.Modification), ("$mtime_nsec", (long)entry.Stamp.ModificationNanoseconds),
                ("$change", entry.Stamp.Change), ("$change_nsec", (long)entry.Stamp.ChangeNanoseconds),
                ("$mode", (long)entry.Mode), ("$links", (long)entry.Links), ("$owner", index == 0 ? 1 : 0));
        }
    }

    private static byte[] Digest(FileRemovalPlan plan, ReadOnlySpan<byte> rawSha256, ReadOnlySpan<byte> caller,
        WorkspaceRemovalSnapshot snapshot)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges exact removal plan v1\0"u8);
        Append(hash, rawSha256);
        Append(hash, caller);
        Append(hash, plan.ToByteArray());
        Append(hash, snapshot.RootIdentity.Bytes);
        Span<byte> frame = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(frame, snapshot.RootIdentity.Platform);
        hash.AppendData(frame);
        // The action is the existing ledger's QUARANTINE candidate. It is not an effect or proof a root is available.
        BinaryPrimitives.WriteInt32BigEndian(frame, 1);
        hash.AppendData(frame);
        foreach (var entry in snapshot.Entries)
        {
            BinaryPrimitives.WriteInt32BigEndian(frame, entry.NativeIdentity.Platform);
            hash.AppendData(frame);
            Append(hash, entry.NativeIdentity.Bytes);
            Append(hash, entry.FingerprintSha256);
        }

        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> size = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(size, value.Length);
        hash.AppendData(size);
        hash.AppendData(value);
    }
}
