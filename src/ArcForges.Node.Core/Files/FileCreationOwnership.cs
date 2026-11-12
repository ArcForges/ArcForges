// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Files;

/// <summary>
/// Creation evidence is metadata, not cleanup authority. A positive observation below is only a planning input;
/// cleanup still needs the exact plan, current policy, native exclusion and all strict section 5 guards.
/// </summary>
internal static class FileCreationOwnership
{
    /// <summary>Records only a completed expected-absent journal in the same transaction as its receipt and audit.</summary>
    internal static void RecordCompleted(StoreTransaction transaction, ReadOnlySpan<byte> commandId,
        WorkspaceCreatedOwnership evidence, long size, ReadOnlySpan<byte> sha256)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (transaction.Durability != CommitDurability.Full || commandId.Length != 16 || evidence.Marker is not { Length: 32 } ||
            sha256.Length != 32 || size is < 0 or > 4_194_304)
            throw new InvalidOperationException("Invalid completed creation evidence.");
        using (var receipt = transaction.CreateCommand("""
            SELECT d.outcome, j.correlation_id FROM file_operation_journal j
            JOIN command_dedup d ON d.command_id = j.command_id AND d.payload_digest = j.request_sha256
            WHERE j.command_id = $command AND d.method = 'arcforges.node.v1.FileService/WriteFile' AND d.outcome IS NOT NULL;
            """))
        {
            receipt.Parameters.AddWithValue("$command", commandId.ToArray());
            using var row = receipt.ExecuteReader();
            if (!row.Read()) throw new InvalidOperationException("The completed creation receipt is unavailable.");
            FileServiceWriteFileResponse response;
            try { response = FileServiceWriteFileResponse.Parser.ParseFrom((byte[])row.GetValue(0)); }
            catch (InvalidProtocolBufferException error) { throw new InvalidDataException("Invalid creation receipt.", error); }
            var result = response.Value?.Result;
            var observations = response.Audit?.Observations;
            if (!NodeShapes.IsValid(response) || response.Error is not null ||
                response.Meta?.CorrelationId?.Value.Span.SequenceEqual((byte[])row.GetValue(1)) != true ||
                result?.CommandId?.Value.Span.SequenceEqual(commandId) != true || !result.HasSizeBytes ||
                result.SizeBytes != (ulong)size || !result.HasSha256 ||
                !CryptographicOperations.FixedTimeEquals(result.Sha256.Span, sha256) ||
                observations is null || observations.Count != 1 || observations[0].Kind != FileAuditKind.WrittenBytes ||
                observations[0].SizeBytes != (ulong)size || observations[0].DigestInputBytes != (ulong)size ||
                !CryptographicOperations.FixedTimeEquals(observations[0].Sha256.Span, sha256))
                throw new InvalidDataException("The completed creation receipt does not match its evidence.");
        }
        var key = StableKey(evidence.Identity.Platform, evidence.Identity.Bytes)
            ?? throw new InvalidOperationException("The created object identity is unavailable.");
        var count = transaction.Execute("""
            INSERT INTO file_creation_ownership
              (workspace_id, relative_path, caller, creation_command_id, creation_request_sha256,
               root_platform, root_identity, object_platform, object_identity, object_key, creation_marker,
               last_written_size, last_written_sha256, global_generation, object_generation, recorded_at)
            SELECT j.workspace_id, j.relative_path, j.caller, j.command_id, j.request_sha256,
                   j.identity_platform, j.root_identity, $platform, $object, $key, $marker, $size, $hash,
                   g.generation, o.generation, $now
            FROM file_operation_journal j CROSS JOIN file_ownership_generation g
            JOIN file_ownership_object_generation o ON o.object_platform = $platform AND o.object_key = $key
            WHERE g.singleton = 1 AND j.command_id = $command AND j.kind = 1 AND j.phase = 2 AND j.expected_absent = 1
              AND j.target_identity IS NULL AND j.identity_platform = $platform
              AND j.intended_size = $size AND j.intended_sha256 = $hash;
            """, ("$command", commandId.ToArray()), ("$platform", evidence.Identity.Platform),
            ("$object", evidence.Identity.Bytes), ("$key", key), ("$marker", evidence.Marker), ("$size", size),
            ("$hash", sha256.ToArray()), ("$now", transaction.NowMicroseconds));
        if (count != 1) throw new InvalidOperationException("The created object does not match its completed intent.");
    }

    /// <summary>Specific-caller proof from the old marker, identity and hash on the same guarded target.</summary>
    internal sealed record UpdateProof(byte[] Workspace, string Path, CenterCaller Caller, byte[] CallerBytes,
        int RootPlatform, byte[] RootIdentity, int ObjectPlatform, byte[] ObjectIdentity, byte[] Marker,
        long OldSize, byte[] OldHash, long GlobalGeneration, long ObjectGeneration);

    internal static UpdateProof? PrepareUpdate(StoreReader reader, CenterCaller caller, ReadOnlySpan<byte> workspace,
        WorkspacePath root, string path, WorkspaceWriteGuard guard, ReadOnlySpan<byte> expectedSha256,
        CancellationToken cancellationToken)
    {
        if (!HasSchema(reader) || expectedSha256.Length != 32) return null;
        var record = Read(reader, workspace, path);
        if (record is null || !CenterRouting.SameFileCaller(record.Caller, caller) ||
            !CryptographicOperations.FixedTimeEquals(record.Hash, expectedSha256)) return null;
        var selectedRoot = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        if (selectedRoot.Platform != record.RootPlatform || !selectedRoot.Bytes.AsSpan().SequenceEqual(record.RootIdentity))
            return null;
        try
        {
            var identity = new RegisteredWorkspaces.RootIdentity(record.ObjectPlatform, record.ObjectIdentity);
            if (!root.MatchesHeldOwnership(path, guard, identity, record.Marker, record.Size, record.Hash, cancellationToken))
                return null;
            return new UpdateProof(workspace.ToArray(), path, record.Caller, record.CallerBytes, record.RootPlatform,
                record.RootIdentity, record.ObjectPlatform, record.ObjectIdentity, record.Marker, record.Size, record.Hash,
                record.GlobalGeneration, record.ObjectGeneration);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    internal static bool ConfirmUpdate(UpdateProof proof, WorkspacePath root, WorkspaceWriteGuard guard,
        long size, ReadOnlySpan<byte> sha256, CancellationToken cancellationToken)
    {
        try
        {
            return root.MatchesHeldOwnership(proof.Path, guard,
                new RegisteredWorkspaces.RootIdentity(proof.ObjectPlatform, proof.ObjectIdentity),
                proof.Marker, size, sha256, cancellationToken);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Advances only the exact unchanged record whose previous content and owner were checked.</summary>
    internal static bool Advance(StoreTransaction transaction, UpdateProof proof, ReadOnlySpan<byte> commandId,
        ReadOnlySpan<byte> workspace, string path, CenterCaller caller, long size, ReadOnlySpan<byte> sha256,
        long objectGeneration)
    {
        if (transaction.Durability != CommitDurability.Full || !proof.Workspace.AsSpan().SequenceEqual(workspace) ||
            !string.Equals(proof.Path, path, StringComparison.Ordinal) || !CenterRouting.SameFileCaller(proof.Caller, caller) ||
            sha256.Length != 32 || size is < 0 or > 4_194_304)
            throw new InvalidOperationException("Invalid controlled ownership update.");
        if (proof.ObjectGeneration == long.MaxValue || objectGeneration != proof.ObjectGeneration + 1) return false;
        var key = StableKey(proof.ObjectPlatform, proof.ObjectIdentity);
        if (key is null) return false;
        return transaction.Execute("""
            UPDATE file_creation_ownership
            SET last_written_size = $size, last_written_sha256 = $hash, object_generation = $new_generation
            WHERE workspace_id = $workspace AND relative_path = $path AND caller = $caller
              AND root_platform = $root_platform AND root_identity = $root AND object_platform = $object_platform
              AND object_identity = $object AND object_key = $key AND creation_marker = $marker
              AND last_written_size = $old_size AND last_written_sha256 = $old_hash
              AND global_generation = $global_generation AND object_generation = $old_generation
              AND EXISTS (SELECT 1 FROM file_ownership_generation g
                          WHERE g.singleton = 1 AND g.generation = $global_generation)
              AND EXISTS (SELECT 1 FROM file_ownership_object_generation o
                          WHERE o.object_platform = $object_platform AND o.object_key = $key AND o.generation = $new_generation)
              AND EXISTS (SELECT 1 FROM file_operation_journal j WHERE j.command_id = $command AND j.phase = 2
                          AND j.expected_absent = 0 AND j.workspace_id = $workspace AND j.relative_path = $path
                          AND j.identity_platform = $object_platform AND j.target_identity = $object);
            """, ("$command", commandId.ToArray()), ("$size", size), ("$hash", sha256.ToArray()), ("$workspace", proof.Workspace),
            ("$path", proof.Path), ("$caller", proof.CallerBytes), ("$root_platform", proof.RootPlatform),
            ("$root", proof.RootIdentity), ("$object_platform", proof.ObjectPlatform), ("$object", proof.ObjectIdentity),
            ("$key", key), ("$marker", proof.Marker), ("$old_size", proof.OldSize), ("$old_hash", proof.OldHash),
            ("$global_generation", proof.GlobalGeneration), ("$old_generation", proof.ObjectGeneration),
            ("$new_generation", objectGeneration)) == 1;
    }

    /// <summary>
    /// Observes a matching agent record against the checked snapshot and a no-follow opened file. Unknown evidence,
    /// other callers, HUMAN/SCRIPT records, inaccessible metadata or changed content remain unowned.
    /// </summary>
    internal static bool IsVerifiedAgent(StoreReader reader, CenterCaller caller, ReadOnlySpan<byte> workspace,
        WorkspacePath root, WorkspaceRemovalEntry entry, CancellationToken cancellationToken,
        WorkspaceOwnershipInputAudit? inputAudit = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(entry);
        if (caller.Kind != CenterCallerKind.NodeRelay || caller.LocalOrigin != Origin.Agent ||
            CenterRouting.Shape(caller) is not null || entry.Kind != WorkspaceEntryType.File)
            return false;
        if (!HasSchema(reader)) return false;
        var record = Read(reader, workspace, entry.Path);
        if (record is null || !CenterRouting.SameFileCaller(record.Caller, caller) ||
            record.RootPlatform != entry.NativeIdentity.Platform || record.ObjectPlatform != entry.NativeIdentity.Platform ||
            !record.ObjectIdentity.AsSpan().SequenceEqual(entry.NativeIdentity.Bytes) ||
            record.Size != (long)entry.Size || HasUnresolvedConflict(reader, workspace, entry))
            return false;
        var selectedRoot = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        if (selectedRoot.Platform != record.RootPlatform || !selectedRoot.Bytes.AsSpan().SequenceEqual(record.RootIdentity))
            return false;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var file = root.OpenReadForOwnership(entry.Path);
            var native = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file), directory: false);
            var before = WorkspacePath.FileStamp(file);
            if (native.Platform != record.ObjectPlatform || !native.Bytes.AsSpan().SequenceEqual(record.ObjectIdentity) ||
                before != entry.Stamp)
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
            var marker = WorkspaceCreationMarker.Read(file, record.Marker);
            if (marker is null || !CryptographicOperations.FixedTimeEquals(record.Marker, marker)) return false;

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[65_536];
            long offset = 0;
            while (offset < record.Size)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var requested = (int)Math.Min(buffer.Length, record.Size - offset);
                if (inputAudit is not null) requested = inputAudit.AllowRead(requested);
                var count = RandomAccess.Read(file, buffer.AsSpan(0, requested), offset);
                if (count <= 0) throw new WorkspaceRemovalPlanException("planned_tree_changed");
                inputAudit?.Append(buffer.AsSpan(0, count));
                hash.AppendData(buffer, 0, count);
                offset += count;
            }
            var digest = hash.GetHashAndReset();
            if (WorkspacePath.FileStamp(file) != before || RandomAccess.GetLength(file) != record.Size)
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
            root.PrepareMutationNameCheck(entry.Path, WorkspacePath.Identity(file), cancellationToken)();
            return CryptographicOperations.FixedTimeEquals(record.Hash, digest);
        }
        catch (WorkspaceRemovalPlanException) { throw; }
        catch (WorkspacePathException error) when (error.Reason is "file_identity_changed" or "directory_identity_changed" or "root_changed")
        {
            throw new WorkspaceRemovalPlanException("planned_tree_changed", error);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // Marker or file metadata that cannot be safely observed is never considered owned.
            return false;
        }
    }

    /// <summary>
    /// Advances one indexed native-object generation. If the affected identity is unknowable, advances a single
    /// global generation instead. Old records and in-memory proofs cannot become valid again after either change.
    /// </summary>
    internal static long? InvalidateAffected(StoreTransaction transaction, ReadOnlySpan<byte> commandId,
        WorkspaceCreatedOwnership? created)
    {
        if (transaction.Durability != CommitDurability.Full)
            throw new InvalidOperationException("Creation evidence requires a FULL transaction.");
        if (!HasSchema(transaction)) return null;
        using var command = transaction.CreateCommand("""
            SELECT identity_platform, target_identity, expected_absent FROM file_operation_journal WHERE command_id = $id;
            """);
        command.Parameters.AddWithValue("$id", commandId.ToArray());
        using var row = command.ExecuteReader();
        if (!row.Read()) throw new InvalidOperationException("The affected file intent is missing.");
        var absent = row.GetInt32(2) != 0;
        var platform = absent && created is not null ? created.Identity.Platform : row.GetInt32(0);
        var identity = absent ? created?.Identity.Bytes : row.IsDBNull(1) ? null : (byte[])row.GetValue(1);
        var key = identity is null ? null : StableKey(platform, identity);
        row.Close();
        if (key is null)
        {
            if (transaction.Execute("""
                UPDATE file_ownership_generation SET generation = generation + 1
                WHERE singleton = 1 AND generation < 9223372036854775807;
                """) != 1)
                throw new InvalidOperationException("The ownership generation cannot advance.");
            return null;
        }
        if (created?.Marker is null && transaction.Scalar("""
            SELECT 1 FROM file_creation_ownership WHERE object_platform = $platform AND object_key = $key LIMIT 1;
            """, ("$platform", platform), ("$key", key)) is null) return null;

        if (transaction.Execute("""
            INSERT INTO file_ownership_object_generation (object_platform, object_key, generation)
            VALUES ($platform, $key, 1)
            ON CONFLICT (object_platform, object_key) DO UPDATE SET generation = generation + 1
            WHERE generation < 9223372036854775807;
            """, ("$platform", platform), ("$key", key)) != 1)
            throw new InvalidOperationException("The object ownership generation cannot advance.");
        return Convert.ToInt64(transaction.Scalar("""
            SELECT generation FROM file_ownership_object_generation WHERE object_platform = $platform AND object_key = $key;
            """, ("$platform", platform), ("$key", key)), System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Forgets at most the exact path row. Other aliases are invalidated by their object generation.</summary>
    internal static void ForgetPath(StoreTransaction transaction, ReadOnlySpan<byte> workspace, string path)
    {
        if (!HasSchema(transaction)) return;
        transaction.Execute("DELETE FROM file_creation_ownership WHERE workspace_id = $workspace AND relative_path = $path;",
            ("$workspace", workspace.ToArray()), ("$path", path));
    }

    private static bool HasUnresolvedConflict(StoreReader reader, ReadOnlySpan<byte> workspace, WorkspaceRemovalEntry entry)
    {
        var selected = StableKey(entry.NativeIdentity.Platform, entry.NativeIdentity.Bytes);
        if (selected is null) return true;
        using var command = reader.CreateCommand("""
            SELECT workspace_id, relative_path, identity_platform, target_identity, expected_absent
            FROM file_operation_journal WHERE phase IN (1, 3) AND held = 1;
            """);
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            // A not-yet-observed new target may be any alias until recovery establishes its outcome.
            if (rows.GetInt32(4) != 0 || rows.IsDBNull(3)) return true;
            if (!rows.IsDBNull(0) && !rows.IsDBNull(1) &&
                ((byte[])rows.GetValue(0)).AsSpan().SequenceEqual(workspace) &&
                string.Equals(rows.GetString(1), entry.Path, StringComparison.Ordinal)) return true;
            var platform = rows.GetInt32(2);
            var key = StableKey(platform, (byte[])rows.GetValue(3));
            if (key is null) return true;
            if (platform == entry.NativeIdentity.Platform && key.AsSpan().SequenceEqual(selected)) return true;
        }
        return false;
    }

    internal static byte[]? StableKey(int platform, byte[] identity) => platform switch
    {
        1 when identity.Length == 33 && identity[0] == 1 => identity.AsSpan(0, 25).ToArray(),
        2 when identity.Length == 53 && identity[0] == 1 => identity.AsSpan(21, 32).ToArray(),
        _ => null,
    };

    private static bool HasSchema(StoreReader reader) => reader.Scalar(
        "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'file_creation_ownership';") is not null;

    private static Record? Read(StoreReader reader, ReadOnlySpan<byte> workspace, string path)
    {
        using var command = reader.CreateCommand("""
            SELECT c.caller, c.root_platform, c.root_identity, c.object_platform, c.object_identity, c.creation_marker,
                   c.last_written_size, c.last_written_sha256, c.global_generation, c.object_generation, c.object_key
            FROM file_creation_ownership c
            JOIN file_ownership_generation g ON g.singleton = 1 AND g.generation = c.global_generation
            JOIN file_ownership_object_generation o ON o.object_platform = c.object_platform AND o.object_key = c.object_key
                                                      AND o.generation = c.object_generation
            WHERE c.workspace_id = $workspace AND c.relative_path = $path;
            """);
        command.Parameters.AddWithValue("$workspace", workspace.ToArray());
        command.Parameters.AddWithValue("$path", path);
        using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        try
        {
            var callerBytes = (byte[])row.GetValue(0);
            var caller = CenterCaller.Parser.ParseFrom(callerBytes);
            var marker = (byte[])row.GetValue(5);
            var hash = (byte[])row.GetValue(7);
            var platform = row.GetInt32(3);
            var identity = (byte[])row.GetValue(4);
            var objectKey = StableKey(platform, identity);
            if (CenterRouting.Shape(caller) is not null || marker.Length != 32 || hash.Length != 32 || objectKey is null ||
                !objectKey.AsSpan().SequenceEqual((byte[])row.GetValue(10))) return null;
            return new Record(caller, callerBytes, row.GetInt32(1), (byte[])row.GetValue(2), platform,
                identity, marker, row.GetInt64(6), hash, row.GetInt64(8), row.GetInt64(9));
        }
        catch (InvalidProtocolBufferException) { return null; }
    }

    private sealed record Record(CenterCaller Caller, byte[] CallerBytes, int RootPlatform, byte[] RootIdentity, int ObjectPlatform,
        byte[] ObjectIdentity, byte[] Marker, long Size, byte[] Hash, long GlobalGeneration, long ObjectGeneration);
}
