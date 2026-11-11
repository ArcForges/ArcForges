// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Files;

/// <summary>
/// A recovered exact private file and its checked directory. The guard stays held until disposal; this does not prove
/// approval, current target identity or authority to perform an effect.
/// </summary>
internal sealed class RecoveredPrivateStage(WorkspacePath directory, WorkspaceWriteGuard guard, long length, byte[] hash,
    RegisteredWorkspaces.RootIdentity identity) : WorkspaceMutationStage
{
    internal WorkspaceWriteGuard Guard { get; } = guard;
    internal override RegisteredWorkspaces.RootIdentity Identity { get; } = identity;
    internal override WorkspaceObjectIdentity ObjectIdentity => Guard.ObjectIdentity;
    internal override long Length { get; } = length;
    internal override ReadOnlyMemory<byte> Sha256 => hash;
    internal override WorkspaceGuardedContent ReadVerified(CancellationToken cancellationToken)
    {
        var content = Guard.ReadForMutation(cancellationToken);
        if (content.Bytes.Length == Length && CryptographicOperations.FixedTimeEquals(content.Sha256.Span, hash)) return content;
        content.Dispose();
        throw new WorkspacePathException("file_identity_changed");
    }
    internal override void CheckIntact() => Guard.CheckIntact();
    public override void Dispose()
    {
        try { Guard.Dispose(); }
        finally { directory.Dispose(); }
    }
}

internal static partial class PrivateStageRegistry
{
    /// <summary>
    /// Opens a READY stage only after the retained command digest and original caller match. The exact previously
    /// recorded directory and object identities are checked and the whole opened file is rehashed under a native
    /// guard. The caller must recheck the current approval, policy and journal in its effect transaction.
    /// </summary>
    internal static RecoveredPrivateStage ReopenReadyStage(StoreReader reader, ReadOnlySpan<byte> commandId, int slot,
        CenterCaller caller, ReadOnlySpan<byte> requestSha256, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(caller);
        StoreIds.Validate(commandId, nameof(commandId));
        if (slot is not (1 or 2) || CenterRouting.Shape(caller) is not null || requestSha256.Length != 32)
            throw new ArgumentException("A verified caller and exact request digest are required.");
        string path;
        int platform;
        byte[] fileId, parentId, hash;
        long size;
        using (var command = reader.CreateCommand("""
            SELECT o.stage_path, o.identity_platform, o.native_identity, o.parent_identity, o.expected_size,
                   o.expected_sha256, r.request_sha256, r.caller
            FROM file_private_stage_object o JOIN file_private_stage_reservation r ON r.command_id = o.command_id
            WHERE o.command_id = $id AND o.slot = $slot AND o.phase = 3 AND r.active = 1;
            """))
        {
            command.Parameters.AddWithValue("$id", commandId.ToArray());
            command.Parameters.AddWithValue("$slot", slot);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.IsDBNull(1) || row.IsDBNull(2) || row.IsDBNull(3) ||
                !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(6), requestSha256) ||
                !CenterRouting.SameFileCaller(CenterCaller.Parser.ParseFrom((byte[])row.GetValue(7)), caller))
                throw new InvalidOperationException("The ready stage does not bind this caller and command.");
            path = row.GetString(0);
            platform = row.GetInt32(1);
            fileId = (byte[])row.GetValue(2);
            parentId = (byte[])row.GetValue(3);
            size = row.GetInt64(4);
            hash = (byte[])row.GetValue(5);
        }
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, fileId);
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, parentId);
        if (!Path.IsPathFullyQualified(path) || size is < 0 or > FileStageBudget.MaximumFileBytes || hash.Length != 32)
            throw new InvalidDataException("The recorded private stage is invalid.");
        var parent = Path.GetDirectoryName(path);
        var name = Path.GetFileName(path);
        if (string.IsNullOrEmpty(parent) || string.IsNullOrEmpty(name))
            throw new InvalidDataException("The recorded private stage has no parent or name.");
        cancellationToken.ThrowIfCancellationRequested();
        WorkspacePath? directory = null;
        WorkspaceWriteGuard? guard = null;
        try
        {
            directory = WorkspacePath.OpenRoot(parent);
            var actualParent = RegisteredWorkspaces.RootIdentity.Encode(directory.RootIdentity);
            if (actualParent.Platform != platform || !CryptographicOperations.FixedTimeEquals(actualParent.Bytes, parentId))
                throw new WorkspacePathException("file_identity_changed");
            var identity = new RegisteredWorkspaces.RootIdentity(platform, fileId);
            guard = OperatingSystem.IsWindows()
                ? directory.ReopenWindowsPrivateNamedStage(identity, name, size, hash, cancellationToken)
                : OperatingSystem.IsLinux()
                    ? directory.ReopenLinuxPrivateNamedStage(identity, name, size, hash, cancellationToken)
                    : throw new WorkspacePathException("file_guard_unavailable");
            var recovered = new RecoveredPrivateStage(directory, guard, size, hash, identity);
            directory = null;
            guard = null;
            return recovered;
        }
        finally
        {
            guard?.Dispose();
            directory?.Dispose();
        }
    }
}
