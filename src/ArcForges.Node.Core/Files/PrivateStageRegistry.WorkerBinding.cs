// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Files;

internal static partial class PrivateStageRegistry
{
    /// <summary>
    /// FULL-binds a real worker-created empty object before any body permission. The supplied native verifier must
    /// establish the actual owned child, original deadline and kernel exclusion before and after this metadata step.
    /// A transacted Windows name may be private until commit; its backend must prove handle-relative creation in that
    /// same active transaction. This method does not fabricate an ordinary guard or grant a target effect.
    /// </summary>
    internal static void BindWorkerEmptyForProtection(StoreTransaction transaction, FileStageProductionReservation reservation,
        int slot, WorkspacePath workspaceRoot, WorkspacePath stageDirectory, string name, SafeFileHandle file,
        Action verifyNativeGuard, CancellationToken cancellationToken, bool transactionPrivateName = false)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(verifyNativeGuard);
        if (slot is not (1 or 2) || WorkspacePath.Components(name).Length != 1 ||
            transactionPrivateName && !OperatingSystem.IsWindows())
            throw new ArgumentException("A real reserved direct stage name is required.");
        cancellationToken.ThrowIfCancellationRequested();
        verifyNativeGuard();
        var actual = WorkspacePath.Identity(file);
        var root = workspaceRoot.RootIdentity;
        var parent = stageDirectory.RootIdentity;
        if (!actual.IsFile || actual.Links != 1 || RandomAccess.GetLength(file) != 0 ||
            actual.Volume != root.Volume || parent.Volume != root.Volume ||
            OperatingSystem.IsLinux() && (actual.High != root.High || parent.High != root.High))
            throw new WorkspacePathException("file_identity_changed");
        var rootId = RegisteredWorkspaces.RootIdentity.Encode(root);
        var parentId = RegisteredWorkspaces.RootIdentity.Encode(parent);
        var identity = RegisteredWorkspaces.RootIdentity.Encode(actual, directory: false);
        if (identity.Platform != reservation.Platform ||
            !CryptographicOperations.FixedTimeEquals(rootId.Bytes, reservation.RootIdentity) ||
            !CryptographicOperations.FixedTimeEquals(parentId.Bytes, reservation.ParentIdentity))
            throw new WorkspacePathException("file_identity_changed");
        using var recheckedRoot = WorkspacePath.OpenRoot(workspaceRoot.RootPath, root);
        using var recheckedParent = WorkspacePath.OpenRoot(stageDirectory.RootPath, parent);
        if (!transactionPrivateName)
        {
            var entry = stageDirectory.InspectEntry(name);
            if (entry.Kind != WorkspaceEntryType.File || entry.Identity.Links != 1 || !actual.SameObject(entry.Identity))
                throw new WorkspacePathException("file_identity_changed");
        }
        RequireActiveUnboundStage(transaction, reservation.CommandId, slot, stageDirectory, name);
        using (var query = transaction.CreateCommand("""
            SELECT r.request_sha256, r.caller, w.platform, w.native_identity FROM file_private_stage_reservation r
            JOIN workspace_root_identity w ON w.workspace_id = r.workspace_id AND w.released_at IS NULL
            WHERE r.command_id = $id AND r.workspace_id = $workspace AND r.active = 1;
            """))
        {
            query.Parameters.AddWithValue("$id", reservation.CommandId);
            query.Parameters.AddWithValue("$workspace", reservation.WorkspaceId);
            using var row = query.ExecuteReader();
            if (!row.Read() || !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(0), reservation.RequestSha256) ||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData((byte[])row.GetValue(1)), reservation.CallerDigest) ||
                row.GetInt32(2) != rootId.Platform || !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(3), rootId.Bytes))
                throw new InvalidOperationException("The actual empty object does not bind the original stage reservation.");
        }
        verifyNativeGuard();
        cancellationToken.ThrowIfCancellationRequested();
        if (transaction.Execute("""
            UPDATE file_private_stage_object SET phase = 2, identity_platform = $platform, native_identity = $identity,
                                                 parent_identity = $parent
            WHERE command_id = $id AND slot = $slot AND phase = 1 AND native_identity IS NULL AND parent_identity IS NULL;
            """, ("$platform", identity.Platform), ("$identity", identity.Bytes), ("$parent", parentId.Bytes),
            ("$id", reservation.CommandId), ("$slot", slot)) != 1)
            throw new InvalidOperationException("The private empty object identity was already bound.");
        FileStageProduction.BindEmptyObject(transaction, reservation, slot, identity);
        verifyNativeGuard();
    }
}
