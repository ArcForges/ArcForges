// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>The pre-effect checked parent and original ancestor chain; it grants no authority or namespace lock.</summary>
internal sealed record WorkspaceLinuxCreationSelection(SafeFileHandle Parent, WorkspaceObjectIdentity ParentIdentity,
    Action<byte[]?> CheckNames);

internal sealed partial class WorkspacePath
{
    internal WorkspaceLinuxCreationSelection PrepareLinuxCreation(string path, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux()) throw new WorkspacePathException("file_guard_unavailable");
        ObjectDisposedException.ThrowIf(_disposed, this);
        var parts = Components(path);
        var parents = new List<(string Name, WorkspaceObjectIdentity Identity)>();
        var parent = RootHandle;
        for (var index = 1; index < parts.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var prefix = string.Join('/', parts.AsSpan(0, index).ToArray());
            parent = OpenDirectory(prefix);
            var identity = Identity(parent);
            if (!identity.IsDirectory || identity.Links == 0) throw new WorkspacePathException("directory_identity_changed");
            parents.Add((prefix, identity));
        }
        var preparedParent = Identity(parent);
        void Check(byte[]? createdIdentity)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var root = Identity(RootHandle);
            if (!root.IsDirectory || root.Links == 0 || !RootIdentity.SameObject(root))
                throw new WorkspacePathException("root_changed");
            using var namedRoot = OpenRoot(RootPath, RootIdentity);
            foreach (var (name, original) in parents)
            {
                var entry = InspectEntry(name);
                if (entry.Kind != WorkspaceEntryType.Directory || !original.SameObject(entry.Identity))
                    throw new WorkspacePathException("directory_identity_changed");
            }
            if (!preparedParent.SameObject(Identity(parent)))
                throw new WorkspacePathException("parent_identity_changed");
            // Absence is decided only by O_EXCL, never by a racy preliminary name observation.
            if (createdIdentity is not null)
            {
                var entry = InspectEntry(path);
                if (entry.Kind != WorkspaceEntryType.File || entry.Identity.Links != 1 ||
                    !CryptographicOperations.FixedTimeEquals(createdIdentity,
                        RegisteredWorkspaces.RootIdentity.Encode(entry.Identity, directory: false).Bytes))
                    throw new WorkspacePathException("file_identity_changed");
            }
        }
        Check(null);
        return new WorkspaceLinuxCreationSelection(parent, preparedParent, Check);
    }
}

internal sealed partial class WorkspaceWriteGuard
{
    internal static void TransferLinuxCreationSource(LinuxOwnedPeer peer, SafeFileHandle root, SafeFileHandle parent,
        WorkspaceWriteGuard source)
    {
        ArgumentNullException.ThrowIfNull(peer);
        if (!OperatingSystem.IsLinux() || !source._privateStage)
            throw new WorkspacePathException("file_guard_unavailable");
        lock (source._sync)
        {
            source.CheckLocked();
            peer.SendDescriptorsOnce([root, parent, source._file!]);
        }
    }
}
