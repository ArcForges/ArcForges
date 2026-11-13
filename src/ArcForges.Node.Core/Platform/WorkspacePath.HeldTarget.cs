// SPDX-License-Identifier: AGPL-3.0-only
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    /// <summary>
    /// Inspects a single child through the already held parent directory, without following a link or opening file
    /// data. This is an observation for a durable target hold, not a namespace lock or authority for an effect.
    /// </summary>
    internal WorkspaceObjectIdentity InspectHeldParentChild(SafeFileHandle parent, string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(parent);
        if (Components(name).Length != 1) throw new WorkspacePathException("path_invalid");
        var parentIdentity = Identity(parent);
        if (!parentIdentity.IsDirectory || parentIdentity.Links == 0 || parentIdentity.Volume != RootIdentity.Volume)
            throw new WorkspacePathException("directory_identity_changed");

        if (OperatingSystem.IsLinux())
        {
            using var metadata = LinuxOpenAt2(parent, name, noCrossMount: true);
            var basic = LinuxBasicIdentity(metadata);
            if (!basic.IsFile || basic.Volume != RootIdentity.Volume || basic.High != RootIdentity.High)
                throw new WorkspacePathException("file_identity_changed");
            return LinuxIdentity(metadata, _linuxFileSystemUuid);
        }

        if (OperatingSystem.IsWindows())
        {
            using var metadata = OpenWindowsEntryMetadata(parent, name);
            if (!GetFileInformationByHandle(metadata, out var basic) || !GetIdentityInformation(metadata, 18, out var id, 24) ||
                id.Volume != RootIdentity.Volume || (basic.FileAttributes & (0x400 | 0x10)) != 0 || GetFileType(metadata) != 1)
                throw new WorkspacePathException("file_identity_changed");
            return new WorkspaceObjectIdentity(id.Volume, id.Low, id.High, basic.CreationTime, 0, basic.NumberOfLinks, 0x8000);
        }

        throw new WorkspacePathException("path_enforcement_unavailable");
    }
}
