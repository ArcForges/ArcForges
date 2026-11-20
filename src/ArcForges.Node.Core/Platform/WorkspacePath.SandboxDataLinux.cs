// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    private const uint LinuxOwnerReadWrite = 0x180;
    private const int LinuxFollowDescriptorLink = 0x400;

    [SupportedOSPlatform("linux")]
    private SafeFileHandle CreateSandboxDataStageLinux(string name)
    {
        RequireSandboxTransferDirectoryLinux(name);
        int noFollow = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 0x8000 : 0x20000;
        // O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW.
        int descriptor = OpenAt(SandboxDataLinuxDescriptor(RootHandle), name, 0x808c2 | noFollow, LinuxOwnerReadWrite);
        if (descriptor < 0) throw NativeFailure();

        var file = new SafeFileHandle(descriptor, ownsHandle: true);
        try
        {
            var identity = RequireSandboxDataLinuxFile(file, links: 1);
            LinuxUseSynchronousFileIo(file);
            if (RandomAccess.GetLength(file) != 0) throw new WorkspacePathException("file_identity_changed");
            RandomAccess.FlushToDisk(file);
            SyncSandboxDataLinuxDirectory(RootHandle);
            RequireSandboxDataLinuxName(RootHandle, name, identity, links: 1);
            return file;
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    [SupportedOSPlatform("linux")]
    private SafeFileHandle OpenSandboxDataStageLinux(string name, WorkspaceObjectIdentity expected, bool writable)
    {
        RequireSandboxTransferDirectoryLinux(name);
        using var metadata = LinuxOpenAt2(RootHandle, name, noCrossMount: true);
        var selected = RequireSandboxDataLinuxFile(metadata, links: 1);
        if (!expected.SameObject(selected)) throw new WorkspacePathException("file_identity_changed");

        var file = LinuxReopenChecked(metadata, directory: false, _linuxFileSystemUuid, afterMetadataOpen: null, writable: writable);
        try
        {
            if (!expected.SameObject(RequireSandboxDataLinuxFile(file, links: 1)))
            {
                throw new WorkspacePathException("file_identity_changed");
            }

            RequireSandboxDataLinuxName(RootHandle, name, expected, links: 1);
            return file;
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    [SupportedOSPlatform("linux")]
    private void PublishSandboxDataStageLinux(SafeFileHandle stage, string stageName, SafeFileHandle targetParent,
        string targetName, Action applied)
    {
        ArgumentNullException.ThrowIfNull(applied);
        RequireSandboxTransferDirectoryLinux(stageName);
        RequireSandboxDataLinuxNameComponent(targetName);
        var parent = LinuxIdentity(targetParent, _linuxFileSystemUuid);
        if (!parent.IsDirectory || parent.Links == 0) throw new WorkspacePathException("directory_identity_changed");
        RequireSandboxDataLinuxVolume(parent);

        var retained = false;
        try
        {
            stage.DangerousAddRef(ref retained);
            var identity = RequireSandboxDataLinuxFile(stage, links: 1);
            RequireSandboxDataLinuxName(RootHandle, stageName, identity, links: 1);
            RandomAccess.FlushToDisk(stage);
            using var proc = LinuxProcFdDirectory();
            var descriptor = SandboxDataLinuxDescriptor(stage).ToString(CultureInfo.InvariantCulture);
            // The kernel resolves the held file descriptor as the source and refuses a preexisting destination.
            if (LinkSandboxDataLinux(SandboxDataLinuxDescriptor(proc), descriptor, SandboxDataLinuxDescriptor(targetParent),
                    targetName, LinuxFollowDescriptorLink) != 0)
            {
                throw NativeFailure();
            }

            applied();
            RandomAccess.FlushToDisk(stage);
            SyncSandboxDataLinuxDirectory(targetParent);

            // Preserve the private name until the destination is durable and both names identify the same inode.
            RequireSandboxDataLinuxName(targetParent, targetName, identity, links: 2);
            RequireSandboxDataLinuxName(RootHandle, stageName, identity, links: 2);
            UnlinkSandboxDataLinuxName(stageName);
            SyncSandboxDataLinuxDirectory(RootHandle);
            RequireSandboxDataLinuxName(targetParent, targetName, identity, links: 1);
        }
        finally
        {
            if (retained) stage.DangerousRelease();
        }
    }

    [SupportedOSPlatform("linux")]
    private void RemoveSandboxDataStageLinux(string name, WorkspaceObjectIdentity expected, Action applied)
    {
        ArgumentNullException.ThrowIfNull(applied);
        RequireSandboxTransferDirectoryLinux(name);
        using var metadata = LinuxOpenAt2(RootHandle, name, noCrossMount: true);
        if (!expected.SameObject(RequireSandboxDataLinuxFile(metadata, links: 1)))
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        UnlinkSandboxDataLinuxName(name);
        applied();
        SyncSandboxDataLinuxDirectory(RootHandle);
        if (LinuxBasicIdentity(metadata).Links != 0)
        {
            throw new WorkspacePathException("file_identity_changed");
        }
    }

    [SupportedOSPlatform("linux")]
    private void RequireSandboxTransferDirectoryLinux(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireSandboxDataLinuxNameComponent(name);
        CheckSandboxDirectory(RootHandle, configuredRoot: false);
        var actual = LinuxIdentity(RootHandle, _linuxFileSystemUuid);
        if (!RootIdentity.SameObject(actual) || !actual.IsDirectory || actual.Links == 0)
        {
            throw new WorkspacePathException("directory_identity_changed");
        }

        using var namedRoot = OpenRoot(RootPath, RootIdentity);
    }

    private static void RequireSandboxDataLinuxNameComponent(string name)
    {
        if (Components(name).Length != 1) throw new WorkspacePathException("path_invalid");
    }

    [SupportedOSPlatform("linux")]
    private WorkspaceObjectIdentity RequireSandboxDataLinuxFile(SafeFileHandle file, uint links)
    {
        var identity = LinuxIdentity(file, _linuxFileSystemUuid);
        if (!identity.IsFile || identity.Links != links || (identity.Mode & 0x1ff) != LinuxOwnerReadWrite)
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        RequireSandboxDataLinuxVolume(identity);
        CheckPrivateLinuxNamedStageSecurity(file);
        return identity;
    }

    private void RequireSandboxDataLinuxVolume(WorkspaceObjectIdentity identity)
    {
        if (identity.Volume != RootIdentity.Volume || identity.High != RootIdentity.High)
        {
            throw new WorkspacePathException("mount_crossing");
        }
    }

    [SupportedOSPlatform("linux")]
    private void RequireSandboxDataLinuxName(SafeFileHandle directory, string name, WorkspaceObjectIdentity expected, uint links)
    {
        using var named = LinuxOpenAt2(directory, name, noCrossMount: true);
        if (!expected.SameObject(RequireSandboxDataLinuxFile(named, links)))
        {
            throw new WorkspacePathException("file_identity_changed");
        }
    }

    private static int SandboxDataLinuxDescriptor(SafeFileHandle file) => checked((int)file.DangerousGetHandle());

    private static void SyncSandboxDataLinuxDirectory(SafeFileHandle directory)
    {
        if (SyncDirectory(SandboxDataLinuxDescriptor(directory)) != 0) throw NativeFailure();
    }

    private void UnlinkSandboxDataLinuxName(string name)
    {
        if (UnlinkSandboxDataLinux(SandboxDataLinuxDescriptor(RootHandle), name, flags: 0) != 0) throw NativeFailure();
    }

    [LibraryImport("libc", EntryPoint = "linkat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int LinkSandboxDataLinux(int sourceParent, string sourceName, int targetParent, string targetName, int flags);

    [LibraryImport("libc", EntryPoint = "unlinkat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int UnlinkSandboxDataLinux(int directory, string name, int flags);
}
