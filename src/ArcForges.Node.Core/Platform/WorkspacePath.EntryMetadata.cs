// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>The observed final entry's type; links and special objects are metadata only.</summary>
internal enum WorkspaceEntryType
{
    File = 1,
    Directory = 2,
    Link = 3,
    Other = 4,
}

/// <summary>A no-follow metadata observation, never an authority to perform a later name-based effect.</summary>
internal readonly record struct WorkspaceEntryMetadata(WorkspaceEntryType Kind, ulong? Size,
    WorkspaceObjectIdentity Identity, WorkspaceFileStamp Stamp)
{
    internal ulong? AllocatedBytes { get; init; }
}

internal sealed partial class WorkspacePath
{
    /// <summary>
    /// Inspects the final entry without opening its data. Ancestors retain the normal checked
    /// no-follow semantics; a final link is reported as a link and is never traversed.
    /// </summary>
    internal WorkspaceEntryMetadata InspectEntry(string path, bool allowRoot = false, bool observeAllocation = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var parts = Components(path, allowRoot);
        if (parts.Length == 0)
        {
            return new WorkspaceEntryMetadata(WorkspaceEntryType.Directory, null, RootIdentity, FileStamp(RootHandle))
            {
                AllocatedBytes = observeAllocation ? ReadEntryAllocation(RootHandle) : null,
            };
        }

        if (OperatingSystem.IsLinux())
        {
            using var metadata = LinuxOpenAt2(RootHandle, string.Join('/', parts), noCrossMount: true);
            var basic = LinuxBasicIdentity(metadata);
            if (basic.Volume != RootIdentity.Volume || basic.High != RootIdentity.High)
            {
                throw new WorkspacePathException("mount_crossing");
            }

            var type = (basic.Mode & 0xf000) switch
            {
                0x8000 => WorkspaceEntryType.File,
                0x4000 => WorkspaceEntryType.Directory,
                0xa000 => WorkspaceEntryType.Link,
                _ => WorkspaceEntryType.Other,
            };
            var identity = type is WorkspaceEntryType.File or WorkspaceEntryType.Directory
                ? LinuxIdentity(metadata, _linuxFileSystemUuid)
                : basic;
            var stamp = FileStamp(metadata);
            if (stamp.Size < 0)
            {
                throw new WorkspacePathException("file_metadata_unavailable");
            }

            return new WorkspaceEntryMetadata(type, type == WorkspaceEntryType.File ? checked((ulong)stamp.Size) : null, identity, stamp)
            {
                AllocatedBytes = observeAllocation ? ReadEntryAllocation(metadata) : null,
            };
        }

        if (OperatingSystem.IsWindows())
        {
            var parent = RootHandle;
            foreach (var component in parts.AsSpan(0, parts.Length - 1))
            {
                parent = RetainCheckedDirectory(OpenChild(parent, component, directory: true));
            }

            using var metadata = OpenWindowsEntryMetadata(parent, parts[^1]);
            if (!GetFileInformationByHandle(metadata, out var basic) ||
                !GetIdentityInformation(metadata, 18, out var id, 24))
            {
                throw new WorkspacePathException("file_metadata_unavailable");
            }

            if (id.Volume != RootIdentity.Volume)
            {
                throw new WorkspacePathException("mount_crossing");
            }

            var type = (basic.FileAttributes & 0x400) != 0
                ? WorkspaceEntryType.Link
                : GetFileType(metadata) != 1
                    ? WorkspaceEntryType.Other
                    : (basic.FileAttributes & 0x10) != 0 ? WorkspaceEntryType.Directory : WorkspaceEntryType.File;
            var mode = type switch
            {
                WorkspaceEntryType.File => 0x8000u,
                WorkspaceEntryType.Directory => 0x4000u,
                WorkspaceEntryType.Link => 0xa000u,
                _ => 0u,
            };
            var identity = new WorkspaceObjectIdentity(id.Volume, id.Low, id.High, basic.CreationTime, 0, basic.NumberOfLinks, mode);
            var stamp = FileStamp(metadata);
            if (stamp.Size < 0)
            {
                throw new WorkspacePathException("file_metadata_unavailable");
            }

            return new WorkspaceEntryMetadata(type, type == WorkspaceEntryType.File ? checked((ulong)stamp.Size) : null, identity, stamp)
            {
                AllocatedBytes = observeAllocation ? ReadEntryAllocation(metadata) : null,
            };
        }

        throw new WorkspacePathException("path_enforcement_unavailable");
    }

    /// <summary>Anchors all observations of one selected Linux directory to the same native descriptor.</summary>
    internal WorkspacePath OpenLinuxEntryDirectory(string path)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!OperatingSystem.IsLinux()) throw new WorkspacePathException("path_enforcement_unavailable");
        var relative = string.Join('/', Components(path));
        using var metadata = LinuxOpenAt2(RootHandle, relative, noCrossMount: true);
        CheckVolume(metadata, _linuxFileSystemUuid);
        var selected = new WorkspacePath();
        try
        {
            var opened = Retain(selected._directories, LinuxReopenChecked(metadata, directory: true,
                knownUuid: _linuxFileSystemUuid, afterMetadataOpen: null));
            selected._rootHandle = opened;
            selected._linuxFileSystemUuid = _linuxFileSystemUuid;
            selected.RootIdentity = LinuxIdentity(opened, _linuxFileSystemUuid);
            selected.RootPath = FinalPath(opened, Path.Combine(RootPath, relative));
            return selected;
        }
        catch
        {
            selected.Dispose();
            throw;
        }
    }

    private static unsafe ulong? ReadEntryAllocation(SafeFileHandle handle)
    {
        if (OperatingSystem.IsLinux())
        {
            const uint blocksMask = 0x400; // STATX_BLOCKS
            var buffer = stackalloc byte[256];
            if (Statx(checked((int)handle.DangerousGetHandle()), string.Empty, 0x1000 | 0x100, blocksMask, buffer) != 0 ||
                (*(uint*)buffer & blocksMask) == 0)
            {
                return null;
            }

            var blocks = *(ulong*)(buffer + 48);
            return blocks <= ulong.MaxValue / 512 ? blocks * 512 : null;
        }

        return OperatingSystem.IsWindows() && GetAllocationInformation(handle, 1, out var standard, (uint)sizeof(FileAllocationInformation)) &&
            standard.AllocationSize >= 0 ? (ulong)standard.AllocationSize : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAllocationInformation
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        public byte DeletePending;
        public byte Directory;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetAllocationInformation(SafeFileHandle file, int informationClass,
        out FileAllocationInformation information, uint size);

    private static unsafe SafeFileHandle OpenWindowsEntryMetadata(SafeFileHandle parent, string name)
    {
        uint caseFlags;
        if (!GetCaseInformation(parent, 23, &caseFlags, sizeof(uint)))
        {
            throw new WorkspacePathException("case_semantics_unavailable");
        }

        var retained = false;
        try
        {
            parent.DangerousAddRef(ref retained);
            fixed (char* characters = name)
            {
                var unicode = new UnicodeString
                {
                    Length = checked((ushort)(name.Length * 2)),
                    MaximumLength = checked((ushort)(name.Length * 2)),
                    Buffer = (nint)characters,
                };
                var attributes = new ObjectAttributes
                {
                    Length = (uint)sizeof(ObjectAttributes),
                    RootDirectory = parent.DangerousGetHandle(),
                    ObjectName = (nint)(&unicode),
                    Attributes = (caseFlags & 1) == 0 ? 0x40u : 0u,
                };
                // Attributes only, OPEN_REPARSE_POINT, no directory/non-directory hint.
                // Opening a FIFO/device data stream is never part of metadata inspection.
                var status = NtCreateFile(out var raw, 0x00100080, ref attributes, out _, 0, 0, 7, 1,
                    0x20 | 0x00200000, 0, 0);
                if (status < 0)
                {
                    throw new WorkspacePathException("native_" + RtlNtStatusToDosError(status).ToString(CultureInfo.InvariantCulture));
                }

                return new SafeFileHandle(raw, ownsHandle: true);
            }
        }
        finally
        {
            if (retained)
            {
                parent.DangerousRelease();
            }
        }
    }
}
