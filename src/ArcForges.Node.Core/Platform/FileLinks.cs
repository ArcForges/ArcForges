// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// The hard-link count of a file, read without following a final symbolic link or reparse point: Linux <c>statx(AT_SYMLINK_NOFOLLOW,
/// STATX_NLINK)</c>; Windows <c>GetFileInformationByHandle</c> on a handle opened with <c>FILE_FLAG_OPEN_REPARSE_POINT</c>. A file with more
/// than one link shares its inode (its data, mode and attributes) with a name elsewhere, so changing it changes that other name too.
/// </summary>
public static partial class FileLinks
{
    /// <summary>The number of hard links of <paramref name="path"/>, or <see langword="null"/> when it cannot be read.</summary>
    public static long? Count(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (OperatingSystem.IsWindows())
        {
            return WindowsCount(path);
        }

        return OperatingSystem.IsLinux() ? LinuxCount(path) : null;
    }

    private static unsafe long? LinuxCount(string path)
    {
        // struct statx: stx_mask (u32) at offset 0, stx_nlink (u32) at offset 16, 256 bytes in all, on every architecture.
        const int AtFdCwd = -100;
        const int AtSymlinkNoFollow = 0x100;
        const uint StatxNlink = 0x4;
        var buffer = stackalloc byte[256];
        if (Statx(AtFdCwd, path, AtSymlinkNoFollow, StatxNlink, buffer) != 0 || (*(uint*)buffer & StatxNlink) == 0)
        {
            return null;
        }

        return *(uint*)(buffer + 16);
    }

    private static long? WindowsCount(string path)
    {
        const uint FileReadAttributes = 0x80;
        const uint ShareAll = 0x7;
        const uint OpenExisting = 3;
        const uint OpenReparsePoint = 0x0020_0000;
        const uint BackupSemantics = 0x0200_0000;
        using var handle = CreateFile(path, FileReadAttributes, ShareAll, 0, OpenExisting, OpenReparsePoint | BackupSemantics, 0);
        return !handle.IsInvalid && GetFileInformationByHandle(handle, out var information) ? information.NumberOfLinks : null;
    }

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static unsafe partial int Statx(int directory, string path, int flags, uint mask, byte* buffer);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFile(string name, uint access, uint share, nint security, uint disposition, uint flags, nint template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

    // BY_HANDLE_FILE_INFORMATION: FILETIMEs are two DWORDs (4-byte aligned), hence Pack = 4 for the ulong fields.
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public ulong CreationTime;
        public ulong LastAccessTime;
        public ulong LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}
