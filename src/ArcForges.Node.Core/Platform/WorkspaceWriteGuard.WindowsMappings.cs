// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspaceWriteGuard
{
    /// <summary>
    /// Rejects native section references which survive closing their original data handles. This query supplements
    /// the retained no-sharing handle; it is not a namespace/tree lock or an enumeration of every external handle.
    /// Unsupported filesystems, unavailable queries and incomplete results never establish an empty reference set.
    /// </summary>
    private static unsafe void CheckWindowsSectionReferences(SafeFileHandle file)
    {
        const int maximumBytes = 4096;
        if (!OperatingSystem.IsWindows() || IntPtr.Size != 8)
            throw new WorkspacePathException("file_guard_unavailable");

        var fileSystem = stackalloc char[32];
        new Span<char>(fileSystem, 32).Clear();
        if (!GetWindowsGuardVolumeInformation(file, null, 0, null, null, null, fileSystem, 32) ||
            !string.Equals(new string(fileSystem), "NTFS", StringComparison.OrdinalIgnoreCase))
            throw new WorkspacePathException("file_guard_unavailable");

        var buffer = stackalloc byte[maximumBytes];
        new Span<byte>(buffer, maximumBytes).Clear();
        // FileProcessIdsUsingFileInformation (47) is a native system information class. Its observed NTFS result
        // includes an independently held section even before MapViewOfFile, and views after section handles close.
        // Keep the exclusive file handle throughout this check and the guard's lifetime.
        var result = QueryWindowsGuardReferences(file, out var status, buffer, maximumBytes, 47);
        if (result != 0 || status.Status != 0 || status.Information < 8 || status.Information > maximumBytes)
            throw new WorkspacePathException("file_guard_unavailable");

        var count = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(buffer, 4));
        if (count > (maximumBytes - 8) / 8 || status.Information != 8u + 8u * count)
            throw new WorkspacePathException("file_guard_unavailable");
        if (count != 0)
            throw new WorkspacePathException("file_in_use");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsGuardIoStatus
    {
        internal nint Status;
        internal nuint Information;
    }

    [LibraryImport("ntdll.dll", EntryPoint = "NtQueryInformationFile")]
    private static unsafe partial int QueryWindowsGuardReferences(SafeFileHandle file, out WindowsGuardIoStatus status,
        byte* information, uint length, uint informationClass);

    [LibraryImport("kernel32.dll", EntryPoint = "GetVolumeInformationByHandleW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool GetWindowsGuardVolumeInformation(SafeFileHandle file, char* volumeName,
        uint volumeNameLength, uint* serial, uint* maximumName, uint* flags, char* fileSystemName, uint fileSystemNameLength);
}
