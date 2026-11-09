// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>Names observed in a single bounded enumeration of an opened directory, with an explicit overflow flag.</summary>
internal sealed record WorkspaceDirectoryPage(IReadOnlyList<string> Names, bool Truncated);

/// <summary>
/// Enumerates through a fresh opened directory handle. Names are not authority: each candidate must still be opened
/// relative to the workspace root with WorkspacePath's checks. This does not lock the namespace against same-user changes.
/// </summary>
internal static partial class WorkspaceDirectoryEntries
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly UnicodeEncoding StrictUtf16 = new(false, false, true);

    internal static WorkspaceDirectoryPage Read(WorkspacePath root, string relative, int maximum, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (maximum is < 1 or > 10_000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximum));
        }

        cancellationToken.ThrowIfCancellationRequested();
        using var handle = root.OpenDirectoryForEnumeration(relative);
        var initialIdentity = WorkspacePath.Identity(handle);
        var initialStamp = WorkspacePath.FileStamp(handle);
        var names = new List<string>();
        var overflow = OperatingSystem.IsLinux()
            ? LinuxRead(handle, names, maximum, cancellationToken)
            : OperatingSystem.IsWindows()
                ? WindowsRead(handle, names, maximum, cancellationToken)
                : throw new WorkspacePathException("path_enforcement_unavailable");
        if (!initialIdentity.SameObject(WorkspacePath.Identity(handle)) || initialStamp != WorkspacePath.FileStamp(handle))
        {
            throw new WorkspacePathException("directory_changed");
        }

        cancellationToken.ThrowIfCancellationRequested();
        names.Sort(StringComparer.Ordinal);
        return new WorkspaceDirectoryPage(names, overflow);
    }

    private static bool Add(List<string> names, string name, int maximum)
    {
        if (name is "." or "..")
        {
            return false;
        }

        // Use exactly the same portable component checks as a subsequent root-relative open.
        _ = WorkspacePath.Components(name);
        if (names.Count == maximum)
        {
            return true;
        }

        names.Add(name);
        return false;
    }

    private static bool LinuxRead(SafeFileHandle handle, List<string> names, int maximum, CancellationToken cancellationToken)
    {
        // Duplicate atomically with close-on-exec: a concurrent child cannot inherit this private directory.
        var copy = Fcntl(checked((int)handle.DangerousGetHandle()), 1030, 0); // F_DUPFD_CLOEXEC
        if (copy < 0)
        {
            throw new WorkspacePathException("directory_enumeration_unavailable");
        }

        var directory = FdOpenDir(copy);
        if (directory == 0)
        {
            _ = Close(copy);
            throw new WorkspacePathException("directory_enumeration_unavailable");
        }

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var entry = ReadDir(directory);
                if (entry == 0)
                {
                    if (Marshal.GetLastPInvokeError() != 0)
                    {
                        throw new WorkspacePathException("directory_enumeration_failed");
                    }

                    return false;
                }

                // Linux x64/arm64 struct dirent: d_reclen at 16 and the NUL-terminated d_name at 19.
                var length = unchecked((ushort)Marshal.ReadInt16(entry, 16));
                if (length < 20)
                {
                    throw new WorkspacePathException("directory_entry_invalid");
                }

                var bytes = new byte[length - 19];
                Marshal.Copy(entry + 19, bytes, 0, bytes.Length);
                var end = Array.IndexOf(bytes, (byte)0);
                if (end < 0)
                {
                    throw new WorkspacePathException("directory_entry_invalid");
                }

                string name;
                try
                {
                    name = StrictUtf8.GetString(bytes, 0, end);
                }
                catch (DecoderFallbackException exception)
                {
                    throw new WorkspacePathException("directory_entry_invalid_utf8", exception);
                }

                if (Add(names, name, maximum))
                {
                    return true;
                }
            }
        }
        finally
        {
            _ = CloseDir(directory); // closedir owns the dup, on every exit.
        }
    }

    private static unsafe bool WindowsRead(SafeFileHandle handle, List<string> names, int maximum, CancellationToken cancellationToken)
    {
        // FILE_ID_BOTH_DIR_INFO, returned by GetFileInformationByHandleEx. Both architectures use this documented layout.
        var buffer = new byte[65_536];
        var informationClass = 11; // FileIdBothDirectoryRestartInfo
        fixed (byte* data = buffer)
        {
            if (((nuint)data & 7) != 0)
            {
                throw new WorkspacePathException("directory_enumeration_unavailable");
            }

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Array.Clear(buffer);
                if (!GetDirectoryInformation(handle, informationClass, data, (uint)buffer.Length))
                {
                    var error = Marshal.GetLastPInvokeError();
                    if (error is 18 or 259) // ERROR_NO_MORE_FILES / ERROR_NO_MORE_ITEMS
                    {
                        return false;
                    }

                    throw new WorkspacePathException("directory_enumeration_failed");
                }

                informationClass = 10; // FileIdBothDirectoryInfo, continue this handle.
                var offset = 0;
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (offset < 0 || offset > buffer.Length - 104)
                    {
                        throw new WorkspacePathException("directory_entry_invalid");
                    }

                    var next = BitConverter.ToUInt32(buffer, offset);
                    var nameBytes = BitConverter.ToUInt32(buffer, offset + 60);
                    if ((nameBytes & 1) != 0 || nameBytes > buffer.Length - offset - 104)
                    {
                        throw new WorkspacePathException("directory_entry_invalid");
                    }

                    string name;
                    try
                    {
                        name = StrictUtf16.GetString(buffer, offset + 104, checked((int)nameBytes));
                    }
                    catch (DecoderFallbackException exception)
                    {
                        throw new WorkspacePathException("directory_entry_invalid_utf16", exception);
                    }

                    if (Add(names, name, maximum))
                    {
                        return true;
                    }

                    if (next == 0)
                    {
                        break;
                    }

                    if (next < 104 || (next & 7) != 0 || next > buffer.Length - offset)
                    {
                        throw new WorkspacePathException("directory_entry_invalid");
                    }

                    offset = checked(offset + (int)next);
                }
            }
        }
    }

    [LibraryImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    private static partial int Fcntl(int fd, int command, int argument);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int Close(int fd);

    [LibraryImport("libc", EntryPoint = "fdopendir", SetLastError = true)]
    private static partial nint FdOpenDir(int fd);

    [LibraryImport("libc", EntryPoint = "readdir", SetLastError = true)]
    private static partial nint ReadDir(nint directory);

    [LibraryImport("libc", EntryPoint = "closedir", SetLastError = true)]
    private static partial int CloseDir(nint directory);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool GetDirectoryInformation(SafeFileHandle file, int informationClass, byte* buffer, uint size);
}
