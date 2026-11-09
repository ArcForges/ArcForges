// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>The identity read from an opened filesystem object, not from its name.</summary>
internal readonly record struct WorkspaceObjectIdentity(ulong Volume, ulong Low, ulong High, ulong Created, uint CreatedNanoseconds, uint Links, uint Mode, ReadOnlyMemory<byte> InstanceToken = default)
{
    /// <summary>True for an ordinary directory.</summary>
    public bool IsDirectory => (Mode & 0xf000) == 0x4000;

    /// <summary>True for an ordinary file.</summary>
    public bool IsFile => (Mode & 0xf000) == 0x8000;

    /// <summary>The persistent object identity; link count and current mode are separate checks.</summary>
    public bool SameObject(WorkspaceObjectIdentity other) => Created == other.Created && CreatedNanoseconds == other.CreatedNanoseconds &&
        (InstanceToken.IsEmpty && other.InstanceToken.IsEmpty
            ? Volume == other.Volume && Low == other.Low && High == other.High
            : !InstanceToken.IsEmpty && !other.InstanceToken.IsEmpty && InstanceToken.Span.SequenceEqual(other.InstanceToken.Span));
}

/// <summary>A closed, non-content-bearing refusal of native workspace resolution.</summary>
internal sealed class WorkspacePathException(string reason, Exception? inner = null) : IOException(reason, inner)
{
    /// <summary>The closed refusal reason.</summary>
    public string Reason { get; } = reason;
}

/// <summary>
/// A handle-anchored workspace path. Native directory handles stay open until the operation ends; final files are opened without
/// following links. All I/O uses the returned handle. This is API path validation, not confinement of another process of the same user.
/// </summary>
internal sealed partial class WorkspacePath : IDisposable
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly List<SafeFileHandle> _directories = [];
    private readonly List<SafeFileHandle> _files = [];
    private SafeFileHandle? _rootHandle;
    private bool _disposed;

    private WorkspacePath()
    {
    }

    /// <summary>The registered root's actual opened identity.</summary>
    public WorkspaceObjectIdentity RootIdentity { get; private set; }

    /// <summary>The opened root's canonical native path.</summary>
    public string RootPath { get; private set; } = string.Empty;

    /// <summary>The root's directory handle.</summary>
    public SafeFileHandle RootHandle => _rootHandle ?? throw new ObjectDisposedException(nameof(WorkspacePath));

    /// <summary>
    /// Opens an existing absolute directory without following any component's link and records the actual root identity.
    /// A supplied expected identity is checked before serving a registered workspace again.
    /// </summary>
    public static WorkspacePath OpenRoot(string path, WorkspaceObjectIdentity? expected = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ValidateUtf8Path(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new WorkspacePathException("root_not_absolute");
        }

        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ?? throw new WorkspacePathException("root_not_absolute");
        if (OperatingSystem.IsWindows() && (root.Length != 3 || !char.IsAsciiLetter(root[0]) || root[1] != ':'))
        {
            throw new WorkspacePathException("root_not_supported");
        }

        var owner = new WorkspacePath();
        try
        {
            var first = OperatingSystem.IsWindows() ? WindowsRoot(root) : LinuxOpen(-100, "/", directory: true);
            owner._directories.Add(first);
            var current = first;
            var relative = full[root.Length..].TrimEnd(Path.DirectorySeparatorChar);
            foreach (var component in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
            {
                ValidateComponent(component);
                current = OpenChild(current, component, directory: true);
                owner._directories.Add(current);
            }

            owner._rootHandle = current;
            owner.RootIdentity = Identity(current);
            if (!owner.RootIdentity.IsDirectory)
            {
                throw new WorkspacePathException("root_not_directory");
            }

            if (expected is { } identity && !identity.SameObject(owner.RootIdentity))
            {
                throw new WorkspacePathException("root_changed");
            }

            owner.RootPath = FinalPath(current);
            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>Validates a portable relative path and returns its exact components.</summary>
    public static string[] Components(string path, bool allowRoot = false)
    {
        ArgumentNullException.ThrowIfNull(path);
        ValidateUtf8Path(path);

        if (path.Length == 0)
        {
            return allowRoot ? [] : throw new WorkspacePathException("root_operation_refused");
        }

        if (path[0] == '/' || (path.Length >= 2 && char.IsAsciiLetter(path[0]) && path[1] == ':') || path.Contains('\\', StringComparison.Ordinal) || path.Contains('\0', StringComparison.Ordinal))
        {
            throw new WorkspacePathException("path_invalid");
        }

        var parts = path.Split('/');
        foreach (var part in parts)
        {
            ValidateComponent(part);
        }

        return parts;
    }

    /// <summary>Opens a checked directory beneath this root, retaining the complete directory chain.</summary>
    public SafeFileHandle OpenDirectory(string path)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var current = RootHandle;
        foreach (var component in Components(path, allowRoot: true))
        {
            current = OpenChild(current, component, directory: true);
            _directories.Add(current);
            CheckVolume(current);
        }

        return current;
    }

    /// <summary>Opens a regular single-link file for reading beneath the root; callers never reopen its unchecked path.</summary>
    public SafeFileHandle OpenRead(string path)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var parts = Components(path);
        var parent = RootHandle;
        foreach (var component in parts.AsSpan(0, parts.Length - 1))
        {
            parent = OpenChild(parent, component, directory: true);
            _directories.Add(parent);
            CheckVolume(parent);
        }

        var file = OpenChild(parent, parts[^1], directory: false);
        try
        {
            var identity = Identity(file);
            if (!identity.IsFile || identity.Links != 1)
            {
                throw new WorkspacePathException(identity.Links != 1 ? "file_hard_link" : "file_not_regular");
            }

            CheckVolume(file);
            _files.Add(file);
            return file;
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    /// <summary>Reads identity, kind and hard-link count from the actual opened handle.</summary>
    public static WorkspaceObjectIdentity Identity(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        return OperatingSystem.IsWindows() ? WindowsIdentity(handle) : LinuxIdentity(handle);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        for (var index = _files.Count - 1; index >= 0; index--)
        {
            _files[index].Dispose();
        }

        for (var index = _directories.Count - 1; index >= 0; index--)
        {
            _directories[index].Dispose();
        }
    }

    private void CheckVolume(SafeFileHandle handle)
    {
        var identity = Identity(handle);
        if (identity.Volume != RootIdentity.Volume || identity.High != RootIdentity.High && OperatingSystem.IsLinux())
        {
            throw new WorkspacePathException("mount_crossing");
        }
    }

    private static void ValidateUtf8Path(string path)
    {
        try
        {
            if (StrictUtf8.GetByteCount(path) > 4096)
            {
                throw new WorkspacePathException("path_too_large");
            }
        }
        catch (EncoderFallbackException exception)
        {
            throw new WorkspacePathException("path_invalid_utf8", exception);
        }
    }

    private static void ValidateComponent(string value)
    {
        if (value.Length == 0 || value is "." or ".." || value.Contains('\0', StringComparison.Ordinal) ||
            value.Contains('/', StringComparison.Ordinal) || value.Contains('\\', StringComparison.Ordinal))
        {
            throw new WorkspacePathException("path_invalid");
        }

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (value.Contains(':', StringComparison.Ordinal) || value.EndsWith(' ') || value.EndsWith('.') ||
            value.Any(static character => character < 32 || character is '<' or '>' or '"' or '|' or '?' or '*'))
        {
            throw new WorkspacePathException("path_reserved");
        }

        var stem = value.Split('.')[0];
        if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase) || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
            ((stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) &&
             stem.Length == 4 && (stem[3] is >= '1' and <= '9' or '\u00b9' or '\u00b2' or '\u00b3')))
        {
            throw new WorkspacePathException("path_reserved");
        }
    }

    private static SafeFileHandle OpenChild(SafeFileHandle parent, string component, bool directory)
    {
        var handle = OperatingSystem.IsWindows() ? WindowsOpen(parent, component, directory) : LinuxOpen(checked((int)parent.DangerousGetHandle()), component, directory);
        try
        {
            var identity = Identity(handle);
            if (directory ? !identity.IsDirectory : !identity.IsFile)
            {
                throw new WorkspacePathException("path_link_or_special");
            }

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle LinuxOpen(int parent, string name, bool directory)
    {
        // O_NONBLOCK prevents a raced-in FIFO from blocking the control loop; fstat refuses any non-regular final object.
        const int ReadOnly = 0;
        const int NonBlock = 0x800;
        const int CloseOnExec = 0x80000;
        const int NoFollow = 0x20000;
        const int Directory = 0x10000;
        var descriptor = OpenAt(parent, name, ReadOnly | NonBlock | CloseOnExec | NoFollow | (directory ? Directory : 0), 0);
        if (descriptor < 0)
        {
            throw NativeFailure();
        }

        return new SafeFileHandle(descriptor, ownsHandle: true);
    }

    private static unsafe WorkspaceObjectIdentity LinuxIdentity(SafeFileHandle handle)
    {
        // Birth time is part of the persistent identity; unsupported metadata cannot silently become zero.
        const uint Required = 0x1000 | 0x800 | 0x100 | 0x4 | 0x1;
        var buffer = stackalloc byte[256];
        if (Statx(checked((int)handle.DangerousGetHandle()), string.Empty, 0x1000 | 0x100, Required, buffer) != 0 ||
            (*(uint*)buffer & Required) != Required)
        {
            throw new WorkspacePathException("identity_unavailable");
        }

        // Inodes and birth times can both repeat within one clock tick. A filesystem UUID and opaque export handle
        // distinguish the actual instance (including its filesystem generation) without treating a volatile mount ID as durable.
        var instance = LinuxInstanceToken(handle, *(ulong*)(buffer + 144));

        var mode = *(ushort*)(buffer + 28);
        var created = unchecked((ulong)*(long*)(buffer + 80));
        var createdNanos = *(uint*)(buffer + 88);
        return new WorkspaceObjectIdentity(((ulong)*(uint*)(buffer + 136) << 32) | *(uint*)(buffer + 140),
            *(ulong*)(buffer + 32), *(ulong*)(buffer + 144), created, createdNanos, *(uint*)(buffer + 16), mode, instance);
    }

    private static SafeFileHandle WindowsRoot(string path)
    {
        var handle = CreateFile(path, 0x00100081, 3, 0, 3, 0x02200000, 0);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw NativeFailure();
        }

        return handle;
    }

    private static unsafe SafeFileHandle WindowsOpen(SafeFileHandle parent, string name, bool directory)
    {
        // FILE_CASE_SENSITIVE_INFO is read from the actual parent. A case-sensitive directory must retain exact-case lookup.
        uint flags;
        if (!GetCaseInformation(parent, 23, &flags, sizeof(uint)))
        {
            throw new WorkspacePathException("case_semantics_unavailable");
        }

        fixed (char* characters = name)
        {
            var unicode = new UnicodeString { Length = checked((ushort)(name.Length * 2)), MaximumLength = checked((ushort)(name.Length * 2)), Buffer = (nint)characters };
            var attributes = new ObjectAttributes
            {
                Length = (uint)sizeof(ObjectAttributes),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = (nint)(&unicode),
                Attributes = (flags & 1) == 0 ? 0x40u : 0u,
            };
            var status = NtCreateFile(out var raw, 0x00100081, ref attributes, out _, 0, 0, directory ? 3u : 1u, 1,
                0x20u | 0x00200000u | (directory ? 1u : 0x40u), 0, 0);
            if (status < 0)
            {
                throw new WorkspacePathException("native_" + RtlNtStatusToDosError(status).ToString(CultureInfo.InvariantCulture));
            }

            return new SafeFileHandle(raw, ownsHandle: true);
        }
    }

    private static unsafe WorkspaceObjectIdentity WindowsIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information) || !GetIdentityInformation(handle, 18, out var id, (uint)sizeof(FileIdInformation)) ||
            (information.FileAttributes & 0x400) != 0 || GetFileType(handle) != 1)
        {
            throw new WorkspacePathException("identity_unavailable_or_reparse");
        }

        return new WorkspaceObjectIdentity(id.Volume, id.Low, id.High, information.CreationTime, 0, information.NumberOfLinks,
            (information.FileAttributes & 0x10) != 0 ? 0x4000u : 0x8000u);
    }

    private static string FinalPath(SafeFileHandle handle)
    {
        if (OperatingSystem.IsWindows())
        {
            var output = new char[32768];
            var count = GetFinalPathNameByHandle(handle, output, (uint)output.Length, 0);
            if (count == 0 || count >= output.Length)
            {
                throw new WorkspacePathException("canonical_path_unavailable");
            }

            var windowsCanonical = new string(output, 0, (int)count);
            return windowsCanonical.StartsWith("\\\\?\\", StringComparison.Ordinal) ? windowsCanonical[4..] : throw new WorkspacePathException("root_not_supported");
        }

        var name = "/proc/self/fd/" + handle.DangerousGetHandle().ToInt64().ToString(CultureInfo.InvariantCulture);
        var bytes = new byte[16384];
        var length = ReadLink(name, bytes, (nuint)bytes.Length);
        if (length <= 0 || length >= bytes.Length)
        {
            throw new WorkspacePathException("canonical_path_unavailable");
        }

        var canonical = StrictUtf8.GetString(bytes, 0, checked((int)length));
        return canonical.EndsWith(" (deleted)", StringComparison.Ordinal) ? throw new WorkspacePathException("root_changed") : canonical;
    }

    private static WorkspacePathException NativeFailure() => new("native_" + Marshal.GetLastPInvokeError().ToString(CultureInfo.InvariantCulture));

    [LibraryImport("libc", EntryPoint = "openat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int OpenAt(int directory, string path, int flags, uint mode);

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static unsafe partial int Statx(int directory, string path, int flags, uint mask, byte* buffer);

    private static unsafe byte[] LinuxInstanceToken(SafeFileHandle handle, ulong mountId)
    {
        var descriptor = checked((int)handle.DangerousGetHandle());
        var fileHandle = stackalloc byte[136];
        new Span<byte>(fileHandle, 136).Clear();
        *(uint*)fileHandle = 128;
        if (NameToHandleAt(descriptor, string.Empty, fileHandle, out var exportedMount, 0x1000) != 0 ||
            *(uint*)fileHandle is 0 or > 128 || (ulong)(uint)exportedMount != mountId)
        {
            throw new WorkspacePathException("identity_handle_unavailable");
        }

        var uuid = stackalloc byte[17];
        new Span<byte>(uuid, 17).Clear();
        // FS_IOC_GETFSUUID, a read-only generic Linux ioctl; fsuuid2 is a length byte plus sixteen UUID bytes.
        if (ReadFileSystemUuid(descriptor, 0x80111500, uuid) != 0 || uuid[0] != 16 ||
            new ReadOnlySpan<byte>(uuid + 1, 16).IndexOfAnyExcept((byte)0) < 0)
        {
            throw new WorkspacePathException("identity_filesystem_unavailable");
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges fs-object v1\0"u8);
        hash.AppendData(new ReadOnlySpan<byte>(uuid + 1, 16));
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteInt32BigEndian(header, *(int*)(fileHandle + 4));
        BinaryPrimitives.WriteUInt32BigEndian(header[4..], *(uint*)fileHandle);
        hash.AppendData(header);
        hash.AppendData(new ReadOnlySpan<byte>(fileHandle + 8, checked((int)*(uint*)fileHandle)));
        return hash.GetHashAndReset();
    }

    [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static unsafe partial int ReadFileSystemUuid(int descriptor, nuint request, byte* buffer);

    [LibraryImport("libc", EntryPoint = "name_to_handle_at", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static unsafe partial int NameToHandleAt(int descriptor, string name, byte* fileHandle, out int mountId, int flags);

    [LibraryImport("libc", EntryPoint = "readlink", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial nint ReadLink(string path, [Out] byte[] buffer, nuint size);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFile(string name, uint access, uint share, nint security, uint disposition, uint flags, nint template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool GetCaseInformation(SafeFileHandle file, int informationClass, uint* buffer, uint size);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetIdentityInformation(SafeFileHandle file, int informationClass, out FileIdInformation information, uint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint GetFileType(SafeFileHandle file);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial uint GetFinalPathNameByHandle(SafeFileHandle file, [Out] char[] path, uint length, uint flags);

    [LibraryImport("ntdll.dll", SetLastError = false)]
    private static partial int NtCreateFile(out nint handle, uint access, ref ObjectAttributes attributes, out IoStatusBlock status, nint allocation,
        uint fileAttributes, uint share, uint disposition, uint options, nint ea, uint eaLength);

    [LibraryImport("ntdll.dll")]
    private static partial uint RtlNtStatusToDosError(int status);

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public uint Length;
        public nint RootDirectory;
        public nint ObjectName;
        public uint Attributes;
        public nint SecurityDescriptor;
        public nint SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public nint Status;
        public nuint Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInformation
    {
        public ulong Volume;
        public ulong Low;
        public ulong High;
    }

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
