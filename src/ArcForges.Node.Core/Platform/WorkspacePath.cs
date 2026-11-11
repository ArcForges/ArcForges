// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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

/// <summary>Observable metadata used to reject an opened file changing while its bytes are inspected.</summary>
internal readonly record struct WorkspaceFileStamp(long Size, long Modification, uint ModificationNanoseconds, long Change, uint ChangeNanoseconds);

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
    private SafeFileHandle? _windowsRootParent;
    private string? _windowsRootName;
    private string? _windowsDriveRoot;
    private byte[]? _linuxFileSystemUuid;
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
    public static WorkspacePath OpenRoot(string path, WorkspaceObjectIdentity? expected = null) => OpenRoot(path, expected, afterRootOpen: null);

    // The callback only coordinates actual filesystem races in component tests; production passes no callback.
    internal static WorkspacePath OpenRoot(string path, WorkspaceObjectIdentity? expected, Action? afterRootOpen)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ValidateUtf8Path(path);
        if (path.Contains('\0', StringComparison.Ordinal))
        {
            throw new WorkspacePathException("path_invalid");
        }

        if (!Path.IsPathFullyQualified(path))
        {
            throw new WorkspacePathException("root_not_absolute");
        }

        // Reject the supplied components before any normalization can erase ".", "..", or an empty component.
        var root = Path.GetPathRoot(path) ?? throw new WorkspacePathException("root_not_absolute");
        if (OperatingSystem.IsWindows() && (root.Length != 3 || !char.IsAsciiLetter(root[0]) || root[1] != ':'))
        {
            throw new WorkspacePathException("root_not_supported");
        }

        var raw = path[root.Length..];
        var parts = raw.Length == 0 ? [] : raw.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.None);
        foreach (var component in parts)
        {
            ValidateComponent(component);
        }

        var owner = new WorkspacePath();
        try
        {
            SafeFileHandle current;
            if (OperatingSystem.IsLinux())
            {
                // Registration may traverse to a filesystem mounted below /; the registered root anchors later NO_XDEV lookups.
                using var slash = LinuxOpenSlash();
                using var metadata = LinuxOpenAt2(slash, parts.Length == 0 ? "." : string.Join('/', parts), noCrossMount: false);
                current = Retain(owner._directories, LinuxReopenChecked(metadata, directory: true, knownUuid: null, afterMetadataOpen: null));
                owner._linuxFileSystemUuid = LinuxFileSystemUuid(current);
            }
            else if (OperatingSystem.IsWindows())
            {
                owner._windowsDriveRoot = root;
                current = Retain(owner._directories, WindowsRoot(root));
                foreach (var component in parts)
                {
                    owner._windowsRootParent = current;
                    owner._windowsRootName = component;
                    current = Retain(owner._directories, OpenChild(current, component, directory: true));
                }
            }
            else
            {
                throw new WorkspacePathException("path_enforcement_unavailable");
            }

            owner._rootHandle = current;
            owner.RootIdentity = Identity(current);
            if (!owner.RootIdentity.IsDirectory || owner.RootIdentity.Links == 0)
            {
                throw new WorkspacePathException("root_not_directory");
            }

            if (expected is { } identity && !identity.SameObject(owner.RootIdentity))
            {
                throw new WorkspacePathException("root_changed");
            }

            afterRootOpen?.Invoke();
            owner.RootPath = FinalPath(current, path);
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

    /// <summary>Opens a checked directory beneath this root, retaining its handle until disposal.</summary>
    public SafeFileHandle OpenDirectory(string path)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var parts = Components(path, allowRoot: true);
        if (parts.Length == 0)
        {
            return RootHandle;
        }

        if (OperatingSystem.IsLinux())
        {
            using var metadata = LinuxOpenAt2(RootHandle, string.Join('/', parts), noCrossMount: true);
            CheckVolume(metadata, _linuxFileSystemUuid);
            return Retain(_directories, LinuxReopenChecked(metadata, directory: true, _linuxFileSystemUuid, afterMetadataOpen: null));
        }

        var current = RootHandle;
        foreach (var component in parts)
        {
            current = RetainCheckedDirectory(OpenChild(current, component, directory: true));
        }

        return current;
    }

    /// <summary>
    /// Opens a fresh directory description for an internal bounded enumeration. Its native position is independent of
    /// the retained anchor; enumeration itself is not a namespace lock and names still require checked root-relative opens.
    /// </summary>
    internal SafeFileHandle OpenDirectoryForEnumeration(string path)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var parts = Components(path, allowRoot: true);
        if (OperatingSystem.IsLinux())
        {
            using var metadata = LinuxOpenAt2(RootHandle, parts.Length == 0 ? "." : string.Join('/', parts), noCrossMount: true);
            CheckVolume(metadata, _linuxFileSystemUuid);
            return Retain(_directories, LinuxReopenChecked(metadata, directory: true, _linuxFileSystemUuid, afterMetadataOpen: null));
        }

        if (OperatingSystem.IsWindows())
        {
            SafeFileHandle? parent;
            SafeFileHandle source;
            string? name;
            if (parts.Length == 0)
            {
                parent = _windowsRootParent;
                name = _windowsRootName;
                source = RootHandle;
            }
            else
            {
                parent = RootHandle;
                foreach (var component in parts.AsSpan(0, parts.Length - 1))
                {
                    parent = RetainCheckedDirectory(OpenChild(parent, component, directory: true));
                }

                name = parts[^1];
                source = RetainCheckedDirectory(OpenChild(parent, name, directory: true));
            }

            // A second root-relative open has its own enumeration position. Keep the source and each parent open
            // without delete sharing, and accept the new handle only if it names the same checked object and volume.
            var expected = Identity(source);
            var reopened = parent is null
                ? WindowsRoot(_windowsDriveRoot ?? throw new WorkspacePathException("path_enforcement_unavailable"))
                : OpenChild(parent, name ?? throw new WorkspacePathException("path_enforcement_unavailable"), directory: true);
            try
            {
                if (!expected.SameObject(Identity(reopened)))
                {
                    throw new WorkspacePathException("directory_identity_changed");
                }

                CheckVolume(reopened);
                return Retain(_directories, reopened);
            }
            catch
            {
                reopened.Dispose();
                throw;
            }
        }

        throw new WorkspacePathException("path_enforcement_unavailable");
    }

    /// <summary>Opens a regular single-link file for reading beneath the root; callers never reopen its unchecked path.</summary>
    public SafeFileHandle OpenRead(string path) => OpenRead(path, afterMetadataOpen: null);

    // The callback only coordinates real filesystem races in component tests; production passes no callback.
    internal SafeFileHandle OpenRead(string path, Action? afterMetadataOpen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var parts = Components(path);
        if (OperatingSystem.IsLinux())
        {
            using var metadata = LinuxOpenAt2(RootHandle, string.Join('/', parts), noCrossMount: true);
            CheckVolume(metadata, _linuxFileSystemUuid);
            return Retain(_files, LinuxReopenChecked(metadata, directory: false, _linuxFileSystemUuid, afterMetadataOpen));
        }

        var parent = RootHandle;
        foreach (var component in parts.AsSpan(0, parts.Length - 1))
        {
            parent = RetainCheckedDirectory(OpenChild(parent, component, directory: true));
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
            return Retain(_files, file);
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Opens and guards an existing regular file for a future in-place mutation. The guard owns its private handle and never
    /// exposes a write operation: journaling, authorization, name revalidation and result settlement are separate requirements.
    /// </summary>
    internal WorkspaceWriteGuard OpenExistingWriteGuard(string path) => OpenExistingWriteGuard(path, afterMetadataOpen: null);

    // The callback only coordinates races on real test-owned filesystem objects.
    internal WorkspaceWriteGuard OpenExistingWriteGuard(string path, Action? afterMetadataOpen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var parts = Components(path);
        SafeFileHandle file;
        if (OperatingSystem.IsLinux())
        {
            using var metadata = LinuxOpenAt2(RootHandle, string.Join('/', parts), noCrossMount: true);
            CheckVolume(metadata, _linuxFileSystemUuid);
            try
            {
                file = LinuxReopenChecked(metadata, directory: false, _linuxFileSystemUuid, afterMetadataOpen, writable: true);
            }
            catch (WorkspacePathException exception) when (exception.Reason is "native_11" or "native_26")
            {
                throw new WorkspacePathException("file_in_use", exception);
            }
        }
        else if (OperatingSystem.IsWindows())
        {
            var parent = RootHandle;
            foreach (var component in parts.AsSpan(0, parts.Length - 1))
            {
                parent = RetainCheckedDirectory(OpenChild(parent, component, directory: true));
            }

            // This first open requests metadata only, before any data-open of a possible special/reparse object.
            SafeFileHandle metadataHandle;
            try
            {
                metadataHandle = WindowsOpen(parent, parts[^1], directory: false, metadataOnly: true);
            }
            catch (WorkspacePathException exception) when (exception.Reason == "native_32")
            {
                throw new WorkspacePathException("file_in_use", exception);
            }

            using var metadata = metadataHandle;
            var before = Identity(metadata);
            if (!before.IsFile || before.Links != 1)
            {
                throw new WorkspacePathException(before.Links != 1 ? "file_hard_link" : "file_not_regular");
            }

            CheckVolume(metadata);
            afterMetadataOpen?.Invoke();
            file = ReOpenFile(metadata, 0xC0000000, 0, 0x00200000);
            if (file.IsInvalid)
            {
                var error = Marshal.GetLastPInvokeError();
                file.Dispose();
                throw new WorkspacePathException(error == 32 ? "file_in_use" : "file_guard_unavailable");
            }

            try
            {
                var held = Identity(metadata);
                var actual = Identity(file);
                if (!held.IsFile || held.Links != 1 || !actual.IsFile || actual.Links != 1 ||
                    !before.SameObject(held) || !held.SameObject(actual))
                {
                    throw new WorkspacePathException("file_identity_changed");
                }

                CheckVolume(file);
            }
            catch
            {
                file.Dispose();
                throw;
            }
        }
        else
        {
            throw new WorkspacePathException("file_guard_unavailable");
        }

        try
        {
            return WorkspaceWriteGuard.Acquire(file);
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

    /// <summary>Reads size, modification and change times from the opened object; no name is reopened.</summary>
    internal static unsafe WorkspaceFileStamp FileStamp(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (OperatingSystem.IsLinux())
        {
            const uint Required = 0x200 | 0x40 | 0x80; // STATX_SIZE, MTIME, CTIME
            var buffer = stackalloc byte[256];
            if (Statx(checked((int)handle.DangerousGetHandle()), string.Empty, 0x1000 | 0x100, Required, buffer) != 0 ||
                (*(uint*)buffer & Required) != Required)
            {
                throw new WorkspacePathException("file_metadata_unavailable");
            }

            return new WorkspaceFileStamp(checked((long)*(ulong*)(buffer + 40)), *(long*)(buffer + 112), *(uint*)(buffer + 120),
                *(long*)(buffer + 96), *(uint*)(buffer + 104));
        }

        if (OperatingSystem.IsWindows())
        {
            if (!GetBasicInformation(handle, 0, out var basic, (uint)sizeof(FileBasicInformation)) ||
                !GetFileInformationByHandle(handle, out var standard))
            {
                throw new WorkspacePathException("file_metadata_unavailable");
            }

            var size = ((ulong)standard.FileSizeHigh << 32) | standard.FileSizeLow;
            return new WorkspaceFileStamp(checked((long)size), basic.LastWriteTime, 0, basic.ChangeTime, 0);
        }

        throw new WorkspacePathException("path_enforcement_unavailable");
    }

    private static SafeFileHandle Retain(List<SafeFileHandle> handles, SafeFileHandle handle)
    {
        try
        {
            handles.Add(handle);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private SafeFileHandle RetainCheckedDirectory(SafeFileHandle directory)
    {
        try
        {
            CheckVolume(directory);
            return Retain(_directories, directory);
        }
        catch
        {
            directory.Dispose();
            throw;
        }
    }

    private void CheckVolume(SafeFileHandle handle, byte[]? linuxUuid = null)
    {
        var identity = OperatingSystem.IsLinux() ? LinuxIdentity(handle, linuxUuid) : Identity(handle);
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
        var handle = WindowsOpen(parent, component, directory);
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

    private static SafeFileHandle LinuxOpenSlash()
    {
        // The literal filesystem root is opened as metadata only; registration does not read ancestors.
        var descriptor = OpenAt(-100, "/", 0x200000 | 0x80000 | 0x20000 | 0x10000, 0);
        return descriptor < 0 ? throw NativeFailure() : new SafeFileHandle(descriptor, ownsHandle: true);
    }

    private static unsafe SafeFileHandle LinuxOpenAt2(SafeFileHandle root, string path, bool noCrossMount)
    {
        // One lookup from the live anchor, so moving a previously opened intermediate directory cannot redirect the rest.
        return LinuxOpenAt2(root, path, 0x200000 | 0x80000 | 0x20000, 0x08 | 0x04 | 0x02 | (noCrossMount ? 0x01u : 0u));
    }

    private static unsafe SafeFileHandle LinuxOpenAt2(SafeFileHandle root, string path, ulong flags, ulong resolve)
    {
        if (RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
        {
            throw new WorkspacePathException("path_enforcement_unavailable");
        }

        var retained = false;
        try
        {
            root.DangerousAddRef(ref retained);
            var how = new LinuxOpenHow { Flags = flags, Resolve = resolve };
            var descriptor = LinuxSyscall(437, checked((int)root.DangerousGetHandle()), path, ref how, (nuint)sizeof(LinuxOpenHow));
            if (descriptor < 0)
            {
                var error = Marshal.GetLastPInvokeError();
                throw error is 1 or 7 or 22 or 38 or 95 ? new WorkspacePathException("path_enforcement_unavailable") : NativeFailure();
            }

            return new SafeFileHandle(checked((nint)descriptor), ownsHandle: true);
        }
        finally
        {
            if (retained)
            {
                root.DangerousRelease();
            }
        }
    }

    private static SafeFileHandle LinuxReopenChecked(SafeFileHandle metadata, bool directory, byte[]? knownUuid, Action? afterMetadataOpen, bool writable = false)
    {
        // O_PATH has no data-open effect. In particular, a FIFO or device is refused before any data handle is opened.
        var original = LinuxBasicIdentity(metadata);
        afterMetadataOpen?.Invoke();
        RequireLinuxKind(original, directory);

        // For ordinary descendants the root's UUID makes the full identity available before the data open.
        var prior = knownUuid is null ? original : LinuxIdentity(metadata, knownUuid);
        if (!SameLinuxSnapshot(original, prior))
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        using var proc = LinuxProcFdDirectory();
        var descriptor = OpenAt(checked((int)proc.DangerousGetHandle()), metadata.DangerousGetHandle().ToInt64().ToString(CultureInfo.InvariantCulture),
            0x80000 | 0x800 | (directory ? 0x10000 : writable ? 2 : 0), 0);
        if (descriptor < 0)
        {
            throw NativeFailure();
        }

        var result = new SafeFileHandle(descriptor, ownsHandle: true);
        try
        {
            var actualUuid = LinuxFileSystemUuid(result);
            if (knownUuid is not null && !knownUuid.AsSpan().SequenceEqual(actualUuid))
            {
                throw new WorkspacePathException("mount_crossing");
            }

            var held = LinuxIdentity(metadata, actualUuid);
            var reopened = LinuxIdentity(result, actualUuid);
            RequireLinuxKind(held, directory);
            RequireLinuxKind(reopened, directory);
            if (!SameLinuxSnapshot(original, held) || !SameLinuxSnapshot(held, reopened) || !held.SameObject(reopened) ||
                (knownUuid is not null && !prior.SameObject(held)))
            {
                throw new WorkspacePathException("file_identity_changed");
            }

            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
    }

    private static void RequireLinuxKind(WorkspaceObjectIdentity identity, bool directory)
    {
        if (directory ? !identity.IsDirectory : !identity.IsFile)
        {
            throw new WorkspacePathException("path_link_or_special");
        }

        if (!directory && identity.Links != 1)
        {
            throw new WorkspacePathException("file_hard_link");
        }

        if (directory && identity.Links == 0)
        {
            throw new WorkspacePathException("root_changed");
        }
    }

    private static bool SameLinuxSnapshot(WorkspaceObjectIdentity first, WorkspaceObjectIdentity second) =>
        first.Volume == second.Volume && first.High == second.High && first.Low == second.Low &&
        first.Created == second.Created && first.CreatedNanoseconds == second.CreatedNanoseconds &&
        first.Mode == second.Mode && first.Links == second.Links;

    private static unsafe WorkspaceObjectIdentity LinuxBasicIdentity(SafeFileHandle handle)
    {
        // Birth time is part of the persistent identity; unsupported metadata cannot silently become zero.
        const uint Required = 0x1000 | 0x800 | 0x100 | 0x4 | 0x1;
        var buffer = stackalloc byte[256];
        if (Statx(checked((int)handle.DangerousGetHandle()), string.Empty, 0x1000 | 0x100, Required, buffer) != 0 ||
            (*(uint*)buffer & Required) != Required)
        {
            throw new WorkspacePathException("identity_unavailable");
        }

        var mode = *(ushort*)(buffer + 28);
        var created = unchecked((ulong)*(long*)(buffer + 80));
        var createdNanos = *(uint*)(buffer + 88);
        return new WorkspaceObjectIdentity(((ulong)*(uint*)(buffer + 136) << 32) | *(uint*)(buffer + 140),
            *(ulong*)(buffer + 32), *(ulong*)(buffer + 144), created, createdNanos, *(uint*)(buffer + 16), mode);
    }

    private static WorkspaceObjectIdentity LinuxIdentity(SafeFileHandle handle, byte[]? knownUuid = null)
    {
        var retained = false;
        try
        {
            handle.DangerousAddRef(ref retained);
            var identity = LinuxBasicIdentity(handle);
            var uuid = knownUuid ?? LinuxFileSystemUuid(handle);
            return identity with { InstanceToken = LinuxInstanceToken(handle, identity.High, uuid) };
        }
        finally
        {
            if (retained)
            {
                handle.DangerousRelease();
            }
        }
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

    private static unsafe SafeFileHandle WindowsOpen(SafeFileHandle parent, string name, bool directory, bool metadataOnly = false)
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
            var status = NtCreateFile(out var raw, metadataOnly ? 0x00100080u : 0x00100081u, ref attributes, out _, 0, 0,
                metadataOnly ? 7u : directory ? 3u : 1u, 1, 0x20u | 0x00200000u | (directory ? 1u : 0x40u), 0, 0);
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

    private static string FinalPath(SafeFileHandle handle, string requestedPath)
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

        using var proc = LinuxProcFdDirectory();
        var descriptorName = handle.DangerousGetHandle().ToInt64().ToString(CultureInfo.InvariantCulture);
        var bytes = new byte[16384];
        var length = ReadLinkAt(checked((int)proc.DangerousGetHandle()), descriptorName, bytes, (nuint)bytes.Length);
        if (length <= 0 || length >= bytes.Length)
        {
            throw new WorkspacePathException("canonical_path_unavailable");
        }

        string canonical;
        try
        {
            canonical = StrictUtf8.GetString(bytes, 0, checked((int)length));
        }
        catch (DecoderFallbackException exception)
        {
            throw new WorkspacePathException("canonical_path_unavailable", exception);
        }

        // The readlink suffix " (deleted)" is ambiguous: use native link count and the exact originally requested name.
        var current = LinuxBasicIdentity(handle);
        if (!current.IsDirectory || current.Links == 0 || !canonical.Equals(requestedPath, StringComparison.Ordinal))
        {
            throw new WorkspacePathException("root_changed");
        }

        return canonical;
    }

    private static unsafe SafeFileHandle LinuxProcFdDirectory()
    {
        var raw = OpenAt(-100, "/proc", 0x200000 | 0x80000 | 0x20000 | 0x10000, 0);
        if (raw < 0)
        {
            throw new WorkspacePathException("procfs_unavailable");
        }

        using var procRoot = new SafeFileHandle(raw, ownsHandle: true);
        RequireProcFs(procRoot);
        var self = new byte[32];
        var count = ReadLinkAt(raw, "self", self, (nuint)self.Length);
        var expected = GetProcessId().ToString(CultureInfo.InvariantCulture);
        if (count <= 0 || count >= self.Length || Encoding.ASCII.GetString(self, 0, checked((int)count)) != expected)
        {
            throw new WorkspacePathException("procfs_unavailable");
        }

        // Resolve the kernel's self link inside the verified proc mount, forbidding any mount crossing.
        var descriptors = LinuxOpenAt2(procRoot, "self/fd", 0x200000 | 0x80000 | 0x10000, 0x08 | 0x01);
        try
        {
            RequireProcFs(descriptors);
            return descriptors;
        }
        catch
        {
            descriptors.Dispose();
            throw;
        }
    }

    private static unsafe void RequireProcFs(SafeFileHandle handle)
    {
        var buffer = stackalloc byte[256];
        if (FStatFs(checked((int)handle.DangerousGetHandle()), buffer) != 0 || *(long*)buffer != 0x9fa0)
        {
            throw new WorkspacePathException("procfs_unavailable");
        }
    }

    private static WorkspacePathException NativeFailure() => new("native_" + Marshal.GetLastPInvokeError().ToString(CultureInfo.InvariantCulture));

    [LibraryImport("libc", EntryPoint = "openat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int OpenAt(int directory, string path, int flags, uint mode);

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static unsafe partial int Statx(int directory, string path, int flags, uint mask, byte* buffer);

    private static unsafe byte[] LinuxFileSystemUuid(SafeFileHandle handle)
    {
        var uuid = stackalloc byte[17];
        new Span<byte>(uuid, 17).Clear();
        // FS_IOC_GETFSUUID, a read-only generic Linux ioctl; fsuuid2 is a length byte plus sixteen UUID bytes.
        if (ReadFileSystemUuid(checked((int)handle.DangerousGetHandle()), 0x80111500, uuid) != 0 || uuid[0] != 16 ||
            new ReadOnlySpan<byte>(uuid + 1, 16).IndexOfAnyExcept((byte)0) < 0)
        {
            throw new WorkspacePathException("identity_filesystem_unavailable");
        }

        return new ReadOnlySpan<byte>(uuid + 1, 16).ToArray();
    }

    private static unsafe byte[] LinuxInstanceToken(SafeFileHandle handle, ulong mountId, ReadOnlySpan<byte> uuid)
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

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges fs-object v1\0"u8);
        hash.AppendData(uuid);
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

    [LibraryImport("libc", EntryPoint = "readlinkat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial nint ReadLinkAt(int directory, string path, [Out] byte[] buffer, nuint size);

    [LibraryImport("libc", EntryPoint = "syscall", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial long LinuxSyscall(long number, int directory, string path, ref LinuxOpenHow how, nuint size);

    [LibraryImport("libc", EntryPoint = "fstatfs", SetLastError = true)]
    private static unsafe partial int FStatFs(int descriptor, byte* buffer);

    [LibraryImport("libc", EntryPoint = "getpid")]
    private static partial int GetProcessId();

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFile(string name, uint access, uint share, nint security, uint disposition, uint flags, nint template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeFileHandle ReOpenFile(SafeFileHandle original, uint access, uint share, uint flags);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool GetCaseInformation(SafeFileHandle file, int informationClass, uint* buffer, uint size);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetBasicInformation(SafeFileHandle file, int informationClass, out FileBasicInformation information, uint size);

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
    private struct LinuxOpenHow
    {
        public ulong Flags;
        public ulong Mode;
        public ulong Resolve;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInformation
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
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
