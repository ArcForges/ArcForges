// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.RunSupervisor.Protocol;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Platform.Linux.Mxc;

/// <summary>Reopens the admitted objects before the SDK receives a same-path request.</summary>
[SupportedOSPlatform("linux")]
internal sealed partial class LinuxRunPathBindings : IDisposable
{
    private const int CloseOnExec = 0x80000;
    private const int OpenPathOnly = 0x200000;
    private const uint RequiredMetadata = 0x190F; // type, mode, nlink, uid, inode, birth time and mount ID
    private const ushort DirectoryType = 0x4000;
    private const ushort FileType = 0x8000;
    private static readonly int s_noFollow = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 0x8000 : 0x20000;
    private static readonly int s_directory = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 0x4000 : 0x10000;
    private static readonly string[] s_privateChildren = ["home", "config", "cache", "tmp", "work", "data"];
    private readonly List<Binding> _bindings = [];

    private LinuxRunPathBindings()
    {
    }

    internal static LinuxRunPathBindings Open(RunLaunchSpec spec)
    {
        if (RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
        {
            throw Refuse("linux_path_identity_unavailable");
        }

        var bindings = new LinuxRunPathBindings();
        try
        {
            using var slash = OpenHandle(-100, "/", OpenPathOnly | CloseOnExec | s_noFollow | s_directory);
            using var proc = OpenHandle(-100, "/proc/self/fd", OpenPathOnly | CloseOnExec | s_noFollow | s_directory);
            if (FileSystemType(proc, out var procInfo) != 0 || procInfo.Type != 0x9FA0)
            {
                throw Refuse("linux_procfd_unavailable");
            }

            bindings.AddPrivatePaths(spec, slash, proc);
            foreach (var mount in spec.Mounts)
            {
                if (mount.HostPath != mount.SandboxPath)
                {
                    throw Refuse("linux_host_grant_path_mismatch");
                }

                bindings.Add(slash, proc, mount.HostPath, DecodeIdentity(mount.NativeIdentity, "linux_host_grant_identity_missing"),
                    privateDirectory: false);
            }

            bindings.Add(slash, proc, spec.Argv[0], DecodeIdentity(spec.ExecutableIdentity, "linux_executable_identity_missing"),
                privateDirectory: false, expectedKind: FileType);
            bindings.Add(slash, proc, spec.WorkingDirectory, DecodeIdentity(spec.WorkingDirectoryIdentity, "linux_working_directory_identity_missing"),
                privateDirectory: false, expectedKind: DirectoryType);
            bindings.Recheck(slash);
            return bindings;
        }
        catch (FormatException)
        {
            bindings.Dispose();
            throw Refuse("linux_path_identity_invalid");
        }
        catch
        {
            bindings.Dispose();
            throw;
        }
    }

    private void AddPrivatePaths(RunLaunchSpec spec, SafeFileHandle slash, SafeFileHandle proc)
    {
        var fields = spec.PrivateRootIdentity?.Split(':');
        var parent = Path.GetDirectoryName(spec.PrivateRoot);
        var data = parent is null ? null : Path.GetDirectoryName(parent);
        if (fields is not { Length: 7 } || fields[0] != "1" || fields[1] != spec.SandboxId || fields[3] != "2"
            || fields[2].Length != 64 || !fields[2].All(char.IsAsciiHexDigitLower) || data is null || parent is null
            || Path.GetFileName(parent) != "sandboxes" || Path.GetFileName(spec.PrivateRoot) != spec.SandboxId
            || Path.GetDirectoryName(spec.ControlDirectory) != Path.Combine(data, "control"))
        {
            throw Refuse("linux_private_root_identity_invalid");
        }

        var anchor = Add(slash, proc, data, Convert.FromBase64String(fields[4]), privateDirectory: true);
        var sandboxes = Add(slash, proc, parent, Convert.FromBase64String(fields[5]), privateDirectory: true);
        var root = Add(slash, proc, spec.PrivateRoot, Convert.FromBase64String(fields[6]), privateDirectory: true);
        if (anchor.Mount != sandboxes.Mount || anchor.Mount != root.Mount)
        {
            throw Refuse("linux_private_root_mount_changed");
        }

        foreach (var child in s_privateChildren)
        {
            var childIdentity = Add(slash, proc, Path.Combine(spec.PrivateRoot, child), null, privateDirectory: true);
            if (childIdentity.Mount != root.Mount)
            {
                throw Refuse("linux_private_bind_mount_changed");
            }
        }
    }

    private static byte[] DecodeIdentity(string? identity, string missing) =>
        identity is { Length: 108 } && identity.StartsWith("2:", StringComparison.Ordinal)
            ? Convert.FromHexString(identity[2..]) : throw Refuse(missing);

    private Metadata Add(SafeFileHandle slash, SafeFileHandle proc, string path, byte[]? expected, bool privateDirectory,
        ushort? expectedKind = null)
    {
        using var metadata = OpenExact(slash, path);
        var original = Inspect(metadata);
        RequireKind(original, privateDirectory);
        if (expectedKind.HasValue && original.Kind != expectedKind)
        {
            throw Refuse("linux_path_kind_changed");
        }

        var raw = metadata.DangerousGetHandle().ToInt32().ToString(CultureInfo.InvariantCulture);
        var flags = CloseOnExec | 0x800 | (original.Kind == DirectoryType ? s_directory : 0);
        var file = OpenHandle(proc.DangerousGetHandle().ToInt32(), raw, flags);
        try
        {
            var actual = Inspect(file);
            RequireKind(actual, privateDirectory);
            if (!actual.SameObject(original) || OriginalPath(file) != path || expected is not null && !Matches(file, actual, expected))
            {
                throw Refuse("linux_path_identity_changed");
            }

            _bindings.Add(new Binding(path, file, actual, privateDirectory));
            return actual;
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    private void Recheck(SafeFileHandle slash)
    {
        foreach (var binding in _bindings)
        {
            using var named = OpenExact(slash, binding.Path);
            var current = Inspect(named);
            var held = Inspect(binding.Handle);
            RequireKind(current, binding.PrivateDirectory);
            RequireKind(held, binding.PrivateDirectory);
            if (!current.SameObject(binding.Identity) || !held.SameObject(binding.Identity) || OriginalPath(binding.Handle) != binding.Path)
            {
                throw Refuse("linux_path_identity_changed");
            }
        }
    }

    private static string? OriginalPath(SafeFileHandle handle) =>
        new FileInfo(LinuxRunCgroup.DescriptorPath(handle)).LinkTarget;

    private static void RequireKind(Metadata item, bool privateDirectory)
    {
        if (item.Kind is not (DirectoryType or FileType) || item.Links == 0 || item.Kind == FileType && item.Links != 1
            || privateDirectory && (item.Mode != 0x41C0 || item.Owner != LinuxRunCgroup.UserId))
        {
            throw Refuse("linux_path_kind_or_permissions_changed");
        }
    }

    private static unsafe bool Matches(SafeFileHandle file, Metadata item, ReadOnlySpan<byte> expected)
    {
        if (expected.Length != 53 || expected[0] != 1 || item.BirthNanoseconds >= 1_000_000_000 ||
            BinaryPrimitives.ReadUInt64BigEndian(expected[1..9]) != item.Volume ||
            BinaryPrimitives.ReadUInt64BigEndian(expected[9..17]) != unchecked((ulong)item.BirthSeconds) ||
            BinaryPrimitives.ReadUInt32BigEndian(expected[17..21]) != item.BirthNanoseconds)
        {
            return false;
        }

        // WorkspacePath's persisted v1 token uses the real filesystem UUID and exported object handle.
        var uuid = stackalloc byte[17];
        new Span<byte>(uuid, 17).Clear();
        var descriptor = file.DangerousGetHandle().ToInt32();
        if (ReadFileSystemUuid(descriptor, 0x80111500, uuid) != 0 || uuid[0] != 16
            || new ReadOnlySpan<byte>(uuid + 1, 16).IndexOfAnyExcept((byte)0) < 0)
        {
            throw NativeError("linux_filesystem_identity_unavailable");
        }

        var exported = stackalloc byte[136];
        new Span<byte>(exported, 136).Clear();
        *(uint*)exported = 128;
        if (NameToHandle(descriptor, "", exported, out var mount, 0x1000) != 0 ||
            *(uint*)exported is 0 or > 128 || (ulong)(uint)mount != item.Mount)
        {
            throw NativeError("linux_exported_identity_unavailable");
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges fs-object v1\0"u8);
        hash.AppendData(new ReadOnlySpan<byte>(uuid + 1, 16));
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteInt32BigEndian(header, *(int*)(exported + 4));
        BinaryPrimitives.WriteUInt32BigEndian(header[4..], *(uint*)exported);
        hash.AppendData(header);
        hash.AppendData(new ReadOnlySpan<byte>(exported + 8, checked((int)*(uint*)exported)));
        return CryptographicOperations.FixedTimeEquals(expected[21..], hash.GetHashAndReset());
    }

    private static SafeFileHandle OpenExact(SafeFileHandle slash, string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.Length < 2 || path != Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)))
        {
            throw Refuse("linux_path_not_exact");
        }

        var options = new OpenHow
        {
            Flags = checked((ulong)(OpenPathOnly | CloseOnExec | s_noFollow)),
            Resolve = 0x08 | 0x04 | 0x02, // beneath, no symlinks, no magic links
        };
        var descriptor = OpenAt2(437, slash.DangerousGetHandle().ToInt32(), path[1..], ref options, 24);
        return descriptor >= 0 ? new SafeFileHandle(checked((int)descriptor), ownsHandle: true) : throw NativeError("linux_open_exact_path");
    }

    private static SafeFileHandle OpenHandle(int directory, string name, int flags)
    {
        var descriptor = OpenAt(directory, name, flags, 0);
        return descriptor >= 0 ? new SafeFileHandle(descriptor, ownsHandle: true) : throw NativeError("linux_open_identity_handle");
    }

    private static Metadata Inspect(SafeFileHandle handle)
    {
        if (Statx(handle, "", 0x1000 | 0x100, RequiredMetadata, out var metadata) != 0)
        {
            throw NativeError("linux_object_metadata_unavailable");
        }

        return (metadata.Mask & RequiredMetadata) == RequiredMetadata
            ? metadata : throw Refuse("linux_object_metadata_unavailable");
    }

    private static RunNativeException Refuse(string code) => new("bind_linux_run_paths", code, payloadNotStarted: true);

    private static RunNativeException NativeError(string code) =>
        Refuse(code + "_" + Marshal.GetLastPInvokeError().ToString(CultureInfo.InvariantCulture));

    public void Dispose()
    {
        foreach (var item in _bindings)
        {
            item.Handle.Dispose();
        }
        _bindings.Clear();
    }

    private sealed record Binding(string Path, SafeFileHandle Handle, Metadata Identity, bool PrivateDirectory);

    [StructLayout(LayoutKind.Sequential)]
    private struct OpenHow
    {
        internal ulong Flags, Mode, Resolve;
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Metadata
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(16)] internal uint Links;
        [FieldOffset(20)] internal uint Owner;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(80)] internal long BirthSeconds;
        [FieldOffset(88)] internal uint BirthNanoseconds;
        [FieldOffset(136)] internal uint Major;
        [FieldOffset(140)] internal uint Minor;
        [FieldOffset(144)] internal ulong Mount;

        internal readonly ushort Kind => (ushort)(Mode & 0xF000);
        internal readonly ulong Volume => ((ulong)Major << 32) | Minor;
        internal readonly bool SameObject(Metadata other) => Volume == other.Volume && Mount == other.Mount && Inode == other.Inode
            && BirthSeconds == other.BirthSeconds && BirthNanoseconds == other.BirthNanoseconds && Kind == other.Kind;
    }

    [StructLayout(LayoutKind.Explicit, Size = 120)]
    private struct ProcFileSystem
    {
        [FieldOffset(0)] internal long Type;
    }

    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenAt(int directory, string path, int flags, uint mode);
    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial long OpenAt2(long number, int directory, string path, ref OpenHow how, nuint size);
    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Statx(SafeFileHandle handle, string path, int flags, uint mask, out Metadata stat);
    [LibraryImport("libc", EntryPoint = "fstatfs", SetLastError = true)]
    private static partial int FileSystemType(SafeFileHandle handle, out ProcFileSystem stat);
    [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static unsafe partial int ReadFileSystemUuid(int descriptor, nuint request, byte* data);
    [LibraryImport("libc", EntryPoint = "name_to_handle_at", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int NameToHandle(int descriptor, string path, byte* data, out int mountId, int flags);
}
