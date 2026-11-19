// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.Node.Core.Platform;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Security;

/// <summary>Protects the filesystem endpoint bound by this Node from being exposed in an MXC payload.</summary>
internal sealed partial class SandboxProtectedEndpoint(string socketPath) : IDisposable
{
    private const int DirectoryFlags = 0x200000 | 0x80000 | 0x20000 | 0x10000; // O_PATH | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
    private const int SocketFlags = DirectoryFlags & ~0x10000;
    private readonly string _requestedDirectory = Path.GetDirectoryName(socketPath) ?? throw Unavailable();
    private readonly string _name = Path.GetFileName(socketPath);
    private readonly Lock _gate = new();
    private Binding? _binding;

    /// <summary>Called after LocalRpc has bound its actual address. Readiness never adopts a later replacement.</summary>
    internal bool TryBind()
    {
        if (!OperatingSystem.IsLinux() || !LinuxOwnedProcessIdentity.HasMatchingProcView())
        {
            return false;
        }

        SafeFileHandle? directory = null;
        SafeFileHandle? socket = null;
        try
        {
            lock (_gate)
            {
                if (_binding is not null)
                {
                    return false;
                }

                directory = OpenDirectory(_requestedDirectory);
                socket = OpenSocket(directory);
                var directoryIdentity = ReadIdentity(directory, 0x4000, 0x1c0);
                var socketIdentity = ReadIdentity(socket, 0xc000, 0x180);
                var descriptorPath = "/proc/self/fd/" + directory.DangerousGetHandle().ToString(CultureInfo.InvariantCulture);
                var canonical = new FileInfo(descriptorPath).LinkTarget;
                if (canonical is null || !Path.IsPathFullyQualified(canonical))
                {
                    throw Unavailable();
                }

                RequireOwnListener(Path.Combine(descriptorPath, _name));
                using var currentSocket = OpenSocket(directory);
                if (ReadIdentity(currentSocket, 0xc000, 0x180) != socketIdentity)
                {
                    throw Unavailable();
                }

                var verified = new Verified(_requestedDirectory, canonical, ReadAncestors(canonical, directoryIdentity));
                _binding = new Binding(directory, socket, directoryIdentity, socketIdentity, verified);
                directory = null;
                socket = null;
                return true;
            }
        }
        catch (Exception error) when (IsUnavailable(error))
        {
            return false;
        }
        finally
        {
            socket?.Dispose();
            directory?.Dispose();
        }
    }

    internal Verified Verify()
    {
        lock (_gate)
        {
            var binding = _binding ?? throw Unavailable();
            using var directory = OpenDirectory(_requestedDirectory);
            using var socket = OpenSocket(directory);
            if (ReadIdentity(directory, 0x4000, 0x1c0) != binding.DirectoryIdentity ||
                ReadIdentity(socket, 0xc000, 0x180) != binding.SocketIdentity ||
                !ReadAncestors(binding.Protection.CanonicalDirectory, binding.DirectoryIdentity)
                    .SetEquals(binding.Protection.Ancestors))
            {
                throw Unavailable();
            }

            return binding.Protection;
        }
    }

    internal bool AllowsPrivateRoot(string privateRoot)
    {
        try
        {
            var endpoint = Verify();
            using var root = OpenDirectory(privateRoot);
            var id = ReadIdentity(root, 0x4000);
            return !endpoint.Overlaps(privateRoot) && !endpoint.Ancestors.Contains(id.Object);
        }
        catch (Exception error) when (IsUnavailable(error))
        {
            return false;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _binding?.Socket.Dispose();
            _binding?.Directory.Dispose();
            _binding = null;
        }
    }

    private static SafeFileHandle OpenDirectory(string path) => Take(OpenAt(-100, path, DirectoryFlags)); // AT_FDCWD

    private SafeFileHandle OpenSocket(SafeFileHandle directory) => Take(OpenAtDirectory(directory, _name, SocketFlags));

    private static SafeFileHandle Take(int fd) => fd >= 0 ? new SafeFileHandle(fd, ownsHandle: true) : throw Unavailable();

    [SupportedOSPlatform("linux")]
    private static void RequireOwnListener(string endpoint)
    {
        using var probe = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified) { Blocking = false };
        probe.Connect(new UnixDomainSocketEndPoint(endpoint));
        var peer = LinuxPeerCredentialReader.Read(probe);
        if (peer.ProcessId != Environment.ProcessId || peer.UserId != GetEffectiveUser())
        {
            throw Unavailable();
        }
    }

    private static HashSet<NativeObject> ReadAncestors(string canonical, NativeIdentity expected)
    {
        using var directory = OpenDirectory(canonical);
        if (ReadIdentity(directory, 0x4000, 0x1c0) != expected)
        {
            throw Unavailable();
        }

        var result = new HashSet<NativeObject> { expected.Object };
        var path = Path.GetDirectoryName(canonical);
        while (path is not null)
        {
            using var ancestor = OpenDirectory(path);
            _ = result.Add(ReadIdentity(ancestor, 0x4000).Object);
            path = Path.GetDirectoryName(path);
        }

        return result;
    }

    private static NativeIdentity ReadIdentity(SafeFileHandle fd, ushort kind, ushort? permissions = null)
    {
        const uint mask = 0x1000 | 0x100 | 0x8 | 0x4 | 0x2 | 0x1; // mount, inode, uid, nlink, mode, type
        if (Statx(fd, string.Empty, 0x1000 | 0x100, mask, out var data) != 0 || (data.Mask & mask) != mask
            || data.Links == 0 || (kind == 0xc000 && data.Links != 1) || (data.Mode & 0xf000) != kind
            || (permissions is { } mode && ((data.Mode & 0x1ff) != mode || data.User != GetEffectiveUser())))
        {
            throw Unavailable();
        }

        return new NativeIdentity(new NativeObject(((ulong)data.Major << 32) | data.Minor, data.Inode), data.Mount);
    }

    private static IOException Unavailable() => new("node_endpoint_identity_unavailable");

    private static bool IsUnavailable(Exception error) => error is IOException or UnauthorizedAccessException or
        ArgumentException or NotSupportedException or EntryPointNotFoundException or DllNotFoundException or SocketException;

    private sealed record Binding(SafeFileHandle Directory, SafeFileHandle Socket, NativeIdentity DirectoryIdentity,
        NativeIdentity SocketIdentity, Verified Protection);

    internal sealed record Verified(string RequestedDirectory, string CanonicalDirectory, IReadOnlySet<NativeObject> Ancestors)
    {
        internal bool Overlaps(string path) => Overlap(path, RequestedDirectory) || Overlap(path, CanonicalDirectory);

        internal bool AliasesAncestor(WorkspaceObjectIdentity identity) => Ancestors.Contains(new NativeObject(identity.Volume, identity.Low));

        private static bool Overlap(string path, string directory) => AtOrBelow(path, directory) || AtOrBelow(directory, path);

        private static bool AtOrBelow(string path, string root) => path.Equals(root, StringComparison.Ordinal) ||
            (path.Length > root.Length && path.StartsWith(root, StringComparison.Ordinal)
                && (root[^1] == '/' || path[root.Length] == '/'));
    }

    internal readonly record struct NativeObject(ulong Device, ulong Inode);
    private readonly record struct NativeIdentity(NativeObject Object, ulong Mount);

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct StatxData
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(16)] internal uint Links;
        [FieldOffset(20)] internal uint User;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(136)] internal uint Major;
        [FieldOffset(140)] internal uint Minor;
        [FieldOffset(144)] internal ulong Mount;
    }

    [LibraryImport("libc", EntryPoint = "openat", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenAt(int directory, string path, int flags);

    [LibraryImport("libc", EntryPoint = "openat", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenAtDirectory(SafeFileHandle directory, string path, int flags);

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Statx(SafeFileHandle directory, string path, int flags, uint mask, out StatxData data);

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint GetEffectiveUser();
}
