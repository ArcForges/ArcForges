// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// Bounded observations of owner, mode, filesystem flags and visible xattrs on one held Linux descriptor. Only ordinary
/// user attributes and a POSIX access ACL are supported; privilege/IMA or unrecognized visible attributes are refused.
/// Invisible attributes are not claimed to have been individually compared.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed unsafe partial class LinuxPreservedMetadata
{
    private const int MaximumNames = 65_536;
    private const int MaximumValue = 65_536;
    private const int MaximumTotal = 1_048_576;
    private readonly uint _uid;
    private readonly uint _gid;
    private readonly ushort _mode;
    private readonly int _flags;
    private readonly byte[] _xattrs;

    private LinuxPreservedMetadata(uint uid, uint gid, ushort mode, int flags, byte[] xattrs)
    {
        _uid = uid;
        _gid = gid;
        _mode = mode;
        _flags = flags;
        _xattrs = xattrs;
    }

    internal static LinuxPreservedMetadata Capture(SafeFileHandle file)
    {
        ArgumentNullException.ThrowIfNull(file);
        var retained = false;
        try
        {
            file.DangerousAddRef(ref retained);
            var fd = checked((int)file.DangerousGetHandle());
            byte* stat = stackalloc byte[256];
            new Span<byte>(stat, 256).Clear();
            const uint Required = 0x1 | 0x8 | 0x10; // mode, uid, gid
            if (Statx(fd, string.Empty, 0x1000 | 0x100, Required, stat) != 0 || (*(uint*)stat & Required) != Required)
                throw new WorkspacePreservationUnavailableException();
            var mode = *(ushort*)(stat + 28);
            if ((mode & 0xc00) != 0) throw new WorkspacePreservationUnavailableException(); // setuid/setgid can be cleared
            var flags = 0;
            if (Ioctl(fd, 0x80086601, &flags) != 0) throw new WorkspacePreservationUnavailableException();
            RefuseIfPresentOrUnobservable(fd, "security.capability"u8);
            RefuseIfPresentOrUnobservable(fd, "security.ima"u8);
            var digest = ObserveVisibleAttributes(fd);
            return new LinuxPreservedMetadata(*(uint*)(stat + 20), *(uint*)(stat + 24), mode, flags, digest);
        }
        finally
        {
            if (retained) file.DangerousRelease();
        }
    }

    internal bool SameAs(LinuxPreservedMetadata other) =>
        _uid == other._uid && _gid == other._gid && _mode == other._mode && _flags == other._flags &&
        CryptographicOperations.FixedTimeEquals(_xattrs, other._xattrs);

    private static void RefuseIfPresentOrUnobservable(int fd, ReadOnlySpan<byte> name)
    {
        Span<byte> terminated = stackalloc byte[name.Length + 1];
        name.CopyTo(terminated);
        terminated[^1] = 0;
        fixed (byte* pointer = terminated)
        {
            if (GetAttribute(fd, pointer, null, 0) >= 0 || Marshal.GetLastPInvokeError() != 61) // ENODATA
                throw new WorkspacePreservationUnavailableException();
        }
    }

    private static byte[] ObserveVisibleAttributes(int fd)
    {
        var length = ListAttributes(fd, null, 0);
        if (length < 0 || length > MaximumNames) throw new WorkspacePreservationUnavailableException();
        var names = new byte[checked((int)length)];
        fixed (byte* pointer = names)
        {
            if (ListAttributes(fd, pointer, (nuint)names.Length) != length)
                throw new WorkspacePreservationUnavailableException();
        }
        var entries = new List<(byte[] Name, byte[] ValueDigest, int ValueLength)>();
        var total = 0;
        for (var offset = 0; offset < names.Length;)
        {
            var end = Array.IndexOf(names, (byte)0, offset);
            if (end <= offset) throw new WorkspacePreservationUnavailableException();
            var name = names.AsSpan(offset, end - offset);
            if (!name.StartsWith("user."u8) && !name.SequenceEqual("system.posix_acl_access"u8))
                throw new WorkspacePreservationUnavailableException();
            var terminated = names.AsSpan(offset, end - offset + 1);
            fixed (byte* namePointer = terminated)
            {
                var size = GetAttribute(fd, namePointer, null, 0);
                if (size < 0 || size > MaximumValue || size > MaximumTotal - total)
                    throw new WorkspacePreservationUnavailableException();
                total += checked((int)size);
                var value = new byte[checked((int)size)];
                try
                {
                    fixed (byte* valuePointer = value)
                    {
                        if (GetAttribute(fd, namePointer, valuePointer, (nuint)value.Length) != size)
                            throw new WorkspacePreservationUnavailableException();
                    }
                    entries.Add((name.ToArray(), SHA256.HashData(value), value.Length));
                }
                finally { CryptographicOperations.ZeroMemory(value); }
            }
            offset = end + 1;
        }
        entries.Sort(static (left, right) => left.Name.AsSpan().SequenceCompareTo(right.Name));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges linux-preserved-metadata v1\0"u8);
        Span<byte> frame = stackalloc byte[8];
        for (var index = 0; index < entries.Count; index++)
        {
            var item = entries[index];
            if (index != 0 && item.Name.AsSpan().SequenceEqual(entries[index - 1].Name))
                throw new WorkspacePreservationUnavailableException();
            BinaryPrimitives.WriteUInt32BigEndian(frame, checked((uint)item.Name.Length));
            BinaryPrimitives.WriteUInt32BigEndian(frame[4..], checked((uint)item.ValueLength));
            hash.AppendData(frame);
            hash.AppendData(item.Name);
            hash.AppendData(item.ValueDigest);
        }
        return hash.GetHashAndReset();
    }

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int Statx(int fd, string path, int flags, uint mask, byte* result);

    [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static partial int Ioctl(int fd, nuint request, int* value);

    [LibraryImport("libc", EntryPoint = "flistxattr", SetLastError = true)]
    private static partial nint ListAttributes(int fd, byte* names, nuint size);

    [LibraryImport("libc", EntryPoint = "fgetxattr", SetLastError = true)]
    private static partial nint GetAttribute(int fd, byte* name, byte* value, nuint size);
}
