// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Tests;

/// <summary>Native marker primitives on test-owned objects; this does not assert an authorized file API creation.</summary>
public sealed partial class CreationMarkerNativeTests
{
    [Fact]
    [Trait("env", "linux-real")]
    public void LinuxMarkerUsesTheCreatedDescriptorPreservesOtherAttributesAndDoesNotAdoptAReplacement()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Linux native xattr fixture."); return; }
        var directory = Directory.CreateTempSubdirectory("arcforges-owner-marker-");
        try
        {
            var path = Path.Combine(directory.FullName, "created");
            var body = Encoding.UTF8.GetBytes("owned-marker-fixture-5299");
            var unrelated = Encoding.UTF8.GetBytes("separate-attribute-fixture");
            byte[] marker;
            WorkspaceObjectIdentity identity;
            using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                file.Write(body);
                file.Flush(flushToDisk: true);
                Assert.Equal(0, SetOther(file.SafeFileHandle, "user.owner_fixture", unrelated, (nuint)unrelated.Length, 1));
                identity = WorkspacePath.Identity(file.SafeFileHandle);
                var encoded = RegisteredWorkspaces.RootIdentity.Encode(identity, directory: false);
                var changedTime = encoded.Bytes.ToArray();
                changedTime[9] ^= 1;
                Assert.Equal(FileCreationOwnership.StableKey(encoded.Platform, encoded.Bytes),
                    FileCreationOwnership.StableKey(encoded.Platform, changedTime));
                changedTime[21] ^= 1;
                Assert.NotEqual(FileCreationOwnership.StableKey(encoded.Platform, encoded.Bytes),
                    FileCreationOwnership.StableKey(encoded.Platform, changedTime));
                var mode = File.GetUnixFileMode(path);
                marker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
                Assert.Equal(32, marker.Length);
                Assert.Equal(marker, WorkspaceCreationMarker.Read(file.SafeFileHandle));
                Assert.Null(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
                Assert.Equal(marker, WorkspaceCreationMarker.Read(file.SafeFileHandle));
                Assert.Equal(unrelated, ReadOther(file.SafeFileHandle));
                Assert.Equal(mode, File.GetUnixFileMode(path));
                Assert.True(identity.SameObject(WorkspacePath.Identity(file.SafeFileHandle)));
            }

            using (var reopened = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Assert.True(identity.SameObject(WorkspacePath.Identity(reopened)));
                Assert.Equal(marker, WorkspaceCreationMarker.Read(reopened));
                Assert.Equal(unrelated, ReadOther(reopened));
            }
            Assert.Equal(body, File.ReadAllBytes(path));

            File.Delete(path); // only this test's newly created object
            using (var replacement = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                Assert.Null(WorkspaceCreationMarker.Read(replacement.SafeFileHandle));
                var replacementMarker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(replacement.SafeFileHandle));
                Assert.NotEqual(marker, replacementMarker);
            }
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    [Trait("env", "windows-real")]
    public void WindowsMarkerPreservesAnExistingEaStreamSecurityAndTheCreatedObject()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native EA fixture."); return; }
        var directory = Directory.CreateTempSubdirectory("arcforges-owner-marker-");
        try
        {
            var path = Path.Combine(directory.FullName, "created");
            var body = Encoding.UTF8.GetBytes("windows-marker-fixture-06d1");
            var other = Encoding.UTF8.GetBytes("separate-existing-ea");
            var stream = Encoding.UTF8.GetBytes("separate-existing-stream");
            byte[] marker;
            WorkspaceObjectIdentity identity;
            using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite,
                       FileShare.ReadWrite | FileShare.Delete))
            {
                file.Write(body);
                file.Flush(flushToDisk: true);
                File.WriteAllBytes(path + ":owner-fixture-stream", stream);
                SetWindowsOther(file.SafeFileHandle, "fixture.prior", other);
                identity = WorkspacePath.Identity(file.SafeFileHandle);
                var encoded = RegisteredWorkspaces.RootIdentity.Encode(identity, directory: false);
                var changedTime = encoded.Bytes.ToArray();
                changedTime[25] ^= 1;
                Assert.Equal(FileCreationOwnership.StableKey(encoded.Platform, encoded.Bytes),
                    FileCreationOwnership.StableKey(encoded.Platform, changedTime));
                changedTime[9] ^= 1;
                Assert.NotEqual(FileCreationOwnership.StableKey(encoded.Platform, encoded.Bytes),
                    FileCreationOwnership.StableKey(encoded.Platform, changedTime));
                var attributes = WorkspacePath.WindowsAttributes(file.SafeFileHandle);
                var security = WindowsSecurityDigest(file.SafeFileHandle);
                marker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
                Assert.Equal(marker, WorkspaceCreationMarker.Read(file.SafeFileHandle));
                Assert.Equal(other, ReadWindowsOther(file.SafeFileHandle, "fixture.prior"));
                Assert.Equal(attributes, WorkspacePath.WindowsAttributes(file.SafeFileHandle));
                Assert.Equal(security, WindowsSecurityDigest(file.SafeFileHandle));
                Assert.True(identity.SameObject(WorkspacePath.Identity(file.SafeFileHandle)));
                Assert.Null(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
                Assert.Equal(marker, WorkspaceCreationMarker.Read(file.SafeFileHandle));
            }
            using (var reopened = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Assert.True(identity.SameObject(WorkspacePath.Identity(reopened)));
                Assert.Equal(marker, WorkspaceCreationMarker.Read(reopened));
                Assert.Equal(other, ReadWindowsOther(reopened, "fixture.prior"));
            }
            Assert.Equal(body, File.ReadAllBytes(path));
            Assert.Equal(stream, File.ReadAllBytes(path + ":owner-fixture-stream"));
        }
        finally { directory.Delete(recursive: true); }
    }

    private static unsafe void SetWindowsOther(SafeFileHandle file, string name, byte[] value)
    {
        var nameBytes = Encoding.ASCII.GetBytes(name);
        var buffer = new byte[9 + nameBytes.Length + value.Length];
        buffer[5] = checked((byte)nameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(6, 2), checked((ushort)value.Length));
        nameBytes.CopyTo(buffer, 8);
        value.CopyTo(buffer, 9 + nameBytes.Length);
        fixed (byte* pointer = buffer)
            Assert.Equal(0, SetWindows(file, out _, pointer, checked((uint)buffer.Length)));
    }

    private static unsafe byte[]? ReadWindowsOther(SafeFileHandle file, string expected)
    {
        var buffer = new byte[65_536];
        IoStatus status;
        int result;
        fixed (byte* pointer = buffer)
            result = QueryWindows(file, out status, pointer, (uint)buffer.Length, 0, 0, 0, 0, 1);
        Assert.Equal(0, result);
        var length = checked((int)status.Information);
        for (var offset = 0; offset < length;)
        {
            var data = buffer.AsSpan(offset, length - offset);
            var next = BinaryPrimitives.ReadUInt32LittleEndian(data);
            var nameLength = data[5];
            var valueLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(6, 2));
            if (string.Equals(Encoding.Latin1.GetString(data.Slice(8, nameLength)), expected, StringComparison.OrdinalIgnoreCase))
                return data.Slice(9 + nameLength, valueLength).ToArray();
            if (next == 0) break;
            offset = checked(offset + (int)next);
        }
        return null;
    }

    private static byte[] WindowsSecurityDigest(SafeFileHandle file)
    {
        Assert.Equal(0U, GetSecurity(file, 1, 7, 0, 0, 0, 0, out var descriptor));
        try
        {
            var length = checked((int)GetSecurityLength(descriptor));
            var data = new byte[length];
            Marshal.Copy(descriptor, data, 0, length);
            return SHA256.HashData(data);
        }
        finally { _ = LocalFree(descriptor); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatus { internal nint Status; internal nuint Information; }

    [LibraryImport("ntdll.dll", EntryPoint = "NtSetEaFile")]
    private static unsafe partial int SetWindows(SafeFileHandle file, out IoStatus io, byte* buffer, uint length);

    [LibraryImport("ntdll.dll", EntryPoint = "NtQueryEaFile")]
    private static unsafe partial int QueryWindows(SafeFileHandle file, out IoStatus io, byte* buffer, uint length,
        byte singleEntry, nint names, uint namesLength, nint index, byte restart);

    [LibraryImport("advapi32.dll", EntryPoint = "GetSecurityInfo")]
    private static partial uint GetSecurity(SafeFileHandle file, int type, uint flags,
        nint owner, nint group, nint dacl, nint sacl, out nint descriptor);

    [LibraryImport("advapi32.dll", EntryPoint = "GetSecurityDescriptorLength")]
    private static partial uint GetSecurityLength(nint descriptor);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint memory);

    private static unsafe byte[] ReadOther(SafeFileHandle file)
    {
        var value = new byte[64];
        fixed (byte* pointer = value)
        {
            var length = GetOther(file, "user.owner_fixture", pointer, (nuint)value.Length);
            Assert.True(length >= 0);
            return value.AsSpan(0, checked((int)length)).ToArray();
        }
    }

    [LibraryImport("libc", EntryPoint = "fsetxattr", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int SetOther(SafeFileHandle file, string name, byte[] value, nuint size, int flags);

    [LibraryImport("libc", EntryPoint = "fgetxattr", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial nint GetOther(SafeFileHandle file, string name, byte* value, nuint size);
}
