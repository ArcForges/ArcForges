// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// A private, per-creation marker on an already opened object. The caller must establish exclusive creation and
/// authorization. This primitive neither reopens a name nor grants ownership or cleanup authority.
/// </summary>
internal static unsafe partial class WorkspaceCreationMarker
{
    private const int MarkerLength = 32;
    private const int MaximumEaBytes = 65_536;
    private const string WindowsPrefix = "ArcForges.Creator.";
    private const string LinuxName = "user.arcforges.creator";

    /// <summary>Only call for an object this operation actually created with an exclusive native create.</summary>
    internal static byte[]? TryWriteNew(SafeFileHandle file)
    {
        ArgumentNullException.ThrowIfNull(file);
        var marker = RandomNumberGenerator.GetBytes(MarkerLength);
        if (OperatingSystem.IsLinux())
        {
            if (SetLinux(file, LinuxName, marker, (nuint)marker.Length, 1) != 0)
            {
                var error = Marshal.GetLastPInvokeError();
                // Existing marker, unavailable facility, or a proven access/quota refusal: do not overwrite or adopt.
                if (error is 1 or 13 or 17 or 28 or 30 or 95) return null;
                throw new IOException("Creation marker write could not be established.");
            }
            var observed = ReadLinux(file);
            if (observed is null || !CryptographicOperations.FixedTimeEquals(marker, observed))
                throw new IOException("Creation marker readback did not match.");
            RandomAccess.FlushToDisk(file);
            var flushed = ReadLinux(file);
            if (flushed is null || !CryptographicOperations.FixedTimeEquals(marker, flushed))
                throw new IOException("Flushed creation marker readback did not match.");
            return marker;
        }

        if (!OperatingSystem.IsWindows() || !IsNtfs(file)) return null;
        var before = ReadWindowsEntries(file);
        // The EA name includes unpredictable bits, so setting it does not intentionally replace an existing EA.
        // NTFS does not offer XATTR_CREATE semantics; a product-reserved prior marker is never adopted.
        if (before is null || before.Keys.Any(name => name.StartsWith(WindowsPrefix, StringComparison.OrdinalIgnoreCase))) return null;
        var markerName = WindowsMarkerName(marker);
        if (before.ContainsKey(markerName)) return null;
        var name = Encoding.ASCII.GetBytes(markerName);
        var input = new byte[8 + name.Length + 1 + marker.Length];
        input[5] = checked((byte)name.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(6, 2), MarkerLength);
        name.CopyTo(input, 8);
        marker.CopyTo(input, 9 + name.Length);
        int status;
        fixed (byte* buffer = input)
        {
            status = SetWindows(file, out _, buffer, checked((uint)input.Length));
        }

        // A failed or successful call is followed by a real observation before treating the write as unavailable.
        // A surprising change is uncertain, never a license to claim a successful ownership record.
        var after = ReadWindowsEntries(file) ?? throw new IOException("Creation marker metadata became unobservable.");
        if (status != 0)
        {
            if (SameEntries(before, after)) return null;
            throw new IOException("Creation marker outcome is uncertain.");
        }
        if (after.Count != before.Count + 1 || !after.TryGetValue(markerName, out var actual) ||
            !CryptographicOperations.FixedTimeEquals(marker, actual))
            throw new IOException("Creation marker readback did not match.");
        foreach (var entry in before)
        {
            if (!after.TryGetValue(entry.Key, out var value) || !entry.Value.AsSpan().SequenceEqual(value))
                throw new IOException("Existing extended attributes changed while marking the created object.");
        }

        RandomAccess.FlushToDisk(file);
        var flushedMarker = Read(file, marker);
        if (flushedMarker is null || !CryptographicOperations.FixedTimeEquals(marker, flushedMarker))
            throw new IOException("Flushed creation marker readback did not match.");
        return marker;
    }

    /// <summary>Reads the marker from the same already checked file handle; null means missing or unavailable.</summary>
    internal static byte[]? Read(SafeFileHandle file, ReadOnlySpan<byte> expected = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (OperatingSystem.IsLinux()) return ReadLinux(file);
        if (!OperatingSystem.IsWindows() || !IsNtfs(file)) return null;
        var entries = ReadWindowsEntries(file);
        if (entries is null) return null;
        if (expected.Length == MarkerLength)
            return entries.TryGetValue(WindowsMarkerName(expected), out var found) && found.Length == MarkerLength ? found : null;
        byte[]? result = null;
        foreach (var entry in entries)
        {
            if (!entry.Key.StartsWith(WindowsPrefix, StringComparison.OrdinalIgnoreCase)) continue;
            if (result is not null || entry.Value.Length != MarkerLength ||
                !string.Equals(entry.Key, WindowsMarkerName(entry.Value), StringComparison.OrdinalIgnoreCase)) return null;
            result = entry.Value;
        }
        return result;
    }

    private static string WindowsMarkerName(ReadOnlySpan<byte> marker) =>
        WindowsPrefix + Convert.ToHexString(marker[..16]);

    private static byte[]? ReadLinux(SafeFileHandle file)
    {
        var buffer = new byte[MarkerLength];
        fixed (byte* value = buffer)
        {
            var size = GetLinux(file, LinuxName, value, (nuint)buffer.Length);
            return size == MarkerLength ? buffer : null;
        }
    }

    private static bool SameEntries(Dictionary<string, byte[]> left, Dictionary<string, byte[]> right) =>
        left.Count == right.Count && left.All(entry =>
            right.TryGetValue(entry.Key, out var value) && entry.Value.AsSpan().SequenceEqual(value));

    private static Dictionary<string, byte[]>? ReadWindowsEntries(SafeFileHandle file)
    {
        var buffer = new byte[MaximumEaBytes];
        IoStatus io;
        int status;
        fixed (byte* pointer = buffer)
        {
            status = QueryWindows(file, out io, pointer, checked((uint)buffer.Length), 0, 0, 0, 0, 1);
        }
        if (status == unchecked((int)0xc0000052)) return new(StringComparer.OrdinalIgnoreCase); // no EAs
        if (status != 0 || io.Information > (nuint)buffer.Length) return null;
        var length = checked((int)io.Information);
        var entries = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        if (length == 0) return entries;
        for (var offset = 0; ;)
        {
            if (offset < 0 || offset > length - 8) return null;
            var span = buffer.AsSpan(offset, length - offset);
            var next = BinaryPrimitives.ReadUInt32LittleEndian(span);
            var nameLength = span[5];
            var valueLength = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(6, 2));
            var itemLength = 9 + nameLength + valueLength;
            if (nameLength == 0 || itemLength > span.Length || span[8 + nameLength] != 0) return null;
            var name = Encoding.Latin1.GetString(span.Slice(8, nameLength));
            if (!entries.TryAdd(name, span.Slice(9 + nameLength, valueLength).ToArray())) return null;
            if (next == 0) break;
            if (next < itemLength || next > span.Length || (next & 3) != 0) return null;
            offset = checked(offset + (int)next);
        }
        return entries;
    }

    private static bool IsNtfs(SafeFileHandle file)
    {
        var name = stackalloc char[32];
        new Span<char>(name, 32).Clear();
        return GetVolumeInformation(file, null, 0, null, null, null, name, 32) &&
            string.Equals(new string(name), "NTFS", StringComparison.OrdinalIgnoreCase);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatus
    {
        internal nint Status;
        internal nuint Information;
    }

    [LibraryImport("libc", EntryPoint = "fsetxattr", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int SetLinux(SafeFileHandle file, string name, byte[] value, nuint size, int flags);

    [LibraryImport("libc", EntryPoint = "fgetxattr", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint GetLinux(SafeFileHandle file, string name, byte* value, nuint size);

    [LibraryImport("ntdll.dll", EntryPoint = "NtSetEaFile")]
    private static partial int SetWindows(SafeFileHandle file, out IoStatus io, byte* buffer, uint length);

    [LibraryImport("ntdll.dll", EntryPoint = "NtQueryEaFile")]
    private static partial int QueryWindows(SafeFileHandle file, out IoStatus io, byte* buffer, uint length,
        byte singleEntry, nint names, uint namesLength, nint index, byte restart);

    [LibraryImport("kernel32.dll", EntryPoint = "GetVolumeInformationByHandleW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetVolumeInformation(SafeFileHandle file, char* volumeName, uint volumeNameLength,
        uint* serial, uint* maximumName, uint* flags, char* fileSystemName, uint fileSystemNameLength);
}
