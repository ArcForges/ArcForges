// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.ContentSandbox.Host;
using ArcForges.LocalRpc;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ContentSandbox.Native;

/// <summary>
/// The two Windows calls the helper needs: mapping and unmapping the shared sections it inherited. Nothing else is imported; the
/// section handles are closed through <see cref="SafeFileHandle"/>, and creating a section is the parent's alone.
/// </summary>
[SuppressMessage("Design", "CA1060", Justification = "One owner type holds the closed set of helper bindings of the Windows profile.")]
internal static partial class HelperWindowsNative
{
    internal const uint FileMapWrite = 0x0002;
    internal const uint FileMapRead = 0x0004;

    [LibraryImport("Kernel32.dll", EntryPoint = "MapViewOfFile", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static partial nint MapViewOfFile(nint section, uint desiredAccess, uint offsetHigh, uint offsetLow, nuint bytes);

    [LibraryImport("Kernel32.dll", EntryPoint = "UnmapViewOfFile", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool UnmapViewOfFile(nint baseAddress);
}

/// <summary>One inherited section mapped into the helper: the read-only input or a writable output slot.</summary>
[SupportedOSPlatform("windows")]
internal sealed unsafe class WindowsMappedView : ILocalRpcBufferMapping, IHelperSlot
{
    private readonly object _gate = new();
    private readonly SafeFileHandle _section;
    private nint _base;
    private int _disposed;

    private WindowsMappedView(SafeFileHandle section, nint baseAddress, long length)
    {
        _section = section;
        _base = baseAddress;
        Length = length;
    }

    /// <inheritdoc />
    public long Length { get; }

    /// <inheritdoc />
    long IParserSlot.Capacity => Length;

    /// <summary>Maps <paramref name="length"/> bytes of an inherited section. The handle is closed with the view.</summary>
    internal static WindowsMappedView Map(ulong sectionHandle, long length, bool writable)
    {
        var section = new SafeFileHandle((nint)sectionHandle, ownsHandle: true);
        var access = writable ? HelperWindowsNative.FileMapRead | HelperWindowsNative.FileMapWrite : HelperWindowsNative.FileMapRead;
        var address = HelperWindowsNative.MapViewOfFile(section.DangerousGetHandle(), access, 0, 0, (nuint)length);
        if (address == 0)
        {
            var error = Marshal.GetLastPInvokeError();
            section.Dispose();
            throw new InvalidOperationException("An inherited section could not be mapped (error " + error + ").");
        }

        return new WindowsMappedView(section, address, length);
    }

    /// <inheritdoc />
    public int Read(long offset, Span<byte> destination)
    {
        if (offset < 0 || offset > Length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        var count = (int)Math.Min(destination.Length, Length - offset);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_base == 0, this);
            new ReadOnlySpan<byte>((byte*)_base + offset, count).CopyTo(destination);
        }

        return count;
    }

    /// <inheritdoc />
    public Span<byte> GetSpan(long offset, int length)
    {
        if (offset < 0 || length < 0 || offset > Length || length > Length - offset)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        ObjectDisposedException.ThrowIf(_base == 0, this);
        return new Span<byte>((byte*)_base + offset, length);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        nint address;
        lock (_gate)
        {
            address = _base;
            _base = 0;
        }

        if (address != 0)
        {
            _ = HelperWindowsNative.UnmapViewOfFile(address);
        }

        _section.Dispose();
    }
}
