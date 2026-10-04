// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.IO.MemoryMappedFiles;
using System.Net.Sockets;
using System.Runtime.Versioning;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using ArcForges.LocalRpc;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ContentSandbox.Native;

/// <summary>
/// The Linux resources of the helper: the two streams are connected Unix sockets it inherited, and the input and every slot are inherited
/// memory-backed files mapped shared. They are opened before the profile is in force, from descriptor numbers the launch frame lists, and
/// from nothing else. Landlock does not affect a descriptor that is already open.
/// </summary>
[SupportedOSPlatform("linux")]
[SuppressMessage("Reliability", "CA2000", Justification = "Every stream and mapping is owned by the returned resources or disposed on the failure paths.")]
internal static class LinuxResources
{
    internal static HelperResources Open(ContentSandboxLaunchFrame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        var opened = new List<IDisposable>();
        try
        {
            var control = SocketStream(HelperEntry.Require(frame, ContentSandboxHandleRole.Control));
            opened.Add(control);
            var service = SocketStream(HelperEntry.Require(frame, ContentSandboxHandleRole.Service));
            opened.Add(service);
            var input = LinuxMappedView.Map(HelperEntry.Require(frame, ContentSandboxHandleRole.Input), checked((long)frame.InputLength), writable: false);
            opened.Add(input);
            var slots = new List<IHelperSlot>();
            for (var index = 0; index < frame.SlotCapacities.Count; index++)
            {
                var role = (ContentSandboxHandleRole)((int)ContentSandboxHandleRole.Slot0 + index);
                var slot = LinuxMappedView.Map(HelperEntry.Require(frame, role), checked((long)frame.SlotCapacities[index]), writable: true);
                opened.Add(slot);
                slots.Add(slot);
            }

            return new HelperResources(control, service, input, slots);
        }
        catch
        {
            foreach (var resource in opened)
            {
                resource.Dispose();
            }

            throw;
        }
    }

    private static NetworkStream SocketStream(ulong descriptor)
    {
        var socket = new Socket(new SafeSocketHandle((nint)descriptor, ownsHandle: true));
        return new NetworkStream(socket, ownsSocket: true);
    }
}

/// <summary>One inherited memory-backed file mapped shared: the read-only input or a writable output slot.</summary>
[SupportedOSPlatform("linux")]
[SuppressMessage("Reliability", "CA2000", Justification = "The stream, the file and the view are owned by the mapping and disposed with it.")]
internal sealed unsafe class LinuxMappedView : ILocalRpcBufferMapping, IHelperSlot
{
    private readonly object _gate = new();
    private readonly MemoryMappedFile _file;
    private readonly MemoryMappedViewAccessor _view;
    private long _base;
    private int _disposed;

    private LinuxMappedView(MemoryMappedFile file, MemoryMappedViewAccessor view, long length)
    {
        _file = file;
        _view = view;
        Length = length;
        byte* pointer = null;
        view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
        _base = (nint)pointer + (nint)view.PointerOffset;
    }

    /// <inheritdoc />
    public long Length { get; }

    /// <inheritdoc />
    long IParserSlot.Capacity => Length;

    internal static LinuxMappedView Map(ulong descriptor, long length, bool writable)
    {
        var stream = new FileStream(new SafeFileHandle((nint)descriptor, ownsHandle: true), writable ? FileAccess.ReadWrite : FileAccess.Read, 1, false);
        var access = writable ? MemoryMappedFileAccess.ReadWrite : MemoryMappedFileAccess.Read;
        MemoryMappedFile file;
        try
        {
            file = MemoryMappedFile.CreateFromFile(stream, null, length, access, HandleInheritability.None, leaveOpen: false);
        }
        catch
        {
            stream.Dispose();
            throw;
        }

        try
        {
            return new LinuxMappedView(file, file.CreateViewAccessor(0, length, access), length);
        }
        catch
        {
            file.Dispose();
            throw;
        }
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
            new ReadOnlySpan<byte>((byte*)(nint)_base + offset, count).CopyTo(destination);
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
        return new Span<byte>((byte*)(nint)_base + offset, length);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        lock (_gate)
        {
            _base = 0;
        }

        _view.SafeMemoryMappedViewHandle.ReleasePointer();
        _view.Dispose();
        _file.Dispose();
    }
}
