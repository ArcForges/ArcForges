// SPDX-License-Identifier: AGPL-3.0-only
using System.IO.MemoryMappedFiles;
using ArcForges.LocalRpc;

namespace ArcForges.ContentSandbox.Broker;

/// <summary>
/// The parent's read view of one anonymous shared mapping. The mapping is created by the launcher, never named, and reaches the helper only
/// through the launch allowlist. Whoever else maps the memory may be writing it, so a read is a raw copy and is never trusted.
/// </summary>
internal sealed unsafe class MappedSlot : ILocalRpcBufferMapping
{
    private readonly object _gate = new();
    private readonly MemoryMappedFile _file;
    private readonly MemoryMappedViewAccessor _view;
    private bool _disposed;

    internal MappedSlot(MemoryMappedFile file, long capacity)
    {
        _file = file;
        Length = capacity;
        _view = file.CreateViewAccessor(0, capacity, MemoryMappedFileAccess.Read);
    }

    /// <summary>The OS handle of the section, for the launcher's handle list only.</summary>
    internal nint SectionHandle => _file.SafeMemoryMappedFileHandle.DangerousGetHandle();

    /// <inheritdoc />
    public long Length { get; }

    /// <inheritdoc />
    public int Read(long offset, Span<byte> destination)
    {
        if (offset < 0 || offset > Length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        var count = (int)Math.Min(destination.Length, Length - offset);
        if (count == 0)
        {
            return 0;
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            byte* pointer = null;
            var handle = _view.SafeMemoryMappedViewHandle;
            handle.AcquirePointer(ref pointer);
            try
            {
                new ReadOnlySpan<byte>(pointer + _view.PointerOffset + offset, count).CopyTo(destination);
            }
            finally
            {
                handle.ReleasePointer();
            }
        }

        return count;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        _view.Dispose();
        _file.Dispose();
    }
}
