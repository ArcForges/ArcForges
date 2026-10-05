// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ArcForges.Native.Abstractions;

namespace ArcForges.Native.Pdf;

/// <summary>
/// A document opened through arc_pdf_open. The native library reads the input through callbacks into <see cref="IPdfInput"/>, so the
/// input must stay valid until this object is disposed. Every failure is a <see cref="PdfNativeException"/> carrying the closed ABI status,
/// or an <see cref="OperationCanceledException"/> for a cancellation. No native pointer or handle value is ever exposed.
/// </summary>
internal sealed unsafe class PdfDocument : IPdfDocument
{
    private const int MaxTextResponseBytes = 64 * 1024 * 1024;
    private const int NativeStructVersion = 1;

    private readonly object _gate = new();
    private readonly GCHandle _inputHandle;
    private ulong _handle;

    private PdfDocument(ulong handle, uint pages, GCHandle inputHandle)
    {
        _handle = handle;
        PageCount = pages;
        _inputHandle = inputHandle;
    }

    /// <inheritdoc />
    public uint PageCount { get; }

    /// <summary>
    /// Opens a document. An empty password is allowed; a password that is required but missing or wrong is a
    /// <see cref="NativeStatus.PermissionDenied"/> failure. A library with no PDF backend linked fails with <see cref="NativeStatus.Unsupported"/>.
    /// </summary>
    public static PdfDocument Open(IPdfInput input, PdfLimits limits, ReadOnlySpan<byte> password, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(limits);
        if (input.Length <= 0)
        {
            throw new PdfNativeException(NativeStatus.Corrupt, "The input is empty.");
        }

        cancellation.ThrowIfCancellationRequested();
        var inputHandle = GCHandle.Alloc(new InputBridge(input));
        var cancelHandle = GCHandle.Alloc(new CancelBridge(cancellation));
        try
        {
            NativeIoV1 io = new()
            {
                StructSize = (uint)sizeof(NativeIoV1),
                StructVersion = NativeStructVersion,
                Context = GCHandle.ToIntPtr(inputHandle),
                Length = (ulong)input.Length,
                MaxLength = (ulong)input.Length,
                ReadAt = &ReadAtCallback,
            };
            NativeLimitsV1 native = ToNative(limits);
            NativeCancelToken token = CancelToken(cancelHandle);
            var (status, handle, pages) = NativeOpen(&io, password, &native, &token);
            if (status != 0)
            {
                throw Failure(status, cancellation);
            }

            if (handle == 0 || pages == 0)
            {
                if (handle != 0)
                {
                    _ = PdfAbi.Close(handle);
                }

                throw new PdfNativeException(NativeStatus.Internal, "The native open reported success without a document.");
            }

            return new PdfDocument(handle, pages, inputHandle);
        }
        catch
        {
            inputHandle.Free();
            throw;
        }
        finally
        {
            cancelHandle.Free();
        }
    }

    /// <inheritdoc />
    public PdfPageGeometry GetPage(uint pageIndex)
    {
        var handle = Live();
        NativePdfPageV1 page = NewPage(0);
        var status = PdfAbi.PageInfo(handle, pageIndex, &page);
        if (status != 0)
        {
            throw Failure(status, CancellationToken.None);
        }

        if (page.PageIndex != pageIndex || !double.IsFinite(page.WidthPoints) || !double.IsFinite(page.HeightPoints) || page.WidthPoints <= 0 || page.HeightPoints <= 0
            || page.Rotation is not (0 or 90 or 180 or 270))
        {
            throw new PdfNativeException(NativeStatus.Corrupt, "The native page geometry is invalid.");
        }

        return new PdfPageGeometry(pageIndex, page.Rotation, page.WidthPoints, page.HeightPoints);
    }

    /// <inheritdoc />
    public PdfTextChunk ExtractText(uint pageIndex, uint start, uint count, CancellationToken cancellation)
    {
        var handle = Live();
        var cancelHandle = GCHandle.Alloc(new CancelBridge(cancellation));
        try
        {
            NativeCancelToken token = CancelToken(cancelHandle);
            for (var attempt = 0; attempt < 3; attempt++)
            {
                NativeBuffer query = default;
                var status = PdfAbi.Text(handle, pageIndex, start, count, &query, &token);
                if (status != (int)NativeStatus.BufferTooSmall)
                {
                    throw status == 0
                        ? new PdfNativeException(NativeStatus.Internal, "The native text query reported success without a size.")
                        : Failure(status, cancellation);
                }

                if (query.Required == 0 || query.Required > MaxTextResponseBytes)
                {
                    throw new PdfNativeException(NativeStatus.ResourceLimit, "The native text response size is out of bounds.");
                }

                var bytes = GC.AllocateUninitializedArray<byte>((int)query.Required);
                fixed (byte* data = bytes)
                {
                    NativeBuffer output = new() { Data = (nint)data, Capacity = (ulong)bytes.Length };
                    status = PdfAbi.Text(handle, pageIndex, start, count, &output, &token);
                    if (status == (int)NativeStatus.BufferTooSmall)
                    {
                        continue; // the page text changed between the two calls; ask again
                    }

                    if (status != 0)
                    {
                        throw Failure(status, cancellation);
                    }

                    if (output.Required != (ulong)bytes.Length)
                    {
                        throw new PdfNativeException(NativeStatus.Internal, "The native text size changed.");
                    }
                }

                return PdfTextJson.Parse(bytes, pageIndex, start);
            }

            throw new PdfNativeException(NativeStatus.Busy, "The native text size kept changing.");
        }
        finally
        {
            cancelHandle.Free();
        }
    }

    /// <inheritdoc />
    public int Render(PdfPageGeometry page, uint x, uint y, uint width, uint height, uint fullWidth, uint fullHeight, uint rowStride, Span<byte> destination, CancellationToken cancellation)
    {
        var handle = Live();
        var cancelHandle = GCHandle.Alloc(new CancelBridge(cancellation));
        try
        {
            NativeCancelToken token = CancelToken(cancelHandle);
            NativePdfPageV1 nativePage = NewPage(page.PageIndex);
            nativePage.Rotation = page.Rotation;
            nativePage.WidthPoints = page.WidthPoints;
            nativePage.HeightPoints = page.HeightPoints;
            NativeRegionV1 region = new()
            {
                StructSize = (uint)sizeof(NativeRegionV1),
                StructVersion = NativeStructVersion,
                X = x,
                Y = y,
                Width = width,
                Height = height,
                RowStride = rowStride,
            };
            fixed (byte* data = destination)
            {
                NativeBuffer buffer = new() { Data = (nint)data, Capacity = (ulong)destination.Length };
                var status = PdfAbi.Render(handle, &nativePage, &region, fullWidth, fullHeight, &buffer, &token);
                if (status != 0)
                {
                    throw Failure(status, cancellation);
                }

                if (buffer.Required > (ulong)destination.Length || buffer.Required > int.MaxValue)
                {
                    throw new PdfNativeException(NativeStatus.Internal, "The native render reported more bytes than it was given.");
                }

                return (int)buffer.Required;
            }
        }
        finally
        {
            cancelHandle.Free();
        }
    }

    /// <summary>Closes the document and releases the input callbacks. The native close waits for calls that are still running.</summary>
    public void Dispose()
    {
        ulong handle;
        lock (_gate)
        {
            handle = _handle;
            _handle = 0;
        }

        if (handle == 0)
        {
            return;
        }

        _ = PdfAbi.Close(handle);
        _inputHandle.Free();
    }

    private static (int Status, ulong Handle, uint Pages) NativeOpen(NativeIoV1* io, ReadOnlySpan<byte> password, NativeLimitsV1* limits, NativeCancelToken* token)
    {
        ulong handle = 0;
        uint pages = 0;
        int status;
        fixed (byte* secret = password)
        {
            NativeStringView view = new() { Data = (nint)secret, Size = (ulong)password.Length };
            status = PdfAbi.Open(io, view, limits, &handle, &pages, token);
        }

        return (status, handle, pages);
    }

    private ulong Live()
    {
        lock (_gate)
        {
            return _handle != 0 ? _handle : throw new ObjectDisposedException(nameof(PdfDocument));
        }
    }

    private static NativePdfPageV1 NewPage(uint index) => new()
    {
        StructSize = (uint)sizeof(NativePdfPageV1),
        StructVersion = NativeStructVersion,
        PageIndex = index,
    };

    private static NativeLimitsV1 ToNative(PdfLimits limits) => new()
    {
        StructSize = (uint)sizeof(NativeLimitsV1),
        StructVersion = NativeStructVersion,
        MaxInputBytes = limits.MaxInputBytes,
        MaxMemoryBytes = limits.MaxMemoryBytes,
        MaxOutputBytes = limits.MaxOutputBytes,
        MaxWidth = limits.MaxWidth,
        MaxHeight = limits.MaxHeight,
        MaxItems = limits.MaxItems,
        TimeoutMs = limits.TimeoutMs,
    };

    private static NativeCancelToken CancelToken(GCHandle cancelHandle) => new()
    {
        StructSize = (uint)sizeof(NativeCancelToken),
        StructVersion = NativeStructVersion,
        IsCancelled = &IsCancelledCallback,
        UserData = GCHandle.ToIntPtr(cancelHandle),
    };

    private static Exception Failure(int status, CancellationToken cancellation)
    {
        if (status == (int)NativeStatus.Cancelled)
        {
            return new OperationCanceledException(cancellation);
        }

        var message = string.Empty;
        try
        {
            message = PdfAbi.LastError().Message;
        }
        catch (InvalidOperationException)
        {
            // The diagnostic is best effort; the status is the contract.
        }

        var known = Enum.IsDefined(typeof(NativeStatus), status) ? (NativeStatus)status : NativeStatus.Internal;
        return new PdfNativeException(known, message);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    [SuppressMessage("Design", "CA1031", Justification = "An exception must never cross the native frame; it becomes the closed I/O status.")]
    private static int ReadAtCallback(nint context, ulong offset, nint destination, ulong requested, ulong* done)
    {
        try
        {
            if (done is null)
            {
                return (int)NativeStatus.InvalidArgument;
            }

            *done = 0;
            var bridge = (InputBridge?)GCHandle.FromIntPtr(context).Target;
            if (bridge is null || requested > int.MaxValue || offset > (ulong)long.MaxValue)
            {
                return (int)NativeStatus.InvalidArgument;
            }

            var count = bridge.Input.ReadAt((long)offset, new Span<byte>((void*)destination, (int)requested));
            if (count < 0 || (ulong)count > requested)
            {
                return (int)NativeStatus.Io;
            }

            *done = (ulong)count;
            return 0;
        }
        catch (Exception)
        {
            return (int)NativeStatus.Io;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    [SuppressMessage("Design", "CA1031", Justification = "An exception must never cross the native frame; an unreadable token counts as cancelled.")]
    private static byte IsCancelledCallback(nint userData)
    {
        try
        {
            return ((CancelBridge?)GCHandle.FromIntPtr(userData).Target)?.Token.IsCancellationRequested == false ? (byte)0 : (byte)1;
        }
        catch (Exception)
        {
            return 1;
        }
    }

    private sealed class InputBridge(IPdfInput input)
    {
        internal IPdfInput Input { get; } = input;
    }

    private sealed class CancelBridge(CancellationToken token)
    {
        internal CancellationToken Token { get; } = token;
    }
}
