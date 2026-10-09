// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.InteropServices;
using ArcForges.Native.Abstractions;

namespace ArcForges.Native.Image;

// One open still image. Reads are serialised per reader (the native handle is single-caller), coverage is
// accounted here as well as natively, and DisposeAsync drains the in-flight read before closing the handle.
public sealed class ImageReader : IAsyncDisposable
{
    private const int MetadataInitialBytes = 64 * 1024;
    private const int MetadataMaximumBytes = 1024 * 1024;

    private readonly ImageHandle _handle;
    private readonly ImageLimits _limits;

    // Guards every native call and the coverage counters. It is never disposed, because a queued waiter
    // may still be releasing it during DisposeAsync.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2213:Disposable fields should be disposed",
        Justification = "The gate is released, not disposed, so queued waiters can finish their Release safely.")]
    private readonly SemaphoreSlim _gate = new(1, 1);

    private readonly CancellationTokenSource _closing = new();
    private ulong _coveredPixels;
    private uint _regionCount;
    private bool _disposed;
    private int _disposeStarted;

    private ImageReader(ImageHandle handle, ImageMetadata metadata, ImageLimits limits)
    {
        _handle = handle;
        Metadata = metadata;
        _limits = limits;
    }

    // Immutable description of the selected level, parsed from the native metadata document.
    public ImageMetadata Metadata { get; }

    // Opens one level of an image. The source is read synchronously by native code for as long as the
    // reader is open. Content is probed from its bytes, so the declared name never selects a codec.
    public static async Task<ImageReader> OpenAsync(ImageByteSource source, ImageOpenOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ImageOpenOptions effective = options ?? new ImageOpenOptions();
        effective.Validate();
        ulong length = SourceLength(source);
        return await Task.Run(() => Open(source, effective, length, cancellationToken), cancellationToken)
            .ConfigureAwait(false);
    }

    // Opens, reads the metadata and closes again. Nothing is retained after the call returns.
    public static async Task<ImageMetadata> ProbeAsync(ImageByteSource source, ImageOpenOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ImageReader reader = await OpenAsync(source, options, cancellationToken).ConfigureAwait(false);
        try
        {
            return reader.Metadata;
        }
        finally
        {
            await reader.DisposeAsync().ConfigureAwait(false);
        }
    }

    // Reads one rectangle. Regions must be disjoint and arrive in raster order (decision D3). A refused or
    // cancelled region changes no coverage, so the caller may retry it.
    public async Task<ImagePixelRegion> ReadRegionAsync(ImageRegion region, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposeStarted) != 0, this);
        ValidateRegion(region);
        ulong bytes = (ulong)region.Width * region.Height * Metadata.BytesPerPixel;
        if (bytes > _limits.MaxOutputBytes)
        {
            throw new ImageNativeException(NativeStatus.ResourceLimit, "The region exceeds the output byte limit.");
        }

        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _closing.Token);
        await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            byte[] pixels = GC.AllocateUninitializedArray<byte>(checked((int)bytes));
            await Task.Run(() => ReadNative(region, pixels, linked.Token), linked.Token).ConfigureAwait(false);

            // A read that finished after cancellation was requested is discarded, so it consumes no coverage and
            // the caller can retry the same region.
            linked.Token.ThrowIfCancellationRequested();
            _coveredPixels += (ulong)region.Width * region.Height;
            _regionCount++;
            return new ImagePixelRegion(region, Metadata.OutputFormat, Metadata.BytesPerPixel, pixels);
        }
        finally
        {
            _gate.Release();
        }
    }

    // Completion step (decision D3). Succeeds only when successful reads covered every pixel of the level.
    // Otherwise it throws ImageCoverageIncompleteException, and no completion record exists.
    public async Task<ImageCompletion> CompleteAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposeStarted) != 0, this);
        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _closing.Token);
        await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ulong total = (ulong)Metadata.Width * Metadata.Height;
            if (_coveredPixels != total)
            {
                throw new ImageCoverageIncompleteException(_coveredPixels, total);
            }

            return new ImageCompletion(Metadata.Width, Metadata.Height, _coveredPixels, _regionCount);
        }
        finally
        {
            _gate.Release();
        }
    }

    // Cancels an in-flight read at its next tile or source boundary, waits for it to end, and then closes the
    // native handle. Calling it more than once is harmless.
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0)
        {
            return;
        }

        await _closing.CancelAsync().ConfigureAwait(false);
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            _disposed = true;
            _handle.Dispose();
        }
        finally
        {
            _gate.Release();
            _closing.Dispose();
        }
    }

    private static ulong SourceLength(ImageByteSource source)
    {
        long length = source.Length;
        if (length < 0)
        {
            throw new ArgumentException("The image source length is negative.", nameof(source));
        }

        return (ulong)length;
    }

    private static unsafe ImageReader Open(ImageByteSource source, ImageOpenOptions options, ulong length,
        CancellationToken cancellationToken)
    {
        ImageAbi.RequireFunctionalAbi();
        GCHandle context = GCHandle.Alloc(source);
        bool transferred = false;
        try
        {
            NativeImageOptionsV1 nativeOptions = options.ToNative();
            int capacity = MetadataInitialBytes;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                byte[] buffer = GC.AllocateUninitializedArray<byte>(capacity);
                ulong image = 0;
                ulong required;
                NativeStatus status;
                using (var bridge = new CancellationBridge(cancellationToken))
                {
                    NativeIoV1 io = new()
                    {
                        StructSize = (uint)sizeof(NativeIoV1),
                        StructVersion = NativeAbiConstants.RecordVersion1,
                        Context = GCHandle.ToIntPtr(context),
                        Length = length,
                        MaxLength = length,
                        ReadAt = &ImageCallbacks.ReadAt,
                    };
                    NativeCancelToken cancel = bridge.Token;
                    NativeCancelToken* cancelPointer = bridge.Enabled ? &cancel : null;
                    fixed (byte* data = buffer)
                    {
                        NativeBuffer metadata = new() { Data = (nint)data, Capacity = (ulong)capacity };
                        status = ImageAbi.OpenNative(&io, &nativeOptions, &image, &metadata, cancelPointer);
                        required = metadata.Required;
                    }
                }

                if (status == NativeStatus.Ok)
                {
                    ImageHandle? handle = new ImageHandle(image, context);
                    transferred = true;
                    try
                    {
                        if (required == 0 || required > (ulong)buffer.Length)
                        {
                            throw new ImageNativeException(NativeStatus.Internal, "The native metadata size is outside its buffer.");
                        }

                        ImageMetadata metadata = ImageMetadata.Parse(buffer.AsSpan(0, checked((int)required)));
                        var reader = new ImageReader(handle, metadata, options.Limits);
                        handle = null;
                        return reader;
                    }
                    finally
                    {
                        handle?.Dispose();
                    }
                }

                if (status == NativeStatus.BufferTooSmall && attempt == 0 && required is > 0 and <= MetadataMaximumBytes)
                {
                    capacity = (int)required;
                    continue;
                }

                throw FailureFor(status, cancellationToken);
            }

            throw new ImageNativeException(NativeStatus.Internal, "The image metadata size did not settle.");
        }
        finally
        {
            if (!transferred && context.IsAllocated)
            {
                context.Free();
            }
        }
    }

    private unsafe void ReadNative(ImageRegion region, byte[] pixels, CancellationToken cancellationToken)
    {
        bool added = false;
        try
        {
            _handle.DangerousAddRef(ref added);
            ulong image = unchecked((ulong)_handle.DangerousGetHandle().ToInt64());
            using var bridge = new CancellationBridge(cancellationToken);
            NativeCancelToken cancel = bridge.Token;
            NativeCancelToken* cancelPointer = bridge.Enabled ? &cancel : null;
            NativeRegionV1 nativeRegion = new()
            {
                StructSize = (uint)sizeof(NativeRegionV1),
                StructVersion = NativeAbiConstants.RecordVersion1,
                X = region.X,
                Y = region.Y,
                Width = region.Width,
                Height = region.Height,
            };

            NativeBuffer output;
            NativeStatus status;
            fixed (byte* data = pixels)
            {
                output = new NativeBuffer { Data = (nint)data, Capacity = (ulong)pixels.Length };
                status = ImageAbi.ReadNative(image, &nativeRegion, &output, cancelPointer);
            }

            if (status != NativeStatus.Ok)
            {
                throw FailureFor(status, cancellationToken);
            }

            if (output.Required != (ulong)pixels.Length)
            {
                throw new ImageNativeException(NativeStatus.Internal, "The native read reported an unexpected output size.");
            }
        }
        finally
        {
            if (added)
            {
                _handle.DangerousRelease();
            }
        }
    }

    // Called on the thread that made the failing native call, so the thread-local diagnostic is still current.
    private static Exception FailureFor(NativeStatus status, CancellationToken cancellationToken) =>
        status == NativeStatus.Cancelled
            ? new OperationCanceledException(cancellationToken)
            : new ImageNativeException(status, ImageAbi.LastErrorMessage(status));

    private void ValidateRegion(ImageRegion region)
    {
        if (region.Width == 0 || region.Height == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(region), "The region must have a positive width and height.");
        }

        if ((ulong)region.X + region.Width > Metadata.Width || (ulong)region.Y + region.Height > Metadata.Height)
        {
            throw new ArgumentOutOfRangeException(nameof(region), "The region lies outside the image.");
        }
    }
}
