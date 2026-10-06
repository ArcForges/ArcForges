// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using ArcForges.Native.Abstractions;

namespace ArcForges.Native.Image;

/// <summary>Closed output profiles. Byte pixels are unassociated in the reported source transfer; float pixels are linear premultiplied.</summary>
public enum ImagePixelFormat
{
    None = 0,
    Rgba8 = 1,
    Rgba32FloatLinearPremultiplied = 2,
}

/// <summary>A bounded immutable, already brokered input. No parser resolves a path.</summary>
public interface IImageInput
{
    long Length { get; }

    int ReadAt(long offset, Span<byte> destination);
}

/// <summary>Positive caller limits, capped by the signed producer profile.</summary>
public sealed record ImageLimits(ulong MaxInputBytes, ulong MaxMemoryBytes, ulong MaxOutputBytes, uint MaxWidth, uint MaxHeight, uint MaxItems, uint TimeoutMs);

/// <summary>Source channel precision remains visible even when the output converts it.</summary>
public sealed record ImageChannel(string Name, string Type, uint Bits);

/// <summary>The selected image and its explicit output conversion.</summary>
public sealed record ImageMetadata(uint Width, uint Height, uint Subimages, uint Mips, uint Subimage, uint Mip, ImagePixelFormat Format,
    string Codec, string SourceColorSpace, bool ConversionLoss, IReadOnlyList<ImageChannel> Channels);

/// <summary>A closed native status, with diagnostic text that is never sent over the sandbox protocol.</summary>
[SuppressMessage("Design", "CA1032", Justification = "A native failure must carry the closed ABI status; untyped construction is not admitted.")]
public sealed class ImageNativeException(NativeStatus status, string message) : IOException(message)
{
    public NativeStatus Status { get; } = status;
}

/// <summary>Bounded image operations. Implementations execute only inside the restricted ContentSandbox process.</summary>
public interface IImageReader : IDisposable, IAsyncDisposable
{
    ImageMetadata Metadata { get; }

    int ReadRegion(uint x, uint y, uint width, uint height, ulong rowStride, Span<byte> destination, CancellationToken cancellation);

    ValueTask<int> ReadRegionAsync(uint x, uint y, uint width, uint height, ulong rowStride, Memory<byte> destination, CancellationToken cancellation);
}

/// <summary>
/// The production OIIO reader of PNG, TIFF and EXR. Instantiate only in the approved restricted helper; this binding itself is not an OS
/// security boundary. Its generation token and callback roots are owned by a dedicated SafeHandle, and all calls drain before close.
/// </summary>
public sealed unsafe class ImageReader : IImageReader
{
    private readonly object _gate = new();
    private readonly ImageSafeHandle _handle;
    private readonly InputState _input;
    [ThreadStatic]
    private static InputState? _callbackInput;
    private bool _reading;
    private bool _closeRequested;

    private ImageReader(ImageSafeHandle handle, ImageMetadata metadata, InputState input)
    {
        _handle = handle;
        Metadata = metadata;
        _input = input;
    }

    public ImageMetadata Metadata { get; }

    public static ValueTask<ImageReader> OpenAsync(IImageInput input, ImageLimits limits, uint subimage, uint mip, ImagePixelFormat format, CancellationToken cancellation) =>
        new(Task.Run(() => Open(input, limits, subimage, mip, format, cancellation), cancellation));

    public static ImageReader Open(IImageInput input, ImageLimits limits, uint subimage, uint mip, ImagePixelFormat format, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(limits);
        var length = input.Length;
        if (length <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(input));
        }

        cancellation.ThrowIfCancellationRequested();
        var inputState = new InputState(input);
        var inputRoot = GCHandle.Alloc(inputState);
        var cancelRoot = GCHandle.Alloc(cancellation);
        ImageSafeHandle? owned = null;
        try
        {
            NativeIoV1 io = new()
            {
                StructSize = (uint)sizeof(NativeIoV1), StructVersion = 1,
                Context = GCHandle.ToIntPtr(inputRoot), Length = (ulong)length, MaxLength = (ulong)length, ReadAt = &ReadAt,
            };
            NativeImageOptionsV1 options = new()
            {
                StructSize = (uint)sizeof(NativeImageOptionsV1), StructVersion = 1, Subimage = subimage, Mip = mip, Format = (uint)format,
                Limits = new NativeLimitsV1
                {
                    StructSize = (uint)sizeof(NativeLimitsV1), StructVersion = 1,
                    MaxInputBytes = limits.MaxInputBytes, MaxMemoryBytes = limits.MaxMemoryBytes, MaxOutputBytes = limits.MaxOutputBytes,
                    MaxWidth = limits.MaxWidth, MaxHeight = limits.MaxHeight, MaxItems = limits.MaxItems, TimeoutMs = limits.TimeoutMs,
                },
            };
            var token = Token(cancelRoot);
            NativeBuffer query = default;
            var (status, handle) = NativeOpen(&io, &options, &query, &token);
            if (status != (int)NativeStatus.BufferTooSmall || handle != 0 || query.Required is 0 or > 65536)
            {
                throw status < 0 ? Failure(status, cancellation) : new ImageNativeException(NativeStatus.Internal, "Invalid native metadata size query.");
            }

            var bytes = new byte[(int)query.Required];
            fixed (byte* pointer = bytes)
            {
                NativeBuffer output = new() { Data = (nint)pointer, Capacity = (ulong)bytes.Length };
                (status, handle) = NativeOpen(&io, &options, &output, &token);
                if (status != 0)
                {
                    throw Failure(status, cancellation);
                }

                if (handle == 0)
                {
                    throw new ImageNativeException(NativeStatus.Internal, "Native image open returned no handle.");
                }

                owned = new ImageSafeHandle(handle, inputRoot);
                inputRoot = default;
                if (output.Required != (ulong)bytes.Length)
                {
                    throw new ImageNativeException(NativeStatus.Internal, "Native image open returned incomplete output.");
                }
            }

            var metadata = ImageMetadataJson.Parse(bytes, limits, subimage, mip, format);
            var reader = new ImageReader(owned, metadata, inputState);
            owned = null;
            return reader;
        }
        finally
        {
            owned?.Dispose();
            if (inputRoot.IsAllocated)
            {
                inputRoot.Free();
            }

            cancelRoot.Free();
        }
    }

    public int ReadRegion(uint x, uint y, uint width, uint height, ulong rowStride, Span<byte> destination, CancellationToken cancellation)
    {
        if (ReferenceEquals(_callbackInput, _input))
        {
            throw new ImageNativeException(NativeStatus.Busy, "The reader cannot be borrowed from its input callback.");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
            if (_reading)
            {
                throw new ImageNativeException(NativeStatus.Busy, "The reader cannot be borrowed from its input callback.");
            }

            cancellation.ThrowIfCancellationRequested();
            var root = GCHandle.Alloc(cancellation);
            _reading = true;
            try
            {
                var token = Token(root);
                NativeRegionV1 region = new()
                {
                    StructSize = (uint)sizeof(NativeRegionV1), StructVersion = 1,
                    X = x, Y = y, Width = width, Height = height, RowStride = rowStride,
                };
                fixed (byte* pointer = destination)
                {
                    NativeBuffer output = new() { Data = (nint)pointer, Capacity = (ulong)destination.Length };
                    var status = ImageAbi.Read(unchecked((ulong)_handle.DangerousGetHandle()), &region, &output, &token);
                    if (status != 0)
                    {
                        throw Failure(status, cancellation);
                    }

                    if (output.Required != checked(rowStride * height) || output.Required > (ulong)destination.Length)
                    {
                        throw new ImageNativeException(NativeStatus.Internal, "Native image tile is incomplete.");
                    }

                    return checked((int)output.Required);
                }
            }
            finally
            {
                root.Free();
                _reading = false;
                if (Volatile.Read(ref _closeRequested))
                {
                    _handle.Dispose();
                    _closeRequested = false;
                }

                GC.KeepAlive(_handle);
            }
        }
    }

    /// <summary>Closes after borrowed work drains. A synchronous input callback defers its close until that borrow returns.</summary>
    public void Dispose()
    {
        if (ReferenceEquals(_callbackInput, _input))
        {
            Volatile.Write(ref _closeRequested, true);
            return;
        }

        lock (_gate)
        {
            if (_reading)
            {
                _closeRequested = true;
                return;
            }

            _handle.Dispose();
        }
    }

    public ValueTask<int> ReadRegionAsync(uint x, uint y, uint width, uint height, ulong rowStride, Memory<byte> destination, CancellationToken cancellation)
    {
        RefuseQueuedCallbackWork();
        return new(Task.Run(() => ReadRegion(x, y, width, height, rowStride, destination.Span, cancellation), cancellation));
    }

    public ValueTask DisposeAsync()
    {
        RefuseQueuedCallbackWork();
        return new(Task.Run(Dispose));
    }

    private void RefuseQueuedCallbackWork()
    {
        if (ReferenceEquals(_callbackInput, _input))
        {
            throw new InvalidOperationException("The reader cannot queue another operation from its input callback.");
        }
    }

    private static NativeCancelToken Token(GCHandle root) => new()
    {
        StructSize = (uint)sizeof(NativeCancelToken), StructVersion = 1, IsCancelled = &Cancelled, UserData = GCHandle.ToIntPtr(root),
    };

    private static (int Status, ulong Handle) NativeOpen(NativeIoV1* io, NativeImageOptionsV1* options, NativeBuffer* output, NativeCancelToken* token)
    {
        ulong handle = 0;
        var status = ImageAbi.Open(io, options, &handle, output, token);
        return (status, handle);
    }

    private static Exception Failure(int status, CancellationToken cancellation)
    {
        if (status == (int)NativeStatus.Cancelled)
        {
            return new OperationCanceledException(cancellation);
        }

        var message = string.Empty;
        try
        {
            message = ImageAbi.GetLastError().Message;
        }
        catch (InvalidOperationException)
        {
            // Preserve the typed status when a diagnostic snapshot cannot be read.
        }

        return new ImageNativeException(status is >= -13 and <= 3 and not 0 ? (NativeStatus)status : NativeStatus.Internal, message);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    [SuppressMessage("Design", "CA1031", Justification = "Callbacks must never throw across the native frame.")]
    private static int ReadAt(nint context, ulong offset, nint destination, ulong requested, ulong* done)
    {
        if (done is null)
        {
            return (int)NativeStatus.InvalidArgument;
        }

        *done = 0;
        var previous = _callbackInput;
        try
        {
            if (GCHandle.FromIntPtr(context).Target is not InputState input || offset > long.MaxValue || requested > int.MaxValue || (destination == 0 && requested != 0))
            {
                return (int)NativeStatus.InvalidArgument;
            }

            _callbackInput = input;
            var count = input.Input.ReadAt((long)offset, new Span<byte>((void*)destination, (int)requested));
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
        finally
        {
            _callbackInput = previous;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    [SuppressMessage("Design", "CA1031", Justification = "An unreadable cancellation bridge fails closed.")]
    private static byte Cancelled(nint context)
    {
        try
        {
            return GCHandle.FromIntPtr(context).Target is CancellationToken token && !token.IsCancellationRequested ? (byte)0 : (byte)1;
        }
        catch (Exception)
        {
            return 1;
        }
    }

    private sealed record InputState(IImageInput Input);

    private sealed class ImageSafeHandle : NativeSafeHandle
    {
        private GCHandle _input;

        internal ImageSafeHandle(ulong token, GCHandle input) : base(token)
        {
            _input = input;
        }

        protected override NativeStatus ReleaseNativeToken(ulong token)
        {
            try
            {
                return (NativeStatus)ImageAbi.Close(token);
            }
            finally
            {
                if (_input.IsAllocated)
                {
                    _input.Free();
                }
            }
        }
    }
}

internal static class ImageMetadataJson
{
    internal static ImageMetadata Parse(ReadOnlyMemory<byte> bytes, ImageLimits limits, uint subimage, uint mip, ImagePixelFormat format)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            RequireFields(root, ["version", "width", "height", "subimages", "mips", "subimage", "mip", "format", "codec", "sourceColorSpace", "conversionLoss", "channels"]);
            var width = root.GetProperty("width").GetUInt32();
            var height = root.GetProperty("height").GetUInt32();
            var subimages = root.GetProperty("subimages").GetUInt32();
            var mips = root.GetProperty("mips").GetUInt32();
            var codec = root.GetProperty("codec").GetString()!;
            var space = root.GetProperty("sourceColorSpace").GetString()!;
            if (root.GetProperty("version").GetUInt32() != 1 || width == 0 || height == 0 || width > limits.MaxWidth || height > limits.MaxHeight ||
                (ulong)width * height > 268435456 || subimages is 0 || subimages > limits.MaxItems || mips is 0 || mips > limits.MaxItems ||
                subimage >= subimages || mip >= mips || root.GetProperty("subimage").GetUInt32() != subimage || root.GetProperty("mip").GetUInt32() != mip ||
                root.GetProperty("format").GetUInt32() != (uint)format || codec is not ("png" or "tiff" or "openexr") || space is null || space.Length is 0 or > 256)
            {
                throw new InvalidDataException("Native image metadata contradicts the admitted request.");
            }

            var channels = new List<ImageChannel>();
            foreach (var channel in root.GetProperty("channels").EnumerateArray())
            {
                RequireFields(channel, ["name", "type", "bits"]);
                var name = channel.GetProperty("name").GetString()!;
                var type = channel.GetProperty("type").GetString()!;
                var bits = channel.GetProperty("bits").GetUInt32();
                if (name is null || name.Length is 0 or > 256 || type is null || type.Length is 0 or > 32 || bits is 0 or > 64 || channels.Count >= 64 || channels.Count >= limits.MaxItems)
                {
                    throw new InvalidDataException("Native image channel metadata is invalid.");
                }

                channels.Add(new ImageChannel(name, type, bits));
            }

            if (channels.Count == 0)
            {
                throw new InvalidDataException("Native image metadata has no channels.");
            }

            return new ImageMetadata(width, height, subimages, mips, subimage, mip, format, codec, space,
                root.GetProperty("conversionLoss").GetBoolean(), channels.AsReadOnly());
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException)
        {
            throw new InvalidDataException("Native image metadata encoding is invalid.", error);
        }
    }

    private static void RequireFields(JsonElement element, string[] names)
    {
        var found = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!names.Contains(property.Name, StringComparer.Ordinal) || !found.Add(property.Name))
            {
                throw new InvalidDataException("Native image metadata has an unknown or duplicate field.");
            }
        }

        if (found.Count != names.Length)
        {
            throw new InvalidDataException("Native image metadata is incomplete.");
        }
    }
}
