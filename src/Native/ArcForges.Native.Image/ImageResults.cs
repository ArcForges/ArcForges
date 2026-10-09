// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Native.Abstractions;

namespace ArcForges.Native.Image;

// A rectangle of one image, in pixels from the top-left of the selected level.
public readonly record struct ImageRegion(uint X, uint Y, uint Width, uint Height);

// Packed pixels for one region. The buffer is owned by this record and never changes after creation.
public sealed record ImagePixelRegion(
    ImageRegion Region,
    ImageOutputFormat Format,
    uint BytesPerPixel,
    ReadOnlyMemory<byte> Pixels);

// Result of the completion step. CoveredPixels equals Width times Height only when every pixel was read.
public sealed record ImageCompletion(uint Width, uint Height, ulong CoveredPixels, uint RegionCount);

// A native call failed. Status is the ABI status; the message is the native diagnostic for that call.
public sealed class ImageNativeException : Exception
{
    public ImageNativeException()
        : this(NativeStatus.Internal, "ArcImageNative failed.")
    {
    }

    public ImageNativeException(string message)
        : this(NativeStatus.Internal, message)
    {
    }

    public ImageNativeException(string message, Exception innerException)
        : base(message, innerException)
    {
        Status = NativeStatus.Internal;
    }

    public ImageNativeException(NativeStatus status, string message)
        : base(message)
    {
        Status = status;
    }

    public NativeStatus Status { get; }
}

// The completion step found pixels that no successful read covered. Nothing is returned for the image.
public sealed class ImageCoverageIncompleteException : Exception
{
    public ImageCoverageIncompleteException()
        : this(0, 0)
    {
    }

    public ImageCoverageIncompleteException(string message)
        : base(message)
    {
    }

    public ImageCoverageIncompleteException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public ImageCoverageIncompleteException(ulong coveredPixels, ulong totalPixels)
        : base("The image regions do not cover every pixel.")
    {
        CoveredPixels = coveredPixels;
        TotalPixels = totalPixels;
    }

    public ulong CoveredPixels { get; }

    public ulong TotalPixels { get; }
}
