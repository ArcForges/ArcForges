// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics.CodeAnalysis;
using ArcForges.Native.Abstractions;

namespace ArcForges.Native.Pdf;

/// <summary>The immutable PDF bytes. The native library reads them through this and never past <see cref="Length"/>.</summary>
internal interface IPdfInput
{
    /// <summary>The byte length of the input.</summary>
    long Length { get; }

    /// <summary>Reads up to <paramref name="destination"/>.Length bytes at <paramref name="offset"/> and returns how many were read; 0 only at the end.</summary>
    int ReadAt(long offset, Span<byte> destination);
}

/// <summary>The budget of one document. Zero is never valid; the native profile maxima apply on top.</summary>
internal sealed record PdfLimits(
    ulong MaxInputBytes,
    ulong MaxMemoryBytes,
    ulong MaxOutputBytes,
    uint MaxWidth,
    uint MaxHeight,
    uint MaxItems,
    uint TimeoutMs);

/// <summary>The geometry of one page in PDF points; rotation is 0, 90, 180 or 270.</summary>
internal readonly record struct PdfPageGeometry(uint PageIndex, uint Rotation, double WidthPoints, double HeightPoints);

/// <summary>A text rectangle. Start and length are UTF-16 offsets into the full page text.</summary>
internal readonly record struct PdfTextBox(uint Start, uint Length, double X, double Y, double Width, double Height);

/// <summary>One bounded chunk of page text. <see cref="Next"/> is the start of the following chunk, or null at the end of the page.</summary>
internal sealed record PdfTextChunk(uint Page, uint Start, uint? Next, string Text, IReadOnlyList<PdfTextBox> Boxes);

/// <summary>A PDF document opened with scripts and actions disabled. Implemented by <see cref="PdfDocument"/> and by test doubles.</summary>
internal interface IPdfDocument : IDisposable
{
    /// <summary>The number of pages, at least one.</summary>
    uint PageCount { get; }

    /// <summary>The geometry of a page.</summary>
    PdfPageGeometry GetPage(uint pageIndex);

    /// <summary>Up to <paramref name="count"/> UTF-16 units of page text from <paramref name="start"/>.</summary>
    PdfTextChunk ExtractText(uint pageIndex, uint start, uint count, CancellationToken cancellation);

    /// <summary>Renders the tile into <paramref name="destination"/> as RGBA8 at the given row stride and returns the number of bytes written.</summary>
    int Render(PdfPageGeometry page, uint x, uint y, uint width, uint height, uint fullWidth, uint fullHeight, uint rowStride, Span<byte> destination, CancellationToken cancellation);
}

/// <summary>A native PDF call failed. The status is the closed ABI status; the message is diagnostic only and is never sent to a peer.</summary>
[SuppressMessage("Design", "CA1064", Justification = "The binding is internal to the helper (no public API surface); the exception stays beside it.")]
internal sealed class PdfNativeException : Exception
{
    public PdfNativeException()
        : this(NativeStatus.Internal, string.Empty)
    {
    }

    public PdfNativeException(string message)
        : this(NativeStatus.Internal, message)
    {
    }

    public PdfNativeException(string message, Exception innerException)
        : base(message, innerException)
    {
        Status = NativeStatus.Internal;
    }

    public PdfNativeException(NativeStatus status, string message)
        : base(message)
    {
        Status = status;
    }

    /// <summary>The ABI status.</summary>
    public NativeStatus Status { get; }
}
