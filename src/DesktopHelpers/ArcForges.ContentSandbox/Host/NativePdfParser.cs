// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Text;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.Native.Pdf;

namespace ArcForges.ContentSandbox.Host;

/// <summary>Opens a document of the native PDF library. The production opener is <see cref="PdfDocument.Open"/>; tests substitute a scripted one.</summary>
internal delegate IPdfDocument PdfDocumentOpener(IPdfInput input, PdfLimits limits, CancellationToken cancellation);

/// <summary>
/// The production PDF parser of the helper: a thin, validating adapter from the sandbox parser interface to the native
/// <c>arc_pdf_*</c> library. It runs only inside the helper process under its restricted profile. It adds no format knowledge of its own; it
/// enforces the budget of the launch on every result it takes from the native side (geometry, page text volume, box count) and turns every
/// native failure, whatever its type, into <see cref="ContentParserException"/> so that nothing a parser says reaches the parent as prose.
/// </summary>
internal sealed class NativePdfParser(PdfDocumentOpener opener) : IPdfParser
{
    /// <summary>The most UTF-16 units one native text call is asked for (the native limit).</summary>
    internal const uint TextUnitsPerCall = 65536;

    /// <summary>The most text of one page the helper assembles (the host rejects more as well).</summary>
    internal const int MaxPageTextUnits = 16 * 1024 * 1024;

    /// <summary>The most boxes of one page the helper assembles.</summary>
    internal const int MaxPageBoxes = 1_000_000;

    private readonly object _gate = new();
    private IPdfDocument? _document;

    /// <inheritdoc />
    public uint Open(ParserInput input, ParserContext context)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(context);
        if (_document is not null)
        {
            throw new ContentParserException("The parser holds a document already.");
        }

        var limits = context.Limits;
        var native = new PdfLimits(limits.MaxInputBytes, limits.MaxMemoryBytes, limits.MaxOutputBytes, limits.MaxWidth, limits.MaxHeight, limits.MaxItems, limits.TimeoutMs);
        var document = Translate(() => opener(new ParserInputAdapter(input), native, context.Cancelled));
        if (document.PageCount == 0)
        {
            document.Dispose();
            throw new ContentParserException("The document has no pages.");
        }

        lock (_gate)
        {
            _document = document;
        }

        return document.PageCount;
    }

    /// <inheritdoc />
    public SandboxPdfPage GetPage(uint pageIndex, ParserContext context)
    {
        var document = Document();
        var page = Translate(() => document.GetPage(pageIndex));
        if (page.PageIndex != pageIndex || !double.IsFinite(page.WidthPoints) || !double.IsFinite(page.HeightPoints) || page.WidthPoints <= 0 || page.HeightPoints <= 0
            || page.Rotation is not (0 or 90 or 180 or 270))
        {
            throw new ContentParserException("The page geometry is not valid.");
        }

        return new SandboxPdfPage { PageIndex = page.PageIndex, Rotation = page.Rotation, WidthPoints = page.WidthPoints, HeightPoints = page.HeightPoints };
    }

    /// <inheritdoc />
    public PdfPageText GetPageText(uint pageIndex, ParserContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var document = Document();
        var text = new StringBuilder();
        var boxes = new List<SandboxTextBox>();
        uint start = 0;
        while (true)
        {
            context.Cancelled.ThrowIfCancellationRequested();
            var chunk = Translate(() => document.ExtractText(pageIndex, start, TextUnitsPerCall, context.Cancelled));
            if (chunk.Page != pageIndex || chunk.Start != start || text.Length != start)
            {
                throw new ContentParserException("The text chunk answers another position.");
            }

            if ((long)text.Length + chunk.Text.Length > MaxPageTextUnits || boxes.Count + chunk.Boxes.Count > MaxPageBoxes)
            {
                throw new ContentParserException("The page text exceeds its bound.");
            }

            _ = text.Append(chunk.Text);
            foreach (var box in chunk.Boxes)
            {
                boxes.Add(new SandboxTextBox { Start = box.Start, Length = box.Length, X = box.X, Y = box.Y, Width = box.Width, Height = box.Height });
            }

            if (chunk.Next is not { } next)
            {
                break;
            }

            if (next <= start || next != text.Length)
            {
                throw new ContentParserException("The text chunk makes no progress.");
            }

            start = next;
        }

        return new PdfPageText(text.ToString(), boxes);
    }

    /// <inheritdoc />
    public int RenderTile(SandboxPdfPage page, SandboxRegion region, uint fullWidth, uint fullHeight, Span<byte> destination, ParserContext context)
    {
        ArgumentNullException.ThrowIfNull(page);
        ArgumentNullException.ThrowIfNull(region);
        ArgumentNullException.ThrowIfNull(context);
        if (region.RowStride > uint.MaxValue)
        {
            throw new ContentParserException("The row stride is out of range.");
        }

        var document = Document();
        var geometry = new PdfPageGeometry(page.PageIndex, page.Rotation, page.WidthPoints, page.HeightPoints);
        var stride = (uint)region.RowStride;
        var token = context.Cancelled;

        // A Span cannot cross a lambda; the native call is made directly and its failures translated by the same rules.
        try
        {
            var written = document.Render(geometry, region.X, region.Y, region.Width, region.Height, fullWidth, fullHeight, stride, destination, token);
            return written < 0 || written > destination.Length ? throw new ContentParserException("The native render reported an impossible size.") : written;
        }
        catch (Exception exception) when (IsNativeFailure(exception))
        {
            throw new ContentParserException("The native render failed.", exception);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_gate)
        {
            _document?.Dispose();
            _document = null;
        }
    }

    private IPdfDocument Document() => _document ?? throw new ContentParserException("No document is open.");

    [SuppressMessage("Design", "CA1031", Justification = "Every native or loader failure maps to the single parser failure; the text is diagnostic and never sent.")]
    private static T Translate<T>(Func<T> call)
    {
        try
        {
            return call();
        }
        catch (Exception exception) when (IsNativeFailure(exception))
        {
            throw new ContentParserException("The native PDF library failed.", exception);
        }
    }

    private static bool IsNativeFailure(Exception exception) =>
        exception is PdfNativeException or DllNotFoundException or EntryPointNotFoundException or BadImageFormatException or PlatformNotSupportedException
            or InvalidDataException or IOException or ObjectDisposedException or ArgumentException or InvalidOperationException or OverflowException;

    private sealed class ParserInputAdapter(ParserInput input) : IPdfInput
    {
        public long Length => input.Length;

        public int ReadAt(long offset, Span<byte> destination) => input.Read(offset, destination);
    }
}
