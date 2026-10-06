// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Native.Abstractions;
using ArcForges.Native.Image;
using ArcForges.Native.Pdf;

namespace ArcForges.ContentSandbox.Host;

/// <summary>
/// The approved production parser composition of the helper: PDF over the native <c>arc_pdf_*</c> library and still images over the
/// native <c>arc_image_*</c> library. The hostile test parser is never part of this composition.
/// </summary>
/// <remarks>
/// <see cref="Prepare"/> loads and verifies both native libraries BEFORE the operating-system profile is applied: on Linux a seccomp/Landlock
/// profile cannot load a library afterwards, and on Windows the loader must not run late inside the container. A library that has no PDF
/// backend linked (<c>backend=none</c>) fails the preparation, so the helper ends before any parser exists instead of failing per call.
/// </remarks>
internal sealed class ProductionParserProfile(PdfDocumentOpener? opener = null, Action? prepare = null, ImageReaderOpener? imageOpener = null) : IContentParserProfile
{
    /// <summary>The identifier a launch names to select the production composition.</summary>
    internal const string ProfileId = "arcforges-parsers-v1";

    private readonly PdfDocumentOpener _opener = opener ?? OpenNative;
    private readonly ImageReaderOpener _imageOpener = imageOpener ?? OpenImageNative;
    private readonly Action _prepare = prepare ?? LoadNative;

    /// <inheritdoc />
    public string Id => ProfileId;

    /// <inheritdoc />
    public IImageParser? CreateImageParser() => new NativeImageParser(_imageOpener);

    /// <inheritdoc />
    public IPdfParser? CreatePdfParser() => new NativePdfParser(_opener);

    /// <inheritdoc />
    public void Prepare() => _prepare();

    private static PdfDocument OpenNative(IPdfInput input, PdfLimits limits, CancellationToken cancellation) =>
        PdfDocument.Open(input, limits, default, cancellation);

    private static ImageReader OpenImageNative(IImageInput input, ImageLimits limits, uint subimage, uint mip, ImagePixelFormat format, CancellationToken cancellation) =>
        ImageReader.Open(input, limits, subimage, mip, format, cancellation);

    /// <summary>Checks the exact admitted still-image ABI and embedded codec profile before OS restrictions are applied.</summary>
    internal static void VerifyImageLibrary(NativeAbiVersion version, string buildInfo)
    {
        ArgumentNullException.ThrowIfNull(buildInfo);
        if (version.Major != 1 || version.Minor != 1)
        {
            throw new ContentParserException("The image library does not export the functional ABI.");
        }

        var tokens = buildInfo.Split(';', StringSplitOptions.RemoveEmptyEntries);
        foreach (var required in new[] { "abi=1.1", "openimageio=3.1.14.0", "formats=png,tiff,exr", "rgba8", "rgba32fLinearPremultiplied", "maxTileBytes=67108864", "maxHandles=64" })
        {
            if (!tokens.Contains(required, StringComparer.Ordinal))
            {
                throw new ContentParserException("The image library does not match the admitted codec profile.");
            }
        }
    }

    /// <summary>Checks the functional ABI and the exact admitted PDFium producer configuration.</summary>
    internal static void VerifyLibrary(NativeAbiVersion version, string buildInfo)
    {
        ArgumentNullException.ThrowIfNull(buildInfo);
        if (version.Major != 1 || version.Minor < 1)
        {
            throw new ContentParserException("The PDF library does not export the functional ABI.");
        }

        var fields = buildInfo.Split(';');
        if (fields[0] != "ArcPdfNative" || fields.Count(value => value.StartsWith("backend=", StringComparison.Ordinal)) != 1
            || fields.Count(value => value.StartsWith("pdfium=", StringComparison.Ordinal)) != 1
            || fields.Count(value => value.StartsWith("v8=", StringComparison.Ordinal)) != 1
            || fields.Count(value => value.StartsWith("xfa=", StringComparison.Ordinal)) != 1
            || fields.Count(value => value.StartsWith("system-fonts=", StringComparison.Ordinal)) != 1
            || !fields.Contains("backend=linked", StringComparer.Ordinal)
            || !fields.Contains("pdfium=chromium/8044", StringComparer.Ordinal)
            || !fields.Contains("v8=off", StringComparer.Ordinal)
            || !fields.Contains("xfa=off", StringComparer.Ordinal)
            || !fields.Contains("system-fonts=off", StringComparer.Ordinal))
        {
            throw new ContentParserException("The PDF library is not the admitted no-V8/no-XFA producer configuration.");
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "Any load failure is the same fail-closed refusal.")]
    private static void LoadNative()
    {
        try
        {
            VerifyLibrary(PdfAbi.GetAbiVersion(), PdfAbi.GetBuildInfo());
            VerifyImageLibrary(ImageAbi.GetAbiVersion(), ImageAbi.GetBuildInfo());
        }
        catch (ContentParserException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // Every way the library can fail to load (missing file, wrong manifest or hash, wrong bitness, platform, type initialisation)
            // is the same refusal: the helper ends before any parser exists.
            throw new ContentParserException("The production parser libraries could not be loaded.", exception);
        }
    }
}
