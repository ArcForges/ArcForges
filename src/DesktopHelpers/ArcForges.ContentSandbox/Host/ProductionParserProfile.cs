// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Native.Abstractions;
using ArcForges.Native.Pdf;

namespace ArcForges.ContentSandbox.Host;

/// <summary>
/// The approved production parser composition of the helper (WP-13.13). It composes the PDF parser over the native <c>arc_pdf_*</c> library
/// and nothing else: no image parser is composed here (the still-image functions of ArcImageNative do not exist yet), so a launch that opens
/// an image against this composition is refused as unavailable. The hostile test parser is never part of this composition.
/// </summary>
/// <remarks>
/// <see cref="Prepare"/> loads and verifies the native library BEFORE the operating-system profile is applied: on Linux a seccomp/Landlock
/// profile cannot load a library afterwards, and on Windows the loader must not run late inside the container. A library that has no PDF
/// backend linked (<c>backend=none</c>) fails the preparation, so the helper ends before any parser exists instead of failing per call.
/// </remarks>
internal sealed class ProductionParserProfile(PdfDocumentOpener? opener = null, Action? prepare = null) : IContentParserProfile
{
    /// <summary>The identifier a launch names to select the production composition.</summary>
    internal const string ProfileId = "arcforges-parsers-v1";

    private readonly PdfDocumentOpener _opener = opener ?? OpenNative;
    private readonly Action _prepare = prepare ?? LoadNative;

    /// <inheritdoc />
    public string Id => ProfileId;

    /// <inheritdoc />
    public IImageParser? CreateImageParser() => null;

    /// <inheritdoc />
    public IPdfParser? CreatePdfParser() => new NativePdfParser(_opener);

    /// <inheritdoc />
    public void Prepare() => _prepare();

    private static PdfDocument OpenNative(IPdfInput input, PdfLimits limits, CancellationToken cancellation) =>
        PdfDocument.Open(input, limits, default, cancellation);

    /// <summary>Checks what the loaded library reports: the functional ABI (minor 1 or later) and a linked PDF backend.</summary>
    internal static void VerifyLibrary(NativeAbiVersion version, string buildInfo)
    {
        ArgumentNullException.ThrowIfNull(buildInfo);
        if (version.Major != 1 || version.Minor < 1)
        {
            throw new ContentParserException("The PDF library does not export the functional ABI.");
        }

        if (!buildInfo.Contains("backend=linked", StringComparison.Ordinal))
        {
            throw new ContentParserException("The PDF library has no parser linked.");
        }
    }

    [SuppressMessage("Design", "CA1031", Justification = "Any load failure is the same fail-closed refusal.")]
    private static void LoadNative()
    {
        try
        {
            VerifyLibrary(PdfAbi.GetAbiVersion(), PdfAbi.GetBuildInfo());
        }
        catch (ContentParserException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // Every way the library can fail to load (missing file, wrong manifest or hash, wrong bitness, platform, type initialisation)
            // is the same refusal: the helper ends before any parser exists.
            throw new ContentParserException("The PDF library could not be loaded.", exception);
        }
    }
}
