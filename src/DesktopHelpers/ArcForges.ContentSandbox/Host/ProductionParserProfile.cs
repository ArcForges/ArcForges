// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.ContentSandbox.Host;

/// <summary>
/// The production parser composition of the helper. The local PDF parser path is retired (P2-022): no PDF parser is composed and no native
/// PDF library is loaded or linked. The still-image composition is delivered by NAT.31 and is not yet present, so no image parser is composed
/// either and a launch that opens an image against this composition is refused as unavailable. The hostile test parser is never part of this
/// composition.
/// </summary>
internal sealed class ProductionParserProfile : IContentParserProfile
{
    /// <summary>The identifier a launch names to select the production composition.</summary>
    internal const string ProfileId = "arcforges-parsers-v1";

    /// <inheritdoc />
    public string Id => ProfileId;

    /// <inheritdoc />
    public IImageParser? CreateImageParser() => null;
}
