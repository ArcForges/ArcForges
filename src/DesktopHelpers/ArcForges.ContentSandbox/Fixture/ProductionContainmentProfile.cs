// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Host;

namespace ArcForges.ContentSandbox.HostileFixture;

/// <summary>
/// TEST ONLY. Loads both genuine production native libraries before the existing hostile parsers
/// exercise OS restrictions. It parses no genuine format and is never a release composition.
/// </summary>
internal sealed class ProductionContainmentProfile : IContentParserProfile
{
    private readonly ProductionParserProfile _production = new();
    private readonly HostileProfile _hostile = new();

    // This ID selects the existing native bootstrap only within the separate, nonpackable fixture.
    public string Id => ProductionParserProfile.ProfileId;

    public void Prepare() => _production.Prepare();

    public IImageParser? CreateImageParser() => _hostile.CreateImageParser();

    public IPdfParser? CreatePdfParser() => _hostile.CreatePdfParser();
}
