// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.DesignSystem;
using ArcForges.Desktop.Shell.Localization;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests.Localization;

/// <summary>The right-to-left layout pass: RTL is structural (LO-05) and never changes stored layout (LO-06).</summary>
public sealed class FlowDirectionTests
{
    [Fact]
    public void FromCultureClassifiesReadingDirection()
    {
        foreach (string language in new[] { "ar", "he", "fa", "ur" })
        {
            Assert.Equal(FlowDirection.RightToLeft, FlowDirections.FromCulture(CultureInfo.GetCultureInfo(language)));
        }

        foreach (string language in new[] { "en", "de", "ja" })
        {
            Assert.Equal(FlowDirection.LeftToRight, FlowDirections.FromCulture(CultureInfo.GetCultureInfo(language)));
        }

        Assert.Equal(FlowDirection.LeftToRight, FlowDirections.FromCulture(CultureInfo.InvariantCulture));
        Assert.Throws<ArgumentNullException>(() => FlowDirections.FromCulture(null!));
    }

    [Fact]
    public void ToPhysicalMirrorsOnlyTheLeadingAndTrailingEdgesInRightToLeft()
    {
        foreach (DockRegion region in Enum.GetValues<DockRegion>())
        {
            Assert.Equal(region, FlowDirections.ToPhysical(region, FlowDirection.LeftToRight));
        }

        Assert.Equal(DockRegion.Right, FlowDirections.ToPhysical(DockRegion.Left, FlowDirection.RightToLeft));
        Assert.Equal(DockRegion.Left, FlowDirections.ToPhysical(DockRegion.Right, FlowDirection.RightToLeft));
        Assert.Equal(DockRegion.Top, FlowDirections.ToPhysical(DockRegion.Top, FlowDirection.RightToLeft));
        Assert.Equal(DockRegion.Bottom, FlowDirections.ToPhysical(DockRegion.Bottom, FlowDirection.RightToLeft));
        Assert.Equal(DockRegion.Center, FlowDirections.ToPhysical(DockRegion.Center, FlowDirection.RightToLeft));
        Assert.Throws<ArgumentOutOfRangeException>(() => FlowDirections.ToPhysical((DockRegion)99, FlowDirection.LeftToRight));
        Assert.Throws<ArgumentOutOfRangeException>(() => FlowDirections.ToPhysical(DockRegion.Left, (FlowDirection)99));
    }

    [Fact]
    public void MirrorXReflectsSpansExactlyAndIsItsOwnInverse()
    {
        Assert.Equal(900, FlowDirections.MirrorX(0, 100, 1000));
        Assert.Equal(0, FlowDirections.MirrorX(900, 100, 1000));
        Assert.Equal(450, FlowDirections.MirrorX(450, 100, 1000));
        foreach (double x in new[] { 0d, 12.5, 333, 900 })
        {
            Assert.Equal(x, FlowDirections.MirrorX(FlowDirections.MirrorX(x, 100, 1000), 100, 1000));
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => FlowDirections.MirrorX(double.NaN, 1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => FlowDirections.MirrorX(0, -1, 1));
    }

    [Fact]
    public void RightToLeftPanelLayoutIsTheMirrorOfLeftToRightWithoutChangingTheStoredLayout()
    {
        var host = new PanelHost(DensityMode.Comfortable,
        [
            new PanelDefinition(PanelKey.Parse("navigator"), DockRegion.Left),
            new PanelDefinition(PanelKey.Parse("inspector"), DockRegion.Right),
            new PanelDefinition(PanelKey.Parse("editor"), DockRegion.Center),
            new PanelDefinition(PanelKey.Parse("console"), DockRegion.Bottom),
        ]);
        IReadOnlyList<PanelPlacement> stored = host.Snapshot();

        Dictionary<string, DockRegion> leftToRight = stored.ToDictionary(
            static panel => panel.Key.Value,
            panel => FlowDirections.ToPhysical(panel.Region, FlowDirection.LeftToRight),
            StringComparer.Ordinal);
        Dictionary<string, DockRegion> rightToLeft = stored.ToDictionary(
            static panel => panel.Key.Value,
            panel => FlowDirections.ToPhysical(panel.Region, FlowDirection.RightToLeft),
            StringComparer.Ordinal);

        Assert.Equal(DockRegion.Left, leftToRight["navigator"]);
        Assert.Equal(DockRegion.Right, rightToLeft["navigator"]);
        Assert.Equal(DockRegion.Right, leftToRight["inspector"]);
        Assert.Equal(DockRegion.Left, rightToLeft["inspector"]);
        Assert.Equal(DockRegion.Center, rightToLeft["editor"]);
        Assert.Equal(DockRegion.Bottom, rightToLeft["console"]);

        // Presentation mapping never mutates the stored (logical) layout, so a language change cannot alter saved data.
        Assert.Equal(stored, host.Snapshot());
        Assert.Equal(DockRegion.Left, host.Snapshot().Single(static panel => panel.Key.Value == "navigator").Region);
    }
}
