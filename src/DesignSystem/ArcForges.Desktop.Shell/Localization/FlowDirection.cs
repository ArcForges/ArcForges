// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Desktop.Shell.Localization;

/// <summary>The reading and layout direction of the current interface language.</summary>
public enum FlowDirection
{
    LeftToRight,
    RightToLeft,
}

/// <summary>
/// Structural right-to-left support (LO-05). Shell models name leading and trailing edges, not physical left and
/// right; only a UI adapter converts them to physical geometry with these mappings, so no right-to-left rewrite of the
/// models is ever needed. Stored layout and data never change with the interface language (LO-06).
/// </summary>
public static class FlowDirections
{
    private static readonly HashSet<string> RightToLeftLanguages = new(StringComparer.Ordinal)
    {
        "ar", "he", "fa", "ur", "ps", "sd", "ug", "yi", "dv", "ckb", "ks",
    };

    /// <summary>Returns the flow direction for <paramref name="culture"/> using platform data with a built-in language fallback.</summary>
    public static FlowDirection FromCulture(CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(culture);
        return culture.TextInfo.IsRightToLeft || RightToLeftLanguages.Contains(culture.TwoLetterISOLanguageName)
            ? FlowDirection.RightToLeft
            : FlowDirection.LeftToRight;
    }

    /// <summary>
    /// Maps a logical dock region to the physical region to draw. <see cref="DockRegion.Left"/> is the leading edge and
    /// <see cref="DockRegion.Right"/> the trailing edge, so they swap in a right-to-left layout; Top, Bottom and Center
    /// never change.
    /// </summary>
    public static DockRegion ToPhysical(DockRegion logical, FlowDirection direction)
    {
        if (!Enum.IsDefined(logical))
        {
            throw new ArgumentOutOfRangeException(nameof(logical));
        }

        if (!Enum.IsDefined(direction))
        {
            throw new ArgumentOutOfRangeException(nameof(direction));
        }

        if (direction == FlowDirection.LeftToRight)
        {
            return logical;
        }

        return logical switch
        {
            DockRegion.Left => DockRegion.Right,
            DockRegion.Right => DockRegion.Left,
            _ => logical,
        };
    }

    /// <summary>Mirrors a horizontal span inside a container so a right-to-left layout is the exact reflection of the left-to-right one.</summary>
    public static double MirrorX(double x, double width, double containerWidth)
    {
        if (!double.IsFinite(x) || !double.IsFinite(width) || !double.IsFinite(containerWidth) ||
            width < 0 || containerWidth < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(containerWidth));
        }

        return containerWidth - x - width;
    }
}
