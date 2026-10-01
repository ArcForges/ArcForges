// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;

namespace ArcForges.Desktop.Shell;

/// <summary>
/// Where a panel docks. <see cref="Left"/> and <see cref="Right"/> are the leading and trailing edges of the reading
/// direction, not physical sides, so one saved layout mirrors correctly under a right-to-left interface language.
/// UI adapters draw with <see cref="Localization.FlowDirections.ToPhysical"/>.
/// </summary>
public enum DockRegion
{
    Left,
    Right,
    Top,
    Bottom,
    Center
}

/// <summary>A validated device-independent window rectangle, expressed in platform logical units.</summary>
public readonly record struct WindowBounds(double X, double Y, double Width, double Height)
{
    internal const double MaximumCoordinate = 1_000_000;
    internal const double MaximumExtent = 100_000;

    public bool IsValid
        => double.IsFinite(X)
            && double.IsFinite(Y)
            && double.IsFinite(Width)
            && double.IsFinite(Height)
            && Math.Abs(X) <= MaximumCoordinate
            && Math.Abs(Y) <= MaximumCoordinate
            && Width > 0
            && Width <= MaximumExtent
            && Height > 0
            && Height <= MaximumExtent;
}

public sealed record WindowPlacement(WindowId Id, DisplayId Display, WindowBounds Bounds);

public sealed record PanelDefinition(PanelKey Key, DockRegion InitialRegion = DockRegion.Left, bool InitiallyCollapsed = false);

public sealed record PanelPlacement(PanelKey Key, DockRegion Region, bool IsCollapsed, int Order);

/// <summary>An immutable, validated snapshot independent of any UI framework.</summary>
public sealed class LayoutSnapshot
{
    private LayoutSnapshot(ApplicationKey application, LayoutKey layout, WindowPlacement[] windows, PanelPlacement[] panels)
    {
        Application = application;
        Layout = layout;
        Windows = Array.AsReadOnly(windows);
        Panels = Array.AsReadOnly(panels);
    }

    public ApplicationKey Application { get; }

    public LayoutKey Layout { get; }

    public ReadOnlyCollection<WindowPlacement> Windows { get; }

    public ReadOnlyCollection<PanelPlacement> Panels { get; }

    public static LayoutSnapshot Create(
        ApplicationKey application,
        LayoutKey layout,
        IEnumerable<WindowPlacement> windows,
        IEnumerable<PanelPlacement> panels)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(windows);
        ArgumentNullException.ThrowIfNull(panels);

        var windowItems = windows.Take(65).ToArray();
        if (windowItems.Length > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(windows), "A saved layout has too many windows.");
        }

        var panelItems = panels.Take(257).ToArray();
        if (panelItems.Length > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(panels), "A saved layout has too many panels.");
        }

        var windowIds = new HashSet<WindowId>();
        foreach (var item in windowItems)
        {
            ArgumentNullException.ThrowIfNull(item);
            ArgumentNullException.ThrowIfNull(item.Id);
            ArgumentNullException.ThrowIfNull(item.Display);
            if (!item.Bounds.IsValid || !windowIds.Add(item.Id))
            {
                throw new ArgumentException("Window placements must be valid and unique.", nameof(windows));
            }
        }

        var panelIds = new HashSet<PanelKey>();
        foreach (var item in panelItems)
        {
            ArgumentNullException.ThrowIfNull(item);
            ArgumentNullException.ThrowIfNull(item.Key);
            if (!Enum.IsDefined(item.Region) || item.Order is < 0 or > 100_000 || !panelIds.Add(item.Key))
            {
                throw new ArgumentException("Panel placements must use a known dock region and unique key.", nameof(panels));
            }
        }

        return new LayoutSnapshot(application, layout, windowItems, panelItems);
    }
}

public sealed record DisplayWorkArea(DisplayId Id, WindowBounds Bounds, bool IsPrimary = false);

/// <summary>A point-in-time display topology, including exactly one primary work area.</summary>
public sealed class DisplayTopology
{
    private readonly Dictionary<DisplayId, DisplayWorkArea> _byId;

    public DisplayTopology(IEnumerable<DisplayWorkArea> displays)
    {
        ArgumentNullException.ThrowIfNull(displays);
        var items = displays.Take(65).ToArray();
        if (items.Length is < 1 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(displays), "A display topology must contain between one and 64 displays.");
        }

        _byId = new Dictionary<DisplayId, DisplayWorkArea>();
        foreach (var display in items)
        {
            ArgumentNullException.ThrowIfNull(display);
            ArgumentNullException.ThrowIfNull(display.Id);
            if (!display.Bounds.IsValid || !_byId.TryAdd(display.Id, display))
            {
                throw new ArgumentException("Display work areas must be valid and uniquely identified.", nameof(displays));
            }
        }

        var primaryDisplays = items.Where(static display => display.IsPrimary).ToArray();
        if (primaryDisplays.Length != 1)
        {
            throw new ArgumentException("A display topology must have exactly one primary display.", nameof(displays));
        }

        Primary = primaryDisplays[0];
        Displays = Array.AsReadOnly(items);
    }

    public ReadOnlyCollection<DisplayWorkArea> Displays { get; }

    public DisplayWorkArea Primary { get; }

    public bool TryGet(DisplayId id, out DisplayWorkArea? display)
    {
        ArgumentNullException.ThrowIfNull(id);
        return _byId.TryGetValue(id, out display);
    }
}
