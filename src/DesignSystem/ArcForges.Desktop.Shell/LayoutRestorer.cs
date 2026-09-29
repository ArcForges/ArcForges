// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Desktop.Shell;

/// <summary>Applies a saved layout while safely adapting to current panels and displays.</summary>
public static class LayoutRestorer
{
    private const double MinimumWindowWidth = 320;
    private const double MinimumWindowHeight = 200;

    public static LayoutRestoreReport Restore(
        LayoutSnapshot layout,
        WindowRegistry windows,
        PanelHost panels,
        DisplayTopology displays)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(windows);
        ArgumentNullException.ThrowIfNull(panels);
        ArgumentNullException.ThrowIfNull(displays);

        var restored = new List<WindowPlacement>();
        var unavailableDisplays = new List<DisplayId>();
        var duplicateWindows = new List<WindowId>();
        foreach (var saved in layout.Windows)
        {
            var display = displays.TryGet(saved.Display, out var currentDisplay) ? currentDisplay! : displays.Primary;
            if (display.Id != saved.Display)
            {
                unavailableDisplays.Add(saved.Display);
            }

            var placement = saved with { Display = display.Id, Bounds = Clamp(saved.Bounds, display.Bounds) };
            if (windows.TryOpen(placement))
            {
                restored.Add(placement);
            }
            else
            {
                duplicateWindows.Add(placement.Id);
            }
        }

        var panelReport = panels.Restore(layout.Panels);
        return new LayoutRestoreReport(
            restored,
            unavailableDisplays.Distinct().ToArray(),
            duplicateWindows,
            panelReport.MissingPanels,
            panelReport.DuplicatePanels);
    }

    private static WindowBounds Clamp(WindowBounds saved, WindowBounds workArea)
    {
        var width = Math.Min(Math.Max(saved.Width, MinimumWindowWidth), workArea.Width);
        var height = Math.Min(Math.Max(saved.Height, MinimumWindowHeight), workArea.Height);

        var maximumX = workArea.X + workArea.Width - width;
        var maximumY = workArea.Y + workArea.Height - height;
        return new WindowBounds(
            Math.Clamp(saved.X, workArea.X, maximumX),
            Math.Clamp(saved.Y, workArea.Y, maximumY),
            width,
            height);
    }
}

public sealed record LayoutRestoreReport(
    IReadOnlyList<WindowPlacement> RestoredWindows,
    IReadOnlyList<DisplayId> UnavailableDisplays,
    IReadOnlyList<WindowId> DuplicateWindows,
    IReadOnlyList<PanelKey> MissingPanels,
    IReadOnlyList<PanelKey> DuplicatePanels);
