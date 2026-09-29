// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.DesignSystem;

namespace ArcForges.Desktop.Shell;

/// <summary>Framework-neutral state for dockable and collapsible panels.</summary>
public sealed class PanelHost
{
    private readonly Dictionary<PanelKey, PanelPlacement> _panels = [];
    private readonly Dictionary<PanelKey, PanelPlacement> _defaults = [];

    public PanelHost(DensityMode density, IEnumerable<PanelDefinition> definitions)
    {
        ArgumentNullException.ThrowIfNull(definitions);
        var items = definitions.Take(257).ToArray();
        if (items.Length > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(definitions), "A panel host cannot contain more than 256 panels.");
        }

        var tokens = DesignTokens.Get(ThemeMode.Light, density);
        Measurements = tokens.Measurements;

        foreach (var definition in items)
        {
            ArgumentNullException.ThrowIfNull(definition);
            ArgumentNullException.ThrowIfNull(definition.Key);
            var placement = new PanelPlacement(definition.Key, definition.InitialRegion, definition.InitiallyCollapsed, _panels.Count);
            if (!Enum.IsDefined(definition.InitialRegion) || !_panels.TryAdd(definition.Key, placement))
            {
                throw new ArgumentException("Panel definitions must have unique keys and known dock regions.", nameof(definitions));
            }

            _defaults.Add(definition.Key, placement);
        }
    }

    public DensityTokens Measurements { get; }

    public IReadOnlyList<PanelPlacement> Snapshot()
        => _panels.Values
            .OrderBy(static panel => panel.Region)
            .ThenBy(static panel => panel.Order)
            .ThenBy(static panel => panel.Key.Value, StringComparer.Ordinal)
            .ToArray();

    public bool Dock(PanelKey key, DockRegion region, int order)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (!Enum.IsDefined(region))
        {
            throw new ArgumentOutOfRangeException(nameof(region));
        }

        if (order is < 0 or > 100_000)
        {
            throw new ArgumentOutOfRangeException(nameof(order));
        }

        if (!_panels.TryGetValue(key, out var current))
        {
            return false;
        }

        _panels[key] = current with { Region = region, Order = order };
        return true;
    }

    public bool SetCollapsed(PanelKey key, bool isCollapsed)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (!_panels.TryGetValue(key, out var current))
        {
            return false;
        }

        _panels[key] = current with { IsCollapsed = isCollapsed };
        return true;
    }

    public PanelRestoreReport Restore(IEnumerable<PanelPlacement> placements)
    {
        ArgumentNullException.ThrowIfNull(placements);
        var items = placements.Take(257).ToArray();
        if (items.Length > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(placements), "A layout cannot restore more than 256 panels.");
        }

        foreach (var placement in items)
        {
            ArgumentNullException.ThrowIfNull(placement);
            ArgumentNullException.ThrowIfNull(placement.Key);
            if (!Enum.IsDefined(placement.Region) || placement.Order is < 0 or > 100_000)
            {
                throw new ArgumentException("Panel placement is invalid.", nameof(placements));
            }
        }

        var applied = new HashSet<PanelKey>();
        var missing = new List<PanelKey>();
        var duplicates = new List<PanelKey>();
        var appliedCount = 0;

        foreach (var panel in _defaults)
        {
            _panels[panel.Key] = panel.Value;
        }

        foreach (var placement in items)
        {
            if (!applied.Add(placement.Key))
            {
                duplicates.Add(placement.Key);
                continue;
            }

            if (!_panels.ContainsKey(placement.Key))
            {
                missing.Add(placement.Key);
                continue;
            }

            _panels[placement.Key] = placement;
            appliedCount++;
        }

        return new PanelRestoreReport(appliedCount, missing, duplicates);
    }
}

public sealed record PanelRestoreReport(int AppliedCount, IReadOnlyList<PanelKey> MissingPanels, IReadOnlyList<PanelKey> DuplicatePanels);
