// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Desktop.Shell;

/// <summary>Tracks live windows owned by one per-launch instance identity.</summary>
public sealed class WindowRegistry
{
    private readonly object _gate = new();
    private readonly Dictionary<WindowId, WindowPlacement> _windows = [];

    public WindowRegistry(InstanceId instance)
    {
        if (instance.Equals(default(InstanceId)))
        {
            throw new ArgumentException("A live window registry requires a non-default launch instance identity.", nameof(instance));
        }

        Instance = instance;
    }

    public InstanceId Instance { get; }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _windows.Count;
            }
        }
    }

    public bool TryOpen(WindowPlacement placement)
    {
        ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(placement.Id);
        ArgumentNullException.ThrowIfNull(placement.Display);
        if (!placement.Bounds.IsValid)
        {
            throw new ArgumentException("A live window requires valid bounds.", nameof(placement));
        }

        lock (_gate)
        {
            return _windows.Count < 64 && _windows.TryAdd(placement.Id, placement);
        }
    }

    public bool TryClose(WindowId id)
    {
        ArgumentNullException.ThrowIfNull(id);
        lock (_gate)
        {
            return _windows.Remove(id);
        }
    }

    public IReadOnlyList<WindowPlacement> Snapshot()
    {
        lock (_gate)
        {
            return _windows.Values
                .OrderBy(static placement => placement.Id.Value, StringComparer.Ordinal)
                .ToArray();
        }
    }
}
