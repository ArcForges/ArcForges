// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Desktop.Shell.Localization;

namespace ArcForges.Desktop.Shell.Accessibility;

/// <summary>A physical arrow-key direction, before flow-direction mapping.</summary>
public enum FocusDirection
{
    Up,
    Down,
    Left,
    Right,
}

/// <summary>
/// The keyboard focus contract of a shell surface as executable behaviour (AX-01, AX-02): Tab and Shift+Tab visit the
/// tab stops in focus order, arrow keys move inside a roving group (mirrored in a right-to-left layout), a modal element
/// traps focus until it is dismissed, and dismissal restores focus to its origin. Focus is always on a visible element;
/// focus and selection stay separate. UI adapters mirror this behaviour; tests drive it to prove keyboard-only workflows.
/// The navigator holds UI focus state, so like all UI work it is used from the UI thread only and is not synchronised.
/// </summary>
public sealed class FocusNavigator
{
    private readonly FlowDirection _flow;
    private readonly List<Frame> _frames = [];

    public FocusNavigator(ShellSurface surface, FlowDirection flow = FlowDirection.LeftToRight)
    {
        ArgumentNullException.ThrowIfNull(surface);
        if (!Enum.IsDefined(flow))
        {
            throw new ArgumentOutOfRangeException(nameof(flow));
        }

        _flow = flow;
        _frames.Add(new Frame(surface, origin: null));
    }

    /// <summary>The id of the focused element, or null when the active surface has no focusable element.</summary>
    public string? CurrentId => _frames[^1].CurrentId;

    /// <summary>True while a modal surface traps focus.</summary>
    public bool IsModalOpen => _frames.Count > 1;

    /// <summary>The id of the surface that currently owns focus.</summary>
    public string ActiveSurfaceId => _frames[^1].Surface.Id;

    /// <summary>Tab: moves to the next tab stop, wrapping inside the active surface.</summary>
    public bool MoveNext() => _frames[^1].Step(1);

    /// <summary>Shift+Tab: moves to the previous tab stop, wrapping inside the active surface.</summary>
    public bool MovePrevious() => _frames[^1].Step(-1);

    /// <summary>An arrow key: moves inside a roving group, with horizontal groups mirrored in a right-to-left layout. Returns false at an edge or outside a group.</summary>
    public bool Move(FocusDirection direction)
    {
        if (!Enum.IsDefined(direction))
        {
            throw new ArgumentOutOfRangeException(nameof(direction));
        }

        return _frames[^1].MoveWithinGroup(direction, _flow);
    }

    /// <summary>Enter or Space: returns the command the focused element performs, or null.</summary>
    public string? Activate() => _frames[^1].Current is { State.Disabled: false } node ? node.CommandId : null;

    /// <summary>Opens a modal surface, trapping focus inside it and remembering the focused element to restore. Returns false for a surface that is not modal or has nothing focusable.</summary>
    public bool OpenModal(ShellSurface modal)
    {
        ArgumentNullException.ThrowIfNull(modal);
        if (!modal.Root.IsModal)
        {
            return false;
        }

        var frame = new Frame(modal, origin: CurrentId);
        if (frame.CurrentId is null)
        {
            return false;
        }

        _frames.Add(frame);
        return true;
    }

    /// <summary>Escape: closes the topmost modal, restores focus to its origin and returns its dismiss command; null when no modal is open.</summary>
    public string? Dismiss()
    {
        if (_frames.Count < 2)
        {
            return null;
        }

        Frame closing = _frames[^1];
        _frames.RemoveAt(_frames.Count - 1);
        _frames[^1].Restore(closing.Origin);
        return closing.Surface.Root.DismissCommandId;
    }

    private sealed class Frame
    {
        private readonly List<AccessibleNode> _stops;
        private readonly Dictionary<string, int> _active = new(StringComparer.Ordinal);
        private int _index;

        internal Frame(ShellSurface surface, string? origin)
        {
            Surface = surface;
            Origin = origin;
            var collected = new List<AccessibleNode>();
            Collect(surface.Root, collected);
            _stops = collected.OrderBy(static stop => stop.FocusOrder ?? int.MaxValue).ToList();
        }

        internal ShellSurface Surface { get; }

        internal string? Origin { get; }

        internal string? CurrentId => Current?.Id;

        internal AccessibleNode? Current
        {
            get
            {
                if (_stops.Count == 0)
                {
                    return null;
                }

                AccessibleNode stop = _stops[_index];
                List<AccessibleNode> roving = Roving(stop);
                return roving.Count == 0 ? stop : roving[Math.Min(_active.GetValueOrDefault(stop.Id), roving.Count - 1)];
            }
        }

        internal bool Step(int delta)
        {
            if (_stops.Count < 2)
            {
                return false;
            }

            _index = (_index + delta + _stops.Count) % _stops.Count;
            return true;
        }

        internal bool MoveWithinGroup(FocusDirection direction, FlowDirection flow)
        {
            if (_stops.Count == 0)
            {
                return false;
            }

            AccessibleNode stop = _stops[_index];
            List<AccessibleNode> roving = Roving(stop);
            if (roving.Count == 0)
            {
                return false;
            }

            int delta = (stop.Orientation, direction) switch
            {
                (NavigationOrientation.Vertical, FocusDirection.Down) => 1,
                (NavigationOrientation.Vertical, FocusDirection.Up) => -1,
                (NavigationOrientation.Horizontal, FocusDirection.Right) => flow == FlowDirection.LeftToRight ? 1 : -1,
                (NavigationOrientation.Horizontal, FocusDirection.Left) => flow == FlowDirection.LeftToRight ? -1 : 1,
                _ => 0,
            };
            int current = Math.Min(_active.GetValueOrDefault(stop.Id), roving.Count - 1);
            int next = current + delta;
            if (delta == 0 || next < 0 || next >= roving.Count)
            {
                return false;
            }

            _active[stop.Id] = next;
            return true;
        }

        internal void Restore(string? origin)
        {
            if (origin is null)
            {
                return;
            }

            for (int index = 0; index < _stops.Count; index++)
            {
                AccessibleNode stop = _stops[index];
                if (string.Equals(stop.Id, origin, StringComparison.Ordinal))
                {
                    _index = index;
                    return;
                }

                List<AccessibleNode> roving = Roving(stop);
                int position = roving.FindIndex(child => string.Equals(child.Id, origin, StringComparison.Ordinal));
                if (position >= 0)
                {
                    _index = index;
                    _active[stop.Id] = position;
                    return;
                }
            }
        }

        private static List<AccessibleNode> Roving(AccessibleNode stop) =>
            stop.Children.Where(static child => child.Keyboard == KeyboardAccess.Roving).ToList();

        private static void Collect(AccessibleNode node, List<AccessibleNode> stops)
        {
            if (node.State.Disabled)
            {
                return;
            }

            if (node.Keyboard == KeyboardAccess.TabStop)
            {
                stops.Add(node);
            }

            foreach (AccessibleNode child in node.Children)
            {
                Collect(child, stops);
            }
        }
    }
}
