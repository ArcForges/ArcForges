// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using ArcForges.Desktop.Shell.Localization;

namespace ArcForges.Desktop.Shell.Accessibility;

/// <summary>The assistive-technology role a UI adapter must expose for a shell element.</summary>
public enum AccessibleRole
{
    Window,
    Dialog,
    AlertDialog,
    Region,
    Group,
    Toolbar,
    List,
    ListItem,
    Button,
    ToggleButton,
    TextBox,
    SearchBox,
    Splitter,
    Label,
    Image,
    Status,
    Alert,
    Link,
}

/// <summary>How an element is reached without a pointer (AX-01, DP-04).</summary>
public enum KeyboardAccess
{
    /// <summary>Not interactive; assistive technology still reads it.</summary>
    None,

    /// <summary>One stop in the Tab order, ordered by <see cref="AccessibleNode.FocusOrder"/>.</summary>
    TabStop,

    /// <summary>A child of a tab-stop container reached with arrow keys; the container owns the Tab stop.</summary>
    Roving,

    /// <summary>Reached only through its command and shortcut, never focused.</summary>
    Command,
}

/// <summary>The non-pointer cues that carry an element's state (AX-05); colour alone is never sufficient.</summary>
[Flags]
public enum StateCues
{
    None = 0,
    Colour = 1,
    Text = 2,
    Icon = 4,
    Shape = 8,
}

public enum LiveRegionPoliteness
{
    Off,
    Polite,
    Assertive,
}

/// <summary>The axis along which the roving children of a container are arranged.</summary>
public enum NavigationOrientation
{
    Vertical,
    Horizontal,
}

/// <summary>
/// One element of a shell surface as assistive technology sees it. Names and descriptions are resource keys with
/// arguments so they are localised and never concatenated (BR-07). A UI adapter binds each node to its framework
/// control and must expose exactly this role, name, state, focus order and keyboard access (AX-01, AX-03).
/// </summary>
public sealed record AccessibleNode
{
    private const int MaximumChildren = 64;

    public AccessibleNode(
        string id,
        AccessibleRole role,
        LocalizedText? name = null,
        LocalizedText? description = null,
        KeyboardAccess keyboard = KeyboardAccess.None,
        int? focusOrder = null,
        string? commandId = null,
        bool isIconOnly = false,
        LiveRegionPoliteness live = LiveRegionPoliteness.Off,
        StateCues stateCues = StateCues.None,
        NavigationOrientation orientation = NavigationOrientation.Vertical,
        bool isModal = false,
        string? dismissCommandId = null,
        IEnumerable<AccessibleNode>? children = null)
    {
        if (!IsIdentifier(id))
        {
            throw new ArgumentException("A node id must be a bounded lowercase dotted identifier.", nameof(id));
        }

        if (commandId is not null && !IsIdentifier(commandId))
        {
            throw new ArgumentException("A command id must be a bounded lowercase dotted identifier.", nameof(commandId));
        }

        if (dismissCommandId is not null && !IsIdentifier(dismissCommandId))
        {
            throw new ArgumentException("A dismiss command id must be a bounded lowercase dotted identifier.", nameof(dismissCommandId));
        }

        if (focusOrder is < 1 or > 100_000)
        {
            throw new ArgumentOutOfRangeException(nameof(focusOrder));
        }

        AccessibleNode[] items = (children ?? []).Take(MaximumChildren + 1).ToArray();
        if (items.Length > MaximumChildren || items.Any(static child => child is null))
        {
            throw new ArgumentException("A node has at most 64 non-null children.", nameof(children));
        }

        Id = id;
        Role = role;
        Name = name;
        Description = description;
        Keyboard = keyboard;
        FocusOrder = focusOrder;
        CommandId = commandId;
        IsIconOnly = isIconOnly;
        Live = live;
        StateCues = stateCues;
        Orientation = orientation;
        IsModal = isModal;
        DismissCommandId = dismissCommandId;
        Children = new ReadOnlyCollection<AccessibleNode>(items);
    }

    public string Id { get; }

    public AccessibleRole Role { get; }

    /// <summary>The accessible name; required for every role except a generic <see cref="AccessibleRole.Group"/> (AX-03, AX-04).</summary>
    public LocalizedText? Name { get; }

    public LocalizedText? Description { get; }

    public KeyboardAccess Keyboard { get; }

    /// <summary>The Tab sequence number of a tab stop; strictly increasing in reading order within a surface.</summary>
    public int? FocusOrder { get; }

    /// <summary>The command a focused element performs on Enter or Space, and the command that reaches a command-only element.</summary>
    public string? CommandId { get; }

    public bool IsIconOnly { get; }

    public LiveRegionPoliteness Live { get; }

    public StateCues StateCues { get; }

    public NavigationOrientation Orientation { get; }

    /// <summary>True when focus is trapped inside this element until it is dismissed, then restored to its origin (AX-02).</summary>
    public bool IsModal { get; }

    /// <summary>The command that dismisses a modal element, bound to Escape.</summary>
    public string? DismissCommandId { get; }

    public IReadOnlyList<AccessibleNode> Children { get; }

    internal static bool IsIdentifier(string? value) =>
        !string.IsNullOrEmpty(value) &&
        value.Length <= 128 &&
        value[0] is >= 'a' and <= 'z' &&
        value[^1] is >= 'a' and <= 'z' or >= '0' and <= '9' &&
        value.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-') &&
        !value.Contains("..", StringComparison.Ordinal) &&
        !value.Contains("--", StringComparison.Ordinal);
}

/// <summary>A top-level shell surface: its stable identity and the root of its accessibility tree.</summary>
public sealed record ShellSurface
{
    public ShellSurface(string id, AccessibleNode root)
    {
        if (!AccessibleNode.IsIdentifier(id))
        {
            throw new ArgumentException("A surface id must be a bounded lowercase dotted identifier.", nameof(id));
        }

        ArgumentNullException.ThrowIfNull(root);
        Id = id;
        Root = root;
    }

    public string Id { get; }

    public AccessibleNode Root { get; }
}
