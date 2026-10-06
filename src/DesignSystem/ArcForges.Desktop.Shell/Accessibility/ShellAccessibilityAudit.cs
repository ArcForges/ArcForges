// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Desktop.Shell.Localization;

namespace ArcForges.Desktop.Shell.Accessibility;

/// <summary>Stable identifiers for the automated accessibility rules.</summary>
public static class AccessibilityRules
{
    public const string Role = "AX-ROLE";
    public const string Name = "AX-NAME";
    public const string IconName = "AX-ICON";
    public const string Keyboard = "AX-KEYBOARD";
    public const string Command = "AX-COMMAND";
    public const string FocusOrder = "AX-FOCUS-ORDER";
    public const string Dialog = "AX-DIALOG";
    public const string LiveRegion = "AX-LIVE";
    public const string Colour = "AX-COLOUR";
    public const string Identity = "AX-ID";
    public const string Text = "AX-TEXT";
    public const string State = "AX-STATE";
    public const string Menu = "AX-MENU";
}

/// <summary>One violation of the shell accessibility contract. The message is a developer diagnostic, not user text.</summary>
public sealed record AccessibilityFinding(string Rule, string SurfaceId, string NodeId, string Message);

/// <summary>
/// Offline accessibility checks over shell surface declarations (AX-01 to AX-05, BR-05). They prove the contract a UI
/// adapter must honour; they do not read a real platform accessibility tree, so they never replace the dated manual
/// assistive-technology verification.
/// </summary>
public static class ShellAccessibilityAudit
{
    private const int MaximumSurfaces = 64;
    private const int MaximumNodes = 4096;

    /// <summary>Returns every contract violation across <paramref name="surfaces"/>; an empty list means the declarations conform.</summary>
    public static IReadOnlyList<AccessibilityFinding> Evaluate(IEnumerable<ShellSurface> surfaces, CultureInfo? culture = null)
    {
        ArgumentNullException.ThrowIfNull(surfaces);
        ShellSurface[] items = surfaces.Take(MaximumSurfaces + 1).ToArray();
        if (items.Length > MaximumSurfaces || items.Any(static surface => surface is null))
        {
            throw new ArgumentException("An audit covers at most 64 non-null surfaces.", nameof(surfaces));
        }

        CultureInfo effective = culture ?? CultureInfo.CurrentUICulture;
        var findings = new List<AccessibilityFinding>();
        var nodeIds = new HashSet<string>(StringComparer.Ordinal);
        var surfaceIds = new HashSet<string>(StringComparer.Ordinal);
        int visited = 0;

        foreach (ShellSurface surface in items)
        {
            if (!surfaceIds.Add(surface.Id))
            {
                findings.Add(new AccessibilityFinding(AccessibilityRules.Identity, surface.Id, surface.Root.Id, "Duplicate surface id."));
            }

            int lastOrder = 0;
            Visit(surface, surface.Root, parent: null, effective, nodeIds, findings, ref lastOrder, ref visited);
        }

        return Array.AsReadOnly(findings.ToArray());
    }

    private static void Visit(
        ShellSurface surface,
        AccessibleNode node,
        AccessibleNode? parent,
        CultureInfo culture,
        HashSet<string> nodeIds,
        List<AccessibilityFinding> findings,
        ref int lastOrder,
        ref int visited)
    {
        if (++visited > MaximumNodes)
        {
            throw new InvalidOperationException("The accessibility tree exceeds the audited size.");
        }

        void Add(string rule, string message) => findings.Add(new AccessibilityFinding(rule, surface.Id, node.Id, message));

        if (!nodeIds.Add(node.Id))
        {
            Add(AccessibilityRules.Identity, "Duplicate node id.");
        }

        if (!Enum.IsDefined(node.Role))
        {
            Add(AccessibilityRules.Role, "Unknown role.");
        }

        if (node.Role == AccessibleRole.ToggleButton && node.State.Toggled is null)
        {
            Add(AccessibilityRules.State, "A toggle button must expose its checked state.");
        }

        if (node.State.Toggled is not null && node.Role is not (AccessibleRole.ToggleButton or AccessibleRole.MenuItem))
        {
            Add(AccessibilityRules.State, "Checked state applies only to toggle buttons and checkable menu items.");
        }

        if (node.State.Selected is not null && node.Role is not (AccessibleRole.ListItem or AccessibleRole.MenuItem))
        {
            Add(AccessibilityRules.State, "Selection applies only to selectable items.");
        }

        if (node.State.Expanded is not null && node.Role is not (AccessibleRole.Button or AccessibleRole.ToggleButton or AccessibleRole.MenuItem))
        {
            Add(AccessibilityRules.State, "Expanded state applies only to a control that opens content.");
        }

        if (node.Role is AccessibleRole.MenuBar or AccessibleRole.Menu)
        {
            if (node.Keyboard != KeyboardAccess.TabStop ||
                node.Children.Any(static child => child.Role != AccessibleRole.MenuItem || child.Keyboard != KeyboardAccess.Roving))
            {
                Add(AccessibilityRules.Menu, "A menu is one tab stop whose menu items use roving keyboard access.");
            }
        }

        if (node.Role == AccessibleRole.MenuItem && parent?.Role is not (AccessibleRole.MenuBar or AccessibleRole.Menu))
        {
            Add(AccessibilityRules.Menu, "A menu item must belong to a menu or menu bar.");
        }

        if (node.Role == AccessibleRole.MenuItem && node.CommandId is null)
        {
            Add(AccessibilityRules.Command, "A menu item must name the command its owner executes.");
        }

        CheckText(node.Name, "name", Add, culture);
        CheckText(node.Description, "description", Add, culture);
        if (node.Name is null && node.Role != AccessibleRole.Group)
        {
            Add(node.IsIconOnly ? AccessibilityRules.IconName : AccessibilityRules.Name, "Every role except a generic group needs an accessible name.");
        }

        if (IsInteractive(node.Role) && node.Keyboard == KeyboardAccess.None)
        {
            Add(AccessibilityRules.Keyboard, "An interactive element must be reachable without a pointer.");
        }

        if (node.Keyboard == KeyboardAccess.Command && node.CommandId is null)
        {
            Add(AccessibilityRules.Command, "A command-only element needs its command id.");
        }

        CheckFocusOrder(node, parent, Add, ref lastOrder);

        if (node.Role is AccessibleRole.Dialog or AccessibleRole.AlertDialog)
        {
            if (!node.IsModal)
            {
                Add(AccessibilityRules.Dialog, "A dialog must trap focus.");
            }
        }

        if (node.IsModal)
        {
            if (node.DismissCommandId is null)
            {
                Add(AccessibilityRules.Dialog, "A modal element needs a dismiss command bound to Escape.");
            }

            if (!Descendants(node).Any(static child => child.Keyboard == KeyboardAccess.TabStop))
            {
                Add(AccessibilityRules.Dialog, "A modal element needs at least one focusable control.");
            }
        }

        if (node.Role == AccessibleRole.Alert && node.Live != LiveRegionPoliteness.Assertive)
        {
            Add(AccessibilityRules.LiveRegion, "An alert must be an assertive live region.");
        }

        if (node.Role == AccessibleRole.Status && node.Live == LiveRegionPoliteness.Off)
        {
            Add(AccessibilityRules.LiveRegion, "A status element must announce changes.");
        }

        if (node.StateCues.HasFlag(StateCues.Colour) &&
            (node.StateCues & (StateCues.Text | StateCues.Icon | StateCues.Shape)) == StateCues.None)
        {
            Add(AccessibilityRules.Colour, "Colour must be paired with text, an icon or a shape.");
        }

        foreach (AccessibleNode child in node.Children)
        {
            Visit(surface, child, node, culture, nodeIds, findings, ref lastOrder, ref visited);
        }
    }

    private static void CheckFocusOrder(AccessibleNode node, AccessibleNode? parent, Action<string, string> add, ref int lastOrder)
    {
        switch (node.Keyboard)
        {
            case KeyboardAccess.TabStop:
                if (node.FocusOrder is not int order)
                {
                    add(AccessibilityRules.FocusOrder, "A tab stop needs a focus order.");
                }
                else if (order <= lastOrder)
                {
                    add(AccessibilityRules.FocusOrder, "Focus order must increase strictly in reading order.");
                }
                else
                {
                    lastOrder = order;
                }

                break;
            case KeyboardAccess.Roving:
                if (parent is not { Keyboard: KeyboardAccess.TabStop })
                {
                    add(AccessibilityRules.FocusOrder, "A roving element must sit inside a tab-stop container.");
                }

                if (node.FocusOrder is not null)
                {
                    add(AccessibilityRules.FocusOrder, "A roving element is ordered by position, not by a focus order.");
                }

                break;
            default:
                if (node.FocusOrder is not null)
                {
                    add(AccessibilityRules.FocusOrder, "Only a tab stop carries a focus order.");
                }

                break;
        }
    }

    private static void CheckText(LocalizedText? text, string purpose, Action<string, string> add, CultureInfo culture)
    {
        if (text is null)
        {
            return;
        }

        if (!ShellText.Defines(text.Key))
        {
            add(AccessibilityRules.Text, $"The {purpose} key is not defined in the shell resources.");
            return;
        }

        try
        {
            if (string.IsNullOrWhiteSpace(ShellText.Resolve(text, culture)))
            {
                add(AccessibilityRules.Name, $"The {purpose} resolves to blank text.");
            }
        }
        catch (FormatException)
        {
            add(AccessibilityRules.Text, $"The {purpose} cannot be formatted with its arguments.");
        }
    }

    private static bool IsInteractive(AccessibleRole role) =>
        role is AccessibleRole.MenuItem or AccessibleRole.Button or AccessibleRole.ToggleButton or AccessibleRole.TextBox or
            AccessibleRole.SearchBox or AccessibleRole.Splitter or AccessibleRole.Link or AccessibleRole.ListItem;

    private static IEnumerable<AccessibleNode> Descendants(AccessibleNode node)
    {
        foreach (AccessibleNode child in node.Children)
        {
            yield return child;
            foreach (AccessibleNode nested in Descendants(child))
            {
                yield return nested;
            }
        }
    }
}
