// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Desktop.Shell.Localization;

namespace ArcForges.Desktop.Shell.Accessibility;

/// <summary>
/// Shell-owned command identifiers that surface elements perform. They name semantic actions, never labels, so they are
/// stable and never localised (LO-02). Products bind them to their own command registrations.
/// </summary>
public static class ShellCommandIds
{
    public const string PaletteOpen = "shell.palette.open";
    public const string PaletteClose = "shell.palette.close";
    public const string PaletteRunSelected = "shell.palette.run-selected";
    public const string AttentionOpen = "shell.attention.open";
    public const string AttentionOpenItem = "shell.attention.open-item";
    public const string SettingsOpen = "shell.settings.open";
    public const string SettingsReset = "shell.settings.reset";
    public const string PanelToggle = "shell.panel.toggle";
    public const string ErrorCopyReference = "shell.error.copy-reference";
    public const string ErrorRetry = "shell.error.retry";
    public const string ErrorClose = "shell.error.close";
    public const string ShutdownKeepWorking = "shell.shutdown.keep-working";
    public const string ShutdownQuit = "shell.shutdown.quit";
}

/// <summary>
/// The accessibility declaration of every shell surface whose state model ships in this assembly: the workspace window,
/// the command palette, scoped settings, the attention centre, error presentation and the shutdown prompt. A UI adapter binds each node to a
/// framework control. List and status arguments (counts, titles, scope names) are representative samples; the adapter
/// supplies live values through the same resource keys. Product content hosted inside a region is the product's own
/// surface and is audited by the product with <see cref="ShellAccessibilityAudit"/>.
/// </summary>
public static class ShellSurfaceCatalog
{
    private static readonly IReadOnlyList<ShellSurface> AllSurfaces =
    [
        Workspace(),
        CommandPalette(),
        Settings(),
        AttentionCentre(),
        ErrorDialog(),
        ShutdownPrompt(),
    ];

    /// <summary>Every declared shell surface in a stable order.</summary>
    public static IReadOnlyList<ShellSurface> All => AllSurfaces;

    /// <summary>The main workspace window with its toolbar, dockable panel regions, splitters and status area.</summary>
    public static ShellSurface WorkspaceSurface => AllSurfaces[0];

    /// <summary>The modal command palette.</summary>
    public static ShellSurface CommandPaletteSurface => AllSurfaces[1];

    /// <summary>The scoped settings pane.</summary>
    public static ShellSurface SettingsSurface => AllSurfaces[2];

    /// <summary>The attention centre listing durable items beside best-effort notifications.</summary>
    public static ShellSurface AttentionSurface => AllSurfaces[3];

    /// <summary>The modal error presentation dialog.</summary>
    public static ShellSurface ErrorSurface => AllSurfaces[4];

    /// <summary>The modal shutdown prompt that states the consequences of quitting with running or unsaved work.</summary>
    public static ShellSurface ShutdownSurface => AllSurfaces[5];

    private static LocalizedText Text(string key, params (string Name, object? Value)[] arguments) =>
        new(key, arguments.Length == 0 ? null : arguments.ToDictionary(static pair => pair.Name, static pair => pair.Value, StringComparer.Ordinal));

    private static ShellSurface Workspace() => new("shell.workspace", new AccessibleNode(
        "shell.workspace",
        AccessibleRole.Window,
        Text("workspace.window.name"),
        children:
        [
            new AccessibleNode(
                "shell.workspace.toolbar",
                AccessibleRole.Toolbar,
                Text("workspace.toolbar.name"),
                orientation: NavigationOrientation.Horizontal,
                children:
                [
                    new AccessibleNode(
                        "shell.workspace.palette-button",
                        AccessibleRole.Button,
                        Text("workspace.palette-button.name"),
                        Text("workspace.palette-button.description"),
                        KeyboardAccess.TabStop,
                        focusOrder: 10,
                        commandId: ShellCommandIds.PaletteOpen,
                        isIconOnly: true),
                    new AccessibleNode(
                        "shell.workspace.attention-button",
                        AccessibleRole.Button,
                        Text("workspace.attention-button.name", ("count", 0)),
                        keyboard: KeyboardAccess.TabStop,
                        focusOrder: 20,
                        commandId: ShellCommandIds.AttentionOpen,
                        isIconOnly: true,
                        stateCues: StateCues.Colour | StateCues.Text | StateCues.Icon),
                    new AccessibleNode(
                        "shell.workspace.settings-button",
                        AccessibleRole.Button,
                        Text("workspace.settings-button.name"),
                        keyboard: KeyboardAccess.TabStop,
                        focusOrder: 30,
                        commandId: ShellCommandIds.SettingsOpen,
                        isIconOnly: true),
                ]),
            new AccessibleNode(
                "shell.workspace.panel-start",
                AccessibleRole.Region,
                Text("workspace.panel-start.name"),
                children:
                [
                    PanelToggle("shell.workspace.panel-start.toggle", "workspace.panel-start.toggle.name", 40),
                ]),
            new AccessibleNode(
                "shell.workspace.splitter-start",
                AccessibleRole.Splitter,
                Text("workspace.splitter-start.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 50),
            new AccessibleNode(
                "shell.workspace.center",
                AccessibleRole.Region,
                Text("workspace.center.name")),
            new AccessibleNode(
                "shell.workspace.splitter-end",
                AccessibleRole.Splitter,
                Text("workspace.splitter-end.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 60),
            new AccessibleNode(
                "shell.workspace.panel-end",
                AccessibleRole.Region,
                Text("workspace.panel-end.name"),
                children:
                [
                    PanelToggle("shell.workspace.panel-end.toggle", "workspace.panel-end.toggle.name", 70),
                ]),
            new AccessibleNode(
                "shell.workspace.panel-bottom",
                AccessibleRole.Region,
                Text("workspace.panel-bottom.name"),
                children:
                [
                    PanelToggle("shell.workspace.panel-bottom.toggle", "workspace.panel-bottom.toggle.name", 80),
                ]),
            new AccessibleNode(
                "shell.workspace.status",
                AccessibleRole.Status,
                Text("workspace.status.name"),
                live: LiveRegionPoliteness.Polite),
        ]));

    private static AccessibleNode PanelToggle(string id, string nameKey, int focusOrder) => new(
        id,
        AccessibleRole.ToggleButton,
        Text(nameKey),
        keyboard: KeyboardAccess.TabStop,
        focusOrder: focusOrder,
        commandId: ShellCommandIds.PanelToggle,
        isIconOnly: true,
        stateCues: StateCues.Icon | StateCues.Text);

    private static ShellSurface CommandPalette() => new("shell.command-palette", new AccessibleNode(
        "shell.command-palette",
        AccessibleRole.Dialog,
        Text("command-palette.name"),
        isModal: true,
        dismissCommandId: ShellCommandIds.PaletteClose,
        children:
        [
            new AccessibleNode(
                "shell.command-palette.query",
                AccessibleRole.SearchBox,
                Text("command-palette.query.name"),
                Text("command-palette.query.description"),
                KeyboardAccess.TabStop,
                focusOrder: 1),
            new AccessibleNode(
                "shell.command-palette.results",
                AccessibleRole.List,
                Text("command-palette.results.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 2,
                children:
                [
                    new AccessibleNode(
                        "shell.command-palette.result",
                        AccessibleRole.ListItem,
                        Text("command-palette.result.name", ("title", "Example command")),
                        keyboard: KeyboardAccess.Roving,
                        commandId: ShellCommandIds.PaletteRunSelected,
                        stateCues: StateCues.Colour | StateCues.Shape),
                ]),
            new AccessibleNode(
                "shell.command-palette.result-count",
                AccessibleRole.Status,
                Text("command-palette.result-count.name", ("count", 0)),
                live: LiveRegionPoliteness.Polite),
            new AccessibleNode(
                "shell.command-palette.close",
                AccessibleRole.Button,
                Text("command-palette.close.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 3,
                commandId: ShellCommandIds.PaletteClose),
        ]));

    private static ShellSurface Settings() => new("shell.settings", new AccessibleNode(
        "shell.settings",
        AccessibleRole.Region,
        Text("settings.name"),
        children:
        [
            new AccessibleNode(
                "shell.settings.search",
                AccessibleRole.SearchBox,
                Text("settings.search.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 1),
            new AccessibleNode(
                "shell.settings.scopes",
                AccessibleRole.List,
                Text("settings.scopes.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 2,
                children:
                [
                    ScopeItem("shell.settings.scope.application", "settings.scope.application.name"),
                    ScopeItem("shell.settings.scope.workspace", "settings.scope.workspace.name"),
                    ScopeItem("shell.settings.scope.device", "settings.scope.device.name"),
                    ScopeItem("shell.settings.scope.instance", "settings.scope.instance.name"),
                ]),
            new AccessibleNode(
                "shell.settings.effective",
                AccessibleRole.Label,
                Text("settings.effective.name", ("scope", "device"))),
            new AccessibleNode(
                "shell.settings.reset",
                AccessibleRole.Button,
                Text("settings.reset.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 3,
                commandId: ShellCommandIds.SettingsReset),
        ]));

    private static AccessibleNode ScopeItem(string id, string nameKey) => new(
        id,
        AccessibleRole.ListItem,
        Text(nameKey),
        keyboard: KeyboardAccess.Roving,
        stateCues: StateCues.Colour | StateCues.Text);

    private static ShellSurface AttentionCentre() => new("shell.attention", new AccessibleNode(
        "shell.attention",
        AccessibleRole.Region,
        Text("attention.name"),
        children:
        [
            new AccessibleNode(
                "shell.attention.live",
                AccessibleRole.Status,
                Text("attention.live.name"),
                live: LiveRegionPoliteness.Polite),
            new AccessibleNode(
                "shell.attention.items",
                AccessibleRole.List,
                Text("attention.items.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 1,
                children:
                [
                    new AccessibleNode(
                        "shell.attention.item",
                        AccessibleRole.ListItem,
                        Text("attention.item.name", ("title", "Example item")),
                        keyboard: KeyboardAccess.Roving,
                        commandId: ShellCommandIds.AttentionOpenItem,
                        stateCues: StateCues.Colour | StateCues.Text | StateCues.Icon),
                ]),
            new AccessibleNode(
                "shell.attention.open-item",
                AccessibleRole.Button,
                Text("attention.open-item.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 2,
                commandId: ShellCommandIds.AttentionOpenItem),
        ]));

    private static ShellSurface ErrorDialog() => new("shell.error-dialog", new AccessibleNode(
        "shell.error-dialog",
        AccessibleRole.AlertDialog,
        Text("error-dialog.name"),
        isModal: true,
        dismissCommandId: ShellCommandIds.ErrorClose,
        children:
        [
            new AccessibleNode(
                "shell.error-dialog.details",
                AccessibleRole.Alert,
                Text("error-dialog.details.name"),
                live: LiveRegionPoliteness.Assertive,
                children:
                [
                    new AccessibleNode("shell.error-dialog.what", AccessibleRole.Label, Text("error-dialog.what.name")),
                    new AccessibleNode("shell.error-dialog.retry", AccessibleRole.Label, Text("error-dialog.retry.name")),
                    new AccessibleNode("shell.error-dialog.action", AccessibleRole.Label, Text("error-dialog.action.name")),
                    new AccessibleNode("shell.error-dialog.reference", AccessibleRole.Label, Text("error-dialog.reference.name")),
                ]),
            new AccessibleNode(
                "shell.error-dialog.copy",
                AccessibleRole.Button,
                Text("error-dialog.copy.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 1,
                commandId: ShellCommandIds.ErrorCopyReference,
                isIconOnly: true),
            new AccessibleNode(
                "shell.error-dialog.try-again",
                AccessibleRole.Button,
                Text("error-dialog.try-again.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 2,
                commandId: ShellCommandIds.ErrorRetry),
            new AccessibleNode(
                "shell.error-dialog.close",
                AccessibleRole.Button,
                Text("error-dialog.close.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 3,
                commandId: ShellCommandIds.ErrorClose),
        ]));

    private static ShellSurface ShutdownPrompt() => new("shell.shutdown-prompt", new AccessibleNode(
        "shell.shutdown-prompt",
        AccessibleRole.AlertDialog,
        Text("shutdown-prompt.name"),
        isModal: true,
        dismissCommandId: ShellCommandIds.ShutdownKeepWorking,
        children:
        [
            new AccessibleNode(
                "shell.shutdown-prompt.consequences",
                AccessibleRole.Alert,
                Text("shutdown-prompt.consequences.name"),
                live: LiveRegionPoliteness.Assertive),
            new AccessibleNode(
                "shell.shutdown-prompt.keep-working",
                AccessibleRole.Button,
                Text("shutdown-prompt.keep-working.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 1,
                commandId: ShellCommandIds.ShutdownKeepWorking),
            new AccessibleNode(
                "shell.shutdown-prompt.quit",
                AccessibleRole.Button,
                Text("shutdown-prompt.quit.name"),
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 2,
                commandId: ShellCommandIds.ShutdownQuit),
        ]));
}
