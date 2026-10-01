// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Desktop.Shell.Accessibility;
using ArcForges.Desktop.Shell.Commands;
using ArcForges.Desktop.Shell.Errors;
using ArcForges.Desktop.Shell.Localization;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests.Accessibility;

/// <summary>
/// Keyboard-only workflows driven over the real shell models (command palette, attention model, error presenter) and
/// the focus contract. No UI framework, window or pointer is involved, so these prove the contract a UI adapter must
/// honour, not any adapter's rendering; assistive-technology behaviour of a real adapter is verified manually.
/// </summary>
public sealed class KeyboardOnlyWorkflowTests
{
    private static readonly CultureInfo Culture = CultureInfo.InvariantCulture;

    [Fact]
    public void ARegisteredCommandIsRunFromTheKeyboardThroughThePaletteWithAnnouncedResults()
    {
        var palette = new ShellCommandPalette(new AlwaysAvailableProvider());
        ShellCommand open = Command("workspace.open", "Open workspace", "shell.action.workspace.open", new CommandShortcut("k", CommandShortcutModifiers.Control));
        ShellCommand reopen = Command("workspace.reopen", "Reopen recent workspace", "shell.action.workspace.reopen");
        ShellCommand save = Command("workspace.save", "Save workspace", "shell.action.workspace.save");
        Assert.True(palette.TryRegister(open));
        Assert.True(palette.TryRegister(reopen));
        Assert.True(palette.TryRegister(save));

        // A shortcut is a second keyboard path that needs no pointer and no palette.
        Assert.True(palette.TryResolveShortcut(new CommandShortcut("K", CommandShortcutModifiers.Control), out ShellCommand? viaShortcut));
        Assert.Equal(open, viaShortcut);

        var navigator = new FocusNavigator(ShellSurfaceCatalog.WorkspaceSurface);
        Assert.Equal(ShellCommandIds.PaletteOpen, navigator.Activate());
        Assert.True(navigator.OpenModal(ShellSurfaceCatalog.CommandPaletteSurface));
        Assert.Equal("shell.command-palette.query", navigator.CurrentId);

        // The user types a query; the adapter rebuilds the result list from the palette and announces the count.
        IReadOnlyList<ShellCommand> results = palette.SearchPalette("open");
        Assert.Equal([open, reopen], results);
        Assert.Equal("2 commands match", ShellText.Resolve(new LocalizedText("command-palette.result-count.name", Count(results.Count)), Culture));
        Assert.Equal("No commands match", ShellText.Resolve(new LocalizedText("command-palette.result-count.name", Count(palette.SearchPalette("zzz").Count)), Culture));

        ShellSurface live = PaletteWith(results);
        Assert.Empty(ShellAccessibilityAudit.Evaluate([live], Culture));
        var typing = new FocusNavigator(ShellSurfaceCatalog.WorkspaceSurface);
        Assert.True(typing.OpenModal(live));
        Assert.True(typing.MoveNext());
        Assert.Equal("shell.command-palette.result-0", typing.CurrentId);
        Assert.True(typing.Move(FocusDirection.Down));
        Assert.Equal("shell.command-palette.result-1", typing.CurrentId);
        Assert.Equal(ShellCommandIds.PaletteRunSelected, typing.Activate());
        Assert.Equal(ShellCommandIds.PaletteClose, typing.Dismiss());
        Assert.Equal("shell.workspace.palette-button", typing.CurrentId);

        // Every registered command is reachable through the palette alone, so none is pointer-only.
        Assert.Equal(palette.Snapshot().Count, palette.SearchPalette(string.Empty, 64).Count);
        Assert.All(palette.Snapshot(), command => Assert.Contains(command, palette.SearchPalette(string.Empty, 64)));
        Assert.Equal(ShellCommandIds.PaletteClose, navigator.Dismiss());
    }

    [Fact]
    public void ADurableAttentionItemStaysReachableByKeyboardAfterAMissedNotificationUntilItsOwnerResolvesIt()
    {
        var model = new AttentionModel();
        var approval = new AttentionItem("approval-17", "Access approval required", "Review the requested project access.", AttentionDurability.Durable);
        bool delivered = model.Publish(approval, static _ => false);
        Assert.False(delivered);

        ShellSurface surface = AttentionWith(model.Snapshot());
        Assert.Empty(ShellAccessibilityAudit.Evaluate([surface], Culture));

        var navigator = new FocusNavigator(surface);
        Assert.Equal("shell.attention.item-0", navigator.CurrentId);
        Assert.Equal(ShellCommandIds.AttentionOpenItem, navigator.Activate());
        Assert.Equal("Access approval required", ShellText.Resolve(new LocalizedText("attention.item.name", new Dictionary<string, object?> { ["title"] = approval.Title }), Culture));

        Assert.True(model.RemoveResolved(approval.Id));
        FocusNavigator afterResolution = new(AttentionWith(model.Snapshot()));
        Assert.Equal("shell.attention.items", afterResolution.CurrentId);
        Assert.Null(afterResolution.Activate());
    }

    [Fact]
    public void AFailureDialogIsCompletedAndDismissedByKeyboardWithFocusRestoredToItsOrigin()
    {
        var presentation = ErrorPresenter.Present(TypedFailure.Create("perm.resource_denied"));
        Assert.False(string.IsNullOrWhiteSpace(presentation.WhatHappened));
        Assert.True(Guid.TryParseExact(presentation.SupportReferenceId, "D", out _));

        var navigator = new FocusNavigator(ShellSurfaceCatalog.AttentionSurface);
        string origin = navigator.CurrentId!;
        Assert.True(navigator.OpenModal(ShellSurfaceCatalog.ErrorSurface));

        Assert.Equal("shell.error-dialog.copy", navigator.CurrentId);
        Assert.Equal(ShellCommandIds.ErrorCopyReference, navigator.Activate());
        Assert.True(navigator.MoveNext());
        Assert.Equal(ShellCommandIds.ErrorRetry, navigator.Activate());
        Assert.True(navigator.MoveNext());
        Assert.Equal("shell.error-dialog.close", navigator.CurrentId);
        Assert.Equal(ShellCommandIds.ErrorClose, navigator.Activate());

        // Escape and the Close button reach the same dismissal, and focus returns to where the user was.
        Assert.Equal(ShellCommandIds.ErrorClose, navigator.Dismiss());
        Assert.Equal(origin, navigator.CurrentId);
    }

    private static ShellSurface PaletteWith(IReadOnlyList<ShellCommand> results)
    {
        AccessibleNode template = ShellSurfaceCatalog.CommandPaletteSurface.Root;
        AccessibleNode query = template.Children[0];
        AccessibleNode list = template.Children[1];
        AccessibleNode count = template.Children[2];
        AccessibleNode close = template.Children[3];
        AccessibleNode[] items = results
            .Select(static (command, index) => new AccessibleNode(
                $"shell.command-palette.result-{index}",
                AccessibleRole.ListItem,
                new LocalizedText("command-palette.result.name", new Dictionary<string, object?> { ["title"] = command.Title }),
                keyboard: KeyboardAccess.Roving,
                commandId: ShellCommandIds.PaletteRunSelected,
                stateCues: StateCues.Colour | StateCues.Shape))
            .ToArray();
        var rebuiltList = new AccessibleNode(list.Id, list.Role, list.Name, keyboard: list.Keyboard, focusOrder: list.FocusOrder, children: items);
        return new ShellSurface(
            "shell.command-palette",
            new AccessibleNode(template.Id, template.Role, template.Name, isModal: true, dismissCommandId: template.DismissCommandId, children: [query, rebuiltList, count, close]));
    }

    private static ShellSurface AttentionWith(IReadOnlyList<AttentionItem> items)
    {
        AccessibleNode template = ShellSurfaceCatalog.AttentionSurface.Root;
        AccessibleNode live = template.Children[0];
        AccessibleNode list = template.Children[1];
        AccessibleNode open = template.Children[2];
        AccessibleNode[] rows = items
            .Select(static (item, index) => new AccessibleNode(
                $"shell.attention.item-{index}",
                AccessibleRole.ListItem,
                new LocalizedText("attention.item.name", new Dictionary<string, object?> { ["title"] = item.Title }),
                keyboard: KeyboardAccess.Roving,
                commandId: ShellCommandIds.AttentionOpenItem,
                stateCues: StateCues.Colour | StateCues.Text | StateCues.Icon))
            .ToArray();
        var rebuiltList = new AccessibleNode(list.Id, list.Role, list.Name, keyboard: list.Keyboard, focusOrder: list.FocusOrder, children: rows);
        return new ShellSurface("shell.attention", new AccessibleNode(template.Id, template.Role, template.Name, children: [live, rebuiltList, open]));
    }

    private static Dictionary<string, object?> Count(int count) => new() { ["count"] = count };

    private static ShellCommand Command(string id, string title, string actionKey, CommandShortcut? shortcut = null) =>
        new(id, title, new ActionKey(actionKey), shortcut: shortcut);

    private sealed class AlwaysAvailableProvider : ICapabilityProvider
    {
        bool ICapabilityProvider.IsBoundToCapability(ActionKey actionKey, string capabilityKey) => false;

        ValueTask<Outcome<AvailabilityResult>> ICapabilityProvider.EvaluateAvailabilityAsync(
            ActionKey actionKey,
            FrozenContextSnapshot context,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(Outcome.Success(AvailabilityResult.Available));
    }
}
