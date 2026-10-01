// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Desktop.Shell.Accessibility;
using ArcForges.Desktop.Shell.Localization;
using ArcForges.Desktop.Shell.Tests.Localization;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests.Accessibility;

/// <summary>The focus contract as executable behaviour: order, roving groups, right-to-left mirroring, trap and restore (AX-01, AX-02).</summary>
public sealed class FocusNavigatorTests
{
    private static readonly LocalizedText Named = new("settings.name");

    [Fact]
    public void TabAndShiftTabVisitEveryTabStopInFocusOrderAndWrap()
    {
        var navigator = new FocusNavigator(ShellSurfaceCatalog.WorkspaceSurface);
        string[] expected =
        [
            "shell.workspace.palette-button",
            "shell.workspace.attention-button",
            "shell.workspace.settings-button",
            "shell.workspace.panel-start.toggle",
            "shell.workspace.splitter-start",
            "shell.workspace.splitter-end",
            "shell.workspace.panel-end.toggle",
            "shell.workspace.panel-bottom.toggle",
        ];

        var visited = new List<string?> { navigator.CurrentId };
        for (int index = 1; index < expected.Length; index++)
        {
            Assert.True(navigator.MoveNext());
            visited.Add(navigator.CurrentId);
        }

        Assert.Equal(expected, visited);

        Assert.True(navigator.MoveNext());
        Assert.Equal(expected[0], navigator.CurrentId);
        Assert.True(navigator.MovePrevious());
        Assert.Equal(expected[^1], navigator.CurrentId);
        Assert.Equal("shell.workspace", navigator.ActiveSurfaceId);
        Assert.False(navigator.IsModalOpen);
    }

    [Fact]
    public void FocusIsAlwaysOnAVisibleElementAndEmptySurfacesHaveNone()
    {
        var empty = new FocusNavigator(new ShellSurface("test.empty", new AccessibleNode("test.empty", AccessibleRole.Region, Named)));
        var single = new FocusNavigator(new ShellSurface("test.single", new AccessibleNode(
            "test.single",
            AccessibleRole.Region,
            Named,
            children: [new AccessibleNode("test.single.only", AccessibleRole.Button, Named, keyboard: KeyboardAccess.TabStop, focusOrder: 1, commandId: "test.run")])));

        Assert.Null(empty.CurrentId);
        Assert.False(empty.MoveNext());
        Assert.False(empty.Move(FocusDirection.Down));
        Assert.Null(empty.Activate());
        Assert.Null(empty.Dismiss());

        Assert.Equal("test.single.only", single.CurrentId);
        Assert.False(single.MoveNext());
        Assert.False(single.MovePrevious());
        Assert.Equal("test.single.only", single.CurrentId);
        Assert.Equal("test.run", single.Activate());
    }

    [Fact]
    public void ArrowKeysMoveInsideARovingGroupWithoutWrappingAndKeepTheGroupAsOneTabStop()
    {
        var navigator = new FocusNavigator(ShellSurfaceCatalog.SettingsSurface);
        Assert.Equal("shell.settings.search", navigator.CurrentId);

        Assert.True(navigator.MoveNext());
        Assert.Equal("shell.settings.scope.application", navigator.CurrentId);
        Assert.False(navigator.Move(FocusDirection.Up));
        Assert.False(navigator.Move(FocusDirection.Left));
        Assert.True(navigator.Move(FocusDirection.Down));
        Assert.Equal("shell.settings.scope.workspace", navigator.CurrentId);
        Assert.True(navigator.Move(FocusDirection.Down));
        Assert.True(navigator.Move(FocusDirection.Down));
        Assert.Equal("shell.settings.scope.instance", navigator.CurrentId);
        Assert.False(navigator.Move(FocusDirection.Down));
        Assert.True(navigator.Move(FocusDirection.Up));
        Assert.Equal("shell.settings.scope.device", navigator.CurrentId);

        // Leaving and returning by Tab lands on the remembered item: the group is a single tab stop.
        Assert.True(navigator.MoveNext());
        Assert.Equal("shell.settings.reset", navigator.CurrentId);
        Assert.True(navigator.MovePrevious());
        Assert.Equal("shell.settings.scope.device", navigator.CurrentId);
        Assert.Throws<ArgumentOutOfRangeException>(() => navigator.Move((FocusDirection)99));
    }

    [Theory]
    [InlineData(FlowDirection.LeftToRight, FocusDirection.Right, FocusDirection.Left)]
    [InlineData(FlowDirection.RightToLeft, FocusDirection.Left, FocusDirection.Right)]
    public void HorizontalGroupsAdvanceInTheReadingDirectionAndIgnoreVerticalKeys(FlowDirection flow, FocusDirection forward, FocusDirection backward)
    {
        var surface = new ShellSurface("test.tabs", new AccessibleNode(
            "test.tabs",
            AccessibleRole.Region,
            Named,
            children:
            [
                new AccessibleNode(
                    "test.tabs.strip",
                    AccessibleRole.List,
                    Named,
                    keyboard: KeyboardAccess.TabStop,
                    focusOrder: 1,
                    orientation: NavigationOrientation.Horizontal,
                    children:
                    [
                        new AccessibleNode("test.tabs.first", AccessibleRole.ListItem, Named, keyboard: KeyboardAccess.Roving),
                        new AccessibleNode("test.tabs.second", AccessibleRole.ListItem, Named, keyboard: KeyboardAccess.Roving),
                        new AccessibleNode("test.tabs.third", AccessibleRole.ListItem, Named, keyboard: KeyboardAccess.Roving),
                    ]),
            ]));
        var navigator = new FocusNavigator(surface, flow);

        Assert.Equal("test.tabs.first", navigator.CurrentId);
        Assert.False(navigator.Move(FocusDirection.Down));
        Assert.False(navigator.Move(FocusDirection.Up));
        Assert.False(navigator.Move(backward));
        Assert.True(navigator.Move(forward));
        Assert.Equal("test.tabs.second", navigator.CurrentId);
        Assert.True(navigator.Move(forward));
        Assert.False(navigator.Move(forward));
        Assert.Equal("test.tabs.third", navigator.CurrentId);
        Assert.True(navigator.Move(backward));
        Assert.Equal("test.tabs.second", navigator.CurrentId);
        Assert.Throws<ArgumentOutOfRangeException>(() => new FocusNavigator(surface, (FlowDirection)99));
    }

    [Fact]
    public void ModalSurfaceTrapsFocusAndDismissRestoresTheOriginatingElement()
    {
        var navigator = new FocusNavigator(ShellSurfaceCatalog.WorkspaceSurface);
        Assert.Equal("shell.workspace.palette-button", navigator.CurrentId);
        Assert.Equal(ShellCommandIds.PaletteOpen, navigator.Activate());

        Assert.True(navigator.OpenModal(ShellSurfaceCatalog.CommandPaletteSurface));
        Assert.True(navigator.IsModalOpen);
        Assert.Equal("shell.command-palette", navigator.ActiveSurfaceId);
        Assert.Equal("shell.command-palette.query", navigator.CurrentId);

        // Tab cycles only through the modal's own stops; nothing behind it can take focus.
        var inside = new HashSet<string?> { navigator.CurrentId };
        for (int index = 0; index < 8; index++)
        {
            Assert.True(navigator.MoveNext());
            inside.Add(navigator.CurrentId);
        }

        Assert.All(inside, static id => Assert.StartsWith("shell.command-palette.", id, StringComparison.Ordinal));
        Assert.Equal(3, inside.Count);

        Assert.Equal(ShellCommandIds.PaletteClose, navigator.Dismiss());
        Assert.False(navigator.IsModalOpen);
        Assert.Equal("shell.workspace", navigator.ActiveSurfaceId);
        Assert.Equal("shell.workspace.palette-button", navigator.CurrentId);
        Assert.Null(navigator.Dismiss());
    }

    [Fact]
    public void FocusReturnsToTheOriginEvenWhenItWasAnotherTabStopOrNestedModalsAreOpen()
    {
        var navigator = new FocusNavigator(ShellSurfaceCatalog.WorkspaceSurface);
        navigator.MoveNext();
        navigator.MoveNext();
        Assert.Equal("shell.workspace.settings-button", navigator.CurrentId);

        Assert.True(navigator.OpenModal(ShellSurfaceCatalog.CommandPaletteSurface));
        navigator.MoveNext();
        Assert.Equal("shell.command-palette.result", navigator.CurrentId);
        Assert.True(navigator.OpenModal(ShellSurfaceCatalog.ErrorSurface));
        Assert.Equal("shell.error-dialog.copy", navigator.CurrentId);

        Assert.Equal(ShellCommandIds.ErrorClose, navigator.Dismiss());
        Assert.Equal("shell.command-palette.result", navigator.CurrentId);
        Assert.Equal(ShellCommandIds.PaletteClose, navigator.Dismiss());
        Assert.Equal("shell.workspace.settings-button", navigator.CurrentId);
    }

    [Fact]
    public void RovingOriginIsRestoredAndNonModalOrEmptyModalsAreRefused()
    {
        var navigator = new FocusNavigator(ShellSurfaceCatalog.AttentionSurface);
        Assert.Equal("shell.attention.item", navigator.CurrentId);

        Assert.False(navigator.OpenModal(ShellSurfaceCatalog.SettingsSurface));
        var hollow = new ShellSurface("test.hollow", new AccessibleNode(
            "test.hollow",
            AccessibleRole.Dialog,
            Named,
            isModal: true,
            dismissCommandId: "test.close"));
        Assert.False(navigator.OpenModal(hollow));
        Assert.False(navigator.IsModalOpen);

        Assert.True(navigator.OpenModal(ShellSurfaceCatalog.ErrorSurface));
        Assert.Equal(ShellCommandIds.ErrorClose, navigator.Dismiss());
        Assert.Equal("shell.attention.item", navigator.CurrentId);
        Assert.Equal(ShellCommandIds.AttentionOpenItem, navigator.Activate());
        Assert.Throws<ArgumentNullException>(() => new FocusNavigator(null!));
        Assert.Throws<ArgumentNullException>(() => navigator.OpenModal(null!));
    }

    [Fact]
    public void EveryInteractiveElementOfEverySurfaceIsReachableWithTheKeyboardAlone()
    {
        foreach (ShellSurface surface in ShellSurfaceCatalog.All)
        {
            var reachable = new HashSet<string>(StringComparer.Ordinal);
            var navigator = new FocusNavigator(surface);
            int stops = PseudoLocalisationTests.Flatten(surface.Root).Count(static node => node.Keyboard == KeyboardAccess.TabStop);

            for (int step = 0; step <= stops + 1; step++)
            {
                if (navigator.CurrentId is { } id)
                {
                    reachable.Add(id);
                }

                while (navigator.Move(FocusDirection.Down) || navigator.Move(FocusDirection.Right))
                {
                    reachable.Add(navigator.CurrentId!);
                }

                navigator.MoveNext();
            }

            string[] unreachable = PseudoLocalisationTests.Flatten(surface.Root)
                .Where(static node => node.Keyboard == KeyboardAccess.Roving ||
                    (node.Keyboard == KeyboardAccess.TabStop && !node.Children.Any(static child => child.Keyboard == KeyboardAccess.Roving)))
                .Select(static node => node.Id)
                .Where(id => !reachable.Contains(id))
                .ToArray();

            Assert.Empty(unreachable);
        }
    }
}
