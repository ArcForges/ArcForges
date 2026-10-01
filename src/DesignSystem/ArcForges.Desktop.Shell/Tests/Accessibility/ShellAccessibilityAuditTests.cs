// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Desktop.Shell.Accessibility;
using ArcForges.Desktop.Shell.Localization;
using ArcForges.Desktop.Shell.Tests.Localization;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests.Accessibility;

/// <summary>Offline automated accessibility checks over shell surface declarations (AX-01 to AX-05, BR-05).</summary>
public sealed class ShellAccessibilityAuditTests
{
    private static readonly LocalizedText Named = new("settings.name");

    [Fact]
    public void EveryShellSurfaceConformsToTheAccessibilityContractInNeutralAndPseudoLocales()
    {
        Assert.Equal(6, ShellSurfaceCatalog.All.Count);
        Assert.Equal(
            ["shell.workspace", "shell.command-palette", "shell.settings", "shell.attention", "shell.error-dialog", "shell.shutdown-prompt"],
            ShellSurfaceCatalog.All.Select(static surface => surface.Id));

        foreach (string culture in new[] { "", "en-US", "de-DE", "ar" })
        {
            Assert.Empty(ShellAccessibilityAudit.Evaluate(ShellSurfaceCatalog.All, CultureInfo.GetCultureInfo(culture)));
        }

        using IDisposable pseudo = ShellText.BeginPseudoLocalisation();
        Assert.Empty(ShellAccessibilityAudit.Evaluate(ShellSurfaceCatalog.All, CultureInfo.InvariantCulture));
    }

    [Fact]
    public void CatalogExposesRoleNameKeyboardPathAndStateCuesForEveryInteractiveElement()
    {
        var nodes = ShellSurfaceCatalog.All.SelectMany(static surface => PseudoLocalisationTests.Flatten(surface.Root)).ToArray();

        Assert.True(nodes.Length > 40);
        foreach (AccessibleNode node in nodes)
        {
            if (node.Role != AccessibleRole.Group)
            {
                Assert.NotNull(node.Name);
            }

            if (node.Keyboard == KeyboardAccess.TabStop)
            {
                Assert.NotNull(node.FocusOrder);
            }

            if (node.IsIconOnly)
            {
                Assert.NotNull(node.Name);
                Assert.False(string.IsNullOrWhiteSpace(ShellText.Resolve(node.Name!, CultureInfo.InvariantCulture)));
            }

            if (node.StateCues.HasFlag(StateCues.Colour))
            {
                Assert.NotEqual(StateCues.None, node.StateCues & ~StateCues.Colour);
            }
        }

        Assert.Equal(nodes.Length, nodes.Select(static node => node.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.Contains(nodes, static node => node.IsIconOnly);
        Assert.Contains(nodes, static node => node.Live == LiveRegionPoliteness.Assertive);
        Assert.Contains(nodes, static node => node.Live == LiveRegionPoliteness.Polite);
    }

    [Fact]
    public void EveryShellSurfaceStringIsUsedAndEveryUsedKeyIsDefined()
    {
        string[] defined = PseudoLocalisationTests.AllResourceStrings()
            .Where(static entry => entry.Set == ShellText.SurfaceSet)
            .Select(static entry => entry.Key)
            .ToArray();
        string[] used = ShellSurfaceCatalog.All
            .SelectMany(static surface => PseudoLocalisationTests.Flatten(surface.Root))
            .SelectMany(static node => new[] { node.Name, node.Description })
            .OfType<LocalizedText>()
            .Select(static text => text.Key)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        Assert.Empty(used.Except(defined, StringComparer.Ordinal));
        Assert.Empty(defined.Except(used, StringComparer.Ordinal));
    }

    [Fact]
    public void AuditReportsEachContractViolationWithItsStableRule()
    {
        // Each case is a surface that violates exactly one rule; the audit must name that rule.
        (string Rule, AccessibleNode Root)[] cases =
        [
            (AccessibilityRules.Name, Root(new AccessibleNode("bad.label", AccessibleRole.Label))),
            (AccessibilityRules.IconName, Root(new AccessibleNode("bad.icon", AccessibleRole.Button, keyboard: KeyboardAccess.TabStop, focusOrder: 1, isIconOnly: true))),
            (AccessibilityRules.Keyboard, Root(new AccessibleNode("bad.pointer", AccessibleRole.Button, Named))),
            (AccessibilityRules.Command, Root(new AccessibleNode("bad.command", AccessibleRole.Label, Named, keyboard: KeyboardAccess.Command))),
            (AccessibilityRules.FocusOrder, Root(
                new AccessibleNode("bad.first", AccessibleRole.Button, Named, keyboard: KeyboardAccess.TabStop, focusOrder: 5),
                new AccessibleNode("bad.second", AccessibleRole.Button, Named, keyboard: KeyboardAccess.TabStop, focusOrder: 5))),
            (AccessibilityRules.FocusOrder, Root(new AccessibleNode("bad.unordered", AccessibleRole.Button, Named, keyboard: KeyboardAccess.TabStop))),
            (AccessibilityRules.FocusOrder, Root(new AccessibleNode("bad.stray", AccessibleRole.Label, Named, focusOrder: 3))),
            (AccessibilityRules.FocusOrder, Root(new AccessibleNode("bad.roving", AccessibleRole.ListItem, Named, keyboard: KeyboardAccess.Roving))),
            (AccessibilityRules.Dialog, new AccessibleNode("bad.dialog", AccessibleRole.Dialog, Named, children: [Stop("bad.dialog.ok", 1)])),
            (AccessibilityRules.Dialog, new AccessibleNode("bad.modal", AccessibleRole.Dialog, Named, isModal: true, children: [Stop("bad.modal.ok", 1)])),
            (AccessibilityRules.Dialog, new AccessibleNode("bad.trap", AccessibleRole.AlertDialog, Named, isModal: true, dismissCommandId: "bad.close")),
            (AccessibilityRules.LiveRegion, Root(new AccessibleNode("bad.alert", AccessibleRole.Alert, Named, live: LiveRegionPoliteness.Polite))),
            (AccessibilityRules.LiveRegion, Root(new AccessibleNode("bad.status", AccessibleRole.Status, Named))),
            (AccessibilityRules.FocusOrder, Root(new AccessibleNode(
                "bad.group",
                AccessibleRole.List,
                Named,
                keyboard: KeyboardAccess.TabStop,
                focusOrder: 1,
                children: [new AccessibleNode("bad.group.item", AccessibleRole.ListItem, Named, keyboard: KeyboardAccess.Roving, focusOrder: 2)]))),
            (AccessibilityRules.Dialog, new AccessibleNode(
                "bad.static",
                AccessibleRole.Dialog,
                Named,
                isModal: true,
                dismissCommandId: "bad.close",
                children: [new AccessibleNode("bad.static.text", AccessibleRole.Label, Named)])),
            (AccessibilityRules.Colour, Root(new AccessibleNode("bad.colour", AccessibleRole.Label, Named, stateCues: StateCues.Colour))),
            (AccessibilityRules.Text, Root(new AccessibleNode("bad.key", AccessibleRole.Label, new LocalizedText("surface.undefined.name")))),
            (AccessibilityRules.Text, Root(new AccessibleNode("bad.args", AccessibleRole.Label, new LocalizedText("workspace.attention-button.name")))),
            (AccessibilityRules.Identity, Root(
                new AccessibleNode("bad.same", AccessibleRole.Label, Named),
                new AccessibleNode("bad.same", AccessibleRole.Label, Named))),
        ];

        foreach ((string rule, AccessibleNode root) in cases)
        {
            IReadOnlyList<AccessibilityFinding> findings = ShellAccessibilityAudit.Evaluate([new ShellSurface("test.surface", root)], CultureInfo.InvariantCulture);

            Assert.Contains(findings, finding => finding.Rule == rule);
        }

        IReadOnlyList<AccessibilityFinding> duplicateSurface = ShellAccessibilityAudit.Evaluate(
            [new ShellSurface("test.same", Root()), new ShellSurface("test.same", Root())],
            CultureInfo.InvariantCulture);
        Assert.Contains(duplicateSurface, static finding => finding.Rule == AccessibilityRules.Identity && finding.NodeId == "test.root");

        IReadOnlyList<AccessibilityFinding> unknownRole = ShellAccessibilityAudit.Evaluate(
            [new ShellSurface("test.surface", Root(new AccessibleNode("bad.role", (AccessibleRole)99, Named)))],
            CultureInfo.InvariantCulture);
        Assert.Contains(unknownRole, static finding => finding.Rule == AccessibilityRules.Role);
    }

    [Fact]
    public void ConformingSurfaceProducesNoFindingsAndValidatesInputs()
    {
        var surface = new ShellSurface("test.good", new AccessibleNode(
            "test.good",
            AccessibleRole.Dialog,
            Named,
            isModal: true,
            dismissCommandId: "test.close",
            children:
            [
                new AccessibleNode("test.good.field", AccessibleRole.TextBox, Named, keyboard: KeyboardAccess.TabStop, focusOrder: 1),
                new AccessibleNode(
                    "test.good.list",
                    AccessibleRole.List,
                    Named,
                    keyboard: KeyboardAccess.TabStop,
                    focusOrder: 2,
                    children: [new AccessibleNode("test.good.item", AccessibleRole.ListItem, Named, keyboard: KeyboardAccess.Roving, stateCues: StateCues.Colour | StateCues.Text)]),
            ]));

        Assert.Empty(ShellAccessibilityAudit.Evaluate([surface], CultureInfo.InvariantCulture));
        Assert.Throws<ArgumentNullException>(() => ShellAccessibilityAudit.Evaluate(null!));
        Assert.Throws<ArgumentException>(() => ShellAccessibilityAudit.Evaluate(Enumerable.Repeat(surface, 65)));
        Assert.Throws<ArgumentException>(() => new AccessibleNode("Bad Id", AccessibleRole.Label));
        Assert.Throws<ArgumentException>(() => new AccessibleNode("ok.id", AccessibleRole.Button, commandId: "Bad Command"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AccessibleNode("ok.id", AccessibleRole.Button, focusOrder: 0));
        Assert.Throws<ArgumentException>(() => new ShellSurface("Bad Surface", surface.Root));
        Assert.Throws<ArgumentException>(() => new AccessibleNode(
            "ok.id",
            AccessibleRole.Group,
            children: Enumerable.Range(0, 65).Select(static index => new AccessibleNode($"child.{index}", AccessibleRole.Group))));
    }

    private static AccessibleNode Root(params AccessibleNode[] children) =>
        new("test.root", AccessibleRole.Region, Named, children: children);

    private static AccessibleNode Stop(string id, int order) =>
        new(id, AccessibleRole.Button, Named, keyboard: KeyboardAccess.TabStop, focusOrder: order);
}
