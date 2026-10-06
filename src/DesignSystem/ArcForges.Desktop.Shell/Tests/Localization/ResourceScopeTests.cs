// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Resources;
using ArcForges.Desktop.Shell.Accessibility;
using ArcForges.Desktop.Shell.Localization;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests.Localization;

public sealed class ResourceScopeTests
{
    private const string BaseName = "ArcForges.Desktop.Shell.Tests.Localization.ResourceScopeStrings";
    private static ShellResourceScope Scope() => new(BaseName, typeof(ResourceScopeTests).Assembly);

    [Fact]
    public void ExactEmbeddedBindingRefusesUnavailableResourcesAndDoesNotFallBackToShellKeys()
    {
        Assert.Throws<ArgumentNullException>(() => new ShellResourceScope(BaseName, null!));
        Assert.Throws<ArgumentException>(() => new ShellResourceScope(" ../bad", typeof(ResourceScopeTests).Assembly));
        Assert.Throws<MissingManifestResourceException>(() => new ShellResourceScope(BaseName, typeof(ShellText).Assembly));
        Assert.Throws<MissingManifestResourceException>(() => new ShellResourceScope(BaseName + ".absent", typeof(ResourceScopeTests).Assembly));
        ShellResourceScope scope = Scope();
        Assert.Equal("Assistant history", scope.Resolve(new LocalizedText("module.name"), CultureInfo.InvariantCulture));
        Assert.Equal("Module settings", scope.Resolve(new LocalizedText("settings.name")));
        Assert.NotEqual(scope.Resolve(new LocalizedText("settings.name")), ShellText.Resolve(new LocalizedText("settings.name")));
        Assert.Throws<InvalidOperationException>(() => scope.Resolve(new LocalizedText("workspace.window.name")));
        Assert.Throws<ArgumentNullException>(() => scope.Resolve(null!));
    }

    [Fact]
    public void MissingBlankInvalidAndThrowingResourcesNeverReturnFallbackOrSensitiveArguments()
    {
        ShellResourceScope scope = Scope();
        foreach (string key in new[] { "module.absent", "module.blank" })
        {
            Assert.Throws<InvalidOperationException>(() => scope.Resolve(new LocalizedText(key)));
        }

        Assert.Throws<FormatException>(() => scope.Resolve(new LocalizedText("module.invalid")));
        Assert.Throws<FormatException>(() => scope.Resolve(new LocalizedText("module.argument")));
        Assert.Throws<InvalidOperationException>(() => scope.Resolve(new LocalizedText("module.argument", new Dictionary<string, object?> { ["value"] = "   " })));
        FormatException error = Assert.Throws<FormatException>(() => scope.Resolve(new LocalizedText("module.invalid", new Dictionary<string, object?> { ["count"] = "private-secret" })));
        Assert.DoesNotContain("private-secret", error.Message, StringComparison.Ordinal);
        Assert.Throws<FormatException>(() => scope.Resolve(new LocalizedText("module.argument", new Dictionary<string, object?> { ["value"] = new InvalidValue() })));
        using IDisposable marker = ShellText.BeginPseudoLocalisation();
        Assert.Throws<InvalidOperationException>(() => scope.Resolve(new LocalizedText("module.argument", new Dictionary<string, object?> { ["value"] = "   " })));
    }

    [Fact]
    public void ActualCulturePluralPseudoAndRightToLeftUseTheSharedPolicy()
    {
        ShellResourceScope scope = Scope();
        var number = new LocalizedText("module.number", new Dictionary<string, object?> { ["value"] = 12.5m });
        Assert.Equal("Measured 12,5", scope.Resolve(number, CultureInfo.GetCultureInfo("de-DE")));
        Assert.Equal("Measured 12.5", scope.Resolve(number, CultureInfo.InvariantCulture));
        var count = new LocalizedText("module.count", new Dictionary<string, object?> { ["count"] = 3L });
        Assert.Equal("few messages", scope.Resolve(count, CultureInfo.GetCultureInfo("ru")));
        Assert.Equal("3 messages", scope.Resolve(count, CultureInfo.GetCultureInfo("en-US")));
        Assert.Equal(FlowDirection.RightToLeft, FlowDirections.FromCulture(CultureInfo.GetCultureInfo("ar")));
        string normal = scope.Resolve(new LocalizedText("module.name"), CultureInfo.GetCultureInfo("ar"));
        using (ShellText.BeginPseudoLocalisation())
        {
            Assert.Equal(PseudoLocaliser.Transform(normal), scope.Resolve(new LocalizedText("module.name"), CultureInfo.GetCultureInfo("ar")));
            Assert.NotEqual(normal, scope.Resolve(new LocalizedText("module.name")));
        }

        Assert.Equal(normal, scope.Resolve(new LocalizedText("module.name"), CultureInfo.GetCultureInfo("ar")));
    }

    [Fact]
    public async Task PseudoScopeDoesNotLeakBetweenConcurrentOwners()
    {
        ShellResourceScope scope = Scope();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<string> pseudo = Task.Run(async () =>
        {
            using IDisposable marker = ShellText.BeginPseudoLocalisation();
            entered.SetResult();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken).ConfigureAwait(true);
            return scope.Resolve(new LocalizedText("module.name"));
        });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken).ConfigureAwait(true);
        Assert.Equal("Assistant history", scope.Resolve(new LocalizedText("module.name")));
        release.SetResult();
        Assert.Equal(PseudoLocaliser.Transform("Assistant history"), await pseudo.ConfigureAwait(true));
    }

    [Fact]
    public void ResourceBoundAuditUsesActualModuleNamesAndRefusesEveryLookupFailure()
    {
        ShellResourceScope scope = Scope();
        static ShellSurface Surface(string key) => new("module.surface", new AccessibleNode("module.root", AccessibleRole.Region, new LocalizedText(key)));
        Assert.Empty(ShellAccessibilityAudit.Evaluate(scope, [Surface("module.name")], CultureInfo.GetCultureInfo("ar")));
        Assert.Contains(ShellAccessibilityAudit.Evaluate([Surface("module.name")]), finding => finding.Rule == AccessibilityRules.Text);
        Assert.Empty(ShellAccessibilityAudit.Evaluate(ShellSurfaceCatalog.All, null));
        foreach (string key in new[] { "module.absent", "module.blank", "module.invalid", "module.argument" })
        {
            Assert.Contains(ShellAccessibilityAudit.Evaluate(scope, [Surface(key)]), finding => finding.Rule == AccessibilityRules.Text);
        }

        Assert.Throws<ArgumentNullException>(() => ShellAccessibilityAudit.Evaluate(null!, [Surface("module.name")], null));
        Assert.Throws<ArgumentNullException>(() => ShellAccessibilityAudit.Evaluate(scope, null!));
        using IDisposable marker = ShellText.BeginPseudoLocalisation();
        Assert.Empty(ShellAccessibilityAudit.Evaluate(scope, [Surface("module.name")]));
    }

    private sealed class InvalidValue : IFormattable
    {
        public string ToString(string? format, IFormatProvider? formatProvider) => throw new FormatException("The value cannot be formatted.");
    }

    [Fact]
    public void PseudoAndRepeatedPlaceholdersFormatEachStatefulValueExactlyOnceWithoutTransformingUserText()
    {
        ShellResourceScope scope = Scope();
        var value = new StatefulValue();
        var text = new LocalizedText("module.repeated", new Dictionary<string, object?> { ["value"] = value });
        using IDisposable marker = ShellText.BeginPseudoLocalisation();
        string rendered = scope.Resolve(text);
        Assert.Equal(1, value.Calls);
        Assert.True(PseudoLocaliser.IsWholePseudoMessage(rendered));
        Assert.Contains("Ada / Ada", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("Á", rendered, StringComparison.Ordinal);
    }

    [Fact]
    public void FormatExceptionFromActualValueCannotDiscloseItsSecretThroughMessageInnerExceptionOrAudit()
    {
        ShellResourceScope scope = Scope();
        var text = new LocalizedText("module.argument", new Dictionary<string, object?> { ["value"] = new SecretValue() });
        foreach (bool pseudo in new[] { false, true })
        {
            using IDisposable? marker = pseudo ? ShellText.BeginPseudoLocalisation() : null;
            FormatException error = Assert.Throws<FormatException>(() => scope.Resolve(text));
            Assert.DoesNotContain("private-secret", error.ToString(), StringComparison.Ordinal);
            Assert.Null(error.InnerException);
            var surface = new ShellSurface("module.surface", new AccessibleNode("module.root", AccessibleRole.Region, text));
            var findings = ShellAccessibilityAudit.Evaluate(scope, [surface]);
            Assert.Contains(findings, finding => finding.Rule == AccessibilityRules.Text);
            Assert.All(findings, finding => Assert.DoesNotContain("private-secret", finding.Message, StringComparison.Ordinal));
        }
    }

    private sealed class StatefulValue : IFormattable
    {
        internal int Calls { get; private set; }
        public string ToString(string? format, IFormatProvider? formatProvider) => ++Calls == 1 ? "Ada" : "   ";
    }

    private sealed class SecretValue : IFormattable
    {
        public string ToString(string? format, IFormatProvider? formatProvider) => throw new FormatException("private-secret");
    }
}
