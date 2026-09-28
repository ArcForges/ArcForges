// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;
using ArcForges.DesignSystem;

namespace ArcForges.DesignSystem.Tests;

public sealed partial class DesignTokenTests
{
    [Xunit.Fact]
    public void EveryThemeProvidesSemanticColorsAndMeetsContrastTargets()
    {
        foreach (var theme in Enum.GetValues<ThemeMode>())
        {
            var palette = DesignTokens.Get(theme, DensityMode.Comfortable).Colors;
            var surfaces = new[] { palette.Canvas, palette.Surface, palette.ElevatedSurface };

            foreach (var surface in surfaces)
            {
                AssertContrast(theme, "primary text", palette.TextPrimary, surface, minimum: 4.5);
                AssertContrast(theme, "secondary text", palette.TextSecondary, surface, minimum: 4.5);
                AssertContrast(theme, "disabled text", palette.TextDisabled, surface, minimum: 4.5);
            }

            AssertContrast(theme, "accent label", palette.OnAccent, palette.Accent, minimum: 4.5);
            AssertContrast(theme, "danger label", palette.OnDanger, palette.Danger, minimum: 4.5);
            AssertContrast(theme, "warning label", palette.OnWarning, palette.Warning, minimum: 4.5);
            AssertContrast(theme, "success label", palette.OnSuccess, palette.Success, minimum: 4.5);
            AssertContrast(theme, "information label", palette.OnInformational, palette.Informational, minimum: 4.5);
            AssertContrast(theme, "focus ring", palette.FocusRing, palette.Canvas, minimum: 3.0);
        }
    }

    [Xunit.Fact]
    public void DensityModesHaveDistinctStableLayoutSnapshots()
    {
        var expected = new Dictionary<DensityMode, DensityTokens>
        {
            [DensityMode.Comfortable] = new(36, 40, 24, 24, 12),
            [DensityMode.Compact] = new(30, 32, 16, 16, 8),
            [DensityMode.ProfessionalDense] = new(24, 28, 12, 12, 6),
        };

        foreach (var density in Enum.GetValues<DensityMode>())
        {
            Xunit.Assert.Equal(expected[density], DesignTokens.Get(ThemeMode.Light, density).Measurements);
        }

        Xunit.Assert.Equal(3, expected.Values.Distinct().Count());
    }

    [Xunit.Fact]
    public void SemanticScalesIncludeTabularNumbersAndRestrainedMotion()
    {
        var tokens = DesignTokens.Get(ThemeMode.Dark, DensityMode.ProfessionalDense);

        Xunit.Assert.True(tokens.Typography.TabularNumber.UsesTabularFigures);
        Xunit.Assert.Equal(FontFamilyToken.Numeric, tokens.Typography.TabularNumber.Family);
        Xunit.Assert.False(tokens.Typography.Body.UsesTabularFigures);
        Xunit.Assert.Equal(tokens.Typography.TabularNumber, tokens.Typography.For(TypographyRole.TabularNumber));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => tokens.Typography.For((TypographyRole)99));
        Xunit.Assert.True(tokens.Spacing.Roomy > tokens.Spacing.Section);
        Xunit.Assert.True(tokens.Shape.Dialog > tokens.Shape.Control);
        Xunit.Assert.True(tokens.Elevation.Overlay.BlurRadius > tokens.Elevation.Raised.BlurRadius);
        Xunit.Assert.True(tokens.Motion.Fast > TimeSpan.Zero);
        Xunit.Assert.True(tokens.Motion.Fast < tokens.Motion.Standard);
        Xunit.Assert.True(tokens.Motion.Standard < tokens.Motion.Emphasized);
        Xunit.Assert.Equal(TimeSpan.Zero, tokens.Motion.Resolve(MotionDuration.Fast, MotionPreference.Reduced));
        Xunit.Assert.Equal(tokens.Motion.Emphasized, tokens.Motion.Resolve(MotionDuration.Emphasized, MotionPreference.Standard));
        Xunit.Assert.Equal(MotionCurve.Emphasized, tokens.Motion.CurveFor(MotionDuration.Emphasized));
        Xunit.Assert.Equal(7, Enum.GetValues<TypographyRole>().Length);
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => tokens.Motion.Resolve((MotionDuration)99, MotionPreference.Standard));
    }

    [Xunit.Fact]
    public void ComponentMarkupPolicyRejectsLiteralColorsAndMeasurements()
    {
        Xunit.Assert.True(HasRawVisualValue("<Border Background=\"#1A2B3C\" />"));
        Xunit.Assert.True(HasRawVisualValue("<TextBlock FontSize=\"14\" />"));
        Xunit.Assert.True(HasRawVisualValue("<StackPanel Margin=\"4, 8\" />"));
        Xunit.Assert.False(HasRawVisualValue("<Border Background=\"{DynamicResource Surface}\" Padding=\"{StaticResource PanelPadding}\" />"));
    }

    [Xunit.Fact]
    public void ExistingDesignSystemComponentMarkupContainsNoRawVisualValues()
    {
        var directory = FindSolutionRoot();
        var designSystem = Path.Combine(directory, "src", "DesignSystem");
        var violations = Directory.Exists(designSystem)
            ? Directory.EnumerateFiles(designSystem, "*.*", SearchOption.AllDirectories)
                .Where(static path => Path.GetExtension(path) is ".axaml" or ".xaml")
                .SelectMany(static path => File.ReadAllLines(path)
                    .Select((line, index) => (path, index: index + 1, line))
                    .Where(static entry => HasRawVisualValue(entry.line)))
                .Select(entry => $"{Path.GetRelativePath(directory, entry.path)}:{entry.index}: {entry.line.Trim()}")
                .ToArray()
            : ["src/DesignSystem does not exist"];

        Xunit.Assert.Empty(violations);
    }

    [Xunit.Theory]
    [Xunit.InlineData((ThemeMode)99, DensityMode.Comfortable)]
    [Xunit.InlineData(ThemeMode.Light, (DensityMode)99)]
    public void UnknownThemeOrDensityIsRejected(ThemeMode theme, DensityMode density)
    {
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => DesignTokens.Get(theme, density));
    }

    private static bool HasRawVisualValue(string markup)
        => RawColor().IsMatch(markup) || RawDimension().IsMatch(markup);

    private static void AssertContrast(ThemeMode theme, string role, RgbaColor foreground, RgbaColor background, double minimum)
    {
        var ratio = ColorContrast.Ratio(foreground, background);
        Xunit.Assert.True(ratio >= minimum, $"{theme} {role} contrast was {ratio:F2}:1; minimum is {minimum:F1}:1.");
    }

    private static string FindSolutionRoot()
    {
        for (var current = new DirectoryInfo(AppContext.BaseDirectory); current is not null; current = current.Parent)
        {
            if (File.Exists(Path.Combine(current.FullName, "DesktopPlatform.slnx")))
            {
                return current.FullName;
            }
        }

        throw new DirectoryNotFoundException("Could not locate DesktopPlatform.slnx from the test output directory.");
    }

    [GeneratedRegex("""(?<![\w])#(?:[0-9A-Fa-f]{3,4}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})(?![\w])|\b(?:rgb|rgba|hsl|hsla)\s*\(""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RawColor();

    [GeneratedRegex("""\b(?:FontSize|Width|Height|MinWidth|MinHeight|MaxWidth|MaxHeight|Margin|Padding|Spacing|CornerRadius|ColumnSpacing|RowSpacing|HorizontalSpacing|VerticalSpacing|BorderThickness)\s*=\s*(["'])(?:\s*-?\d+(?:\.\d+)?(?:\s*,\s*-?\d+(?:\.\d+)?){0,3}\s*)\1""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RawDimension();
}
