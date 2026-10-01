// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Desktop.Shell.Localization;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests.Localization;

public sealed class MessageFormatterTests
{
    private const string ItemPattern = "{count, plural, =0 {No items} one {# item} other {# items}}";

    [Fact]
    public void FormatSubstitutesNamedArgumentsAndSelectsPluralBranchesWithLocaleNumbers()
    {
        CultureInfo english = CultureInfo.GetCultureInfo("en-US");
        CultureInfo german = CultureInfo.GetCultureInfo("de-DE");

        Assert.Equal("Hello Ada", ShellMessageFormatter.Format("Hello {name}", Args(("name", "Ada")), english));
        Assert.Equal("No items", ShellMessageFormatter.Format(ItemPattern, Args(("count", 0)), english));
        Assert.Equal("1 item", ShellMessageFormatter.Format(ItemPattern, Args(("count", 1)), english));
        Assert.Equal("5 items", ShellMessageFormatter.Format(ItemPattern, Args(("count", 5)), english));
        Assert.Equal("1,234 items", ShellMessageFormatter.Format(ItemPattern, Args(("count", 1234)), english));
        Assert.Equal("1.234 items", ShellMessageFormatter.Format(ItemPattern, Args(("count", 1234L)), german));

        // A translator may reorder words because the sentence is one pattern with named parameters.
        Assert.Equal(
            "Ada owns 3 items.",
            ShellMessageFormatter.Format("{name} owns {count, plural, one {# item} other {# items}}.", Args(("name", "Ada"), ("count", 3)), english));
        Assert.Equal(
            "3 items belong to Ada.",
            ShellMessageFormatter.Format("{count, plural, one {# item belongs} other {# items belong}} to {name}.", Args(("name", "Ada"), ("count", 3)), english));
    }

    [Fact]
    public void EscapedBracesAreLiteralAndNestedArgumentsWorkInsideBranches()
    {
        CultureInfo culture = CultureInfo.InvariantCulture;

        Assert.Equal("{literal} and }", ShellMessageFormatter.Format("{{literal}} and }}", null, culture));
        Assert.Equal(
            "2 files for Ada",
            ShellMessageFormatter.Format("{count, plural, one {# file for {name}} other {# files for {name}}}", Args(("count", 2), ("name", "Ada")), culture));
    }

    [Theory]
    [InlineData("en", 0L, "other")]
    [InlineData("en", 1L, "one")]
    [InlineData("en", 2L, "other")]
    [InlineData("fr", 0L, "one")]
    [InlineData("fr", 2L, "other")]
    [InlineData("ja", 1L, "other")]
    [InlineData("ru", 1L, "one")]
    [InlineData("ru", 21L, "one")]
    [InlineData("ru", 11L, "many")]
    [InlineData("ru", 3L, "few")]
    [InlineData("ru", 13L, "many")]
    [InlineData("ru", 5L, "many")]
    [InlineData("ar", 0L, "zero")]
    [InlineData("ar", 1L, "one")]
    [InlineData("ar", 2L, "two")]
    [InlineData("ar", 7L, "few")]
    [InlineData("ar", 11L, "many")]
    [InlineData("ar", 100L, "other")]
    public void PluralCategoriesFollowTheLanguageFamilyRules(string language, long count, string expected)
    {
        const string pattern = "{n, plural, zero {zero} one {one} two {two} few {few} many {many} other {other}}";
        CultureInfo culture = CultureInfo.GetCultureInfo(language);

        Assert.Equal(expected, ShellMessageFormatter.Format(pattern, Args(("n", count)), culture));
    }

    [Fact]
    public void InvalidPatternsAndArgumentsFailClosedWithoutEchoingValues()
    {
        CultureInfo culture = CultureInfo.InvariantCulture;
        const string secret = "C:\\private\\token.txt";

        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format("Hello {name}", null, culture));
        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format("Hello {name}", Args(("name", null)), culture));
        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format("Hello {name", Args(("name", secret)), culture));
        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format("Hello name}", null, culture));
        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format("{n, plural, one {x}}", Args(("n", 1)), culture));
        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format("{n, plural, one {x} one {y} other {z}}", Args(("n", 1)), culture));
        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format("{n, select, other {x}}", Args(("n", 1)), culture));
        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format("{1bad}", Args(("1bad", 1)), culture));
        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format("{n, plural, other {{a, plural, other {{b, plural, other {{c, plural, other {x}}}}}}}}", Args(("n", 1), ("a", 1), ("b", 1), ("c", 1)), culture));
        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format(new string('a', MessagePattern.MaximumPatternLength + 1), null, culture));

        FormatException notAnInteger = Assert.Throws<FormatException>(() => ShellMessageFormatter.Format(ItemPattern, Args(("count", secret)), culture));
        Assert.DoesNotContain(secret, notAnInteger.Message, StringComparison.Ordinal);
        Assert.Throws<FormatException>(() => ShellMessageFormatter.Format(ItemPattern, Args(("count", 1.5m)), culture));
        Assert.Throws<ArgumentNullException>(() => ShellMessageFormatter.Format(null!, null, culture));
        Assert.Throws<ArgumentNullException>(() => ShellMessageFormatter.Format("x", null, null!));
    }

    [Fact]
    public void LocalizedTextValidatesKeysAndArgumentNamesAndCopiesArguments()
    {
        var source = new Dictionary<string, object?>(StringComparer.Ordinal) { ["count"] = 2 };
        var text = new LocalizedText("surface.example.name", source);
        source["count"] = 99;

        Assert.Equal(2, text.Arguments["count"]);
        Assert.Empty(new LocalizedText("surface.example.name").Arguments);
        Assert.Throws<ArgumentException>(() => new LocalizedText("Not A Key"));
        Assert.Throws<ArgumentException>(() => new LocalizedText("trailing."));
        Assert.Throws<ArgumentException>(() => new LocalizedText("surface.example.name", new Dictionary<string, object?> { ["1bad"] = 1 }));
    }

    private static Dictionary<string, object?> Args(params (string Name, object? Value)[] arguments) =>
        arguments.ToDictionary(static pair => pair.Name, static pair => pair.Value, StringComparer.Ordinal);
}
