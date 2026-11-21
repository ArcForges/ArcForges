// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// Portable Windows command-line quoting, its round trip and the Windows command-line limit.
/// Generated comparisons with native argument parsing are in <see cref="CommandLineProperties"/>.
/// </summary>
public sealed class CommandLineTests
{
    /// <summary>Arguments whose quoting is easy to get wrong: spaces, quotes, backslash runs before quotes and at the end, Unicode.</summary>
    internal static readonly string[][] Corpus =
    [
        ["prog", "simple"],
        ["prog", ""],
        ["prog", "two words"],
        ["prog", "tab\there"],
        ["prog", "quote\"inside"],
        ["prog", "\"leading and trailing\""],
        ["prog", "back\\slash"],
        ["prog", "trailing\\"],
        ["prog", "trailing space\\"],
        ["prog", "\\\\server\\share\\"],
        ["prog", "a\\\"b"],
        ["prog", "a\\\\\"b"],
        ["prog", "\\\""],
        ["prog", "unicode äöü 中文 🚀"],
        ["prog", "%PATH%", "!x!", "^&|<>"],
        ["C:\\Program Files\\tool\\tool.exe", "arg"],
        ["prog", "line\nbreak"],
    ];

    /// <summary>The indexes of <see cref="Corpus"/>.</summary>
    public static TheoryData<int> QuotingCorpus => [.. Enumerable.Range(0, Corpus.Length)];

    [Theory]
    [MemberData(nameof(QuotingCorpus))]
    public void TheCommandLineParsesBackToTheArgumentVector(int index)
    {
        var argv = Corpus[index];
        var line = WindowsCommandLine.Build(argv);
        Assert.Equal(argv, WindowsCommandLine.Parse(line));
    }

    [Fact]
    public void AProgramTokenWithAQuoteIsRefused()
    {
        var refusal = Assert.Throws<CommandRefusedException>(() => WindowsCommandLine.Build(["bad\"name", "x"]));
        Assert.Equal("invalid_argument", refusal.Code);
    }

    [Fact]
    public void ACommandLineOverTheWindowsLimitIsRefused()
    {
        var refusal = Assert.Throws<CommandRefusedException>(() => WindowsCommandLine.Build(["prog", new string('x', WindowsCommandLine.MaxLength)]));
        Assert.Equal("invalid_argument", refusal.Code);
        Assert.Contains("32766", refusal.Reason.Replace(",", string.Empty, StringComparison.Ordinal), StringComparison.Ordinal);
    }
}
