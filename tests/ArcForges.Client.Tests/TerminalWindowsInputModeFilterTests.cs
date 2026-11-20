// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;

namespace ArcForges.Client.Tests;

public sealed class TerminalWindowsInputModeFilterTests
{
    private const string Enable = "\u001b[?9001h";
    private const string Disable = "\u001b[?9001l";

    [Theory]
    [InlineData(Enable)]
    [InlineData(Disable)]
    public void DefersEveryIncompleteNegotiationPrefixUntilTheFinalCharacter(string sequence)
    {
        Assert.Equal(WindowsTerminalInputModeFilter.MaxDeferredCharacters, sequence.Length - 1);
        for (int split = 1; split < sequence.Length; split++)
        {
            var filter = new WindowsTerminalInputModeFilter();
            Assert.Equal("before", Feed(filter, "before" + sequence[..split]));
            Assert.Empty(Feed(filter, ReadOnlySpan<char>.Empty));
            Assert.Equal("星🪟", Feed(filter, sequence[split..] + "星🪟"));
        }
    }

    [Theory]
    [InlineData(Enable + Disable, "")]
    [InlineData("星" + Enable + "🪟" + Disable + "é", "星🪟é")]
    [InlineData("\u001b[?1004h" + Enable + "\u001b[?1004l", "\u001b[?1004h\u001b[?1004l")]
    [InlineData("\u001b[?9002h\u001b[?9001H\u001b[?9001;1004h", "\u001b[?9002h\u001b[?9001H\u001b[?9001;1004h")]
    [InlineData("\u001b[?9001\u001b[?1004h", "\u001b[?9001\u001b[?1004h")]
    [InlineData("\u001b" + Enable + "\u001b[?9001" + Disable + "Ω", "\u001b\u001b[?9001Ω")]
    [InlineData("\u001b[?9001d\u001b[?90010l", "\u001b[?9001d\u001b[?90010l")]
    public void RemovesOnlyExactNegotiationAcrossEveryFrameBoundary(string input, string expected)
    {
        for (int split = 0; split <= input.Length; split++)
        {
            var filter = new WindowsTerminalInputModeFilter();
            string first = Feed(filter, input.AsSpan(0, split));
            string next = Feed(filter, input.AsSpan(split));
            Assert.Equal(expected, first + next);
        }

        var streaming = new WindowsTerminalInputModeFilter();
        var observed = new StringBuilder();
        for (int index = 0; index < input.Length; index++)
        {
            observed.Append(Feed(streaming, input.AsSpan(index, 1)));
        }

        Assert.Equal(expected, observed.ToString());
    }

    private static string Feed(WindowsTerminalInputModeFilter filter, ReadOnlySpan<char> text)
    {
        Span<char> output = new char[text.Length + WindowsTerminalInputModeFilter.MaxDeferredCharacters];
        int written = filter.Filter(text, output);
        Assert.InRange(written, 0, output.Length);
        return new string(output[..written]);
    }
}
