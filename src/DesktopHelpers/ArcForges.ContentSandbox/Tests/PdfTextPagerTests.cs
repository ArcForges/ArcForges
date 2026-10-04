// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.ContentSandbox.Host;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using Xunit;
using Check = ArcForges.Contracts.LocalRpc.Sandbox.SandboxProfile;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>Pagination of page text into bounded chunks: UTF-16 positions, surrogate pairs, box coverage, progress and the response bound.</summary>
public sealed class PdfTextPagerTests
{
    private static PdfPageText Page(string text, params (uint Start, uint Length)[] boxes)
    {
        var list = boxes.Select(box => new SandboxTextBox { Start = box.Start, Length = box.Length, X = 0, Y = 0, Width = 1, Height = 1 }).ToList();
        return new PdfPageText(text, list);
    }

    private static string Emoji(int count) => string.Concat(Enumerable.Repeat(char.ConvertFromUtf32(0x1F600), count));

    [Fact]
    public void ASmallPageIsOneChunkWithoutANextPosition()
    {
        var chunk = PdfTextPager.Cut(0, 0, Page("hello world", (0, 5), (6, 5)), 1024, 60 * 1024)!;
        Assert.Equal("hello world", chunk.Text);
        Assert.False(chunk.HasNext);
        Assert.Equal(2, chunk.Boxes.Count);
        Assert.True(Check.IsValid(chunk));
    }

    [Fact]
    public void AnEmptyPageIsAnEmptyChunk()
    {
        var chunk = PdfTextPager.Cut(3, 0, Page(string.Empty), 1024, 60 * 1024)!;
        Assert.Equal(string.Empty, chunk.Text);
        Assert.False(chunk.HasNext);
        Assert.Equal(3u, chunk.PageIndex);
    }

    [Fact]
    public void ALongPageIsPaginatedWithProgressAndNoLossAndEveryChunkIsValid()
    {
        var text = string.Concat(Enumerable.Range(0, 20000).Select(i => "w" + i + " ")) + Emoji(5000);
        var boxes = new List<(uint, uint)>();
        var position = 0;
        foreach (var word in text.Split(' '))
        {
            if (word.Length > 0 && !char.IsHighSurrogate(word[0]))
            {
                boxes.Add(((uint)position, (uint)word.Length));
            }

            position += word.Length + 1;
        }

        var page = Page(text, [.. boxes]);
        var rebuilt = new StringBuilder();
        uint start = 0;
        var chunks = 0;
        while (true)
        {
            var chunk = PdfTextPager.Cut(0, start, page, 1024, 60 * 1024)!;
            Assert.NotNull(chunk);
            Assert.True(Check.IsValid(chunk), "chunk " + chunks);
            Assert.True(chunk.CalculateSize() <= 64 * 1024);
            Assert.True(chunk.Boxes.Count <= 1024);
            Assert.Equal(start, chunk.Start);
            _ = rebuilt.Append(chunk.Text);
            chunks++;
            if (!chunk.HasNext)
            {
                break;
            }

            Assert.True(chunk.Next > start);
            start = chunk.Next;
            Assert.True(chunks < 100000);
        }

        Assert.Equal(text, rebuilt.ToString());
        Assert.True(chunks > 3);
    }

    [Fact]
    public void ACutNeverSplitsASurrogatePair()
    {
        var text = new string('a', 16 * 1024 - 1) + Emoji(4);
        var first = PdfTextPager.Cut(0, 0, Page(text), 1024, 60 * 1024)!;
        Assert.True(first.HasNext);
        Assert.False(char.IsLowSurrogate(text[(int)first.Next]));
        Assert.False(char.IsHighSurrogate(first.Text[^1]));
        Assert.True(Check.IsValid(first));
    }

    [Fact]
    public void AStartInTheMiddleOfAPairOrPastTheEndIsRefused()
    {
        var text = "ab" + Emoji(2);
        Assert.Null(PdfTextPager.Cut(0, 3, Page(text), 1024, 60 * 1024));
        Assert.Null(PdfTextPager.Cut(0, (uint)text.Length + 1, Page(text), 1024, 60 * 1024));
        Assert.NotNull(PdfTextPager.Cut(0, 2, Page(text), 1024, 60 * 1024));
    }

    [Fact]
    public void OnlyBoxesWhollyInsideTheChunkAreCarried()
    {
        var text = new string('a', 20000);
        var chunk = PdfTextPager.Cut(0, 0, Page(text, (0, 10), (16380, 20), (19000, 10)), 1024, 60 * 1024)!;
        Assert.True(chunk.HasNext);
        Assert.All(chunk.Boxes, box => Assert.True(box.Start + box.Length <= chunk.Next));
        Assert.True(Check.IsValid(chunk));
    }

    [Fact]
    public void TheBoxBoundCutsTheChunkAndStillMakesProgress()
    {
        var text = string.Concat(Enumerable.Repeat("ab ", 100));
        var boxes = Enumerable.Range(0, 100).Select(i => ((uint)(i * 3), 2u)).ToArray();
        var chunk = PdfTextPager.Cut(0, 0, Page(text, boxes), 10, 60 * 1024)!;
        Assert.Equal(10, chunk.Boxes.Count);
        Assert.True(chunk.HasNext);
        Assert.True(chunk.Next > 0);
        Assert.Null(PdfTextPager.Cut(0, 0, Page("ab", (0, 1), (0, 1)), 0, 60 * 1024));
    }

    [Fact]
    public void AByteBoundTooSmallForOneCharacterRefusesInsteadOfLooping() =>
        Assert.Null(PdfTextPager.Cut(0, 0, Page("abc"), 1024, 4));
}
