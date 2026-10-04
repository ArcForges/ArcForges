// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.LocalRpc.Sandbox.V1;

namespace ArcForges.ContentSandbox.Host;

/// <summary>
/// Cuts the text of a page into the bounded chunks of annex 09 section 5: positions are zero-based UTF-16 offsets, a chunk never splits a
/// surrogate pair, a chunk carries only the boxes that lie wholly inside it, the whole message stays under the response bound, and every chunk
/// of a non-empty remainder makes progress. Truncation is always explicit pagination through the next position.
/// </summary>
internal static class PdfTextPager
{
    private const int FirstTry = 16 * 1024;

    /// <summary>
    /// The chunk of <paramref name="page"/> that starts at <paramref name="start"/>, or null when <paramref name="start"/> is not a position
    /// a chunk can start at or no bounded chunk exists.
    /// </summary>
    internal static SandboxPdfText? Cut(uint pageIndex, uint start, PdfPageText page, uint maxBoxes, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(page);
        var text = page.Text;
        var length = text.Length;
        if (start > length || (start > 0 && start < length && char.IsLowSurrogate(text[(int)start]) && char.IsHighSurrogate(text[(int)start - 1])))
        {
            return null;
        }

        var first = (int)start;
        var end = (int)Math.Min((long)length, (long)first + FirstTry);
        while (true)
        {
            end = StayOnBoundary(text, first, end);
            var boxes = BoxesWithin(page.Boxes, start, (uint)end);
            if (boxes.Count > maxBoxes)
            {
                var cut = (int)boxes[(int)maxBoxes].Start;
                if (cut <= first)
                {
                    return null;
                }

                end = cut;
                continue;
            }

            var chunk = new SandboxPdfText
            {
                PageIndex = pageIndex,
                Start = start,
                Text = text.Substring(first, end - first),
            };
            if (end < length)
            {
                chunk.Next = (uint)end;
            }

            chunk.Boxes.AddRange(boxes);
            if (chunk.CalculateSize() <= maxBytes)
            {
                return chunk;
            }

            if (end - first <= 1)
            {
                return null;
            }

            end = first + Math.Max(1, (end - first) / 2);
        }
    }

    private static int StayOnBoundary(string text, int start, int end)
    {
        if (end < text.Length && end > start && char.IsLowSurrogate(text[end]) && char.IsHighSurrogate(text[end - 1]))
        {
            end--;
        }

        if (end == start && start < text.Length)
        {
            end = start + (char.IsHighSurrogate(text[start]) && start + 1 < text.Length && char.IsLowSurrogate(text[start + 1]) ? 2 : 1);
        }

        return end;
    }

    private static List<SandboxTextBox> BoxesWithin(IReadOnlyList<SandboxTextBox> boxes, uint start, uint end)
    {
        var result = new List<SandboxTextBox>();
        foreach (var box in boxes)
        {
            if (box.Start >= start && (ulong)box.Start + box.Length <= end)
            {
                result.Add(box.Clone());
            }
        }

        return result;
    }
}
