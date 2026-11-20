// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Client;

/// <summary>Suppresses the inner ConPTY's Win32 input negotiation only when rendering on the caller's console.</summary>
internal sealed class WindowsTerminalInputModeFilter
{
    internal const int MaxDeferredCharacters = 7;
    private const string Prefix = "\u001b[?9001";

    private int _matched;

    /// <summary>Writes to a span with room for the input plus up to seven deferred prefix characters.</summary>
    internal int Filter(ReadOnlySpan<char> text, Span<char> filtered)
    {
        if (text.IsEmpty)
        {
            return 0;
        }

        if (filtered.Length - text.Length < _matched)
        {
            throw new ArgumentException("The output span cannot hold the input and deferred prefix.", nameof(filtered));
        }

        int written = 0;
        foreach (char character in text)
        {
            if (_matched < Prefix.Length && character == Prefix[_matched])
            {
                _matched++;
                continue;
            }

            if (_matched == Prefix.Length && character is 'h' or 'l')
            {
                _matched = 0;
                continue;
            }

            if (_matched != 0)
            {
                Prefix.AsSpan(0, _matched).CopyTo(filtered[written..]);
                written += _matched;
                _matched = 0;
            }

            // A mismatch may itself start the next sequence.
            if (character == Prefix[0])
            {
                _matched = 1;
            }
            else
            {
                filtered[written++] = character;
            }
        }

        return written;
    }
}
