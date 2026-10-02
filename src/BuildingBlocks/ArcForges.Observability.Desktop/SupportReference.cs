// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.Observability.Desktop;

/// <summary>
/// The support reference identifier of a diagnostic report (observability architecture DG-07): a random,
/// non-derived value a user can quote in a support case without attaching any data.
/// </summary>
internal static class SupportReference
{
    private const string Prefix = "ARC-";
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private const int Groups = 3;
    private const int GroupLength = 4;

    internal static string Create()
    {
        Span<byte> random = stackalloc byte[Groups * GroupLength];
        RandomNumberGenerator.Fill(random);
        Span<char> text = stackalloc char[Prefix.Length + (Groups * GroupLength) + (Groups - 1)];
        Prefix.CopyTo(text);
        int position = Prefix.Length;
        for (int group = 0; group < Groups; group++)
        {
            if (group > 0)
            {
                text[position++] = '-';
            }

            for (int index = 0; index < GroupLength; index++)
            {
                text[position++] = Alphabet[random[(group * GroupLength) + index] & 31];
            }
        }

        return new string(text);
    }

    internal static bool IsValid(string? value)
    {
        if (value is null || value.Length != Prefix.Length + (Groups * GroupLength) + (Groups - 1)
            || !value.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        int position = Prefix.Length;
        for (int group = 0; group < Groups; group++)
        {
            if (group > 0 && value[position++] != '-')
            {
                return false;
            }

            for (int index = 0; index < GroupLength; index++)
            {
                if (!Alphabet.Contains(value[position++], StringComparison.Ordinal))
                {
                    return false;
                }
            }
        }

        return true;
    }
}
