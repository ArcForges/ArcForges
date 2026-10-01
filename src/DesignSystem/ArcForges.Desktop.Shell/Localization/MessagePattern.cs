// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;

namespace ArcForges.Desktop.Shell.Localization;

/// <summary>
/// Parsed form of a localisable message. The grammar is a deliberately small ICU subset:
/// <c>{name}</c>, <c>{name, plural, one {# item} other {# items}}</c> with an optional <c>=N</c> exact selector,
/// <c>#</c> inside a plural branch, and <c>{{</c> / <c>}}</c> as literal braces. A sentence is therefore one
/// resource with named parameters and plural branches instead of concatenated fragments (BR-07, LO-03).
/// </summary>
internal sealed class MessagePattern
{
    internal const int MaximumPatternLength = 4096;
    private const int MaximumDepth = 3;
    private const int MaximumBranches = 8;

    private MessagePattern(IReadOnlyList<MessageNode> nodes)
    {
        Nodes = nodes;
    }

    internal IReadOnlyList<MessageNode> Nodes { get; }

    internal static MessagePattern Parse(string pattern)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        if (pattern.Length > MaximumPatternLength)
        {
            throw Invalid();
        }

        var parser = new Parser(pattern);
        IReadOnlyList<MessageNode> nodes = parser.ParseSequence(0, insideBranch: false);
        if (!parser.AtEnd)
        {
            throw Invalid();
        }

        return new MessagePattern(nodes);
    }

    internal static FormatException Invalid() => new("The message pattern is not valid.");

    private sealed class Parser(string text)
    {
        private int _position;

        internal bool AtEnd => _position >= text.Length;

        internal List<MessageNode> ParseSequence(int depth, bool insideBranch)
        {
            if (depth > MaximumDepth)
            {
                throw Invalid();
            }

            var nodes = new List<MessageNode>();
            var literal = new StringBuilder();

            void Flush()
            {
                if (literal.Length > 0)
                {
                    nodes.Add(new TextNode(literal.ToString()));
                    literal.Clear();
                }
            }

            while (_position < text.Length)
            {
                char current = text[_position];
                if (current == '{')
                {
                    if (Peek(1) == '{')
                    {
                        literal.Append('{');
                        _position += 2;
                        continue;
                    }

                    Flush();
                    _position++;
                    nodes.Add(ParseArgument(depth));
                    continue;
                }

                if (current == '}')
                {
                    if (Peek(1) == '}' && !insideBranch)
                    {
                        literal.Append('}');
                        _position += 2;
                        continue;
                    }

                    if (insideBranch)
                    {
                        break;
                    }

                    throw Invalid();
                }

                if (current == '#' && insideBranch)
                {
                    Flush();
                    nodes.Add(NumberNode.Instance);
                    _position++;
                    continue;
                }

                literal.Append(current);
                _position++;
            }

            Flush();
            return nodes;
        }

        private MessageNode ParseArgument(int depth)
        {
            string name = ReadUntil(',', '}').Trim();
            if (!ShellMessageFormatter.IsArgumentName(name) || AtEnd)
            {
                throw Invalid();
            }

            if (text[_position] == '}')
            {
                _position++;
                return new ArgumentNode(name);
            }

            _position++;
            string kind = ReadUntil(',', '}').Trim();
            if (!string.Equals(kind, "plural", StringComparison.Ordinal) || AtEnd || text[_position] != ',')
            {
                throw Invalid();
            }

            _position++;
            var branches = new List<PluralBranch>();
            while (true)
            {
                SkipWhitespace();
                if (AtEnd)
                {
                    throw Invalid();
                }

                if (text[_position] == '}')
                {
                    _position++;
                    break;
                }

                int start = _position;
                while (_position < text.Length && !char.IsWhiteSpace(text[_position]) && text[_position] != '{' && text[_position] != '}')
                {
                    _position++;
                }

                string selector = text[start.._position];
                SkipWhitespace();
                if (!IsSelector(selector) || AtEnd || text[_position] != '{' || branches.Count >= MaximumBranches)
                {
                    throw Invalid();
                }

                _position++;
                IReadOnlyList<MessageNode> body = ParseSequence(depth + 1, insideBranch: true);
                if (AtEnd || text[_position] != '}')
                {
                    throw Invalid();
                }

                _position++;
                if (branches.Any(existing => string.Equals(existing.Selector, selector, StringComparison.Ordinal)))
                {
                    throw Invalid();
                }

                branches.Add(new PluralBranch(selector, body));
            }

            if (!branches.Any(static branch => branch.Selector == "other"))
            {
                throw Invalid();
            }

            return new PluralNode(name, branches);
        }

        private static bool IsSelector(string selector)
        {
            if (selector is "zero" or "one" or "two" or "few" or "many" or "other")
            {
                return true;
            }

            return selector.Length is > 1 and <= 10 &&
                selector[0] == '=' &&
                selector.AsSpan(1).IndexOfAnyExceptInRange('0', '9') < 0;
        }

        private string ReadUntil(char first, char second)
        {
            int start = _position;
            while (_position < text.Length && text[_position] != first && text[_position] != second && text[_position] != '{')
            {
                _position++;
            }

            if (_position < text.Length && text[_position] == '{')
            {
                throw Invalid();
            }

            return text[start.._position];
        }

        private void SkipWhitespace()
        {
            while (_position < text.Length && char.IsWhiteSpace(text[_position]))
            {
                _position++;
            }
        }

        private char Peek(int offset) => _position + offset < text.Length ? text[_position + offset] : '\0';
    }
}

internal abstract record MessageNode;

internal sealed record TextNode(string Text) : MessageNode;

internal sealed record ArgumentNode(string Name) : MessageNode;

internal sealed record NumberNode : MessageNode
{
    internal static readonly NumberNode Instance = new();
}

internal sealed record PluralBranch(string Selector, IReadOnlyList<MessageNode> Body);

internal sealed record PluralNode(string Name, IReadOnlyList<PluralBranch> Branches) : MessageNode;

/// <summary>CLDR plural categories for the integer counts the shell formats.</summary>
internal enum PluralCategory
{
    Zero,
    One,
    Two,
    Few,
    Many,
    Other,
}

/// <summary>
/// A compact table of CLDR integer plural rules for language families whose category sets differ structurally
/// (single-form, one/other, Slavic, Arabic). Unlisted languages use the English-style one/other default, which is
/// the CLDR rule for most of them; adding a shipped locale adds its row and a test.
/// </summary>
internal static class PluralRules
{
    internal static PluralCategory Select(CultureInfo culture, long count)
    {
        ArgumentNullException.ThrowIfNull(culture);
        long n = count == long.MinValue ? long.MaxValue : Math.Abs(count);
        string language = culture.TwoLetterISOLanguageName;
        long mod10 = n % 10;
        long mod100 = n % 100;
        return language switch
        {
            "ja" or "zh" or "ko" or "vi" or "th" or "id" or "ms" => PluralCategory.Other,
            "fr" or "pt" => n is 0 or 1 ? PluralCategory.One : PluralCategory.Other,
            "ru" or "uk" or "be" => (mod10, mod100) switch
            {
                (1, not 11) => PluralCategory.One,
                (2 or 3 or 4, not (12 or 13 or 14)) => PluralCategory.Few,
                _ => PluralCategory.Many,
            },
            "ar" => n switch
            {
                0 => PluralCategory.Zero,
                1 => PluralCategory.One,
                2 => PluralCategory.Two,
                _ when mod100 is >= 3 and <= 10 => PluralCategory.Few,
                _ when mod100 is >= 11 and <= 99 => PluralCategory.Many,
                _ => PluralCategory.Other,
            },
            _ => n == 1 ? PluralCategory.One : PluralCategory.Other,
        };
    }

    internal static string Name(PluralCategory category) => category switch
    {
        PluralCategory.Zero => "zero",
        PluralCategory.One => "one",
        PluralCategory.Two => "two",
        PluralCategory.Few => "few",
        PluralCategory.Many => "many",
        _ => "other",
    };
}
