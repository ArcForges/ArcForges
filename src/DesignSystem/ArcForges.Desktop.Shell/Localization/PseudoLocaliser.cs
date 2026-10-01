// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;

namespace ArcForges.Desktop.Shell.Localization;

/// <summary>
/// Produces a deterministic pseudo-locale rendering of a message pattern so that hard-coded strings, truncation and
/// concatenation are visible before any real translation exists (LO-04). Letters gain accents, the text expands to
/// approximate longer languages, and exactly one start and one end marker wraps each whole message. A literal that was
/// never routed through a resource lacks the markers; two fragments joined by a program show a marker in the middle;
/// a clipped control loses the end marker. Placeholders, plural syntax and escapes are preserved, so a pseudo pattern
/// still formats.
/// </summary>
public static class PseudoLocaliser
{
    /// <summary>The marker that opens every pseudo-localised message.</summary>
    public const char StartMarker = '⟦';

    /// <summary>The marker that closes every pseudo-localised message.</summary>
    public const char EndMarker = '⟧';

    private const string Source = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Accented = "åƃçðéƒĝĥîĵķļɱñöþǫŗšţûṽŵẋýž" +
        "ÅƁÇÐÉƑĜĤÎĴĶĻṀÑÖÞǪŖŠŢÛṼŴẊÝŽ";

    /// <summary>Transforms <paramref name="message"/> (a message pattern) into its pseudo-localised form.</summary>
    public static string Transform(string message)
    {
        ArgumentNullException.ThrowIfNull(message);
        MessagePattern pattern = MessagePattern.Parse(message);
        var output = new StringBuilder();
        int visibleLetters = 0;
        Emit(output, pattern.Nodes, ref visibleLetters);

        // Roughly 35 percent expansion so layouts and accessible names are exercised with longer text.
        int padding = (visibleLetters * 35 + 99) / 100;
        output.Insert(0, StartMarker);
        output.Append('~', padding);
        output.Append(EndMarker);
        return output.ToString();
    }

    /// <summary>Returns true when <paramref name="text"/> is exactly one whole pseudo-localised message.</summary>
    public static bool IsWholePseudoMessage(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return text.Length >= 2 &&
            text[0] == StartMarker &&
            text[^1] == EndMarker &&
            text.Count(static character => character == StartMarker) == 1 &&
            text.Count(static character => character == EndMarker) == 1;
    }

    private static void Emit(StringBuilder output, IReadOnlyList<MessageNode> nodes, ref int visibleLetters)
    {
        foreach (MessageNode node in nodes)
        {
            switch (node)
            {
                case TextNode text:
                    foreach (char character in text.Text)
                    {
                        int index = Source.IndexOf(character, StringComparison.Ordinal);
                        if (index >= 0)
                        {
                            output.Append(Accented[index]);
                            visibleLetters++;
                        }
                        else if (character is '{' or '}')
                        {
                            output.Append(character, 2);
                        }
                        else
                        {
                            output.Append(character);
                        }
                    }

                    break;
                case ArgumentNode argument:
                    output.Append('{').Append(argument.Name).Append('}');
                    // Argument values are unknown at transform time; budget a short value.
                    visibleLetters += 6;
                    break;
                case NumberNode:
                    output.Append('#');
                    break;
                case PluralNode plural:
                    output.Append('{').Append(plural.Name).Append(", plural,");
                    foreach (PluralBranch branch in plural.Branches)
                    {
                        output.Append(' ').Append(branch.Selector).Append(" {");
                        Emit(output, branch.Body, ref visibleLetters);
                        output.Append('}');
                    }

                    output.Append('}');
                    break;
                default:
                    throw MessagePattern.Invalid();
            }
        }
    }
}
