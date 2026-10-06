// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;

namespace ArcForges.Desktop.Shell.Localization;

/// <summary>
/// Formats a localised message pattern with named arguments and plural branches. Callers never build a sentence
/// by concatenating fragments, so a translator can reorder words and choose the plural form for the locale.
/// </summary>
public static class ShellMessageFormatter
{
    internal const int MaximumArguments = 16;
    private const int MaximumOutputLength = 16 * 1024;

    /// <summary>Formats <paramref name="pattern"/> for <paramref name="culture"/>; invalid input fails with <see cref="FormatException"/> and never echoes argument values.</summary>
    public static string Format(string pattern, IReadOnlyDictionary<string, object?>? arguments, CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(culture);
        MessagePattern parsed = MessagePattern.Parse(pattern);
        var output = new StringBuilder();
        Append(output, parsed.Nodes, arguments, culture, pluralNumber: null);
        return output.ToString();
    }

    internal static bool IsArgumentName(string? value) =>
        !string.IsNullOrEmpty(value) &&
        value.Length <= 32 &&
        value[0] is >= 'a' and <= 'z' or >= 'A' and <= 'Z' &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '_');

    private static void Append(
        StringBuilder output,
        IReadOnlyList<MessageNode> nodes,
        IReadOnlyDictionary<string, object?>? arguments,
        CultureInfo culture,
        long? pluralNumber)
    {
        foreach (MessageNode node in nodes)
        {
            switch (node)
            {
                case TextNode text:
                    output.Append(text.Text);
                    break;
                case ArgumentNode argument:
                    output.Append(FormatValue(Lookup(arguments, argument.Name), culture));
                    break;
                case NumberNode when pluralNumber is long number:
                    output.Append(number.ToString("N0", culture));
                    break;
                case PluralNode plural:
                    AppendPlural(output, plural, arguments, culture);
                    break;
                default:
                    throw MessagePattern.Invalid();
            }

            if (output.Length > MaximumOutputLength)
            {
                throw new FormatException("The formatted message is too long.");
            }
        }
    }

    private static void AppendPlural(
        StringBuilder output,
        PluralNode plural,
        IReadOnlyDictionary<string, object?>? arguments,
        CultureInfo culture)
    {
        long count = ToCount(Lookup(arguments, plural.Name));
        string exact = "=" + count.ToString(CultureInfo.InvariantCulture);
        string category = PluralRules.Name(PluralRules.Select(culture, count));
        PluralBranch? branch =
            plural.Branches.FirstOrDefault(candidate => string.Equals(candidate.Selector, exact, StringComparison.Ordinal))
            ?? plural.Branches.FirstOrDefault(candidate => string.Equals(candidate.Selector, category, StringComparison.Ordinal))
            ?? plural.Branches.First(static candidate => string.Equals(candidate.Selector, "other", StringComparison.Ordinal));
        Append(output, branch.Body, arguments, culture, count);
    }

    private static object Lookup(IReadOnlyDictionary<string, object?>? arguments, string name)
    {
        if (arguments is null || !arguments.TryGetValue(name, out object? value) || value is null)
        {
            throw new FormatException("A required message argument is missing.");
        }

        return value;
    }

    private static long ToCount(object value) => value switch
    {
        long number => number,
        int number => number,
        short number => number,
        byte number => number,
        sbyte number => number,
        uint number => number,
        ushort number => number,
        ulong number when number <= long.MaxValue => (long)number,
        _ => throw new FormatException("A plural argument must be an integer count."),
    };

    internal static string FormatValue(object value, CultureInfo culture) => value switch
    {
        string text => text,
        IFormattable formattable => formattable.ToString(null, culture),
        _ => Convert.ToString(value, culture) ?? string.Empty,
    };
}
