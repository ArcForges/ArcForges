// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;

namespace ArcForges.Desktop.Shell.Localization;

/// <summary>
/// User-visible shell text expressed as a resource key plus named arguments, never as a literal sentence.
/// Persistent identifiers are never localised (LO-02); only the text resolved from the key is.
/// </summary>
public sealed record LocalizedText
{
    private static readonly ReadOnlyDictionary<string, object?> NoArguments =
        new(new Dictionary<string, object?>(StringComparer.Ordinal));

    public LocalizedText(string key, IReadOnlyDictionary<string, object?>? arguments = null)
    {
        if (!IsResourceKey(key))
        {
            throw new ArgumentException("A text key must be a bounded lowercase dotted resource key.", nameof(key));
        }

        Key = key;
        if (arguments is null || arguments.Count == 0)
        {
            Arguments = NoArguments;
            return;
        }

        if (arguments.Count > ShellMessageFormatter.MaximumArguments)
        {
            throw new ArgumentOutOfRangeException(nameof(arguments));
        }

        var copy = new Dictionary<string, object?>(arguments.Count, StringComparer.Ordinal);
        foreach (KeyValuePair<string, object?> argument in arguments)
        {
            if (!ShellMessageFormatter.IsArgumentName(argument.Key))
            {
                throw new ArgumentException("Argument names must be bounded ASCII identifiers.", nameof(arguments));
            }

            copy.Add(argument.Key, argument.Value);
        }

        Arguments = new ReadOnlyDictionary<string, object?>(copy);
    }

    /// <summary>The stable resource key, for example <c>surface.command-palette.name</c>.</summary>
    public string Key { get; }

    /// <summary>Named values substituted into the localised pattern; a pattern is never concatenated by callers.</summary>
    public IReadOnlyDictionary<string, object?> Arguments { get; }

    internal static bool IsResourceKey(string? value) =>
        !string.IsNullOrEmpty(value) &&
        value.Length <= 128 &&
        value[0] is >= 'a' and <= 'z' &&
        value[^1] is >= 'a' and <= 'z' or >= '0' and <= '9' &&
        value.All(static character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_');
}
