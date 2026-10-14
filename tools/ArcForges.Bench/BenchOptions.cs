// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Bench;

/// <summary>An invalid command line; the tool exits with <see cref="ExitCodes.Usage"/>.</summary>
internal sealed class UsageException(string message) : Exception(message);

/// <summary>Parses <c>--name value</c> options; options listed as repeatable may occur more than once.</summary>
internal sealed class BenchOptions
{
    private readonly List<KeyValuePair<string, string>> _values = [];
    private readonly HashSet<string> _used = new(StringComparer.Ordinal);

    private BenchOptions()
    {
    }

    public static BenchOptions Parse(IReadOnlyList<string> arguments, params string[] repeatable)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var options = new BenchOptions();
        for (var i = 0; i < arguments.Count; i += 2)
        {
            var name = arguments[i];
            if (!name.StartsWith("--", StringComparison.Ordinal) || name.Length < 3)
            {
                throw new UsageException($"Expected an option name, found '{name}'.");
            }

            if (i + 1 >= arguments.Count)
            {
                throw new UsageException($"Option '{name}' needs a value.");
            }

            var key = name[2..];
            if (!repeatable.Contains(key, StringComparer.Ordinal) && options._values.Any(pair => pair.Key == key))
            {
                throw new UsageException($"Option '{name}' is given more than once.");
            }

            options._values.Add(new(key, arguments[i + 1]));
        }

        return options;
    }

    public string? GetString(string name)
    {
        _used.Add(name);
        return _values.LastOrDefault(pair => pair.Key == name).Value;
    }

    public string GetRequired(string name) =>
        GetString(name) ?? throw new UsageException($"Option '--{name}' is required.");

    public IReadOnlyList<string> GetAll(string name)
    {
        _used.Add(name);
        return _values.Where(pair => pair.Key == name).Select(pair => pair.Value).ToList();
    }

    public long? GetInt64(string name, long minimum, long maximum)
    {
        var text = GetString(name);
        if (text is null)
        {
            return null;
        }

        if (!long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value < minimum || value > maximum)
        {
            throw new UsageException(
                string.Create(CultureInfo.InvariantCulture, $"Option '--{name}' must be a whole number between {minimum} and {maximum}, found '{text}'."));
        }

        return value;
    }

    public double? GetDouble(string name, double minimum, double maximum)
    {
        var text = GetString(name);
        if (text is null)
        {
            return null;
        }

        if (!double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var value) || value < minimum || value > maximum)
        {
            throw new UsageException(
                string.Create(CultureInfo.InvariantCulture, $"Option '--{name}' must be a number between {minimum} and {maximum}, found '{text}'."));
        }

        return value;
    }

    public void EnsureAllUsed()
    {
        var unknown = _values.Select(pair => pair.Key).Where(name => !_used.Contains(name)).Distinct().ToList();
        if (unknown.Count > 0)
        {
            throw new UsageException($"Unknown option(s): {string.Join(", ", unknown.Select(name => "--" + name))}.");
        }
    }
}
