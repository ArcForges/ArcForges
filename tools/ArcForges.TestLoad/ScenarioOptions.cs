// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.TestLoad;

/// <summary>An invalid command line; the tool exits with <see cref="ExitCodes.Usage"/>.</summary>
internal sealed class UsageException(string message) : Exception(message);

/// <summary>
/// Parses <c>--name value</c> options and records every resolved value (including defaults), so the
/// canonical parameter text identifies the workload exactly.
/// </summary>
internal sealed class ScenarioOptions
{
    private readonly Dictionary<string, string> _given = new(StringComparer.Ordinal);
    private readonly SortedDictionary<string, string> _resolved = new(StringComparer.Ordinal);
    private readonly HashSet<string> _hidden = new(StringComparer.Ordinal);

    private ScenarioOptions()
    {
    }

    public static ScenarioOptions Parse(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var options = new ScenarioOptions();
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

            if (!options._given.TryAdd(name[2..], arguments[i + 1]))
            {
                throw new UsageException($"Option '{name}' is given more than once.");
            }
        }

        return options;
    }

    /// <summary>The resolved public parameters, ordered by name.</summary>
    public IReadOnlyDictionary<string, string> Parameters =>
        _resolved.Where(pair => !_hidden.Contains(pair.Key)).ToDictionary(StringComparer.Ordinal);

    /// <summary>Canonical text of the resolved public parameters (<c>name=value;...</c>).</summary>
    public string Canonical(string scenario) =>
        $"{scenario};" + string.Join(';', Parameters.Select(pair => $"{pair.Key}={pair.Value}"));

    public long GetInt64(string name, long defaultValue, long minimum, long maximum, bool hidden = false)
    {
        var value = defaultValue;
        if (_given.TryGetValue(name, out var text)
            && !long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value))
        {
            throw new UsageException($"Option '--{name}' needs a whole number, found '{text}'.");
        }

        if (value < minimum || value > maximum)
        {
            throw new UsageException(
                string.Create(CultureInfo.InvariantCulture, $"Option '--{name}' must be between {minimum} and {maximum}, found {value}."));
        }

        Record(name, value.ToString(CultureInfo.InvariantCulture), hidden);
        return value;
    }

    public ulong GetSeed(string name = "seed")
    {
        ulong value = 1;
        if (_given.TryGetValue(name, out var text)
            && !ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value))
        {
            throw new UsageException($"Option '--{name}' needs a whole number, found '{text}'.");
        }

        Record(name, value.ToString(CultureInfo.InvariantCulture), hidden: false);
        return value;
    }

    public string GetChoice(string name, string defaultValue, params string[] choices)
    {
        var value = _given.GetValueOrDefault(name, defaultValue);
        if (!choices.Contains(value, StringComparer.Ordinal))
        {
            throw new UsageException($"Option '--{name}' must be one of {string.Join(", ", choices)}, found '{value}'.");
        }

        Record(name, value, hidden: false);
        return value;
    }

    /// <summary>An optional text parameter, recorded (and passed to child processes) only when given.</summary>
    public string? GetOptional(string name)
    {
        if (!_given.TryGetValue(name, out var value))
        {
            return null;
        }

        Record(name, value, hidden: false);
        return value;
    }

    /// <summary>A free-text option that does not identify the workload (for example a report path).</summary>
    public string? GetUnrecorded(string name)
    {
        if (!_given.TryGetValue(name, out var value))
        {
            return null;
        }

        _hidden.Add(name);
        _resolved[name] = value;
        return value;
    }

    /// <summary>Rejects options that no scenario parameter consumed.</summary>
    public void EnsureAllUsed()
    {
        var unknown = _given.Keys.Where(name => !_resolved.ContainsKey(name)).Order(StringComparer.Ordinal).ToList();
        if (unknown.Count > 0)
        {
            throw new UsageException($"Unknown option(s): {string.Join(", ", unknown.Select(name => "--" + name))}.");
        }
    }

    private void Record(string name, string value, bool hidden)
    {
        _resolved[name] = value;
        if (hidden)
        {
            _hidden.Add(name);
        }
    }
}
