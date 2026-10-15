// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.CommandLine;

/// <summary>CLI durations (experience/cli.md section 1): a whole number with <c>s</c>, <c>m</c>, <c>h</c> or <c>d</c>, for example <c>90s</c>.</summary>
public static class Durations
{
    /// <summary>Parses a duration; false for anything else (zero and negative values included).</summary>
    public static bool TryParse(string? text, out TimeSpan duration)
    {
        duration = default;
        if (string.IsNullOrEmpty(text) || text.Length < 2)
        {
            return false;
        }

        var unit = char.ToLowerInvariant(text[^1]);
        if (!long.TryParse(text.AsSpan(0, text.Length - 1), NumberStyles.None, CultureInfo.InvariantCulture, out var amount) || amount <= 0
            || amount > 1_000_000)
        {
            return false;
        }

        duration = unit switch
        {
            's' => TimeSpan.FromSeconds(amount),
            'm' => TimeSpan.FromMinutes(amount),
            'h' => TimeSpan.FromHours(amount),
            'd' => TimeSpan.FromDays(amount),
            _ => TimeSpan.Zero,
        };
        return duration > TimeSpan.Zero;
    }

    /// <summary>A short relative time for human output (<c>just now</c>, <c>5 min ago</c>, <c>in 2 h</c>).</summary>
    public static string Relative(DateTimeOffset time, DateTimeOffset now)
    {
        var delta = now - time;
        var future = delta < TimeSpan.Zero;
        var span = delta.Duration();
        string text;
        if (span < TimeSpan.FromSeconds(5))
        {
            return "just now";
        }

        if (span < TimeSpan.FromMinutes(1))
        {
            text = string.Create(CultureInfo.InvariantCulture, $"{(int)span.TotalSeconds} s");
        }
        else if (span < TimeSpan.FromHours(1))
        {
            text = string.Create(CultureInfo.InvariantCulture, $"{(int)span.TotalMinutes} min");
        }
        else if (span < TimeSpan.FromDays(1))
        {
            text = string.Create(CultureInfo.InvariantCulture, $"{(int)span.TotalHours} h");
        }
        else
        {
            text = string.Create(CultureInfo.InvariantCulture, $"{(int)span.TotalDays} d");
        }

        return future ? "in " + text : text + " ago";
    }
}
