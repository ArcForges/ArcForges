// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;

namespace ArcForges.Foundation.Versions;

/// <summary>An explicitly bounded or unbounded interval within one version axis.</summary>
public sealed class VersionRange<T> where T : struct, IVersionAxis<T>
{
    public T? Lower { get; }
    public T? Upper { get; }
    public bool IncludeLower { get; }
    public bool IncludeUpper { get; }

    public VersionRange(T? lower, bool includeLower, T? upper, bool includeUpper)
    {
        if (lower is { IsValid: false } || upper is { IsValid: false })
            throw new ArgumentException("Range boundaries must be explicit versions or null for unbounded.");
        if (lower.HasValue && upper.HasValue)
        {
            var order = lower.Value.CompareTo(upper.Value);
            if (order > 0 || (order == 0 && (!includeLower || !includeUpper)))
                throw new ArgumentException("The version interval is reversed or empty.");
        }

        Lower = lower;
        Upper = upper;
        IncludeLower = lower.HasValue && includeLower;
        IncludeUpper = upper.HasValue && includeUpper;
    }

    public bool Contains(T value)
    {
        if (!value.IsValid) return false;
        if (Lower.HasValue)
        {
            var order = value.CompareTo(Lower.Value);
            if (order < 0 || (order == 0 && !IncludeLower)) return false;
        }

        if (Upper.HasValue)
        {
            var order = value.CompareTo(Upper.Value);
            if (order > 0 || (order == 0 && !IncludeUpper)) return false;
        }

        return true;
    }

    /// <summary>Parses *, an exact value, [lower,upper) intervals, or semantic-axis 1.* / 1.2.* prefixes.</summary>
    public static VersionRange<T> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text == "*") return new(null, false, null, false);
        if (text.Length >= 3 && text[0] is '[' or '(' && text[^1] is ']' or ')')
        {
            var endpoints = text[1..^1].Split(',');
            if (endpoints.Length != 2) throw new FormatException("An interval requires two endpoints.");
            var lower = endpoints[0].Length == 0 ? (T?)null : T.Parse(endpoints[0]);
            var upper = endpoints[1].Length == 0 ? (T?)null : T.Parse(endpoints[1]);
            if ((!lower.HasValue && text[0] != '(') || (!upper.HasValue && text[^1] != ')'))
                throw new FormatException("An unbounded endpoint must be exclusive.");
            return new(lower, text[0] == '[', upper, text[^1] == ']');
        }

        if (text.EndsWith(".*", StringComparison.Ordinal))
        {
            var parts = text[..^2].Split('.');
            if (parts.Length is < 1 or > 2 || !VersionCore.TryParse(text[..^2], out var prefix) ||
                prefix.Prerelease is not null || prefix.Metadata is not null)
                throw new FormatException("A partial range requires a major or major.minor prefix.");
            var lower = T.Parse(string.Create(CultureInfo.InvariantCulture, $"{prefix.Major}.{prefix.Minor}.0"));
            T? upper;
            if (parts.Length == 1 || prefix.Minor == uint.MaxValue)
            {
                upper = prefix.Major == uint.MaxValue ? null : T.Parse(string.Create(CultureInfo.InvariantCulture, $"{prefix.Major + 1}.0.0"));
            }
            else
            {
                upper = T.Parse(string.Create(CultureInfo.InvariantCulture, $"{prefix.Major}.{prefix.Minor + 1}.0"));
            }

            return new(lower, true, upper, false);
        }

        var exact = T.Parse(text);
        return new(exact, true, exact, true);
    }
}
