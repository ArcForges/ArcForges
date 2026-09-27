// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;

namespace ArcForges.Foundation.Versions;

internal readonly record struct VersionCore(uint Major, uint Minor, uint Patch, string? Prerelease, string? Metadata, bool IsValid) : IComparable<VersionCore>
{
    internal static VersionCore Parse(string text)
    {
        if (!TryParse(text, out var value))
        {
            throw new FormatException("Expected one to three unsigned version components and optional SemVer prerelease/build identifiers.");
        }

        return value;
    }

    internal static bool TryParse(string? text, out VersionCore value)
    {
        value = default;
        if (string.IsNullOrEmpty(text) || text.Length > 1024)
        {
            return false;
        }

        var buildAt = text.IndexOf('+', StringComparison.Ordinal);
        var metadata = buildAt >= 0 ? text[(buildAt + 1)..] : null;
        var withoutBuild = buildAt >= 0 ? text[..buildAt] : text;
        var releaseAt = withoutBuild.IndexOf('-', StringComparison.Ordinal);
        var prerelease = releaseAt >= 0 ? withoutBuild[(releaseAt + 1)..] : null;
        var core = releaseAt >= 0 ? withoutBuild[..releaseAt] : withoutBuild;
        var parts = core.Split('.');
        if (parts.Length is < 1 or > 3 || !IdentifiersValid(metadata, false) || !IdentifiersValid(prerelease, true))
        {
            return false;
        }

        Span<uint> numbers = stackalloc uint[3];
        numbers.Clear();
        for (var index = 0; index < parts.Length; index++)
        {
            var part = parts[index];
            if (part.Length == 0 || (part.Length > 1 && part[0] == '0') ||
                !uint.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out numbers[index]))
            {
                return false;
            }
        }

        value = new(numbers[0], numbers[1], numbers[2], prerelease, metadata, true);
        return true;
    }

    private static bool IdentifiersValid(string? value, bool rejectNumericLeadingZero)
    {
        if (value is null)
        {
            return true;
        }

        foreach (var part in value.Split('.'))
        {
            if (part.Length == 0 || part.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '-'))
            {
                return false;
            }

            if (rejectNumericLeadingZero && part.Length > 1 && part[0] == '0' && part.All(char.IsAsciiDigit))
            {
                return false;
            }
        }

        return true;
    }

    public int CompareTo(VersionCore other)
    {
        EnsureValid();
        other.EnsureValid();
        var result = Major.CompareTo(other.Major);
        if (result == 0) result = Minor.CompareTo(other.Minor);
        if (result == 0) result = Patch.CompareTo(other.Patch);
        if (result != 0) return result;
        if (Prerelease is null) return other.Prerelease is null ? 0 : 1;
        if (other.Prerelease is null) return -1;
        var left = Prerelease.Split('.');
        var right = other.Prerelease.Split('.');
        for (var index = 0; index < Math.Min(left.Length, right.Length); index++)
        {
            var leftNumeric = left[index].All(char.IsAsciiDigit);
            var rightNumeric = right[index].All(char.IsAsciiDigit);
            if (leftNumeric && rightNumeric)
            {
                result = left[index].Length.CompareTo(right[index].Length);
                if (result == 0) result = string.CompareOrdinal(left[index], right[index]);
            }
            else if (leftNumeric != rightNumeric)
            {
                result = leftNumeric ? -1 : 1;
            }
            else
            {
                result = string.CompareOrdinal(left[index], right[index]);
            }

            if (result != 0) return result;
        }

        return left.Length.CompareTo(right.Length);
    }

    internal void EnsureValid()
    {
        if (!IsValid) throw new InvalidOperationException("An absent version is not an implemented version zero.");
    }

    public override string ToString()
    {
        EnsureValid();
        return string.Create(CultureInfo.InvariantCulture, $"{Major}.{Minor}.{Patch}") +
            (Prerelease is null ? string.Empty : "-" + Prerelease) +
            (Metadata is null ? string.Empty : "+" + Metadata);
    }
}
