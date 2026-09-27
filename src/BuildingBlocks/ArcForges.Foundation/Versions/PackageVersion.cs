// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Foundation.Versions;

/// <summary>The PackageVersion axis, independently sourced and never implicitly convertible to another axis.</summary>
public readonly record struct PackageVersion : IVersionAxis<PackageVersion>
{
    private readonly VersionCore _value;

    private PackageVersion(VersionCore value) => _value = value;

    public bool IsValid => _value.IsValid;
    public uint Major { get { _value.EnsureValid(); return _value.Major; } }
    public uint Minor { get { _value.EnsureValid(); return _value.Minor; } }
    public uint Patch { get { _value.EnsureValid(); return _value.Patch; } }

    public static PackageVersion Parse(string text) => new(VersionCore.Parse(text));

    public static bool TryParse(string? text, out PackageVersion value)
    {
        var valid = VersionCore.TryParse(text, out var core);
        value = valid ? new(core) : default;
        return valid;
    }

    public int CompareTo(PackageVersion other) => _value.CompareTo(other._value);
    public override string ToString() => _value.ToString();
    public static bool operator <(PackageVersion left, PackageVersion right) => left.CompareTo(right) < 0;
    public static bool operator >(PackageVersion left, PackageVersion right) => left.CompareTo(right) > 0;
    public static bool operator <=(PackageVersion left, PackageVersion right) => left.CompareTo(right) <= 0;
    public static bool operator >=(PackageVersion left, PackageVersion right) => left.CompareTo(right) >= 0;
}
