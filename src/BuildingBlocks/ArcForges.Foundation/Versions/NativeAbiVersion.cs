// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Foundation.Versions;

/// <summary>The NativeAbiVersion axis, independently sourced and never implicitly convertible to another axis.</summary>
public readonly record struct NativeAbiVersion : IVersionAxis<NativeAbiVersion>
{
    private readonly VersionCore _value;

    private NativeAbiVersion(VersionCore value) => _value = value;

    public bool IsValid => _value.IsValid;
    public uint Major { get { _value.EnsureValid(); return _value.Major; } }
    public uint Minor { get { _value.EnsureValid(); return _value.Minor; } }
    public uint Patch { get { _value.EnsureValid(); return _value.Patch; } }

    public static NativeAbiVersion Parse(string text) => new(VersionCore.Parse(text));

    public static bool TryParse(string? text, out NativeAbiVersion value)
    {
        var valid = VersionCore.TryParse(text, out var core);
        value = valid ? new(core) : default;
        return valid;
    }

    public int CompareTo(NativeAbiVersion other) => _value.CompareTo(other._value);
    public override string ToString() => _value.ToString();
    public static bool operator <(NativeAbiVersion left, NativeAbiVersion right) => left.CompareTo(right) < 0;
    public static bool operator >(NativeAbiVersion left, NativeAbiVersion right) => left.CompareTo(right) > 0;
    public static bool operator <=(NativeAbiVersion left, NativeAbiVersion right) => left.CompareTo(right) <= 0;
    public static bool operator >=(NativeAbiVersion left, NativeAbiVersion right) => left.CompareTo(right) >= 0;
}
