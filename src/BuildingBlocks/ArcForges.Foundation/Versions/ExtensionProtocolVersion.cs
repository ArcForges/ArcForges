// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Foundation.Versions;

/// <summary>The ExtensionProtocolVersion axis, independently sourced and never implicitly convertible to another axis.</summary>
public readonly record struct ExtensionProtocolVersion : IVersionAxis<ExtensionProtocolVersion>
{
    private readonly VersionCore _value;

    private ExtensionProtocolVersion(VersionCore value) => _value = value;

    public bool IsValid => _value.IsValid;
    public uint Major { get { _value.EnsureValid(); return _value.Major; } }
    public uint Minor { get { _value.EnsureValid(); return _value.Minor; } }
    public uint Patch { get { _value.EnsureValid(); return _value.Patch; } }

    public static ExtensionProtocolVersion Parse(string text) => new(VersionCore.Parse(text));

    public static bool TryParse(string? text, out ExtensionProtocolVersion value)
    {
        var valid = VersionCore.TryParse(text, out var core);
        value = valid ? new(core) : default;
        return valid;
    }

    public int CompareTo(ExtensionProtocolVersion other) => _value.CompareTo(other._value);
    public override string ToString() => _value.ToString();
    public static bool operator <(ExtensionProtocolVersion left, ExtensionProtocolVersion right) => left.CompareTo(right) < 0;
    public static bool operator >(ExtensionProtocolVersion left, ExtensionProtocolVersion right) => left.CompareTo(right) > 0;
    public static bool operator <=(ExtensionProtocolVersion left, ExtensionProtocolVersion right) => left.CompareTo(right) <= 0;
    public static bool operator >=(ExtensionProtocolVersion left, ExtensionProtocolVersion right) => left.CompareTo(right) >= 0;
}
