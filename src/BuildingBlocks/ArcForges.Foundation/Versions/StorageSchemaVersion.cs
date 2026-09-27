// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;

namespace ArcForges.Foundation.Versions;

/// <summary>Highest applied migration number; not a semantic application or package version.</summary>
public readonly record struct StorageSchemaVersion : IVersionAxis<StorageSchemaVersion>
{
    private readonly uint _number;
    public bool IsValid { get; }
    public uint Number => IsValid ? _number : throw new InvalidOperationException("An absent schema version is not migration zero.");

    public StorageSchemaVersion(uint number)
    {
        _number = number;
        IsValid = true;
    }

    public static StorageSchemaVersion Parse(string text) => TryParse(text, out var value)
        ? value : throw new FormatException("A storage schema version must be a canonical unsigned migration number.");

    public static bool TryParse(string? text, out StorageSchemaVersion value)
    {
        value = default;
        if (string.IsNullOrEmpty(text) || (text.Length > 1 && text[0] == '0') ||
            !uint.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var number)) return false;
        value = new(number);
        return true;
    }

    public int CompareTo(StorageSchemaVersion other) => Number.CompareTo(other.Number);
    public override string ToString() => Number.ToString(CultureInfo.InvariantCulture);
    public static bool operator <(StorageSchemaVersion left, StorageSchemaVersion right) => left.CompareTo(right) < 0;
    public static bool operator >(StorageSchemaVersion left, StorageSchemaVersion right) => left.CompareTo(right) > 0;
    public static bool operator <=(StorageSchemaVersion left, StorageSchemaVersion right) => left.CompareTo(right) <= 0;
    public static bool operator >=(StorageSchemaVersion left, StorageSchemaVersion right) => left.CompareTo(right) >= 0;
}
