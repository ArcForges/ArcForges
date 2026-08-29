// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies a device registered against the account.</summary>
/// <remarks>
/// <para>Device presence is not device trust. A device can be reachable and still be untrusted, so this identity never implies an authorisation decision (architecture §9).</para>
/// </remarks>
[JsonConverter(typeof(DeviceIdJsonConverter))]
public readonly record struct DeviceId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static DeviceId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static DeviceId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out DeviceId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new DeviceId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="DeviceId"/> as a bare canonical GUID string.</summary>
public sealed class DeviceIdJsonConverter : GuidIdJsonConverter<DeviceId>
{
    protected override DeviceId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(DeviceId value) => value.Value;
}
