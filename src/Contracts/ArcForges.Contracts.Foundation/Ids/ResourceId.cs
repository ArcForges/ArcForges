// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies a resource independently of where its bytes currently live.</summary>
/// <remarks>
/// <para>The identity is stable across local, cloud and unavailable states. Availability is a separate field on <see cref="ResourceRef"/>, so a resource does not change identity when it is uploaded or evicted.</para>
/// </remarks>
[JsonConverter(typeof(ResourceIdJsonConverter))]
public readonly record struct ResourceId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static ResourceId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static ResourceId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out ResourceId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new ResourceId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="ResourceId"/> as a bare canonical GUID string.</summary>
public sealed class ResourceIdJsonConverter : GuidIdJsonConverter<ResourceId>
{
    protected override ResourceId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(ResourceId value) => value.Value;
}
