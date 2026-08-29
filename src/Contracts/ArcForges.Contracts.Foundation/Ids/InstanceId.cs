// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies one running instance of a product for the lifetime of its process.</summary>
/// <remarks>
/// <para>An instance is not a product and is not an OS process id. <c>ProductId</c> names what is installed, <see cref="InstanceId"/> names a run of it, and the OS process id is a diagnostic detail that never stands in for either (architecture §5.1). A restarted product keeps its <c>ProductId</c> and takes a new <see cref="InstanceId"/>.</para>
/// </remarks>
[JsonConverter(typeof(InstanceIdJsonConverter))]
public readonly record struct InstanceId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static InstanceId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static InstanceId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out InstanceId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new InstanceId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="InstanceId"/> as a bare canonical GUID string.</summary>
public sealed class InstanceIdJsonConverter : GuidIdJsonConverter<InstanceId>
{
    protected override InstanceId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(InstanceId value) => value.Value;
}
