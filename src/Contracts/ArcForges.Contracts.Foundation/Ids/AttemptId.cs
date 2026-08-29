// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies one attempt at a step.</summary>
/// <remarks>
/// <para>An attempt identity is not a <see cref="CommandId"/>. A command's idempotency key is stable across retries by design, whereas every attempt is a distinct execution and takes a new value.</para>
/// </remarks>
[JsonConverter(typeof(AttemptIdJsonConverter))]
public readonly record struct AttemptId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static AttemptId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static AttemptId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out AttemptId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new AttemptId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="AttemptId"/> as a bare canonical GUID string.</summary>
public sealed class AttemptIdJsonConverter : GuidIdJsonConverter<AttemptId>
{
    protected override AttemptId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(AttemptId value) => value.Value;
}
