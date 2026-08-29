// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies one step within a run.</summary>
[JsonConverter(typeof(StepIdJsonConverter))]
public readonly record struct StepId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static StepId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static StepId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out StepId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new StepId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="StepId"/> as a bare canonical GUID string.</summary>
public sealed class StepIdJsonConverter : GuidIdJsonConverter<StepId>
{
    protected override StepId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(StepId value) => value.Value;
}
