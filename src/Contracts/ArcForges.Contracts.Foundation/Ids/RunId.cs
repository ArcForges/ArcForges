// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies one run of a task.</summary>
/// <remarks>
/// <para>A task can have several runs; a run has exactly one logical agent. Multi-agent execution does not exist in V1 (architecture §6.2).</para>
/// </remarks>
[JsonConverter(typeof(RunIdJsonConverter))]
public readonly record struct RunId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static RunId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static RunId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out RunId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new RunId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="RunId"/> as a bare canonical GUID string.</summary>
public sealed class RunIdJsonConverter : GuidIdJsonConverter<RunId>
{
    protected override RunId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(RunId value) => value.Value;
}
