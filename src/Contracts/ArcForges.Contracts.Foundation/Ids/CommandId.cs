// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>The idempotency identity of one write command.</summary>
/// <remarks>
/// <para>A command identity is not a UI <c>AppCommandId</c>, not a <see cref="TaskId"/>, not an <see cref="AttemptId"/> and not a trace id. It exists so a write can be retried without being applied twice; a retry reuses the same value and a genuinely new intent takes a new one (architecture §5.1).</para>
/// <para>Business ordering is never expressed by the order commands arrive. A write carries its owner identity and an <c>ExpectedRevision</c> instead.</para>
/// </remarks>
[JsonConverter(typeof(CommandIdJsonConverter))]
public readonly record struct CommandId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static CommandId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static CommandId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out CommandId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new CommandId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="CommandId"/> as a bare canonical GUID string.</summary>
public sealed class CommandIdJsonConverter : GuidIdJsonConverter<CommandId>
{
    protected override CommandId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(CommandId value) => value.Value;
}
