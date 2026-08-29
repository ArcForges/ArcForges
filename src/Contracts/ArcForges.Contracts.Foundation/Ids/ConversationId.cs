// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies a conversation.</summary>
[JsonConverter(typeof(ConversationIdJsonConverter))]
public readonly record struct ConversationId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static ConversationId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static ConversationId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out ConversationId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new ConversationId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="ConversationId"/> as a bare canonical GUID string.</summary>
public sealed class ConversationIdJsonConverter : GuidIdJsonConverter<ConversationId>
{
    protected override ConversationId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(ConversationId value) => value.Value;
}
