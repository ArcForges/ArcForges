// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Identifies a message within a conversation.</summary>
[JsonConverter(typeof(MessageIdJsonConverter))]
public readonly record struct MessageId(Guid Value)
{
    /// <summary>A new identity. Version 7 so the value sorts by creation time.</summary>
    public static MessageId New() => new(Guid.CreateVersion7());

    /// <summary>Parses a canonical GUID string, throwing on anything else.</summary>
    /// <exception cref="ArgumentException">The text is not a GUID.</exception>
    public static MessageId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out MessageId id)
    {
        if (Guid.TryParse(s, out var value))
        {
            id = new MessageId(value);
            return true;
        }

        id = default;
        return false;
    }

    /// <summary>True when this is <c>default</c> and therefore carries no identity.</summary>
    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

/// <summary>Serialises <see cref="MessageId"/> as a bare canonical GUID string.</summary>
public sealed class MessageIdJsonConverter : GuidIdJsonConverter<MessageId>
{
    protected override MessageId FromGuid(Guid value) => new(value);

    protected override Guid ToGuid(MessageId value) => value.Value;
}
