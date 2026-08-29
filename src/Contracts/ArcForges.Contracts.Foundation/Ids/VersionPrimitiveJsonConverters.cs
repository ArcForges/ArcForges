// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>Serialises <see cref="Revision"/> transparently as a bare JSON number.</summary>
/// <remarks>
/// <para>
/// Without an explicit converter a <c>readonly record struct</c> serialises as an object, which would put
/// <c>{"value":7,"exists":true}</c> on the wire: the wrong shape, and a derived property leaked into the
/// contract. Every store that holds a revision holds an integer column, so the wire form is a bare number.
/// </para>
/// <para>
/// A fractional or out-of-range number is refused rather than truncated, because silently rounding a version
/// would make two different revisions compare equal.
/// </para>
/// </remarks>
public sealed class RevisionJsonConverter : JsonConverter<Revision>
{
    public override Revision Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number)
        {
            throw new JsonException($"Expected a revision number but found {reader.TokenType}.");
        }

        if (!reader.TryGetInt64(out var value))
        {
            throw new JsonException("A revision must be a 64-bit integer.");
        }

        if (value < 0)
        {
            throw new JsonException("A revision cannot be negative.");
        }

        return new Revision(value);
    }

    public override void Write(Utf8JsonWriter writer, Revision value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteNumberValue(value.Value);
    }
}

/// <summary>Serialises <see cref="Sequence"/> transparently as a bare JSON number.</summary>
/// <remarks>
/// Same reasoning as <see cref="RevisionJsonConverter"/>. A stream position is an integer everywhere it is
/// stored, and a wrapper object would break every consumer that reads a cursor.
/// </remarks>
public sealed class SequenceJsonConverter : JsonConverter<Sequence>
{
    public override Sequence Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number)
        {
            throw new JsonException($"Expected a sequence number but found {reader.TokenType}.");
        }

        if (!reader.TryGetInt64(out var value))
        {
            throw new JsonException("A sequence must be a 64-bit integer.");
        }

        if (value < 0)
        {
            throw new JsonException("A sequence cannot be negative.");
        }

        return new Sequence(value);
    }

    public override void Write(Utf8JsonWriter writer, Sequence value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteNumberValue(value.Value);
    }
}
