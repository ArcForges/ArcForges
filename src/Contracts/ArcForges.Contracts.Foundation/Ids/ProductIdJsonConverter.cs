// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// Serialises <see cref="ProductId"/> transparently as one of the seven frozen bare strings.
/// </summary>
/// <remarks>
/// Transparent means the wire carries <c>"arcchat"</c>, never <c>{"value":"arcchat"}</c>. An unknown string
/// is rejected here rather than deserialised into an unrecognised product, which is what stops a value that
/// is not in the closed set from travelling as though it were.
/// </remarks>
public sealed class ProductIdJsonConverter : JsonConverter<ProductId>
{
    public override ProductId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"Expected a product identity string but found {reader.TokenType}.");
        }

        var value = reader.GetString();
        if (!ProductId.TryParse(value, out var product))
        {
            throw new JsonException($"Unknown product identity '{value}'.");
        }

        return product;
    }

    public override void Write(Utf8JsonWriter writer, ProductId value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(value.Value);
    }

    public override ProductId ReadAsPropertyName(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        if (!ProductId.TryParse(value, out var product))
        {
            throw new JsonException($"Unknown product identity '{value}'.");
        }

        return product;
    }

    public override void WriteAsPropertyName(Utf8JsonWriter writer, ProductId value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WritePropertyName(value.Value);
    }
}
