// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// Serialises a GUID-backed identity transparently as a bare lower-case canonical GUID string.
/// </summary>
/// <typeparam name="TId">The identity wrapper.</typeparam>
/// <remarks>
/// <para>
/// Transparent means the wire carries <c>"0192f1f4-8b7c-7c3a-9a1f-4d2b6f0c5e11"</c>, never
/// <c>{"value":"..."}</c>. Every identity in this assembly shares this shape so a reader can move a value
/// between contracts without a per-type wire rule.
/// </para>
/// <para>
/// Derived converters exist per identity rather than one open-generic converter because System.Text.Json
/// source generation binds a concrete converter to a concrete type through <c>[JsonConverter]</c>.
/// </para>
/// </remarks>
public abstract class GuidIdJsonConverter<TId> : JsonConverter<TId>
    where TId : struct
{
    /// <summary>Wraps a raw GUID in the identity type.</summary>
    protected abstract TId FromGuid(Guid value);

    /// <summary>Unwraps the raw GUID carried by the identity type.</summary>
    protected abstract Guid ToGuid(TId value);

    public override TId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"Expected a {typeof(TId).Name} string but found {reader.TokenType}.");
        }

        if (!reader.TryGetGuid(out var value))
        {
            throw new JsonException($"Value is not a canonical GUID for {typeof(TId).Name}.");
        }

        return FromGuid(value);
    }

    public override void Write(Utf8JsonWriter writer, TId value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(ToGuid(value));
    }

    public override TId ReadAsPropertyName(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (!reader.TryGetGuid(out var value))
        {
            throw new JsonException($"Property name is not a canonical GUID for {typeof(TId).Name}.");
        }

        return FromGuid(value);
    }

    public override void WriteAsPropertyName(Utf8JsonWriter writer, TId value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WritePropertyName(ToGuid(value).ToString("D", System.Globalization.CultureInfo.InvariantCulture));
    }
}
