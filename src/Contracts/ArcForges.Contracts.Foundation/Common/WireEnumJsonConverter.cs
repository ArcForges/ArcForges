// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.Contracts.Foundation;

/// <summary>
/// Serialises a closed wire enum as one of a frozen set of lower-case strings.
/// </summary>
/// <typeparam name="TEnum">The enum being carried.</typeparam>
/// <remarks>
/// <para>
/// An unknown wire value is rejected. It is never mapped onto a known member and never falls back to the
/// zero value, because for these enums the zero value is a meaningful state — silently landing on it would
/// turn an unreadable message into a plausible-looking one. A newer peer sending a member this build does not
/// know is a contract mismatch the caller has to see, so the read throws and the caller keeps the resource id
/// and revision to re-read after upgrading.
/// </para>
/// <para>
/// The numeric form is rejected as well. Wire values are the frozen strings, so an integer on the wire means
/// the producer is not speaking this contract.
/// </para>
/// </remarks>
public abstract class WireEnumJsonConverter<TEnum> : JsonConverter<TEnum>
    where TEnum : struct, Enum
{
    private readonly Dictionary<TEnum, string> _toWire;
    private readonly Dictionary<string, TEnum> _fromWire;

    /// <param name="mapping">Every member of <typeparamref name="TEnum"/> and its frozen wire value.</param>
    protected WireEnumJsonConverter(IReadOnlyDictionary<TEnum, string> mapping)
    {
        ArgumentNullException.ThrowIfNull(mapping);

        var members = Enum.GetValues<TEnum>();
        if (mapping.Count != members.Length)
        {
            throw new ArgumentException(
                $"{typeof(TEnum).Name} has {members.Length} members but {mapping.Count} wire values are mapped.",
                nameof(mapping));
        }

        _toWire = new Dictionary<TEnum, string>(mapping);
        _fromWire = mapping.ToDictionary(pair => pair.Value, pair => pair.Key, StringComparer.Ordinal);
    }

    /// <summary>The frozen wire values, for tests and schema emission.</summary>
    public IReadOnlyCollection<string> WireValues => _fromWire.Keys;

    public override TEnum Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException(
                $"Expected a {typeof(TEnum).Name} wire string but found {reader.TokenType}.");
        }

        var value = reader.GetString();
        if (value is null || !_fromWire.TryGetValue(value, out var member))
        {
            throw new JsonException(
                $"Unsupported contract: '{value}' is not a known {typeof(TEnum).Name} value.");
        }

        return member;
    }

    public override void Write(Utf8JsonWriter writer, TEnum value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);

        if (!_toWire.TryGetValue(value, out var wire))
        {
            throw new JsonException($"{typeof(TEnum).Name} value '{value}' has no frozen wire value.");
        }

        writer.WriteStringValue(wire);
    }
}

/// <summary>Frozen wire values for <see cref="ResourceAvailability"/>.</summary>
public sealed class ResourceAvailabilityJsonConverter : WireEnumJsonConverter<ResourceAvailability>
{
    public ResourceAvailabilityJsonConverter()
        : base(new Dictionary<ResourceAvailability, string>
        {
            [ResourceAvailability.LocalOnline] = "local_online",
            [ResourceAvailability.LocalOffline] = "local_offline",
            [ResourceAvailability.Cloud] = "cloud",
            [ResourceAvailability.Preparing] = "preparing",
            [ResourceAvailability.Unavailable] = "unavailable",
        })
    {
    }
}

/// <summary>Frozen wire values for <see cref="ResourceSensitivity"/>.</summary>
public sealed class ResourceSensitivityJsonConverter : WireEnumJsonConverter<ResourceSensitivity>
{
    public ResourceSensitivityJsonConverter()
        : base(new Dictionary<ResourceSensitivity, string>
        {
            [ResourceSensitivity.Public] = "public",
            [ResourceSensitivity.Internal] = "internal",
            [ResourceSensitivity.Confidential] = "confidential",
            [ResourceSensitivity.Restricted] = "restricted",
        })
    {
    }
}

/// <summary>Frozen wire values for <see cref="PreviewAvailability"/>.</summary>
public sealed class PreviewAvailabilityJsonConverter : WireEnumJsonConverter<PreviewAvailability>
{
    public PreviewAvailabilityJsonConverter()
        : base(new Dictionary<PreviewAvailability, string>
        {
            [PreviewAvailability.None] = "none",
            [PreviewAvailability.Metadata] = "metadata",
            [PreviewAvailability.Thin] = "thin",
            [PreviewAvailability.Rich] = "rich",
        })
    {
    }
}

/// <summary>Frozen wire values for <see cref="ErrorCategory"/>.</summary>
public sealed class ErrorCategoryJsonConverter : WireEnumJsonConverter<ErrorCategory>
{
    public ErrorCategoryJsonConverter()
        : base(new Dictionary<ErrorCategory, string>
        {
            [ErrorCategory.ConnectionProtocol] = "connection_protocol",
            [ErrorCategory.RemoteInvocation] = "remote_invocation",
            [ErrorCategory.Business] = "business",
        })
    {
    }
}
