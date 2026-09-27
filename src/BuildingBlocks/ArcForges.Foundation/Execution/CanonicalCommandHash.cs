// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Foundation.Execution;

/// <summary>Canonical owner-bound semantic command hash; never a hash of protobuf bytes or transport metadata.</summary>
public static class CanonicalCommandHash
{
    private static readonly JsonWriterOptions WriterOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public static string Compute(string operation, RealmId realm, WorkspaceId workspace, UserId actor,
        string revisionKind, string revisionValue, string semanticJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operation);
        ArgumentException.ThrowIfNullOrWhiteSpace(revisionKind);
        ArgumentException.ThrowIfNullOrWhiteSpace(revisionValue);
        ArgumentNullException.ThrowIfNull(semanticJson);
        if (operation.Length > 128 || operation.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '.' and not '_' and not ':' and not '/' and not '-'))
        {
            throw new ArgumentException("An operation must be a canonical registry key.", nameof(operation));
        }

        if (revisionKind == "cloud")
        {
            ArgumentOutOfRangeException.ThrowIfNegative(ExactInteger.ParseInt64(revisionValue), nameof(revisionValue));
        }
        else if (revisionKind == "native")
        {
            _ = ExactInteger.ParseUInt64(revisionValue);
        }
        else
        {
            throw new ArgumentException("A declared cloud or native revision kind is required.", nameof(revisionKind));
        }
        _ = realm.ToWire();
        _ = workspace.ToWire();
        _ = actor.ToWire();
        if (Encoding.UTF8.GetByteCount(semanticJson) > 4 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(semanticJson));
        }

        using var document = JsonDocument.Parse(semanticJson, new JsonDocumentOptions { MaxDepth = 100 });
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("Command semantic fields must be an object.", nameof(semanticJson));
        }

        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.Name is "requestId" or "correlationId" or "authorization" or "accessToken" or "refreshToken")
            {
                throw new ArgumentException("Transport metadata and credentials are not semantic command fields.", nameof(semanticJson));
            }
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("actor", actor.Value.ToString("D", CultureInfo.InvariantCulture));
            writer.WriteString("operation", operation);
            writer.WriteString("profile", "arcforges.command.v1");
            writer.WriteString("realm", realm.Value.ToString("D", CultureInfo.InvariantCulture));
            writer.WriteString("revisionKind", revisionKind);
            writer.WriteString("revisionValue", revisionValue);
            writer.WritePropertyName("semantic");
            WriteCanonical(writer, document.RootElement);
            writer.WriteString("workspace", workspace.Value.ToString("D", CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }

        return Convert.ToHexStringLower(SHA256.HashData(buffer.WrittenSpan));
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject().OrderBy(property => property.Name, StringComparer.Ordinal))
                {
                    if (property.Name.Any(character => character > 127) || !names.Add(property.Name))
                    {
                        throw new ArgumentException("Canonical properties must be unique ASCII names.", nameof(element));
                    }

                    writer.WritePropertyName(property.Name);
                    WriteCanonical(writer, property.Value);
                }

                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteCanonical(writer, item);
                }

                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                var text = element.GetString()!;
                _ = new UTF8Encoding(false, true).GetByteCount(text);
                writer.WriteStringValue(text);
                break;
            case JsonValueKind.Number:
                // Exact int64/uint64/decimal fields must arrive as their canonical string projections.
                if (!element.TryGetInt32(out var value))
                {
                    throw new ArgumentException("Only int32 JSON numbers are admitted; exact wider values use strings.", nameof(element));
                }

                writer.WriteNumberValue(value);
                break;
            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;
            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;
            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
            default:
                throw new ArgumentException("Unsupported canonical value.", nameof(element));
        }
    }
}
