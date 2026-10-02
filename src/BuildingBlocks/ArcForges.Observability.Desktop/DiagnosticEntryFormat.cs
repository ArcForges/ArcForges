// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Globalization;
using System.Text.Json;

namespace ArcForges.Observability.Desktop;

/// <summary>
/// The on-disk and in-report form of one diagnostic entry: one JSON object per line. Writing and reading both pass
/// every field through the Observability scrubbing processor, so a stored line that was altered or written by anything
/// other than this library still cannot put an unreviewed field or value into the local view or into a report.
/// </summary>
internal static class DiagnosticEntryFormat
{
    internal const int FormatVersion = 1;
    internal const int MaxLineBytes = 16 * 1024;
    internal const string SupportReferenceField = "support.reference";
    internal const string Redacted = "redacted";

    /// <summary>An event name is a dotted identifier of ASCII words; any other text is stored as <c>redacted</c>.</summary>
    internal static string NormalizeName(string? name) => IsOperationName(name) ? name! : Redacted;

    internal static bool IsOperationName(string? name)
    {
        if (name is not { Length: > 0 and <= 80 })
        {
            return false;
        }

        bool wordStart = true;
        foreach (char character in name)
        {
            if (character == '.')
            {
                if (wordStart)
                {
                    return false;
                }

                wordStart = true;
            }
            else if (char.IsAsciiLetter(character) || (!wordStart && char.IsAsciiDigit(character)))
            {
                wordStart = false;
            }
            else
            {
                return false;
            }
        }

        return !wordStart;
    }

    /// <summary>The reviewed telemetry fields that pass <see cref="RedactionProcessor"/>, plus a well-formed support reference.</summary>
    internal static Dictionary<string, object?> ValidateFields(IEnumerable<KeyValuePair<string, object?>> fields)
    {
        var kept = new Dictionary<string, object?>(StringComparer.Ordinal);
        var reviewed = new List<KeyValuePair<string, object?>>();
        foreach (KeyValuePair<string, object?> field in fields)
        {
            if (string.Equals(field.Key, SupportReferenceField, StringComparison.Ordinal))
            {
                if (field.Value is string reference && SupportReference.IsValid(reference))
                {
                    kept[field.Key] = reference;
                }
            }
            else
            {
                reviewed.Add(field);
            }
        }

        foreach (KeyValuePair<string, object?> field in RedactionProcessor.ScrubFields(reviewed))
        {
            kept[field.Key] = field.Value;
        }

        return kept;
    }

    internal static byte[] Serialize(DateTimeOffset occurredAt, string name, SignalLevel level, DiagnosticTier tier,
        IReadOnlyDictionary<string, object?> fields)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            WriteEntry(writer, occurredAt, name, level, tier, fields);
        }

        buffer.GetSpan(1)[0] = (byte)'\n';
        buffer.Advance(1);
        return buffer.WrittenSpan.ToArray();
    }

    internal static void WriteEntry(Utf8JsonWriter writer, DateTimeOffset occurredAt, string name, SignalLevel level,
        DiagnosticTier tier, IReadOnlyDictionary<string, object?> fields)
    {
        writer.WriteStartObject();
        writer.WriteNumber("v", FormatVersion);
        writer.WriteString("t", occurredAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        writer.WriteString("n", name);
        writer.WriteString("l", level.ToString());
        writer.WriteString("tier", tier.ToString());
        writer.WriteStartObject("f");
        foreach (KeyValuePair<string, object?> field in fields.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            WriteValue(writer, field.Key, field.Value);
        }

        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void WriteValue(Utf8JsonWriter writer, string name, object? value)
    {
        switch (value)
        {
            case string text:
                writer.WriteString(name, text);
                break;
            case double number when double.IsFinite(number):
                writer.WriteNumber(name, number);
                break;
            case ulong unsigned:
                writer.WriteNumber(name, unsigned);
                break;
            case sbyte or byte or short or ushort or int or uint or long:
                writer.WriteNumber(name, Convert.ToInt64(value, CultureInfo.InvariantCulture));
                break;
            default:
                // Validated fields never reach this branch; an unexpected shape is dropped, never stringified.
                break;
        }
    }

    internal static bool TryParse(ReadOnlySpan<byte> line, out LocalDiagnosticEntry? entry)
    {
        entry = null;
        try
        {
            using JsonDocument document = JsonDocument.Parse(line.ToArray(), new JsonDocumentOptions { MaxDepth = 3 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("v", out JsonElement version) || !version.TryGetInt32(out int number) || number != FormatVersion
                || !TryString(root, "t", out string? time)
                || !DateTimeOffset.TryParse(time, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset occurredAt)
                || !TryString(root, "n", out string? name)
                || !TryString(root, "l", out string? levelText)
                || !Enum.TryParse(levelText, ignoreCase: false, out SignalLevel level) || !Enum.IsDefined(level)
                || !TryString(root, "tier", out string? tierText)
                || !Enum.TryParse(tierText, ignoreCase: false, out DiagnosticTier tier) || !Enum.IsDefined(tier)
                || !root.TryGetProperty("f", out JsonElement fieldsElement) || fieldsElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            var candidates = new List<KeyValuePair<string, object?>>();
            foreach (JsonProperty property in fieldsElement.EnumerateObject())
            {
                if (TryReadValue(property.Name, property.Value, out object? value))
                {
                    candidates.Add(new KeyValuePair<string, object?>(property.Name, value));
                }
            }

            entry = new LocalDiagnosticEntry(occurredAt, NormalizeName(name), level, tier, ValidateFields(candidates));
            return true;
        }
        catch (Exception error) when (error is JsonException or ArgumentException or InvalidOperationException or FormatException)
        {
            entry = null;
            return false;
        }
    }

    private static bool TryString(JsonElement parent, string name, out string? value)
    {
        value = null;
        if (!parent.TryGetProperty(name, out JsonElement element) || element.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = element.GetString();
        return value is not null;
    }

    private static bool TryReadValue(string name, JsonElement element, out object? value)
    {
        value = null;
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                value = element.GetString();
                return value is not null;
            case JsonValueKind.Number:
                // The two reviewed duration fields are doubles; every other reviewed number is a non-negative integer.
                if (name is "duration.ms" or "queue.time.ms")
                {
                    value = element.GetDouble();
                    return true;
                }

                if (element.TryGetInt64(out long integer))
                {
                    value = integer;
                    return true;
                }

                if (element.TryGetUInt64(out ulong unsigned))
                {
                    value = unsigned;
                    return true;
                }

                return false;
            default:
                return false;
        }
    }
}
