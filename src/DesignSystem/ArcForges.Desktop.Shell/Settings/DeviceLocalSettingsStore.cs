// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Foundation;
using ArcForges.Foundation.Versions;

namespace ArcForges.Desktop.Shell;

public enum SettingsLoadStatus
{
    Missing,
    Loaded,
    Migrated,
    Corrupt,
    Unavailable,
    MigrationRefused
}

public sealed record SettingsLoadResult(SettingsLoadStatus Status, SettingsSnapshot Snapshot);

/// <summary>
/// Stores preference values under the current user's local application-data directory. This store never
/// performs network or synchronization work; callers must use the explicit sync projection instead.
/// </summary>
public sealed class DeviceLocalSettingsStore
{
    private const int MaximumDocumentBytes = 256 * 1024;
    private const int MaximumValues = 4096;
    private readonly string _filePath;
    private readonly AtomicLayoutFileWriter _writer;

    public DeviceLocalSettingsStore(ApplicationKey application)
        : this(application, GetLocalApplicationDataRoot(), new AtomicLayoutFileWriter())
    {
    }

    internal DeviceLocalSettingsStore(ApplicationKey application, string localApplicationDataRoot)
        : this(application, localApplicationDataRoot, new AtomicLayoutFileWriter())
    {
    }

    internal DeviceLocalSettingsStore(ApplicationKey application, string localApplicationDataRoot, AtomicLayoutFileWriter writer)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentException.ThrowIfNullOrWhiteSpace(localApplicationDataRoot);
        ArgumentNullException.ThrowIfNull(writer);
        _writer = writer;
        var root = Path.GetFullPath(localApplicationDataRoot);
        _filePath = Path.Combine(root, "ArcForges", "DesktopSettings", Hash(application.Value) + ".json");
    }

    public SettingsLoadResult Load(IEnumerable<ISettingSchema> schemas)
    {
        ArgumentNullException.ThrowIfNull(schemas);
        var byKey = SchemaMap(schemas);

        byte[] bytes;
        try
        {
            using var stream = new FileStream(_filePath, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete, 4096, FileOptions.SequentialScan);
            if (stream.Length > MaximumDocumentBytes)
            {
                return new SettingsLoadResult(SettingsLoadStatus.Corrupt, Empty());
            }

            bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
        }
        catch (FileNotFoundException)
        {
            return new SettingsLoadResult(SettingsLoadStatus.Missing, Empty());
        }
        catch (DirectoryNotFoundException)
        {
            return new SettingsLoadResult(SettingsLoadStatus.Missing, Empty());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new SettingsLoadResult(SettingsLoadStatus.Unavailable, Empty());
        }

        SettingsSnapshot original;
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 24 });
            if (!TryReadDocument(document.RootElement, out original))
            {
                return new SettingsLoadResult(SettingsLoadStatus.Corrupt, Empty());
            }
        }
        catch (JsonException)
        {
            return new SettingsLoadResult(SettingsLoadStatus.Corrupt, Empty());
        }

        List<ScopedSettingValue> migrated = [];
        var changed = false;
        try
        {
            foreach (var value in original.Entries)
            {
                if (!byKey.TryGetValue(value.Key, out var schema))
                {
                    // Retain values whose owning schema is not loaded; a later application version may own them.
                    migrated.Add(value);
                    continue;
                }

                var current = schema.Migrate(value);
                changed |= current.SchemaVersion.Number != value.SchemaVersion.Number;
                migrated.Add(current);
            }
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or JsonException)
        {
            return new SettingsLoadResult(SettingsLoadStatus.MigrationRefused, original);
        }

        var snapshot = new SettingsSnapshot(migrated);
        if (!changed)
        {
            return new SettingsLoadResult(SettingsLoadStatus.Loaded, snapshot);
        }

        try
        {
            Save(snapshot.Entries);
            return new SettingsLoadResult(SettingsLoadStatus.Migrated, snapshot);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Report the pre-migration snapshot; the original file remains authoritative if the atomic replace failed.
            return new SettingsLoadResult(SettingsLoadStatus.Unavailable, original);
        }
    }

    public void Save(IEnumerable<ScopedSettingValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var snapshot = new SettingsSnapshot(values);
        if (snapshot.Entries.Count > MaximumValues)
        {
            throw new ArgumentOutOfRangeException(nameof(values), "A settings document has too many values.");
        }

        foreach (var value in snapshot.Entries)
        {
            if (!SettingKey.IsValid(value.Key) || !Enum.IsDefined(value.Scope)
                || !IsHash(value.ScopeIdHash) || !value.SchemaVersion.IsValid || value.SchemaVersion.Number == 0
                || value.Value.ValueKind == JsonValueKind.Undefined)
            {
                throw new ArgumentException("A stored setting value is malformed.", nameof(values));
            }
        }

        using var memory = new MemoryStream();
        using (var writer = new Utf8JsonWriter(memory, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("formatVersion", 1);
            writer.WriteStartArray("settings");
            foreach (var value in snapshot.Entries)
            {
                writer.WriteStartObject();
                writer.WriteString("key", value.Key);
                writer.WriteString("scope", FormatScope(value.Scope));
                writer.WriteString("scopeIdHash", value.ScopeIdHash);
                writer.WriteNumber("schemaVersion", value.SchemaVersion.Number);
                writer.WritePropertyName("value");
                value.Value.WriteTo(writer);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.Flush();
        }

        if (memory.Length > MaximumDocumentBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(values), "A settings document exceeds the size limit.");
        }

        _writer.WriteAtomically(_filePath, memory.ToArray());
    }

    /// <summary>Creates an explicit network-facing view containing only scopes opted in by each setting schema.</summary>
    public SettingsSnapshot CreateSyncSnapshot(SettingsSnapshot local, IEnumerable<ISettingSchema> schemas)
    {
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(schemas);
        var byKey = SchemaMap(schemas);
        List<ScopedSettingValue> syncable = [];
        foreach (var value in local.Entries)
        {
            if (value.Scope is SettingScope.Device or SettingScope.Instance
                || !byKey.TryGetValue(value.Key, out var schema)
                || !schema.AllowedScopes.Contains(value.Scope)
                || !schema.SyncableScopes.Contains(value.Scope))
            {
                continue;
            }

            syncable.Add(schema.Migrate(value));
        }

        return new SettingsSnapshot(syncable);
    }

    internal string FilePath => _filePath;

    private static bool TryReadDocument(JsonElement root, out SettingsSnapshot snapshot)
    {
        snapshot = Empty();
        if (!TryReadFields(root, ["formatVersion", "settings"], out var rootFields)
            || !rootFields["formatVersion"].TryGetInt32(out var formatVersion) || formatVersion != 1
            || rootFields["settings"].ValueKind != JsonValueKind.Array
            || rootFields["settings"].GetArrayLength() > MaximumValues)
        {
            return false;
        }

        List<ScopedSettingValue> values = [];
        foreach (var item in rootFields["settings"].EnumerateArray())
        {
            if (!TryReadFields(item, ["key", "scope", "scopeIdHash", "schemaVersion", "value"], out var fields)
                || !fields["key"].TryGetString(out var key) || !SettingKey.IsValid(key)
                || !fields["scope"].TryGetString(out var scopeText) || !TryParseScope(scopeText, out var scope)
                || !fields["scopeIdHash"].TryGetString(out var scopeIdHash) || !IsHash(scopeIdHash)
                || !fields["schemaVersion"].TryGetUInt32(out var schemaVersion) || schemaVersion == 0
                || fields["value"].ValueKind == JsonValueKind.Undefined)
            {
                return false;
            }

            values.Add(new ScopedSettingValue(key, scope, scopeIdHash, new StorageSchemaVersion(schemaVersion), fields["value"]));
        }

        try
        {
            snapshot = new SettingsSnapshot(values);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool TryReadFields(JsonElement element, string[] expected, out Dictionary<string, JsonElement> fields)
    {
        fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !fields.TryAdd(property.Name, property.Value))
            {
                return false;
            }
        }

        return fields.Count == expected.Length;
    }

    private static Dictionary<string, ISettingSchema> SchemaMap(IEnumerable<ISettingSchema> schemas)
    {
        var items = schemas.ToArray();
        if (items.Any(schema => schema is null))
        {
            throw new ArgumentException("Setting schemas cannot contain null entries.", nameof(schemas));
        }

        var result = new Dictionary<string, ISettingSchema>(StringComparer.Ordinal);
        foreach (var schema in items)
        {
            if (!result.TryAdd(schema.Key, schema))
            {
                throw new ArgumentException("Setting schema keys must be unique.", nameof(schemas));
            }
        }

        return result;
    }

    private static SettingsSnapshot Empty() => new([]);

    private static string GetLocalApplicationDataRoot()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return !string.IsNullOrWhiteSpace(root)
            ? root
            : throw new InvalidOperationException("The current user's local application-data directory is unavailable.");
    }

    private static string Hash(string value)
        => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static bool IsHash(string? value)
        => value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string FormatScope(SettingScope scope) => scope switch
    {
        SettingScope.Application => "application",
        SettingScope.Workspace => "workspace",
        SettingScope.Device => "device",
        SettingScope.Instance => "instance",
        _ => throw new ArgumentOutOfRangeException(nameof(scope))
    };

    private static bool TryParseScope(string? value, out SettingScope scope)
    {
        scope = value switch
        {
            "application" => SettingScope.Application,
            "workspace" => SettingScope.Workspace,
            "device" => SettingScope.Device,
            "instance" => SettingScope.Instance,
            _ => (SettingScope)(-1)
        };
        return Enum.IsDefined(scope);
    }
}
