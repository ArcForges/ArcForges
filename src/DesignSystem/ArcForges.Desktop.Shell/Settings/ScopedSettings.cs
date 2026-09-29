// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using ArcForges.Foundation.Versions;

namespace ArcForges.Desktop.Shell;

public enum SettingScope
{
    Application,
    Workspace,
    Device,
    Instance
}

/// <summary>Scope identities for one resolution request. Identities are hashed before storage or comparison.</summary>
public sealed class SettingScopeContext
{
    private readonly ReadOnlyDictionary<SettingScope, string> _identities;

    public string? this[SettingScope scope]
        => _identities.TryGetValue(scope, out var value) ? value : null;

    public SettingScopeContext(
        string applicationId,
        string? workspaceId = null,
        string? deviceId = null,
        string? instanceId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationId);
        var identities = new Dictionary<SettingScope, string>
        {
            [SettingScope.Application] = SettingScopeIdentity.Hash(applicationId)
        };
        Add(identities, SettingScope.Workspace, workspaceId);
        Add(identities, SettingScope.Device, deviceId);
        Add(identities, SettingScope.Instance, instanceId);
        _identities = new ReadOnlyDictionary<SettingScope, string>(identities);
    }

    private static void Add(Dictionary<SettingScope, string> identities, SettingScope scope, string? identity)
    {
        if (identity is null)
        {
            return;
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(identity);
        identities.Add(scope, SettingScopeIdentity.Hash(identity));
    }
}

/// <summary>A schema-versioned, typed setting with an explicitly owned scope set and precedence order.</summary>
public sealed class SettingDefinition<T> : ISettingSchema
{
    private readonly JsonTypeInfo<T> _jsonTypeInfo;
    private readonly ReadOnlyCollection<SettingMigrationStep> _migrations;

    public string Key { get; }

    public T DefaultValue { get; }

    public StorageSchemaVersion SchemaVersion { get; }

    public ReadOnlyCollection<SettingScope> AllowedScopes { get; }

    /// <summary>Each definition owns its own order; there is intentionally no global scope chain.</summary>
    public ReadOnlyCollection<SettingScope> ResolutionOrder { get; }

    public ReadOnlyCollection<SettingScope> SyncableScopes { get; }

    public SettingDefinition(
        string key,
        T defaultValue,
        JsonTypeInfo<T> jsonTypeInfo,
        StorageSchemaVersion schemaVersion,
        IEnumerable<SettingScope> allowedScopes,
        IEnumerable<SettingScope> resolutionOrder,
        IEnumerable<SettingScope>? syncableScopes = null,
        IEnumerable<SettingMigrationStep>? migrations = null)
    {
        if (!SettingKey.IsValid(key))
        {
            throw new ArgumentException("A setting key must be a bounded dotted lower-case identifier with single internal hyphens.", nameof(key));
        }

        ArgumentNullException.ThrowIfNull(jsonTypeInfo);
        if (!schemaVersion.IsValid || schemaVersion.Number == 0)
        {
            throw new ArgumentException("A setting schema version must be positive.", nameof(schemaVersion));
        }

        ArgumentNullException.ThrowIfNull(allowedScopes);
        ArgumentNullException.ThrowIfNull(resolutionOrder);
        Key = key;
        DefaultValue = defaultValue;
        SchemaVersion = schemaVersion;
        _jsonTypeInfo = jsonTypeInfo;

        var allowed = CopyScopes(allowedScopes, nameof(allowedScopes));
        var order = CopyScopes(resolutionOrder, nameof(resolutionOrder));
        if (allowed.Count == 0 || order.Count != allowed.Count || !allowed.ToHashSet().SetEquals(order))
        {
            throw new ArgumentException("The setting resolution order must list each allowed scope exactly once.", nameof(resolutionOrder));
        }

        var syncable = CopyScopes(syncableScopes ?? [], nameof(syncableScopes));
        if (syncable.Any(scope => !allowed.Contains(scope) || scope is SettingScope.Device or SettingScope.Instance))
        {
            throw new ArgumentException("Only allowed application/workspace scopes may be synchronized.", nameof(syncableScopes));
        }

        AllowedScopes = Array.AsReadOnly(allowed.ToArray());
        ResolutionOrder = Array.AsReadOnly(order.ToArray());
        SyncableScopes = Array.AsReadOnly(syncable.ToArray());

        var migrationItems = (migrations ?? []).ToArray();
        if (migrationItems.Any(step => step is null)
            || migrationItems.Select(step => step.FromVersion.Number).Distinct().Count() != migrationItems.Length
            || migrationItems.Select(step => step.Id).Distinct(StringComparer.Ordinal).Count() != migrationItems.Length)
        {
            throw new ArgumentException("Setting migrations must have unique versions and identities.", nameof(migrations));
        }

        var orderedMigrations = migrationItems.OrderBy(step => step.FromVersion.Number).ToArray();
        var expectedFrom = 1u;
        foreach (var step in orderedMigrations)
        {
            if (step.FromVersion.Number != expectedFrom)
            {
                throw new ArgumentException("A setting migration plan must preserve a contiguous numbered history from version 1.", nameof(migrations));
            }

            expectedFrom = step.ToVersion.Number;
        }

        if (expectedFrom != schemaVersion.Number)
        {
            throw new ArgumentException("The migration plan must reach the declared setting schema version.", nameof(migrations));
        }

        _migrations = Array.AsReadOnly(orderedMigrations);
        _ = JsonSerializer.SerializeToElement(defaultValue, _jsonTypeInfo);
    }

    public ScopedSettingValue ToStoredValue(SettingScope scope, string scopeId, T value)
    {
        if (!AllowedScopes.Contains(scope))
        {
            throw new ArgumentException("The setting is not allowed at the requested scope.", nameof(scope));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(scopeId);
        return new ScopedSettingValue(Key, scope, SettingScopeIdentity.Hash(scopeId), SchemaVersion,
            JsonSerializer.SerializeToElement(value, _jsonTypeInfo));
    }

    internal T ReadValue(ScopedSettingValue value)
    {
        if (!string.Equals(value.Key, Key, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The stored value belongs to another setting schema.");
        }

        return value.Value.Deserialize(_jsonTypeInfo)!;
    }

    ScopedSettingValue ISettingSchema.Migrate(ScopedSettingValue value)
        => Migrate(value);

    internal ScopedSettingValue Migrate(ScopedSettingValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!string.Equals(value.Key, Key, StringComparison.Ordinal) || !AllowedScopes.Contains(value.Scope))
        {
            throw new InvalidOperationException("The stored value does not belong to an allowed setting scope.");
        }

        var version = value.SchemaVersion.Number;
        if (version > SchemaVersion.Number)
        {
            throw new InvalidOperationException("A newer setting schema cannot be downgraded.");
        }

        var current = value;
        while (version < SchemaVersion.Number)
        {
            var step = _migrations.SingleOrDefault(candidate => candidate.FromVersion.Number == version)
                ?? throw new InvalidOperationException("The setting migration history has a gap; the stored value was not changed.");
            current = new ScopedSettingValue(Key, value.Scope, value.ScopeIdHash, step.ToVersion, step.Apply(current.Value));
            version = step.ToVersion.Number;
        }

        _ = ReadValue(current);
        return current;
    }

    private static List<SettingScope> CopyScopes(IEnumerable<SettingScope> scopes, string parameterName)
    {
        var copy = scopes.ToArray();
        if (copy.Any(scope => !Enum.IsDefined(scope)) || copy.Distinct().Count() != copy.Length)
        {
            throw new ArgumentException("Scopes must be known and unique.", parameterName);
        }

        return copy.ToList();
    }
}

internal static class SettingKey
{
    internal static bool IsValid(string? key)
    {
        if (string.IsNullOrWhiteSpace(key) || key.Length > 128)
        {
            return false;
        }

        return key.Split('.').All(segment =>
        {
            if (segment.Length == 0)
            {
                return false;
            }

            var previousWasSeparator = true;
            foreach (var character in segment)
            {
                var separator = character == '-';
                if (separator && previousWasSeparator)
                {
                    return false;
                }

                if (!separator && character is not (>= 'a' and <= 'z' or >= '0' and <= '9'))
                {
                    return false;
                }

                previousWasSeparator = separator;
            }

            return !previousWasSeparator;
        });
    }
}

/// <summary>A typed schema surface used by the device-local store to validate and migrate persisted values.</summary>
public interface ISettingSchema
{
    string Key { get; }

    StorageSchemaVersion SchemaVersion { get; }

    ReadOnlyCollection<SettingScope> AllowedScopes { get; }

    ReadOnlyCollection<SettingScope> SyncableScopes { get; }

    ScopedSettingValue Migrate(ScopedSettingValue value);
}

/// <summary>One immutable version transition. The step runs only against older stored values.</summary>
public sealed class SettingMigrationStep
{
    private readonly Func<JsonElement, JsonElement> _transform;

    public StorageSchemaVersion FromVersion { get; }

    public StorageSchemaVersion ToVersion { get; }

    public string Id { get; }

    public SettingMigrationStep(StorageSchemaVersion fromVersion, string id, Func<JsonElement, JsonElement> transform)
    {
        if (!fromVersion.IsValid || fromVersion.Number == 0 || fromVersion.Number == uint.MaxValue)
        {
            throw new ArgumentException("A migration source version must be positive and incrementable.", nameof(fromVersion));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(transform);
        FromVersion = fromVersion;
        ToVersion = new StorageSchemaVersion(fromVersion.Number + 1);
        Id = id;
        _transform = transform;
    }

    internal JsonElement Apply(JsonElement value)
    {
        var migrated = _transform(value.Clone());
        if (migrated.ValueKind == JsonValueKind.Undefined)
        {
            throw new InvalidOperationException("A setting migration returned an undefined value.");
        }

        return migrated.Clone();
    }
}

public sealed class ScopedSettingValue
{
    internal ScopedSettingValue(string key, SettingScope scope, string scopeIdHash, StorageSchemaVersion schemaVersion, JsonElement value)
    {
        Key = key;
        Scope = scope;
        ScopeIdHash = scopeIdHash;
        SchemaVersion = schemaVersion;
        Value = value.Clone();
    }

    public string Key { get; }

    public SettingScope Scope { get; }

    public string ScopeIdHash { get; }

    public StorageSchemaVersion SchemaVersion { get; }

    public JsonElement Value { get; }
}

public sealed class SettingsSnapshot
{
    internal SettingsSnapshot(IEnumerable<ScopedSettingValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var copy = values.ToArray();
        if (copy.Any(value => value is null))
        {
            throw new ArgumentException("Settings snapshots cannot contain null entries.", nameof(values));
        }

        var addresses = copy.Select(value => Address(value.Key, value.Scope, value.ScopeIdHash)).ToArray();
        if (addresses.Distinct(StringComparer.Ordinal).Count() != addresses.Length)
        {
            throw new ArgumentException("A setting scope identity can contain only one value per key.", nameof(values));
        }

        Entries = Array.AsReadOnly(copy.OrderBy(value => value.Key, StringComparer.Ordinal)
            .ThenBy(value => value.Scope).ThenBy(value => value.ScopeIdHash, StringComparer.Ordinal).ToArray());
    }

    public ReadOnlyCollection<ScopedSettingValue> Entries { get; }

    internal static string Address(string key, SettingScope scope, string scopeIdHash)
        => string.Concat(key, "\0", (int)scope, "\0", scopeIdHash);
}

public sealed record EffectiveSetting<T>(T Value, SettingScope? SourceScope, bool IsDefault)
{
    public bool IsOverridden => SourceScope is not null;
}

internal static class SettingScopeIdentity
{
    internal static string Hash(string identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);
        if (identity.Length > 256 || identity.Any(char.IsControl))
        {
            throw new ArgumentException("A scope identity must be bounded and contain no control characters.", nameof(identity));
        }

        var normalized = identity.Normalize(NormalizationForm.FormC);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)));
    }
}
