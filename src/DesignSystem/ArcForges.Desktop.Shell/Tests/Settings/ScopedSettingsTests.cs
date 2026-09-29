// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.Json.Serialization;
using ArcForges.Foundation.Versions;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests;

public sealed class ScopedSettingsTests
{
    private static readonly SettingScope[] _allScopes =
    [
        SettingScope.Application,
        SettingScope.Workspace,
        SettingScope.Device,
        SettingScope.Instance
    ];

    [Fact]
    public void ResolutionCoversEveryScopeCombinationAndExplainsTheWinningSource()
    {
        var context = new SettingScopeContext("app", "workspace", "device", "instance");
        var first = Definition("editor.theme", [SettingScope.Instance, SettingScope.Workspace, SettingScope.Device, SettingScope.Application]);
        var second = Definition("editor.font-size", [SettingScope.Device, SettingScope.Application, SettingScope.Instance, SettingScope.Workspace]);

        for (var mask = 0; mask < 1 << _allScopes.Length; mask++)
        {
            var values = new List<ScopedSettingValue>();
            AddValues(first, mask, values);
            AddValues(second, mask, values);
            var snapshot = new SettingsSnapshot(values);

            AssertResolution(first, mask, snapshot, context);
            AssertResolution(second, mask, snapshot, context);
        }

        var allValues = new List<ScopedSettingValue>();
        AddValues(first, (1 << _allScopes.Length) - 1, allValues);
        AddValues(second, (1 << _allScopes.Length) - 1, allValues);
        var applicationOnlyContext = new SettingScopeContext("app");
        var applicationOnlySnapshot = new SettingsSnapshot(allValues);
        Assert.Equal(SettingScope.Application,
            ScopedSettingsResolver.Resolve(first, applicationOnlySnapshot, applicationOnlyContext).SourceScope);
        Assert.Equal(SettingScope.Application,
            ScopedSettingsResolver.Resolve(second, applicationOnlySnapshot, applicationOnlyContext).SourceScope);

        Assert.Throws<ArgumentException>(() => Definition("editor.invalid-sync", _allScopes, [SettingScope.Device]));
        Assert.Throws<ArgumentException>(() => Definition("editor.bad--key", [SettingScope.Application]));
    }

    [Fact]
    public void StoreMigratesOlderValuesAtomicallyAndRefusesDowngradeWithoutChangingTheFile()
    {
        using var temporary = new TemporaryDirectory();
        var application = ApplicationKey.Parse("settings-tests");
        var versionOne = Definition("editor.theme", [SettingScope.Application], version: 1);
        var oldValue = versionOne.ToStoredValue(SettingScope.Application, "app", "legacy");
        var store = new DeviceLocalSettingsStore(application, temporary.Path);
        store.Save([oldValue]);

        var versionTwo = Definition("editor.theme", [SettingScope.Application], version: 2,
        [
            new SettingMigrationStep(new StorageSchemaVersion(1), "editor-theme-r1", static value =>
                JsonSerializer.SerializeToElement(value.GetString() + "-migrated", SettingsJsonContext.Default.String))
        ]);
        var migrated = store.Load([versionTwo]);
        var migratedDirectly = ((ISettingSchema)versionTwo).Migrate(oldValue);

        Assert.Equal(SettingsLoadStatus.Migrated, migrated.Status);
        Assert.Equal("legacy-migrated", migratedDirectly.Value.GetString() ?? string.Empty);
        var resolved = ScopedSettingsResolver.Resolve(versionTwo, migrated.Snapshot,
            new SettingScopeContext("app"));
        Assert.Equal("legacy-migrated", resolved.Value);
        Assert.Equal(SettingScope.Application, resolved.SourceScope);
        Assert.False(resolved.IsDefault);

        var migratedBytes = File.ReadAllBytes(store.FilePath);
        var downgrade = store.Load([versionOne]);
        Assert.Equal(SettingsLoadStatus.MigrationRefused, downgrade.Status);
        Assert.Equal(migratedBytes, File.ReadAllBytes(store.FilePath));

        var failedStore = new DeviceLocalSettingsStore(application, temporary.Path,
            new AtomicLayoutFileWriter(static () => throw new IOException("Simulated replace interruption.")));
        var failedMigration = failedStore.Load([Definition("editor.theme", [SettingScope.Application], version: 3,
            migrations:
        [
            new SettingMigrationStep(new StorageSchemaVersion(1), "editor-theme-r1", static value =>
                JsonSerializer.SerializeToElement(value.GetString() + "-migrated", SettingsJsonContext.Default.String)),
            new SettingMigrationStep(new StorageSchemaVersion(2), "editor-theme-r2", static value =>
                JsonSerializer.SerializeToElement(value.GetString() + "-next", SettingsJsonContext.Default.String))
        ])]);

        Assert.Equal(SettingsLoadStatus.Unavailable, failedMigration.Status);
        Assert.Equal(migratedBytes, File.ReadAllBytes(store.FilePath));
    }

    [Fact]
    public void SynchronizationProjectionNeverIncludesDeviceOrInstanceSettings()
    {
        using var temporary = new TemporaryDirectory();
        var versionOne = Definition("editor.theme-name", _allScopes,
            [SettingScope.Application, SettingScope.Workspace]);
        var versionTwo = Definition("editor.theme-name", _allScopes,
            [SettingScope.Application, SettingScope.Workspace], version: 2,
            migrations:
        [
            new SettingMigrationStep(new StorageSchemaVersion(1), "editor-theme-r1", static value =>
                JsonSerializer.SerializeToElement(value.GetString() + "-migrated", SettingsJsonContext.Default.String))
        ]);
        var store = new DeviceLocalSettingsStore(ApplicationKey.Parse("settings-tests"), temporary.Path);
        var values = _allScopes.Select(scope => versionOne.ToStoredValue(scope, ScopeId(scope), scope.ToString())).ToArray();

        store.Save(values);
        var loaded = new SettingsSnapshot(values);
        var sync = store.CreateSyncSnapshot(loaded, [versionTwo]);

        Assert.Equal([SettingScope.Application, SettingScope.Workspace], sync.Entries.Select(value => value.Scope).ToArray());
        Assert.DoesNotContain(sync.Entries, value => value.Scope is SettingScope.Device or SettingScope.Instance);
        Assert.All(sync.Entries, value => Assert.Equal(2u, value.SchemaVersion.Number));
        Assert.All(sync.Entries, value => Assert.EndsWith("-migrated", value.Value.GetString() ?? string.Empty));
    }

    private static SettingDefinition<string> Definition(
        string key,
        IEnumerable<SettingScope> order,
        IEnumerable<SettingScope>? syncable = null,
        uint version = 1,
        IEnumerable<SettingMigrationStep>? migrations = null)
        => new(key, "default", SettingsJsonContext.Default.String, new StorageSchemaVersion(version),
            _allScopes.Where(scope => order.Contains(scope)), order, syncable, migrations);

    private static void AddValues(SettingDefinition<string> definition, int mask, List<ScopedSettingValue> values)
    {
        for (var index = 0; index < _allScopes.Length; index++)
        {
            if ((mask & (1 << index)) != 0 && definition.AllowedScopes.Contains(_allScopes[index]))
            {
                var scope = _allScopes[index];
                values.Add(definition.ToStoredValue(scope, ScopeId(scope), scope.ToString()));
            }
        }
    }

    private static void AssertResolution(SettingDefinition<string> definition, int mask,
        SettingsSnapshot snapshot, SettingScopeContext context)
    {
        var expected = definition.ResolutionOrder.FirstOrDefault(scope =>
            (mask & (1 << Array.IndexOf(_allScopes, scope))) != 0);
        var hasValue = definition.ResolutionOrder.Any(scope =>
            (mask & (1 << Array.IndexOf(_allScopes, scope))) != 0);

        var effective = ScopedSettingsResolver.Resolve(definition, snapshot, context);

        Assert.Equal(hasValue ? expected.ToString() : "default", effective.Value);
        Assert.Equal(hasValue ? expected : null, effective.SourceScope);
        Assert.Equal(!hasValue, effective.IsDefault);
        Assert.Equal(hasValue, effective.IsOverridden);
    }

    private static string ScopeId(SettingScope scope) => scope switch
    {
        SettingScope.Application => "app",
        SettingScope.Workspace => "workspace",
        SettingScope.Device => "device",
        SettingScope.Instance => "instance",
        _ => throw new ArgumentOutOfRangeException(nameof(scope))
    };

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ArcForges-settings-tests", Guid.NewGuid().ToString("N"));

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}

[JsonSerializable(typeof(string))]
internal partial class SettingsJsonContext : JsonSerializerContext
{
}
