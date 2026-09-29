// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Desktop.Shell;

/// <summary>Resolves a typed setting using only that definition's declared scope order.</summary>
public static class ScopedSettingsResolver
{
    public static EffectiveSetting<T> Resolve<T>(
        SettingDefinition<T> definition,
        SettingsSnapshot snapshot,
        SettingScopeContext context)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(context);

        var values = snapshot.Entries
            .Where(value => string.Equals(value.Key, definition.Key, StringComparison.Ordinal))
            .ToDictionary(value => SettingsSnapshot.Address(value.Key, value.Scope, value.ScopeIdHash), StringComparer.Ordinal);

        foreach (var scope in definition.ResolutionOrder)
        {
            var scopeIdHash = context[scope];
            if (scopeIdHash is null)
            {
                continue;
            }

            var address = SettingsSnapshot.Address(definition.Key, scope, scopeIdHash);
            if (values.TryGetValue(address, out var stored))
            {
                var current = definition.Migrate(stored);
                return new EffectiveSetting<T>(definition.ReadValue(current), scope, IsDefault: false);
            }
        }

        return new EffectiveSetting<T>(definition.DefaultValue, SourceScope: null, IsDefault: true);
    }
}
