// SPDX-License-Identifier: AGPL-3.0-only

using System.Collections.ObjectModel;
using ArcForges.Foundation.Versions;

namespace ArcForges.Persistence.Sqlite.Migrations;

/// <summary>The complete historical migration sequence for one owner-controlled database.</summary>
public sealed class MigrationPlan
{
    public ReadOnlyCollection<MigrationStep> Steps { get; }
    public StorageSchemaVersion LatestVersion => Steps.Count == 0 ? new(0) : Steps[^1].Version;

    public MigrationPlan(IEnumerable<MigrationStep> steps)
    {
        ArgumentNullException.ThrowIfNull(steps);
        var copy = steps.ToArray();
        if (copy.Any(step => step is null))
            throw new ArgumentException("Migration steps cannot be null.", nameof(steps));
        if (copy.Select(step => step.Version.Number).Distinct().Count() != copy.Length ||
            copy.Select(step => step.Id).Distinct(StringComparer.Ordinal).Count() != copy.Length)
            throw new ArgumentException("Migration numbers and identities must be unique.", nameof(steps));
        Steps = Array.AsReadOnly(copy.OrderBy(step => step.Version.Number).ToArray());
    }
}
