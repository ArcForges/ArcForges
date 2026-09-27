// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Foundation.Versions;

namespace ArcForges.Persistence.Sqlite.Migrations;

/// <summary>Runs owner-authored migrations before normal writes, committing one numbered step at a time.</summary>
public sealed class MigrationRunner
{
    private const string HistoryTable = "__arcforges_migration_history";
    private readonly StoreDatabase _database;

    internal MigrationRunner(StoreDatabase database) => _database = database;

    /// <summary>The highest durably applied migration, or null when no migration has been applied.</summary>
    public StorageSchemaVersion? CurrentVersion => _database.RunSchemaExclusive(session =>
        session.WithTransaction(context =>
        {
            var history = ReadHistory(context);
            return history.Count == 0 ? (StorageSchemaVersion?)null : new(history[^1].Version);
        }));

    /// <summary>Applies a prefix of the complete immutable history; downgrades are refused without changes.</summary>
    public StorageSchemaVersion MigrateTo(MigrationPlan plan, StorageSchemaVersion target)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!target.IsValid || (target.Number != 0 && !plan.Steps.Any(step => step.Version == target)))
            throw new ArgumentException("The target must be zero or a migration present in the complete plan.", nameof(target));

        return _database.RunSchemaExclusive(session =>
        {
            var history = session.WithTransaction(ReadHistory);
            var current = history.Count == 0 ? 0u : history[^1].Version;
            if (target.Number < current)
                throw new InvalidOperationException($"Storage schema downgrade from {current} to {target.Number} is unsupported; no changes were applied.");
            if (history.Count > plan.Steps.Count)
                throw new InvalidOperationException("The supplied plan omits applied migration history.");
            for (var index = 0; index < history.Count; index++)
            {
                var applied = history[index];
                var expected = plan.Steps[index];
                if (applied.Version != expected.Version.Number || applied.Id != expected.Id || applied.Checksum != expected.Checksum)
                    throw new InvalidOperationException("Applied migration history differs from the supplied plan; preserve the original numbered steps.");
            }

            foreach (var step in plan.Steps.Skip(history.Count).TakeWhile(step => step.Version <= target))
            {
                session.WithTransaction(context =>
                {
                    using (var create = context.CreateCommand($"CREATE TABLE IF NOT EXISTS {HistoryTable} (version INTEGER PRIMARY KEY, step_id TEXT UNIQUE NOT NULL, checksum TEXT NOT NULL)"))
                        create.ExecuteNonQuery();
                    foreach (var sql in step.Statements)
                        context.ExecuteSchemaStatement(sql);
                    using var record = context.CreateCommand($"INSERT INTO {HistoryTable} (version, step_id, checksum) VALUES ($version, $id, $checksum)");
                    record.Parameters.AddWithValue("$version", (long)step.Version.Number);
                    record.Parameters.AddWithValue("$id", step.Id);
                    record.Parameters.AddWithValue("$checksum", step.Checksum);
                    record.ExecuteNonQuery();
                    using var metadata = context.CreateCommand("INSERT INTO sys_meta (key, value) VALUES ('storageSchemaVersion', $version) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
                    metadata.Parameters.AddWithValue("$version", step.Version.ToString());
                    metadata.ExecuteNonQuery();
                    return 0;
                });
            }
            return target;
        });
    }

    private static List<AppliedStep> ReadHistory(SqliteCommitContext context)
    {
        using var exists = context.CreateCommand("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $name");
        exists.Parameters.AddWithValue("$name", HistoryTable);
        if (Convert.ToInt64(exists.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) == 0)
        {
            VerifyMetadata(context, 0);
            return [];
        }
        using var query = context.CreateCommand($"SELECT version, step_id, checksum FROM {HistoryTable} ORDER BY version");
        using var rows = query.ExecuteReader();
        List<AppliedStep> history = [];
        while (rows.Read())
        {
            var version = rows.GetInt64(0);
            if (version <= 0 || version > uint.MaxValue)
                throw new InvalidOperationException("Stored migration history contains an invalid migration number.");
            history.Add(new((uint)version, rows.GetString(1), rows.GetString(2)));
        }
        rows.Close();
        VerifyMetadata(context, history.Count == 0 ? 0 : history[^1].Version);
        return history;
    }

    private static void VerifyMetadata(SqliteCommitContext context, uint highest)
    {
        using var query = context.CreateCommand("SELECT value FROM sys_meta WHERE key = 'storageSchemaVersion'");
        var value = query.ExecuteScalar();
        if (value is null && highest == 0)
            return;
        if (value is not string text || !StorageSchemaVersion.TryParse(text, out var version) || version.Number != highest)
            throw new InvalidOperationException("Storage schema metadata differs from the highest applied migration; preserve evidence before recovery.");
    }

    private sealed record AppliedStep(uint Version, string Id, string Checksum);
}
