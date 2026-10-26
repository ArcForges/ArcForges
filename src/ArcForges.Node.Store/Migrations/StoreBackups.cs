// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Migrations;

/// <summary>
/// Pre-migration backups (13-distribution-updates section 6): before migrating, the store is checkpointed
/// (<c>wal_checkpoint(TRUNCATE)</c>) and copied to <c>records/backups/store-&lt;from&gt;-&lt;to&gt;-&lt;timestamp&gt;.db</c>;
/// the last three backups are kept. Retained copies preserve records and names, but never sealed task values (MR-13).
/// </summary>
public static partial class StoreBackups
{
    /// <summary>How many backups are kept.</summary>
    public const int Kept = 3;

    /// <summary>The backup directory of a data root.</summary>
    public static string Directory(string dataRoot) => Path.Combine(dataRoot, "records", "backups");

    /// <summary>The backups of a data root, oldest first.</summary>
    public static IReadOnlyList<string> List(string dataRoot)
    {
        var directory = Directory(dataRoot);
        if (!System.IO.Directory.Exists(directory))
        {
            return [];
        }

        return [.. System.IO.Directory.EnumerateFiles(directory, "store-*.db")
            .Select(path => (Path: path, Match: BackupName().Match(Path.GetFileName(path))))
            .Where(item => item.Match.Success)
            .OrderBy(item => item.Match.Groups["at"].Value, StringComparer.Ordinal)
            .ThenBy(item => item.Path, StringComparer.Ordinal)
            .Select(item => item.Path)];
    }

    /// <summary>Excludes sealed values from all older retained copies before the node store is opened.</summary>
    internal static void SanitizeRetained(string dataRoot, TimeProvider clock)
    {
        foreach (var path in List(dataRoot))
        {
            Sanitize(path, clock);
        }
    }

    /// <summary>
    /// Checkpoints the store through <paramref name="connection"/> (the writer, before any migration step), copies it with
    /// SQLite's online backup to a temporary file, checks the copy's integrity, publishes it by rename and keeps the last three.
    /// </summary>
    internal static string Create(SqliteConnection connection, string dataRoot, int fromVersion, int toVersion, TimeProvider clock)
    {
        using (var checkpoint = connection.CreateCommand())
        {
            checkpoint.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            checkpoint.ExecuteNonQuery();
        }

        var directory = Directory(dataRoot);
        StorePaths.CreatePrivateDirectory(directory);
        var at = clock.GetUtcNow().UtcDateTime.ToString("yyyyMMdd'T'HHmmssfff'Z'", CultureInfo.InvariantCulture);
        var name = string.Create(CultureInfo.InvariantCulture, $"store-{fromVersion}-{toVersion}-{at}.db");
        var path = Path.Combine(directory, name);
        for (var suffix = 1; File.Exists(path); suffix++)
        {
            path = Path.Combine(directory, string.Create(CultureInfo.InvariantCulture, $"store-{fromVersion}-{toVersion}-{at}.{suffix}.db"));
        }

        var temporary = path + ".partial";
        File.Delete(temporary);
        try
        {
            using (var destination = new SqliteConnection(StorePaths.ConnectionString(temporary, SqliteOpenMode.ReadWriteCreate)))
            {
                destination.Open();
                connection.BackupDatabase(destination);
            }

            Sanitize(temporary, clock);
            File.Move(temporary, path);
        }
        finally
        {
            File.Delete(temporary);
        }

        foreach (var old in List(dataRoot).SkipLast(Kept))
        {
            File.Delete(old);
        }

        return path;
    }

    private static void Sanitize(string path, TimeProvider clock)
    {
        try
        {
            using var copy = new SqliteConnection(StorePaths.ConnectionString(path, SqliteOpenMode.ReadWrite));
            copy.Open();
            using var command = copy.CreateCommand();
            command.CommandText = "PRAGMA secure_delete=ON;";
            command.ExecuteNonQuery();
            command.CommandText = "PRAGMA journal_mode=DELETE;";
            if (!string.Equals(command.ExecuteScalar() as string, "delete", StringComparison.OrdinalIgnoreCase))
            {
                throw new StoreBackupException("The retained backup could not leave WAL mode before sanitization.");
            }

            // An older schema may predate task_secret; never migrate the copy or add tables to it.
            command.CommandText = "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'task_secret';";
            if (Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) != 0)
            {
                command.CommandText = $"UPDATE task_secret SET {TaskSecrets.Tombstone}, purge_after = $now WHERE key_id <> $purged;";
                command.Parameters.AddWithValue("$now", StoreTime.NowMicroseconds(clock));
                command.Parameters.AddWithValue("$purged", TaskSecrets.PurgedKeyId);
                command.ExecuteNonQuery();
                command.Parameters.Clear();
            }

            // Rebuild the copy, including older free pages, so it cannot retain the old encrypted payloads.
            command.CommandText = "VACUUM;";
            command.ExecuteNonQuery();
            command.CommandText = "PRAGMA integrity_check;";
            var result = command.ExecuteScalar() as string;
            if (!string.Equals(result, "ok", StringComparison.Ordinal))
            {
                throw new StoreBackupException($"The retained backup failed its integrity check: {result}.");
            }
        }
        catch (Exception exception) when (exception is not StoreBackupException
            && (exception is SqliteException or IOException or UnauthorizedAccessException))
        {
            throw new StoreBackupException($"The backup {Path.GetFileName(path)} could not exclude sealed task values.", exception);
        }
    }

    [GeneratedRegex(@"^store-(?<from>\d+)-(?<to>\d+)-(?<at>\d{8}T\d{9}Z)(\.\d+)?\.db$", RegexOptions.CultureInvariant)]
    private static partial Regex BackupName();
}

/// <summary>A pre-migration backup could not be written or verified; the store was not migrated.</summary>
public sealed class StoreBackupException : IOException
{
    /// <summary>Creates the exception.</summary>
    public StoreBackupException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public StoreBackupException()
    {
    }

    /// <summary>Creates the exception.</summary>
    public StoreBackupException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
