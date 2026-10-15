// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Migrations;

/// <summary>
/// Pre-migration backups (13-distribution-updates section 6): before migrating, the store is checkpointed
/// (<c>wal_checkpoint(TRUNCATE)</c>) and copied to <c>records/backups/store-&lt;from&gt;-&lt;to&gt;-&lt;timestamp&gt;.db</c>;
/// the last three backups are kept.
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

            using (var check = new SqliteConnection(StorePaths.ConnectionString(temporary, SqliteOpenMode.ReadOnly)))
            {
                check.Open();
                using var command = check.CreateCommand();
                command.CommandText = "PRAGMA integrity_check;";
                var result = command.ExecuteScalar() as string;
                if (!string.Equals(result, "ok", StringComparison.Ordinal))
                {
                    throw new StoreBackupException($"The pre-migration backup failed its integrity check: {result}.");
                }
            }

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
