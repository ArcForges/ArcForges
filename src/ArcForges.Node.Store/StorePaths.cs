// SPDX-License-Identifier: AGPL-3.0-only
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store;

/// <summary>Paths and connection settings of the store (node-store.md section 1, 06-storage-workspaces section 1).</summary>
public static class StorePaths
{
    /// <summary>Owner-only directory mode (0700) for the data root and the store's directories on Linux.</summary>
    public const UnixFileMode PrivateDirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    /// <summary><c>&lt;data root&gt;/store/node.db</c>.</summary>
    public static string Database(string dataRoot) => Path.Combine(dataRoot, "store", "node.db");

    /// <summary>
    /// Creates <paramref name="directory"/> and any missing parents. On Linux a directory this call creates gets mode 0700
    /// (the data root is owner-only; Security.Secrets consumer obligation); existing directories are left as they are.
    /// </summary>
    public static void CreatePrivateDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        var full = Path.GetFullPath(directory);
        if (System.IO.Directory.Exists(full))
        {
            return;
        }

        var parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(full));
        if (parent is not null && !System.IO.Directory.Exists(parent))
        {
            CreatePrivateDirectory(parent);
        }

        if (OperatingSystem.IsWindows())
        {
            System.IO.Directory.CreateDirectory(full);
        }
        else
        {
            System.IO.Directory.CreateDirectory(full, PrivateDirectoryMode);
        }
    }

    /// <summary>The connection string of a store file: no pooling (the writer keeps its connection; readers are short-lived).</summary>
    internal static string ConnectionString(string path, SqliteOpenMode mode) => new SqliteConnectionStringBuilder
    {
        DataSource = path,
        Mode = mode,
        Pooling = false,
        DefaultTimeout = 30,
    }.ToString();
}
