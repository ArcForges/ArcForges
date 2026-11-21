// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Migrations;

/// <summary>The independently restored input for a staged Node contraction.</summary>
internal sealed class VerifiedNodeContractionArchive
{
    private readonly NodeContractionScope _source;
    private readonly string _backupRoot;
    private readonly string _stagingRoot;
    private readonly ContractionPaths.NativeIdentity _originalIdentity;
    private readonly ContractionPaths.NativeIdentity _historyIdentity;
    private readonly ContractionPaths.NativeIdentity _stagingIdentity;

    private VerifiedNodeContractionArchive(NodeContractionScope source, string backupRoot, string stagingRoot,
        ContractionPaths.NativeIdentity originalIdentity, ContractionPaths.NativeIdentity historyIdentity,
        ContractionPaths.NativeIdentity stagingIdentity, string original, string manifest, string history, string restore)
    {
        _source = source;
        _backupRoot = backupRoot;
        _stagingRoot = stagingRoot;
        _originalIdentity = originalIdentity;
        _historyIdentity = historyIdentity;
        _stagingIdentity = stagingIdentity;
        StagedDatabasePath = StorePaths.Database(stagingRoot);
        SourceDatabaseSha256 = original;
        BackupManifestSha256 = manifest;
        HistoryArchiveSha256 = history;
        RestoreDatabaseSha256 = restore;
        ScopeReceiptSha256 = source.ReceiptSha256;
    }

    internal string StagedDatabasePath { get; }
    internal string SourceDatabaseSha256 { get; }
    internal string BackupManifestSha256 { get; }
    internal string HistoryArchiveSha256 { get; }
    internal string RestoreDatabaseSha256 { get; }
    internal string ScopeReceiptSha256 { get; }

    internal static VerifiedNodeContractionArchive Restore(NodeContractionScope source, NodeSecretStore sourceSecrets,
        string backupRoot, NodeSecretStore backupSecrets, string stagingRoot, NodeSecretStore stagingSecrets)
    {
        source.VerifyHeld();
        ContractionPaths.RequireSeparateRoots(source.DataRoot, backupRoot, stagingRoot);
        string original = StorePaths.Database(source.DataRoot);
        string history = StorePaths.Database(backupRoot);
        string staging = StorePaths.Database(stagingRoot);
        RequireCheckpointed(original);
        RequireCheckpointed(history);
        var originalIdentity = ContractionPaths.NamedRegularIdentity(original);
        var historyIdentity = ContractionPaths.NamedRegularIdentity(history);
        if (originalIdentity == historyIdentity)
            throw new StoreIncompatibleException("The historical archive shares the original database file.");
        string originalDigest = Digest(original);
        string historyDigest = Digest(history);
        string manifestDigest = Digest(Manifest(backupRoot));

        // Authenticate the archive against the latest owner and prove it can be restored into a distinct root.
        DurableCommandStore.RestoreBackup(backupRoot, backupSecrets, source.DataRoot, sourceSecrets, stagingRoot, stagingSecrets, source);
        RequireCheckpointed(staging);
        var stagingIdentity = ContractionPaths.NamedRegularIdentity(staging);
        string stagingDigest = Digest(staging);
        if (stagingIdentity == originalIdentity || stagingIdentity == historyIdentity
            || !string.Equals(historyDigest, stagingDigest, StringComparison.Ordinal))
            throw new StoreIncompatibleException("The restored database does not match its historical archive.");

        // The durable manifest fences command receipts. Compare shared settings, legacy history and the other live
        // rows as well, since they can change without advancing the durable command sequence.
        VerifyArchiveRows(original, staging);
        var archive = new VerifiedNodeContractionArchive(source, backupRoot, stagingRoot, originalIdentity, historyIdentity,
            stagingIdentity, originalDigest, manifestDigest, historyDigest, stagingDigest);
        archive.VerifyHeld();
        return archive;
    }

    internal void VerifyHeld()
    {
        VerifyRetainedInputs();
        RequireCheckpointed(StagedDatabasePath);
        VerifyStagedIdentity();
        if (!string.Equals(RestoreDatabaseSha256, Digest(StagedDatabasePath), StringComparison.Ordinal))
            throw new StoreIncompatibleException("The verified staging database changed while held.");
    }

    internal void VerifyStagedIdentity()
    {
        if (_stagingIdentity != ContractionPaths.NamedRegularIdentity(StagedDatabasePath))
            throw new StoreIncompatibleException("The staged database file identity changed during contraction.");
    }

    internal void VerifyCommit()
    {
        VerifyRetainedInputs();
        VerifyStagedIdentity();
    }

    private void VerifyRetainedInputs()
    {
        _source.VerifyHeld();
        ContractionPaths.RequireSeparateRoots(_source.DataRoot, _backupRoot, _stagingRoot);
        string original = StorePaths.Database(_source.DataRoot);
        string history = StorePaths.Database(_backupRoot);
        RequireCheckpointed(original);
        RequireCheckpointed(history);
        if (_originalIdentity != ContractionPaths.NamedRegularIdentity(original)
            || _historyIdentity != ContractionPaths.NamedRegularIdentity(history)
            || !string.Equals(ScopeReceiptSha256, _source.ReceiptSha256, StringComparison.Ordinal)
            || !string.Equals(SourceDatabaseSha256, Digest(original), StringComparison.Ordinal)
            || !string.Equals(BackupManifestSha256, Digest(Manifest(_backupRoot)), StringComparison.Ordinal)
            || !string.Equals(HistoryArchiveSha256, Digest(history), StringComparison.Ordinal))
            throw new StoreIncompatibleException("The verified original or historical archive changed while held.");
    }

    private static void VerifyArchiveRows(string source, string restore)
    {
        using var original = OpenSnapshot(source);
        using var restored = OpenSnapshot(restore);
        var originalSchema = Schema(original);
        if (!originalSchema.SequenceEqual(ReferenceSchema(StoreMigrations.ExpandedSchemaVersion)) || !originalSchema.SequenceEqual(Schema(restored)))
            throw new StoreIncompatibleException("The original and restored schemas must match the released expanded store.");

        foreach (var table in originalSchema.Where(entry => entry.Type == "table"))
        {
            using var columns = original.CreateCommand();
            columns.CommandText = "SELECT name FROM pragma_table_info($table) ORDER BY cid;";
            columns.Parameters.AddWithValue("$table", table.Name);
            using var fields = columns.ExecuteReader();
            var names = new List<string>();
            while (fields.Read())
                names.Add(fields.GetString(0));

            // A managed snapshot may precede the clean-shutdown timestamp. Retained backups purge sealed task values.
            if (table.Name == "store_meta")
                names.Remove("clean_shutdown_at");
            if (table.Name == "task_secret")
            {
                names.RemoveAll(name => name is "key_id" or "nonce" or "ciphertext" or "tag" or "purge_after");
                using var sanitized = restored.CreateCommand();
                sanitized.CommandText = """
                    SELECT EXISTS(SELECT 1 FROM task_secret WHERE key_id <> 'purged' OR nonce <> zeroblob(12)
                        OR ciphertext <> x'00' OR tag <> zeroblob(16));
                    """;
                if (!Equals(sanitized.ExecuteScalar(), 0L))
                    throw new StoreIncompatibleException("The historical archive contains sealed task values.");
            }

            string projection = string.Join(", ", names.Select(QuoteIdentifier));
            string order = string.Join(", ", names.Select(name => $"typeof({QuoteIdentifier(name)}), {QuoteIdentifier(name)} COLLATE BINARY"));
            string query = $"SELECT {projection} FROM {QuoteIdentifier(table.Name)} ORDER BY {order};";
            using var before = original.CreateCommand();
            using var after = restored.CreateCommand();
            before.CommandText = query;
            after.CommandText = query;
            using var originalRows = before.ExecuteReader();
            using var restoredRows = after.ExecuteReader();
            while (originalRows.Read())
            {
                if (!restoredRows.Read())
                    throw new StoreIncompatibleException("The historical archive is missing original rows.");
                for (int column = 0; column < originalRows.FieldCount; column++)
                {
                    object left = originalRows.GetValue(column);
                    object right = restoredRows.GetValue(column);
                    bool equal = left is byte[] a && right is byte[] b ? a.AsSpan().SequenceEqual(b) : Equals(left, right);
                    if (!equal)
                        throw new StoreIncompatibleException("The historical archive disagrees with original retained data.");
                }
            }

            if (restoredRows.Read())
                throw new StoreIncompatibleException("The historical archive contains unbound additional rows.");
        }
    }

    private static (string Type, string Name, string? Sql)[] Schema(SqliteConnection database)
    {
        using var schema = database.CreateCommand();
        schema.CommandText = """
            SELECT type, name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' OR name = 'sqlite_sequence'
            ORDER BY type, name COLLATE BINARY;
            """;
        using var rows = schema.ExecuteReader();
        var definitions = new List<(string Type, string Name, string? Sql)>();
        while (rows.Read())
            definitions.Add((rows.GetString(0), rows.GetString(1), rows.IsDBNull(2) ? null : rows.GetString(2)));
        return [.. definitions];
    }

    internal static void VerifySchema15(SqliteConnection source)
    {
        if (!Schema(source).SequenceEqual(ReferenceSchema(15)))
            throw new StoreIncompatibleException("Preparation requires the original, released Node schema 15.");
    }

    private static (string Type, string Name, string? Sql)[] ReferenceSchema(int version)
    {
        using var database = new SqliteConnection("Data Source=:memory:;Pooling=False");
        database.Open();
        database.CreateFunction<long>("arcforges_store_reader_version", () => version);
        using var step = database.CreateCommand();
        foreach (var migration in StoreMigrations.Expanded.Steps.Take(version))
        {
            step.CommandText = migration.Sql;
            step.ExecuteNonQuery();
        }

        return Schema(database);
    }

    private static SqliteConnection OpenSnapshot(string path)
    {
        string uri = NodeStore.ImmutableStoreUri(path)
            ?? throw new StoreIncompatibleException("The contraction snapshot requires a supported local database path.");
        var database = new SqliteConnection(StorePaths.ConnectionString(uri, SqliteOpenMode.ReadOnly));
        try
        {
            database.Open();
            using var flags = database.CreateCommand();
            flags.CommandText = "PRAGMA trusted_schema=OFF;";
            flags.ExecuteNonQuery();
            return database;
        }
        catch
        {
            database.Dispose();
            throw;
        }
    }

    private static string QuoteIdentifier(string identifier) => "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

    private static void RequireCheckpointed(string path)
    {
        foreach (string suffix in new[] { "-wal", "-journal" })
        {
            try
            {
                _ = File.GetAttributes(path + suffix);
                throw new StoreIncompatibleException("Contraction requires a checkpointed database and verified archive.");
            }
            catch (FileNotFoundException)
            {
            }
        }
    }

    private static string Manifest(string backupRoot) => Path.Combine(backupRoot, "v2-backup.manifest");

    private static string Digest(string path)
    {
        using var bytes = ContractionPaths.OpenRegularRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }
}
