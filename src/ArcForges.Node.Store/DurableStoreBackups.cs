// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.Node.Store;

internal sealed record DurableBackupEntry(string Owner, string Epoch, string KeyReference, long Sequence, string History, string State);
internal sealed record DurableBackupManifest(int Schema, string DatabaseSha256, string SigningKeyReference, DurableBackupEntry[] Epochs);

[JsonSerializable(typeof(DurableBackupManifest))]
internal sealed partial class DurableBackupJsonContext : JsonSerializerContext;

internal sealed partial class DurableCommandStore
{
    // A complete snapshot is a DB, every referenced epoch key, and an authenticated manifest.
    // A legacy pre-migration DB-only backup is intentionally not a ready V2 restore package.
    internal void CreateBackup(string backupRoot, NodeSecretStore backupSecrets)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (MaintenanceRequired || !Path.IsPathFullyQualified(backupRoot) || Directory.Exists(backupRoot))
                throw new DurableStoreMaintenanceException();
            var locks = new List<FileStream>();
            var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            try
            {
                using var catalogue = DurableEpochFence.OpenCatalogueLock(_store.DataRoot);
                var entries = _store.Read(ReadBackupEntries);
                foreach (var owner in entries.Select(e => e.Owner).Distinct(StringComparer.Ordinal).Where(owner => owner != _owner))
                    locks.Add(DurableEpochFence.OpenPrivate(DurableEpochFence.PathFor(_store.DataRoot, owner) + ".lock", FileMode.OpenOrCreate));
                VerifyFenceCatalogue(_store.DataRoot, entries);
                foreach (var entry in entries)
                {
                    if (!entry.KeyReference.StartsWith(_secrets.Backend + "|", StringComparison.Ordinal))
                        throw new DurableStoreMaintenanceException();
                    byte[] key = entry.KeyReference == _fence.KeyReference ? _key : ReadProtectedKey(_secrets, entry.KeyReference);
                    keys.TryAdd(entry.KeyReference, key);
                    var authority = DurableEpochFence.Read(DurableEpochFence.PathFor(_store.DataRoot, entry.Owner), key);
                    if (!Matches(entry, authority)) throw new DurableStoreMaintenanceException();
                }
                StorePaths.CreatePrivateDirectory(backupRoot);
                string database = StorePaths.Database(backupRoot);
                StorePaths.CreatePrivateDirectory(Path.GetDirectoryName(database)!);
                _store.CopyOwnerSnapshot(database); // Reuses the V1 secret-retention sanitization, not V1 identity expiry.
                foreach (var entry in entries)
                {
                    backupSecrets.Store.Write(Target(entry.KeyReference), keys[entry.KeyReference]);
                    var fence = new DurableEpochFence(entry.Owner, Convert.FromHexString(entry.Epoch), entry.KeyReference,
                        entry.Sequence, Convert.FromHexString(entry.History));
                    fence.Write(DurableEpochFence.PathFor(backupRoot, entry.Owner), keys[entry.KeyReference]);
                }
                using var stream = File.OpenRead(database);
                var manifest = new DurableBackupManifest(16, Convert.ToHexStringLower(SHA256.HashData(stream)),
                    _fence.KeyReference, entries);
                byte[] body = JsonSerializer.SerializeToUtf8Bytes(manifest, DurableBackupJsonContext.Default.DurableBackupManifest);
                DurableEpochFence.WritePrivate(Path.Combine(backupRoot, "v2-backup.manifest"),
                    [.. body, .. HMACSHA256.HashData(_key, body)]);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new DurableStoreMaintenanceException();
            }
            finally
            {
                foreach (var key in keys.Values.Where(key => !ReferenceEquals(key, _key))) CryptographicOperations.ZeroMemory(key);
                foreach (var lease in locks) lease.Dispose();
            }
        }
    }

    // The latest authority is retained independently of the backup being restored. Without
    // that outside evidence (or after any missing admission/effect observation), remain offline.
    internal static void RestoreBackup(string backupRoot, NodeSecretStore backupSecrets, string latestAuthorityRoot,
        NodeSecretStore latestAuthoritySecrets, string destinationRoot, NodeSecretStore destinationSecrets)
    {
        if (!Path.IsPathFullyQualified(backupRoot) || !Path.IsPathFullyQualified(latestAuthorityRoot)
            || !Path.IsPathFullyQualified(destinationRoot) || Directory.Exists(destinationRoot))
            throw new DurableStoreMaintenanceException();
        backupRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(backupRoot));
        latestAuthorityRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(latestAuthorityRoot));
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (latestAuthorityRoot.Equals(backupRoot, comparison)
            || latestAuthorityRoot.StartsWith(backupRoot + Path.DirectorySeparatorChar, comparison))
            throw new DurableStoreMaintenanceException();
        var locks = new List<FileStream>();
        var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            using var catalogue = DurableEpochFence.OpenCatalogueLock(latestAuthorityRoot);
            byte[] signed = File.ReadAllBytes(Path.Combine(backupRoot, "v2-backup.manifest"));
            if (signed.Length is < 33 or > 1048576) throw new DurableStoreMaintenanceException();
            byte[] body = signed[..^32];
            var manifest = JsonSerializer.Deserialize(body, DurableBackupJsonContext.Default.DurableBackupManifest)
                ?? throw new DurableStoreMaintenanceException();
            byte[] signingKey = ReadProtectedKey(backupSecrets, manifest.SigningKeyReference);
            keys.Add(manifest.SigningKeyReference, signingKey);
            if (manifest.Schema != 16 || manifest.Epochs.Length == 0 || !CryptographicOperations.FixedTimeEquals(
                HMACSHA256.HashData(signingKey, body), signed.AsSpan(signed.Length - 32)))
                throw new DurableStoreMaintenanceException();
            foreach (string owner in manifest.Epochs.Select(entry => entry.Owner).Distinct(StringComparer.Ordinal))
                locks.Add(DurableEpochFence.OpenPrivate(DurableEpochFence.PathFor(latestAuthorityRoot, owner) + ".lock", FileMode.Open));
            using (var latest = new Microsoft.Data.Sqlite.SqliteConnection(StorePaths.ConnectionString(
                StorePaths.Database(latestAuthorityRoot), Microsoft.Data.Sqlite.SqliteOpenMode.ReadOnly)))
            {
                latest.Open();
                // The independent latest catalogue must be complete/readable. Never substitute
                // the backup's old owner list when it is missing, corrupt or contains new owners.
                if (!ReadBackupEntries(new StoreReader(latest, null, TimeProvider.System)).SequenceEqual(manifest.Epochs))
                    throw new DurableStoreMaintenanceException();
            }
            VerifyFenceCatalogue(latestAuthorityRoot, manifest.Epochs);
            VerifyFenceCatalogue(backupRoot, manifest.Epochs);
            foreach (var entry in manifest.Epochs)
            {
                if (!keys.TryGetValue(entry.KeyReference, out var key)) keys.Add(entry.KeyReference, key = ReadProtectedKey(backupSecrets, entry.KeyReference));
                byte[] currentKey = ReadProtectedKey(latestAuthoritySecrets, entry.KeyReference);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(key, currentKey)
                        || !entry.KeyReference.StartsWith(latestAuthoritySecrets.Backend + "|", StringComparison.Ordinal)
                        || !entry.KeyReference.StartsWith(destinationSecrets.Backend + "|", StringComparison.Ordinal)
                        || !Matches(entry, DurableEpochFence.Read(DurableEpochFence.PathFor(backupRoot, entry.Owner), key))
                        || !Matches(entry, DurableEpochFence.Read(DurableEpochFence.PathFor(latestAuthorityRoot, entry.Owner), currentKey)))
                        throw new DurableStoreMaintenanceException();
                }
                finally { CryptographicOperations.ZeroMemory(currentKey); }
            }
            string database = StorePaths.Database(backupRoot);
            using (var stream = File.OpenRead(database))
                if (Convert.ToHexStringLower(SHA256.HashData(stream)) != manifest.DatabaseSha256)
                    throw new DurableStoreMaintenanceException();
            // Read the actual snapshot and its complete key/identity closure before writing a destination.
            using (var copy = new Microsoft.Data.Sqlite.SqliteConnection(StorePaths.ConnectionString(database, Microsoft.Data.Sqlite.SqliteOpenMode.ReadOnly)))
            {
                copy.Open();
                var reader = new StoreReader(copy, null, TimeProvider.System);
                if (!ReadBackupEntries(reader).SequenceEqual(manifest.Epochs)
                    || !Equals(reader.Scalar("PRAGMA integrity_check;"), "ok")) throw new DurableStoreMaintenanceException();
            }
            StorePaths.CreatePrivateDirectory(Path.GetDirectoryName(StorePaths.Database(destinationRoot))!);
            File.Copy(database, StorePaths.Database(destinationRoot), overwrite: false);
            foreach (var entry in manifest.Epochs)
            {
                destinationSecrets.Store.Write(Target(entry.KeyReference), keys[entry.KeyReference]);
                new DurableEpochFence(entry.Owner, Convert.FromHexString(entry.Epoch), entry.KeyReference, entry.Sequence,
                    Convert.FromHexString(entry.History)).Write(DurableEpochFence.PathFor(destinationRoot, entry.Owner), keys[entry.KeyReference]);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            throw new DurableStoreMaintenanceException();
        }
        finally
        {
            foreach (var key in keys.Values) CryptographicOperations.ZeroMemory(key);
            foreach (var lease in locks) lease.Dispose();
        }
    }

    private static DurableBackupEntry[] ReadBackupEntries(StoreReader reader)
    {
        using var command = reader.CreateCommand("SELECT owner_id,hex(owner_epoch),digest_key_ref,admission_sequence,history_hmac_sha256,state FROM owner_epoch ORDER BY owner_id,owner_epoch;");
        using var rows = command.ExecuteReader();
        var result = new List<DurableBackupEntry>();
        while (rows.Read()) result.Add(new(rows.GetString(0), rows.GetString(1), rows.GetString(2), rows.GetInt64(3), rows.GetString(4), rows.GetString(5)));
        return [.. result];
    }

    private static void VerifyFenceCatalogue(string root, IReadOnlyList<DurableBackupEntry> entries)
    {
        var expected = entries.Select(entry => Path.GetFileName(DurableEpochFence.PathFor(root, entry.Owner))).ToHashSet(StringComparer.Ordinal);
        var actual = Directory.EnumerateFiles(Path.Combine(root, "store"), "v2-owner-*.fence")
            .Select(path => Path.GetFileName(path) ?? throw new DurableStoreMaintenanceException()).ToHashSet(StringComparer.Ordinal);
        if (!expected.SetEquals(actual)) throw new DurableStoreMaintenanceException();
    }

    private static bool Matches(DurableBackupEntry entry, DurableEpochFence fence) =>
        entry.Owner == fence.Owner && Convert.FromHexString(entry.Epoch).AsSpan().SequenceEqual(fence.Epoch)
        && entry.KeyReference == fence.KeyReference && entry.Sequence == fence.Sequence
        && Convert.FromHexString(entry.History).AsSpan().SequenceEqual(fence.History);

    private static string Target(string reference)
    {
        int separator = reference.IndexOf('|');
        if (separator < 1) throw new DurableStoreMaintenanceException();
        string target = reference[(separator + 1)..];
        NodeSecretStores.ValidateTarget(target);
        return target;
    }

    private static byte[] ReadProtectedKey(NodeSecretStore store, string reference)
    {
        // Backup storage can be another explicit protected backend, but the reference is
        // never rewritten. Ready activation additionally requires the recorded destination backend.
        byte[] key = store.Store.Read(Target(reference)) ?? [];
        if (key.Length != 32) throw new DurableStoreMaintenanceException();
        return key;
    }
}
