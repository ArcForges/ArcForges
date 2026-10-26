// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Store.Migrations;
using ArcForges.Node.Store.Proto;
using ArcForges.Tests;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Real SQLite backup/restore retains records, never a second lifetime for sealed values (MR-13).</summary>
public sealed class BackupSecretRetentionTests
{
    [Theory]
    [InlineData(32)]
    [InlineData(131072)]
    public void NewBackupsKeepRecordsButNeverCarrySealedValues(int valueLength)
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var backend = new IsolatedSecretStore();
        using var keys = new NodeDataKeyRing(store, backend.Selection);
        try
        {
            var (taskId, ciphertext) = Seed(store, keys, valueLength);
            Assert.Equal(UnsealStatus.Available, new TaskSecrets(store, keys).Unseal(taskId).Status);
            using var source = OpenWritable(root.Database);
            // The arguments name a backup; no migration plan or schema change is run.
            var backup = StoreBackups.Create(source, root.Path, 1, 2, clock);

            AssertBackup(backup, backend, taskId, ciphertext);
            Assert.Equal(UnsealStatus.Available, new TaskSecrets(store, keys).Unseal(taskId).Status);
            Assert.Equal(1, store.Metadata.SchemaVersion);
            Assert.Null(store.Opening.MigratedFrom);
            Assert.Single(StoreBackups.List(root.Path));
            Assert.Empty(Directory.EnumerateFiles(StoreBackups.Directory(root.Path), "*.partial*"));
        }
        finally
        {
            keys.DeleteKeys();
        }

        TestSecretStores.AssertNoLeaks(store, backend);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OpeningSanitizesEveryLegacyBackupBeforeEitherPurge(bool immediate)
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var backend = new IsolatedSecretStore();
        using var keys = new NodeDataKeyRing(store, backend.Selection);
        try
        {
            var (taskId, ciphertext) = Seed(store, keys, 32);
            var backups = Enumerable.Range(0, 3).Select(index => LegacyBackup(root, index)).ToArray();
            foreach (var backup in backups)
            {
                using var connection = StoreCreationTests.Open(backup);
                Assert.Equal(["1"], StoreCreationTests.Query(connection, "SELECT key_id FROM task_secret;"));
            }

            var unrelated = Path.Combine(StoreBackups.Directory(root.Path), "unrelated.db");
            File.WriteAllText(unrelated, "synthetic unrelated file");
            using (var reopened = root.Open(clock))
            {
                Assert.Null(reopened.Opening.MigratedFrom);
                Assert.Equal(1, reopened.Metadata.SchemaVersion);
                Assert.Equal(UnsealStatus.Available, new TaskSecrets(reopened, keys).Unseal(taskId).Status);
            }

            Assert.Equal(backups, StoreBackups.List(root.Path));
            Assert.Equal("synthetic unrelated file", File.ReadAllText(unrelated));
            foreach (var backup in backups)
            {
                AssertBackup(backup, backend, taskId, ciphertext);
            }

            var sealer = new TaskSecrets(store, keys);
            if (immediate)
            {
                Assert.True(store.Write(transaction => TaskSecrets.PurgeNow(transaction, taskId)));
            }
            else
            {
                Assert.True(store.Write(transaction => TaskSecrets.SchedulePurge(transaction, taskId, transaction.NowMicroseconds, TimeSpan.FromHours(24))));
                clock.Advance(TimeSpan.FromHours(24));
                Assert.Equal(1, sealer.PurgeDue());
            }

            Assert.Equal(UnsealStatus.Unavailable, sealer.Unseal(taskId).Status);
            foreach (var backup in backups)
            {
                AssertBackup(backup, backend, taskId, ciphertext);
            }
        }
        finally
        {
            keys.DeleteKeys();
        }

        TestSecretStores.AssertNoLeaks(store, backend);
    }

    [Fact]
    public void AnUnreadableRetainedBackupRefusesTheOpenAndLeavesLiveValuesUsable()
    {
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var backend = new IsolatedSecretStore();
        using var keys = new NodeDataKeyRing(store, backend.Selection);
        string? corrupt = null;
        try
        {
            var (taskId, _) = Seed(store, keys, 32);
            StorePaths.CreatePrivateDirectory(StoreBackups.Directory(root.Path));
            corrupt = Path.Combine(StoreBackups.Directory(root.Path), "store-1-2-20261015T120000000Z.db");
            File.WriteAllText(corrupt, "synthetic corrupt backup");
            var error = Assert.Throws<StoreBackupException>(() =>
            {
                using var opened = root.Open(clock);
            });
            Assert.Contains("backup", error.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(UnsealStatus.Available, new TaskSecrets(store, keys).Unseal(taskId).Status);
            Assert.Equal("synthetic corrupt backup", File.ReadAllText(corrupt));
            Assert.Equal(1, store.Metadata.SchemaVersion);
        }
        finally
        {
            if (corrupt is not null)
            {
                File.Delete(corrupt);
            }

            keys.DeleteKeys();
        }

        TestSecretStores.AssertNoLeaks(store, backend);
    }

    private static (byte[] Task, byte[] Ciphertext) Seed(NodeStore store, NodeDataKeyRing keys, int length)
    {
        var sealer = new TaskSecrets(store, keys);
        var id = store.Write(transaction =>
        {
            var task = Rows.InsertTask(transaction);
            sealer.Seal(transaction, task, new SecretEnvironment
            {
                Caller = { new EnvEntry { Name = "GITHUB_TOKEN", Value = "synthetic-backup-" + new string('b', length) } },
            });
            transaction.Execute("INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ('backup-kept', '42', 0, 0);");
            return task;
        });
        var ciphertext = store.Read(reader => (byte[])reader.Scalar("SELECT ciphertext FROM task_secret;")!);
        return (id, ciphertext);
    }

    private static string LegacyBackup(TemporaryDataRoot root, int index)
    {
        StorePaths.CreatePrivateDirectory(StoreBackups.Directory(root.Path));
        var backup = Path.Combine(StoreBackups.Directory(root.Path), $"store-1-2-20261015T12000{index}000Z.db");
        using var source = OpenWritable(root.Database);
        using var destination = OpenWritable(backup, create: true);
        source.BackupDatabase(destination);
        return backup;
    }

    private static SqliteConnection OpenWritable(string path, bool create = false)
    {
        var connection = new SqliteConnection(StorePaths.ConnectionString(path, create ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite));
        connection.Open();
        return connection;
    }

    private static void AssertBackup(string backup, IsolatedSecretStore backend, byte[] taskId, byte[] ciphertext)
    {
        using (var connection = StoreCreationTests.Open(backup))
        {
            Assert.Equal(["ok"], StoreCreationTests.Query(connection, "PRAGMA integrity_check;"));
            Assert.Equal(["1"], StoreCreationTests.Query(connection, "SELECT schema_version FROM store_meta;"));
            Assert.Equal(["42"], StoreCreationTests.Query(connection, "SELECT value_json FROM node_setting WHERE name = 'backup-kept';"));
            Assert.Equal([TaskSecrets.PurgedKeyId], StoreCreationTests.Query(connection, "SELECT key_id FROM task_secret;"));
            Assert.Equal(["00"], StoreCreationTests.Query(connection, "SELECT hex(ciphertext) FROM task_secret;"));
            Assert.Equal(["[\"GITHUB_TOKEN\"]"], StoreCreationTests.Query(connection, "SELECT names_json FROM task_secret;"));
        }

        var bytes = File.ReadAllBytes(backup);
        foreach (var offset in new[] { 0, ciphertext.Length / 2, ciphertext.Length - 16 })
        {
            Assert.Equal(-1, bytes.AsSpan().IndexOf(ciphertext.AsSpan(offset, 16)));
        }

        // Restore a real backup to a second isolated root with the original key backend still available.
        using var restoredRoot = new TemporaryDataRoot();
        StorePaths.CreatePrivateDirectory(Path.GetDirectoryName(restoredRoot.Database)!);
        File.Copy(backup, restoredRoot.Database);
        using var restored = restoredRoot.Open(new ManualClock());
        using var restoredKeys = new NodeDataKeyRing(restored, backend.Selection);
        var unsealed = new TaskSecrets(restored, restoredKeys).Unseal(taskId);
        Assert.Equal(UnsealStatus.Unavailable, unsealed.Status);
        Assert.Null(unsealed.Values);
        Assert.Equal("secrets_unavailable", unsealed.Error?.Code);
        Assert.Equal(["GITHUB_TOKEN"], unsealed.Names);
        Assert.Null(restored.Opening.MigratedFrom);
    }
}
