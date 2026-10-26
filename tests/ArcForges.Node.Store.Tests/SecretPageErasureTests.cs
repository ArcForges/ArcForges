// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store.Proto;
using ArcForges.Tests;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>Real SQLite snapshots, secure-delete pages and WAL truncation; only the external key backend is isolated.</summary>
public sealed class SecretPageErasureTests
{
    [Theory(Timeout = 60_000)]
    [InlineData(32)]
    [InlineData(131072)]
    public void RetentionPurgeRetriesABusyCheckpointWhenNoNewRowIsDue(int valueLength)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var backend = new IsolatedSecretStore();
        using var keys = new NodeDataKeyRing(store, backend.Selection);
        try
        {
            var secrets = new TaskSecrets(store, keys);
            var taskId = store.Write(transaction =>
            {
                var id = Rows.InsertTask(transaction);
                secrets.Seal(transaction, id, new SecretEnvironment
                {
                    Set = { new EnvEntry { Name = "API_TOKEN", Value = new string('s', valueLength) } },
                });
                TaskSecrets.SchedulePurge(transaction, id, transaction.NowMicroseconds, TimeSpan.Zero);
                return id;
            });
            var ciphertext = store.Read(reader => (byte[])reader.Scalar("SELECT ciphertext FROM task_secret;")!);
            Assert.True(store.Checkpoint());
            Assert.True(ContainsCiphertext(root.Database, ciphertext));

            using var snapshot = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = root.Database, Mode = SqliteOpenMode.ReadOnly, Pooling = false,
            }.ToString());
            snapshot.Open();
            using var transaction = snapshot.BeginTransaction(deferred: true);
            using var query = snapshot.CreateCommand();
            query.Transaction = transaction;
            query.CommandText = "SELECT ciphertext FROM task_secret;";
            Assert.Equal(ciphertext, (byte[])query.ExecuteScalar()!);

            // This is a real older read snapshot: SQLite cannot checkpoint past it.
            Assert.Equal(1, secrets.PurgeDue());
            Assert.Equal(UnsealStatus.Unavailable, secrets.Unseal(taskId).Status);
            Assert.Equal(ciphertext, (byte[])query.ExecuteScalar()!);
            Assert.True(ContainsCiphertext(root.Database, ciphertext));
            transaction.Dispose();
            snapshot.Dispose();

            // Nothing new becomes due. The next normal pass must still finish the previously blocked erasure.
            Assert.Equal(0, secrets.PurgeDue());
            Assert.False(ContainsCiphertext(root.Database, ciphertext));
            Assert.Equal("ok", store.Read(reader => reader.Scalar("PRAGMA integrity_check;")));
            Assert.Equal(1, store.Metadata.SchemaVersion);
            if (valueLength > 4096)
            {
                Assert.True(store.Read(reader => (long)reader.Scalar("PRAGMA freelist_count;")!) > 0);
            }
        }
        finally
        {
            keys.DeleteKeys();
        }

        TestSecretStores.AssertNoLeaks(store, backend);
    }

    private static bool ContainsCiphertext(string database, byte[] ciphertext)
    {
        foreach (var path in new[] { database, database + "-wal" }.Where(File.Exists))
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            var bytes = copy.ToArray();
            foreach (var start in new[] { 0, ciphertext.Length / 2, ciphertext.Length - 16 })
            {
                if (bytes.AsSpan().IndexOf(ciphertext.AsSpan(start, 16)) >= 0)
                {
                    return true;
                }
            }
        }

        return false;
    }
}
