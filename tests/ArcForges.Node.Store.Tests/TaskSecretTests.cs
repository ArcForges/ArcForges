// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Store.Proto;
using ArcForges.Security.Secrets;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// task_secret sealing with the node data key in the real OS secret store (R-EXE-017; 04-execution section 2): values
/// round-trip across restarts only with the node data key, and a purge after the retention leaves STATE/secrets_unavailable.
/// Windows uses Credential Manager with a uniquely named entry per test node, deleted by the test; Linux uses the owner-only
/// file fallback under the test's data root (never the user's keyring).
/// </summary>
[Trait("env", "windows-real")]
[Trait("env", "linux-real")]
public sealed class TaskSecretTests
{
    [Fact]
    public void SealedValuesRoundTripAcrossARestartWithTheRecordedBackend()
    {
        TestSecretStores.RequireRealSecretStore();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        var secrets = Secrets("synthetic-github-value", "synthetic-npm-value");
        byte[] taskId;
        using (var store = root.Open(clock))
        using (var keys = new NodeDataKeyRing(store, TestSecretStores.Select(root.Path)))
        {
            try
            {
                taskId = store.Write(transaction =>
                {
                    var id = Rows.InsertTask(transaction);
                    new TaskSecrets(store, keys).Seal(transaction, id, secrets);
                    return id;
                });

                var key = Assert.Single(keys.Keys());
                Assert.Equal("1", key.KeyId);
                Assert.Equal(keys.Backend.ToString(), key.Backend);
                Assert.Equal(OperatingSystem.IsWindows() ? "WindowsCredentialManager" : "OwnerOnlyFile", key.Backend);
                Assert.Equal(OperatingSystem.IsWindows() ? "OsSecretStore" : "FileOwnerOnly", key.Protection);
                var stored = store.Read(reader => (byte[])reader.Scalar("SELECT ciphertext FROM task_secret;")!);
                Assert.DoesNotContain("synthetic", Encoding.UTF8.GetString(stored), StringComparison.Ordinal);
                Assert.Equal("[\"GITHUB_TOKEN\",\"NPM_TOKEN\"]", store.Read(reader => reader.Scalar("SELECT names_json FROM task_secret;")));
            }
            catch
            {
                keys.DeleteKeys();
                throw;
            }
        }

        // A restarted node (new store and key ring instances) opens the values with the key the store recorded.
        using (var store = root.Open(clock))
        using (var keys = new NodeDataKeyRing(store, TestSecretStores.Select(root.Path)))
        {
            try
            {
                var opened = new TaskSecrets(store, keys).Unseal(taskId);

                Assert.Equal(UnsealStatus.Available, opened.Status);
                Assert.Equal(secrets, opened.Values);
                Assert.Equal(["GITHUB_TOKEN", "NPM_TOKEN"], opened.Names);
                if (OperatingSystem.IsLinux())
                {
                    var file = Path.Combine(root.Path, "run", "secrets", NodeDataKeyRing.TargetName(store.Metadata.NodeId.Span, "1"));
                    Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
                    Assert.Equal(StorePaths.PrivateDirectoryMode, File.GetUnixFileMode(root.Path));
                }
            }
            finally
            {
                Assert.Equal(1, keys.DeleteKeys());
            }
        }
    }

    [Fact]
    public void SealedValuesOpenOnlyWithTheNodeDataKeyAndTheirTaskId()
    {
        TestSecretStores.RequireRealSecretStore();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        var selection = TestSecretStores.Select(root.Path);
        using var keys = new NodeDataKeyRing(store, selection);
        try
        {
            var secrets = Secrets("synthetic-a", "synthetic-b");
            var (taskId, otherTask) = store.Write(transaction =>
            {
                var id = Rows.InsertTask(transaction);
                new TaskSecrets(store, keys).Seal(transaction, id, secrets);
                return (id, Rows.InsertTask(transaction));
            });

            // The task ID is the associated data: the same sealed row under another task does not open.
            store.Write(transaction => transaction.Execute(
                "INSERT INTO task_secret (task_id, key_id, nonce, ciphertext, tag, names_json, purge_after, created_at) SELECT $other, key_id, nonce, ciphertext, tag, names_json, NULL, created_at FROM task_secret WHERE task_id = $task;",
                ("$other", otherTask),
                ("$task", taskId)));
            AssertUnavailable(new TaskSecrets(store, keys).Unseal(otherTask), "do not open with node data key 1");

            // Another key under the same name (a different node data key) does not open the values.
            var target = NodeDataKeyRing.TargetName(store.Metadata.NodeId.Span, "1");
            selection.Store.Write(target, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
            using (var restarted = new NodeDataKeyRing(store, selection))
            {
                AssertUnavailable(new TaskSecrets(store, restarted).Unseal(taskId), "do not open with node data key 1");
            }

            // A lost key: values sealed under it are unavailable, and the next seal creates key 2.
            Assert.True(selection.Store.Delete(target));
            using (var restarted = new NodeDataKeyRing(store, selection))
            {
                var sealer = new TaskSecrets(store, restarted);
                AssertUnavailable(sealer.Unseal(taskId), "node data key 1 is missing from");
                var newer = store.Write(transaction =>
                {
                    var id = Rows.InsertTask(transaction);
                    sealer.Seal(transaction, id, secrets);
                    return id;
                });

                Assert.Equal(["1", "2"], restarted.Keys().Select(key => key.KeyId));
                Assert.Equal(secrets, sealer.Unseal(newer).Values);
                AssertUnavailable(sealer.Unseal(taskId), "node data key 1 is missing from");
                Assert.Equal(1, restarted.DeleteKeys());
            }
        }
        finally
        {
            keys.DeleteKeys();
        }
    }

    [Fact]
    public void AKeyRecordedInAnotherBackendIsNotReadFromTheSelectedOne()
    {
        TestSecretStores.RequireRealSecretStore();
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        var selection = TestSecretStores.Select(root.Path);
        using var keys = new NodeDataKeyRing(store, selection);
        try
        {
            var secrets = Secrets("synthetic-c", "synthetic-d");
            var taskId = store.Write(transaction =>
            {
                var id = Rows.InsertTask(transaction);
                new TaskSecrets(store, keys).Seal(transaction, id, secrets);
                return id;
            });

            // The store says key 1 lives in a backend other than the one selected now (selection changed between runs).
            var other = selection.Backend == SecretStoreBackend.SecretService ? "OwnerOnlyFile" : "SecretService";
            store.Write(transaction => transaction.Execute(
                "UPDATE node_setting SET value_json = replace(value_json, $from, $to) WHERE name = $name;",
                ("$from", "\"backend\":\"" + selection.Backend + "\""),
                ("$to", "\"backend\":\"" + other + "\""),
                ("$name", NodeDataKeyRing.SettingName)));
            using var restarted = new NodeDataKeyRing(store, selection);
            var sealer = new TaskSecrets(store, restarted);

            AssertUnavailable(sealer.Unseal(taskId), $"node data key 1 is held by {other}, which is not the selected secret store ({selection.Backend})");
            var newer = store.Write(transaction =>
            {
                var id = Rows.InsertTask(transaction);
                sealer.Seal(transaction, id, secrets);
                return id;
            });
            Assert.Equal(["1", "2"], restarted.Keys().Select(key => key.KeyId));
            Assert.Equal(secrets, sealer.Unseal(newer).Values);
            Assert.Equal(1, restarted.DeleteKeys());

            // Key 1 is still in the selected backend under its name; remove it too.
            selection.Store.Delete(NodeDataKeyRing.TargetName(store.Metadata.NodeId.Span, "1"));
        }
        finally
        {
            keys.DeleteKeys();
        }
    }

    [Fact]
    public void PurgeAfterTheRetentionLeavesSecretsUnavailable()
    {
        TestSecretStores.RequireRealSecretStore();
        using var root = new TemporaryDataRoot();
        var clock = new ManualClock();
        using var store = root.Open(clock);
        using var keys = new NodeDataKeyRing(store, TestSecretStores.Select(root.Path));
        try
        {
            var sealer = new TaskSecrets(store, keys);
            var retention = TimeSpan.FromHours(store.Policies.Current().Document.Storage.SecretRetentionHours);
            var (taskId, plain) = store.Write(transaction =>
            {
                var id = Rows.InsertTask(transaction);
                var noSecrets = Rows.InsertTask(transaction);
                sealer.Seal(transaction, id, Secrets("synthetic-purge-value", "synthetic-other"));
                return (id, noSecrets);
            });
            var ciphertext = store.Read(reader => (byte[])reader.Scalar("SELECT ciphertext FROM task_secret;")!);

            // Not terminal yet: nothing to purge, and a retry keeps its environment.
            clock.Advance(TimeSpan.FromDays(3));
            Assert.Equal(0, sealer.PurgeDue());
            var finishedAt = StoreTime.NowMicroseconds(clock);
            Assert.True(store.Write(transaction => TaskSecrets.SchedulePurge(transaction, taskId, finishedAt, retention)));

            clock.Advance(retention - TimeSpan.FromSeconds(1));
            Assert.Equal(0, sealer.PurgeDue());
            Assert.Equal(UnsealStatus.Available, sealer.Unseal(taskId).Status);

            clock.Advance(TimeSpan.FromSeconds(1));
            Assert.Equal(1, sealer.PurgeDue());
            var purged = sealer.Unseal(taskId);
            var error = AssertUnavailable(purged, "purged at " + StoreTime.ToRfc3339(finishedAt + (long)retention.TotalMicroseconds));
            Assert.Equal(["GITHUB_TOKEN", "NPM_TOKEN"], purged.Names);
            Assert.Equal(TaskSecrets.PurgedKeyId, store.Read(reader => reader.Scalar("SELECT key_id FROM task_secret;")));
            Assert.Equal([0], store.Read(reader => (byte[])reader.Scalar("SELECT ciphertext FROM task_secret;")!));
            Assert.Equal(0, sealer.PurgeDue());

            // The ciphertext is gone from the database file and the WAL (secure_delete and the purge checkpoint).
            SqliteConnection.ClearAllPools();
            foreach (var file in new[] { root.Database, root.Database + "-wal" }.Where(File.Exists))
            {
                using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var copy = new MemoryStream();
                stream.CopyTo(copy);
                Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(ciphertext));
            }

            // A task that never had sealed values needs none.
            Assert.Equal(UnsealStatus.None, sealer.Unseal(plain).Status);
            Assert.Null(sealer.Unseal(plain).Error);
            Assert.False(store.Write(transaction => TaskSecrets.SchedulePurge(transaction, plain, finishedAt, retention)));
            Assert.Equal("secrets_unavailable", error.Code);
        }
        finally
        {
            keys.DeleteKeys();
        }
    }

    [Fact]
    public void PurgeTaskRecordPurgesAtOnceAndDeletingTheTaskRemovesTheRow()
    {
        TestSecretStores.RequireRealSecretStore();
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        using var keys = new NodeDataKeyRing(store, TestSecretStores.Select(root.Path));
        try
        {
            var sealer = new TaskSecrets(store, keys);
            var taskId = store.Write(transaction =>
            {
                var id = Rows.InsertTask(transaction);
                sealer.Seal(transaction, id, Secrets("synthetic-e", "synthetic-f"));
                return id;
            });

            Assert.True(store.Write(transaction => TaskSecrets.PurgeNow(transaction, taskId)));
            Assert.False(store.Write(transaction => TaskSecrets.PurgeNow(transaction, taskId)));
            AssertUnavailable(sealer.Unseal(taskId), "purged at " + StoreTime.ToRfc3339(StoreTime.NowMicroseconds(store.Clock)));

            store.Write(transaction => transaction.Execute("DELETE FROM task WHERE task_id = $id;", ("$id", taskId)));
            Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task_secret;")));
        }
        finally
        {
            keys.DeleteKeys();
        }
    }

    private static ArcError AssertUnavailable(UnsealResult result, string reason)
    {
        Assert.Equal(UnsealStatus.Unavailable, result.Status);
        Assert.Null(result.Values);
        var error = Assert.IsType<ArcError>(result.Error);
        Assert.Equal("secrets_unavailable", error.Code);
        Assert.Equal(ErrorCategory.State, error.Category);
        Assert.Equal("error.state.secrets_unavailable", error.MessageKey);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
        Assert.Contains(reason, error.Details.State.Reason, StringComparison.Ordinal);
        return error;
    }

    private static SecretEnvironment Secrets(string caller, string set) => new()
    {
        Caller = { new EnvEntry { Name = "GITHUB_TOKEN", Value = caller } },
        Set = { new EnvEntry { Name = "NPM_TOKEN", Value = set } },
    };
}
