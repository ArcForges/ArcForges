// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Proto;
using ArcForges.Security.Secrets;
using ArcForges.Tests;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// The node data key over the isolated secret-store backends of 16-testing-strategy section 2: the file-backed store of a
/// <c>--test-mode</c> node's data root, and the in-memory backend's scripted faults (unavailable, failed and lost writes, a stale read
/// after delete, L-26) with the node failing closed as 04-execution section 2 specifies. Production never reads a key back after writing
/// it; a lost write surfaces at the next load. Concurrency of sealing is tested here, never against a real OS store.
/// </summary>
public sealed class IsolatedSecretStoreTests
{
    [Fact]
    public void TheDataRootTestStoreKeepsAValueAcrossInstancesAndRemovesItByItsExactName()
    {
        using var root = new TemporaryDataRoot();
        var name = NodeSecretStores.TargetPrefix + new string('A', 64);
        var first = new TestDataRootSecretStore(root.Path);

        Assert.Null(first.Read(name));
        Assert.False(first.Delete(name));
        first.Write(name, [1, 2, 3]);
        first.Write(name, [4, 5]);

        // Another instance (a restarted node) reads the latest value.
        var second = new TestDataRootSecretStore(root.Path);
        Assert.Equal([4, 5], second.Read(name));
        Assert.Equal([name], second.Names());
        if (OperatingSystem.IsLinux())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(second.Directory, name)));
            Assert.Equal(StorePaths.PrivateDirectoryMode, File.GetUnixFileMode(second.Directory));
        }

        Assert.True(second.Delete(name));
        Assert.Null(first.Read(name));
        Assert.Empty(first.Names());
        Assert.Throws<ArgumentException>(() => first.Write("ArcForges.Secrets.v1.not-canonical", [1]));
        Assert.Throws<ArgumentException>(() => first.Read("../" + name));
        Assert.Throws<ArgumentOutOfRangeException>(() => first.Write(name, []));
        Assert.Throws<ArgumentOutOfRangeException>(() => first.Write(name, new byte[TestDataRootSecretStore.MaximumSecretBytes + 1]));
    }

    [Fact]
    public void ALostWriteIsNeverReadBackAndFailsClosedAtTheNextLoad()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        var backend = new IsolatedSecretStore();
        backend.LoseWrites(1);
        byte[] taskId;
        using (var keys = new NodeDataKeyRing(store, backend.Selection))
        {
            // Startup creates key 1: one write, no read-back (04 section 2: the key stays in memory).
            Assert.Equal("1", keys.Prepare(out var unavailable));
            Assert.Null(unavailable);
            Assert.Equal((1, 0), (backend.Writes, backend.Reads));
            var sealer = new TaskSecrets(store, keys);
            taskId = store.Write(transaction =>
            {
                var id = Rows.InsertTask(transaction);
                sealer.Seal(transaction, id, Secrets("synthetic-lost-write"));
                return id;
            });
            Assert.Equal(UnsealStatus.Available, sealer.Unseal(taskId).Status);
            Assert.Equal((1, 0), (backend.Writes, backend.Reads));
        }

        // The next load (a node restart) finds the key missing: the values are unavailable, never a partial environment, and the next
        // seal creates key 2.
        using (var keys = new NodeDataKeyRing(store, backend.Selection))
        {
            var sealer = new TaskSecrets(store, keys);
            var unsealed = sealer.Unseal(taskId);
            Assert.Equal(UnsealStatus.Unavailable, unsealed.Status);
            Assert.Null(unsealed.Values);
            Assert.Contains("node data key 1 is missing from", unsealed.UnavailableReason, StringComparison.Ordinal);
            Assert.Equal("2", keys.Prepare(out _));
            Assert.Equal(1, keys.DeleteKeys());
        }

        TestSecretStores.AssertNoLeaks(store, backend);
    }

    [Fact]
    public void AnUnavailableBackendSealsNothingAndTheKeyIsCreatedOnceItRecovers()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        var backend = new IsolatedSecretStore { Unavailable = true };
        using var keys = new NodeDataKeyRing(store, backend.Selection);
        var sealer = new TaskSecrets(store, keys);

        Assert.Null(keys.Prepare(out var unavailable));
        Assert.StartsWith("secret_store_write_failed backend=" + backend.Backend, unavailable, StringComparison.Ordinal);
        Assert.Throws<NodeDataKeyUnavailableException>(() => store.Write(transaction =>
        {
            var id = Rows.InsertTask(transaction);
            sealer.Seal(transaction, id, Secrets("synthetic-unavailable"));
            return id;
        }));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task_secret;")));
        Assert.Empty(keys.Keys());

        backend.Unavailable = false;
        backend.FailWrites(1);
        Assert.Null(keys.Prepare(out _));
        Assert.Equal("1", keys.Prepare(out _));
        Assert.Equal("1", Assert.Single(keys.Keys()).KeyId);
        Assert.Equal(1, keys.DeleteKeys());
        TestSecretStores.AssertNoLeaks(store, backend);
    }

    [Fact]
    public void AStaleReadAfterDeleteIsFoundByTheCleanupVerificationAndReportedByName()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        var backend = new IsolatedSecretStore();
        using var keys = new NodeDataKeyRing(store, backend.Selection);
        Assert.Equal("1", keys.Prepare(out _));
        var name = NodeDataKeyRing.TargetName(store.Metadata.NodeId.Span, "1");

        // The delete reports success while the value stays readable (L-26): the verification reads it back once and reports it.
        backend.LoseDeletes(1);
        Assert.Equal(1, keys.DeleteKeys());
        Assert.Equal([name], backend.Remaining(TestSecretStores.KeyNames(store)));
        var failure = Assert.ThrowsAny<Exception>(() => TestSecretStores.AssertNoLeaks(store, backend));
        Assert.Contains(name, failure.Message, StringComparison.Ordinal);
        Assert.Empty(backend.Names());
    }

    [Fact]
    public void ConcurrentSealsShareOneNewKeyVersion()
    {
        using var root = new TemporaryDataRoot();
        using var store = root.Open(new ManualClock());
        var backend = new IsolatedSecretStore();
        using (var keys = new NodeDataKeyRing(store, backend.Selection))
        {
            var sealer = new TaskSecrets(store, keys);
            var tasks = new byte[16][];
            Parallel.For(0, tasks.Length, index => tasks[index] = store.Write(transaction =>
            {
                var id = Rows.InsertTask(transaction);
                sealer.Seal(transaction, id, Secrets("synthetic-concurrent-" + index));
                return id;
            }));

            Assert.Equal("1", Assert.Single(keys.Keys()).KeyId);
            Assert.Equal(1, backend.Writes);
            Assert.All(tasks, id => Assert.Equal(UnsealStatus.Available, sealer.Unseal(id).Status));
            Assert.Equal(1, keys.DeleteKeys());
        }

        TestSecretStores.AssertNoLeaks(store, backend);
    }

    private static SecretEnvironment Secrets(string value) => new() { Set = { new EnvEntry { Name = "NPM_TOKEN", Value = value } } };
}
