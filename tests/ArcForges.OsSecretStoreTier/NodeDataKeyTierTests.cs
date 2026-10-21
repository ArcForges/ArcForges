// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Proto;
using ArcForges.Security.Secrets;
using Google.Protobuf;

// One test at a time, in one process: the tier never runs tests in parallel (ArcForges-Design 16-testing-strategy section 1).
[assembly: Xunit.v3.Parallelization(Mode = Xunit.Sdk.ParallelMode.None)]

namespace ArcForges.Tests.SecretStoreTier;

/// <summary>The single, non-parallel collection of every tier test; the tier fixture is shared by all of them.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class OsSecretStoreTierDefinition : ICollectionFixture<OsSecretStoreTier>
{
    public const string Name = "os-secret-store tier";
}

/// <summary>
/// The node binding's OS secret-store tier (ArcForges-Design 16-testing-strategy section 1; AD-0016 amendment of 2026-10-17; L-26): the
/// node data key through <see cref="NodeDataKeyRing"/> over the store the node's production composition root selects without
/// <c>--test-mode</c> (<see cref="NodeSecretStores.ForNode(string, bool)"/>: Windows Credential Manager), for a store with a fresh
/// random node ID, so the key's name is new. One write, read, overwrite, delete and confirmed-absence cycle, sequential and minimal,
/// every call counted and bounded by the tier fixture (at most 4 entries, 32 calls, 10 s per call, 5 minutes), the name listed before
/// it is created and deleted by that exact name only. The read-backs and the absence check are test verification; production never
/// reads a key back after writing it (04-execution section 2), which the first step also shows. The Linux Secret Service binding
/// (on the isolated Linux secret-store test host, ArcForges-Design AD-0019 section 6) is not delivered yet.
/// </summary>
[Collection(OsSecretStoreTierDefinition.Name)]
[Trait("env", "os-secret-store")]
public sealed class NodeDataKeyTierTests(OsSecretStoreTier tier)
{
    [Fact(Skip = OsSecretStoreTier.WindowsTierReason, SkipUnless = nameof(OsSecretStoreTier.WindowsTier), SkipType = typeof(OsSecretStoreTier))]
    [SupportedOSPlatform("windows")]
    public void TheNodeDataKeyIsWrittenReadOverwrittenDeletedAndThenAbsent()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-os-secret-store-tier-").FullName;
        try
        {
            var dataRoot = Path.Combine(root, "data");
            using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = dataRoot, BootIdentity = "os-secret-store-tier" });

            // The production selection (no --test-mode): only constructs the adapter, no store call.
            var selected = NodeSecretStores.ForNode(dataRoot, testMode: false);
            Assert.False(selected.Isolated);
            Assert.Equal(SecretStoreBackend.WindowsCredentialManager, selected.Backend);
            var counted = new NodeSecretStore(new TierCalls(tier, selected.Store), selected.Backend, selected.Protection, selected.FallbackReason);

            // The node data key of this fresh node, listed (and flushed) before the node creates it.
            var name = tier.NewEntry(NodeDataKeyRing.TargetName(store.Metadata.NodeId.Span, "1"), selected.Store);
            var secrets = new SecretEnvironment { Set = { new EnvEntry { Name = "ARCFORGES_TIER_TOKEN", Value = "synthetic-" + Guid.NewGuid().ToString("N") } } };
            byte[] taskId;

            // 1. Write: node startup creates key 1 (one write, no read-back), and sealing uses the key in memory.
            using (var keys = new NodeDataKeyRing(store, counted))
            {
                Assert.Equal("1", keys.Prepare(out var unavailable));
                Assert.Null(unavailable);
                Assert.Equal(1, tier.Calls);
                taskId = store.Write(transaction =>
                {
                    var id = InsertTask(transaction);
                    new TaskSecrets(store, keys).Seal(transaction, id, secrets);
                    return id;
                });
                Assert.Equal(1, tier.Calls);
            }

            // 2. Read: a restarted node reads key 1 from the store and opens the sealed values.
            using (var keys = new NodeDataKeyRing(store, counted))
            {
                var opened = new TaskSecrets(store, keys).Unseal(taskId);
                Assert.True(opened.Status == UnsealStatus.Available, opened.UnavailableReason);
                Assert.Equal(secrets, opened.Values);
            }

            // 3. Overwrite: another value under the same name; the restarted node reads it and the values fail closed.
            var other = RandomNumberGenerator.GetBytes(NodeDataKeyRing.KeyBytes);
            try
            {
                counted.Store.Write(name, other);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(other);
            }

            using (var keys = new NodeDataKeyRing(store, counted))
            {
                var unsealed = new TaskSecrets(store, keys).Unseal(taskId);
                Assert.Equal(UnsealStatus.Unavailable, unsealed.Status);
                Assert.Contains("do not open with node data key 1", unsealed.UnavailableReason, StringComparison.Ordinal);

                // 4. Delete through the node's own delete path, by the exact recorded name.
                Assert.Equal(1, keys.DeleteKeys());
            }

            // 5. Confirm absence: one read-back, never retried (a remaining value is evidence, L-26).
            tier.VerifyAbsent(name, selected.Store);
            Assert.Equal(6, tier.Calls);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] InsertTask(StoreTransaction transaction)
    {
        var taskId = StoreIds.NewUuid7(transaction.Clock);
        transaction.Execute(
            """
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, env_digest, spec_digest, owner, owner_origin, pool,
                              priority, effective_priority, side_effect, side_effect_source, command_fingerprint, command_digest, created_at, rev)
            VALUES ($id, 1, 1, 'tier', 'tier', $spec, NULL, zeroblob(32), $owner, 1, 'default', 3, 3, 4, 1, 'tier', zeroblob(32), $now, 0);
            """,
            ("$id", taskId),
            ("$spec", new TaskSpec { Title = "tier" }.ToByteArray()),
            ("$owner", new ActorRef { Origin = Origin.Human }.ToByteArray()),
            ("$now", transaction.NowMicroseconds));
        return taskId;
    }

    /// <summary>
    /// Routes every call of the node's key ring (and the test's overwrite) through the tier fixture, which counts and bounds it. A write
    /// or delete of a name that is not on the run's name list right now is refused before any store call: the tier never creates or
    /// removes an entry it did not list first.
    /// </summary>
    private sealed class TierCalls(OsSecretStoreTier tier, ISecretBackingStore store) : ISecretBackingStore
    {
        public SecretStoreIsolation Isolation => store.Isolation;

        public void Write(string opaqueTarget, ReadOnlySpan<byte> secret)
        {
            RequireListed(opaqueTarget, "write");
            var copy = secret.ToArray();
            try
            {
                tier.Call("write " + opaqueTarget, () => store.Write(opaqueTarget, copy));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(copy);
            }
        }

        public byte[]? Read(string opaqueTarget) => tier.Call("read " + opaqueTarget, () => store.Read(opaqueTarget));

        public bool Delete(string opaqueTarget)
        {
            RequireListed(opaqueTarget, "delete");
            return tier.Call("delete " + opaqueTarget, () => store.Delete(opaqueTarget));
        }

        private void RequireListed(string opaqueTarget, string operation)
        {
            if (!tier.IsListed(opaqueTarget))
            {
                throw new InvalidOperationException("The OS secret-store tier refused to " + operation + " " + opaqueTarget
                    + ": the name is not on this run's name list.");
            }
        }
    }
}
