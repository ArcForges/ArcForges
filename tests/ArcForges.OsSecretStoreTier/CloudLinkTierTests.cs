// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;

namespace ArcForges.Tests.SecretStoreTier;

/// <summary>
/// N1-13 (AF-CTR-04 CTR4-NODE-06, SEC-17): the node key in the real CNG user key store, created through the production composition root's
/// CNG backend (<see cref="NodeKeyStores"/>) with only the data root and node ID of a fresh test node: listed before it is created, every
/// CNG operation counted and bounded by this class's tier fixture, signed with, found non-exportable, reopened, deleted by its exact name and
/// confirmed absent. Windows only, with the tier's opt-in only (hosted dispatch or the owner's run; agents never run it).
/// </summary>
[Collection(OsSecretStoreTierDefinition.Name)]
[Trait("env", "os-secret-store")]
public sealed class NodeKeyCngTierTests(OsSecretStoreTier tier) : IClassFixture<OsSecretStoreTier>
{
    [Fact(Skip = OsSecretStoreTier.WindowsTierReason, SkipUnless = nameof(OsSecretStoreTier.WindowsTier), SkipType = typeof(OsSecretStoreTier))]
    [SupportedOSPlatform("windows")]
    public void TheNodeKeyIsANonExportableCngKeyThatSurvivesAReopenAndIsDeletedByName()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-os-secret-store-tier-").FullName;
        try
        {
            var production = NodeKeyStores.ForNode(root, testMode: false);
            Assert.Equal("cng", production.Backend.Kind);
            var counted = new CountedKeys(tier, production.Backend);
            var store = new NodeKeyStore(root, counted);
            var nodeId = RandomNumberGenerator.GetBytes(16);
            const string origin = "https://os-secret-store-tier.invalid";
            var name = tier.NewEntry(NodeKeyStore.KeyName(nodeId, origin), counted);

            byte[] publicKey;
            using (var key = store.Create(nodeId, origin, TimeProvider.System))
            {
                publicKey = key.PublicKey;
                var message = RandomNumberGenerator.GetBytes(64);
                var proof = key.Sign(message);
                Assert.True(CloudIdentity.IsLowS(proof));
                using var verifier = ECDsa.Create();
                verifier.ImportSubjectPublicKeyInfo(publicKey, out _);
                Assert.True(verifier.VerifyData(message, proof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            }

            // Not exportable: the private half never leaves the key store.
            using (var handle = tier.Call("open " + name, () => CngKey.Open(name, CngProvider.MicrosoftSoftwareKeyStorageProvider)))
            using (var cng = new ECDsaCng(handle))
            {
                Assert.Equal(CngExportPolicies.None, handle.ExportPolicy);
                Assert.ThrowsAny<CryptographicException>(() => cng.ExportParameters(includePrivateParameters: true));
            }

            // A restart opens the same key; the node's delete removes it by the recorded name.
            using (var reopened = store.Load(nodeId, origin))
            {
                Assert.NotNull(reopened);
                Assert.Equal(publicKey, reopened.PublicKey);
            }

            Assert.True(store.Delete());
            tier.VerifyAbsent(name, counted);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>The CNG backend with every operation counted by the tier, as an entry store for the fixture's listing and cleanup.</summary>
    [SupportedOSPlatform("windows")]
    private sealed class CountedKeys(OsSecretStoreTier tier, INodeKeyBackend backend) : INodeKeyBackend, ISecretBackingStore
    {
        public string Kind => backend.Kind;

        public SecretStoreIsolation Isolation => SecretStoreIsolation.SameUserShared;

        public INodeKey? Open(string name) => tier.Call("open " + name, () => backend.Open(name));

        public INodeKey Create(string name)
        {
            RequireListed(name);
            return tier.Call("create " + name, () => backend.Create(name));
        }

        public bool Delete(string name)
        {
            RequireListed(name);
            return tier.Call("delete " + name, () => backend.Delete(name));
        }

        public IReadOnlyList<string> Names() => [];

        public void Write(string opaqueTarget, ReadOnlySpan<byte> secret) => throw new NotSupportedException("A node key is created, not written.");

        public byte[]? Read(string opaqueTarget)
        {
            using var key = Open(opaqueTarget);
            return key?.PublicKey;
        }

        private void RequireListed(string name)
        {
            if (!tier.IsListed(name))
            {
                throw new InvalidOperationException("The OS secret-store tier refused to touch " + name + ": the name is not on this run's name list.");
            }
        }
    }
}

/// <summary>
/// N1-14 (AF-CTR-04 CTR4-NODE-05; acceptance 3): the node credential record through the cloud link's credential store over the store the
/// node's production composition root selects (Windows Credential Manager), for a fresh node ID: written, read, overwritten, read, deleted
/// by the node's own path and confirmed absent, every call counted and bounded by this class's tier fixture.
/// </summary>
[Collection(OsSecretStoreTierDefinition.Name)]
[Trait("env", "os-secret-store")]
public sealed class NodeCredentialTierTests(OsSecretStoreTier tier) : IClassFixture<OsSecretStoreTier>
{
    [Fact(Skip = OsSecretStoreTier.WindowsTierReason, SkipUnless = nameof(OsSecretStoreTier.WindowsTier), SkipType = typeof(OsSecretStoreTier))]
    [SupportedOSPlatform("windows")]
    public void TheCredentialRecordIsWrittenReadOverwrittenDeletedAndThenAbsent()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-os-secret-store-tier-").FullName;
        try
        {
            var selected = NodeSecretStores.ForNode(root, testMode: false);
            Assert.False(selected.Isolated);
            Assert.Equal(SecretStoreBackend.WindowsCredentialManager, selected.Backend);
            var counted = new CountedSecrets(tier, selected.Store);
            var storage = new CloudCredentialStore(root, new NodeSecretStore(counted, selected.Backend, selected.Protection, selected.FallbackReason));
            var nodeId = RandomNumberGenerator.GetBytes(16);
            var center = CenterEndpoint.Parse("https://os-secret-store-tier.invalid/api");
            var target = tier.NewEntry(CloudCredentialStore.Target(nodeId, center.Origin), counted);
            var record = new CloudCredentialRecord
            {
                NodeId = Convert.ToHexStringLower(nodeId),
                CenterUrl = center.Url,
                InstallationId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)),
                AccessToken = "afa1." + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)),
                RefreshToken = "afr1." + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)),
            };

            storage.WriteRecord(target, record);
            Assert.Equal(record.RefreshToken, storage.ReadRecord(target)!.RefreshToken);
            var rotated = record.Clone();
            rotated.RefreshToken = "afr1." + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
            storage.WriteRecord(target, rotated);
            Assert.Equal(rotated.RefreshToken, storage.ReadRecord(target)!.RefreshToken);
            Assert.True(storage.DeleteRecord(target));
            tier.VerifyAbsent(target, counted);
            Assert.Equal(6, tier.Calls);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class CountedSecrets(OsSecretStoreTier tier, ISecretBackingStore store) : ISecretBackingStore
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
                throw new InvalidOperationException("The OS secret-store tier refused to " + operation + " " + opaqueTarget + ": the name is not on this run's name list.");
            }
        }
    }
}
