// SPDX-License-Identifier: AGPL-3.0-only
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core;
using ArcForges.Security.Secrets;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-4 (REAL files) and N1-12 (unit): the node key (CTR4-NODE-06 as amended, decision G-1) and the node key proof and fingerprint
/// (CTR4-KEY-01/02 as frozen by C0). The proof checks here are same-language self-consistency: the .NET verifier checks the node's own
/// signatures against the contract's byte layout; cross-language evidence exists only from the real center (N1-22) or the Cloud vector file.
/// </summary>
public sealed class NodeKeyTests : IDisposable
{
    private static readonly CenterEndpoint Center = CenterEndpoint.Parse("https://center.example.test/api");
    private readonly string _root = Directory.CreateTempSubdirectory("arcforges-nodekey-").FullName;
    private readonly byte[] _nodeId = RandomNumberGenerator.GetBytes(16);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void TheKeyIsCreatedOnceSurvivesARestartAndKeepsItsPublicHalf()
    {
        var store = NodeKeyStores.ForTestDataRoot(_root);
        using var created = store.Create(_nodeId, Center.Origin, TimeProvider.System);
        Assert.Equal(CloudIdentity.PublicKeyLength, created.PublicKey.Length);

        // A restart: a new store over the same data root opens the same key.
        using var reopened = NodeKeyStores.ForTestDataRoot(_root).Load(_nodeId, Center.Origin);
        Assert.NotNull(reopened);
        Assert.Equal(created.PublicKey, reopened.PublicKey);
        Assert.Equal(CloudIdentity.Fingerprint(created.PublicKey), store.Recorded()!.Fingerprint);
        Assert.Equal(Convert.ToHexStringLower(_nodeId), store.Recorded()!.NodeId);
    }

    [Fact]
    public void TheKeyFileIsOwnerOnlyPkcs8InAnOwnerOnlyDirectory()
    {
        var store = NodeKeyStores.ForTestDataRoot(_root);
        using var key = store.Create(_nodeId, Center.Origin, TimeProvider.System);
        var backend = Assert.IsType<FileNodeKeyBackend>(store.Backend);
        var file = Assert.Single(Directory.GetFiles(backend.Directory));
        using var parsed = ECDsa.Create();
        parsed.ImportPkcs8PrivateKey(File.ReadAllBytes(file), out _);
        Assert.Equal(key.PublicKey, parsed.ExportSubjectPublicKeyInfo());
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(backend.Directory));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(_root, "run", "node-key.json")));
        }
    }

    [Fact]
    public void NodeKeyIsBoundToTheNodeIdAndTheCenterOriginNeverToAPath()
    {
        var name = NodeKeyStore.KeyName(_nodeId, Center.Origin);
        Assert.Matches("^ArcForges\\.NodeKey\\.v1\\.[0-9A-F]{64}$", name);
        var expected = "ArcForges.NodeKey.v1." + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            "arcforges.node-key.v1|" + Convert.ToHexStringLower(_nodeId) + "|https://center.example.test")));
        Assert.Equal(expected, name);
        Assert.NotEqual(name, NodeKeyStore.KeyName(RandomNumberGenerator.GetBytes(16), Center.Origin));
        Assert.NotEqual(name, NodeKeyStore.KeyName(_nodeId, "https://other.example.test"));

        // A data-root relocation keeps the key: the name has no path in it, so a moved data root opens it.
        using (NodeKeyStores.ForTestDataRoot(_root).Create(_nodeId, Center.Origin, TimeProvider.System))
        {
        }

        var moved = Path.Combine(Path.GetTempPath(), "arcforges-nodekey-moved-" + Guid.NewGuid().ToString("N"));
        Directory.Move(_root, moved);
        try
        {
            using var reopened = NodeKeyStores.ForTestDataRoot(moved).Load(_nodeId, Center.Origin);
            Assert.NotNull(reopened);
        }
        finally
        {
            Directory.Move(moved, _root);
        }
    }

    [Fact]
    public void ResetStoreWithSurvivingKeyGetsAFreshKey()
    {
        var store = NodeKeyStores.ForTestDataRoot(_root);
        using var old = store.Create(_nodeId, Center.Origin, TimeProvider.System);

        // A store reset gives a new node ID: the surviving key is never used for it, and creating the new one deletes the stale sibling.
        var newNode = RandomNumberGenerator.GetBytes(16);
        Assert.Null(store.Load(newNode, Center.Origin));
        using var fresh = store.Create(newNode, Center.Origin, TimeProvider.System);
        Assert.NotEqual(old.PublicKey, fresh.PublicKey);
        Assert.Single(Directory.GetFiles(((FileNodeKeyBackend)store.Backend).Directory));
        Assert.Null(store.Load(_nodeId, Center.Origin));
    }

    [Fact]
    public void DeletingTheKeyRemovesItByItsRecordedName()
    {
        var store = NodeKeyStores.ForTestDataRoot(_root);
        using (store.Create(_nodeId, Center.Origin, TimeProvider.System))
        {
        }

        Assert.True(store.Delete());
        Assert.Null(store.Recorded());
        Assert.Empty(Directory.GetFiles(((FileNodeKeyBackend)store.Backend).Directory));
        Assert.False(store.Delete());
    }

    [Fact]
    public void TestModeNeverReachesCngAndTheCngPathTripsTheGuard()
    {
        // Under --test-mode without the tier's opt-in the key is file-backed on both systems.
        Assert.IsType<FileNodeKeyBackend>(NodeKeyStores.ForNode(_root, testMode: true, optIn: null).Backend);
        Assert.IsType<FileNodeKeyBackend>(NodeKeyStores.ForNode(_root, testMode: true, optIn: "0").Backend);
        if (!OperatingSystem.IsWindows())
        {
            Assert.IsType<FileNodeKeyBackend>(NodeKeyStores.ForNode(_root, testMode: false, optIn: null).Backend);
            return;
        }

        // Windows production selects CNG; this test process denies the OS stores, so the CNG path refuses before any CNG call.
        var store = NodeKeyStores.ForNode(_root, testMode: false, optIn: null);
        Assert.Equal("cng", store.Backend.Kind);
        Assert.True(OsSecretStoreGuard.IsDenied);
        Assert.Throws<OsSecretStoreDeniedException>(() => store.Create(_nodeId, Center.Origin, TimeProvider.System));
    }

    [Fact]
    public void TheCngKeyIsCreatedNonExportableForSigningInTheSoftwareProvider() =>
        Assert.Equal(("Microsoft Software Key Storage Provider", false, "signing"), NodeKeyStores.CngCreationParameters);

    [Fact]
    public void TheProofPreimageIsTheContractLayout()
    {
        byte[] flow = RandomNumberGenerator.GetBytes(16);
        var code = new string('A', 42) + "_";
        var message = CloudIdentity.ProofMessage(CloudIdentity.PurposeComplete, Center, _nodeId, CloudIdentity.CompleteBinding(flow, code));
        byte[] expected =
        [
            .. Encoding.ASCII.GetBytes("ArcForges node-key-proof v1\n"), 0x01, .. SHA256.HashData(Encoding.UTF8.GetBytes("https://center.example.test/api")),
            .. _nodeId, .. flow, .. Encoding.ASCII.GetBytes(code),
        ];
        Assert.Equal(28, CloudIdentity.ProofDomain.Length);
        Assert.Equal(expected, message);
        Assert.Equal(28 + 1 + 32 + 16 + 16 + 43, message.Length);

        var device = new string('d', 43);
        Assert.Equal(
            [.. Encoding.ASCII.GetBytes("ArcForges node-key-proof v1\n"), 0x02, .. SHA256.HashData(Encoding.UTF8.GetBytes(Center.Url)), .. _nodeId, .. Encoding.ASCII.GetBytes(device)],
            CloudIdentity.ProofMessage(CloudIdentity.PurposePoll, Center, _nodeId, CloudIdentity.PollBinding(device)));
    }

    [Fact]
    public void TheBindingsAreCheckedBeforeSigningAndReservedPurposesAreRefused()
    {
        Assert.Throws<ArgumentException>(() => CloudIdentity.CompleteBinding(new byte[15], new string('A', 43)));
        Assert.Throws<ArgumentException>(() => CloudIdentity.CompleteBinding(new byte[16], new string('A', 42)));
        Assert.Throws<ArgumentException>(() => CloudIdentity.CompleteBinding(new byte[16], new string('A', 42) + "=")); // not base64url
        Assert.Throws<ArgumentException>(() => CloudIdentity.PollBinding(new string('A', 44)));
        Assert.Throws<ArgumentOutOfRangeException>(() => CloudIdentity.ProofMessage(0x03, Center, _nodeId, []));
        Assert.Throws<ArgumentException>(() => CloudIdentity.ProofMessage(0x01, Center, new byte[15], []));
    }

    [Fact]
    public void TheNodesProofsAreLowSP1363AndVerifyOnlyForTheirOwnMessage()
    {
        var store = NodeKeyStores.ForTestDataRoot(_root);
        using var key = store.Create(_nodeId, Center.Origin, TimeProvider.System);
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(key.PublicKey, out _);
        var flow = RandomNumberGenerator.GetBytes(16);
        var code = new string('c', 43);
        var message = CloudIdentity.ProofMessage(CloudIdentity.PurposeComplete, Center, _nodeId, CloudIdentity.CompleteBinding(flow, code));
        for (var i = 0; i < 40; i++)
        {
            // ECDSA draws a nonce: about half of raw signatures are high-S; every proof the node sends is low-S.
            var proof = key.Sign(message);
            Assert.Equal(CloudIdentity.ProofLength, proof.Length);
            Assert.True(CloudIdentity.IsLowS(proof));
            Assert.True(verifier.VerifyData(message, proof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }

        var signature = key.Sign(message);
        foreach (var other in new[]
        {
            CloudIdentity.ProofMessage(CloudIdentity.PurposePoll, Center, _nodeId, CloudIdentity.CompleteBinding(flow, code)),
            CloudIdentity.ProofMessage(CloudIdentity.PurposeComplete, CenterEndpoint.Parse("https://center.example.test"), _nodeId, CloudIdentity.CompleteBinding(flow, code)),
            CloudIdentity.ProofMessage(CloudIdentity.PurposeComplete, CenterEndpoint.Parse("https://center.example.test/other"), _nodeId, CloudIdentity.CompleteBinding(flow, code)),
            CloudIdentity.ProofMessage(CloudIdentity.PurposeComplete, Center, RandomNumberGenerator.GetBytes(16), CloudIdentity.CompleteBinding(flow, code)),
            CloudIdentity.ProofMessage(CloudIdentity.PurposeComplete, Center, _nodeId, CloudIdentity.CompleteBinding(RandomNumberGenerator.GetBytes(16), code)),
            CloudIdentity.ProofMessage(CloudIdentity.PurposeComplete, Center, _nodeId, CloudIdentity.CompleteBinding(flow, new string('d', 43))),
        })
        {
            Assert.False(verifier.VerifyData(other, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
    }

    [Fact]
    public void NormalizingSReplacesAHighSByItsLowTwin()
    {
        var order = BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture);
        var high = new byte[64];
        high[0] = 1;
        (order - 5).ToByteArray(isUnsigned: true, isBigEndian: true).CopyTo(high, 32);
        var low = CloudIdentity.NormalizeLowS(high);
        Assert.Equal(high[..32], low[..32]);
        Assert.Equal(new BigInteger(5), new BigInteger(low.AsSpan(32), isUnsigned: true, isBigEndian: true));
        Assert.False(CloudIdentity.IsLowS(high));
        Assert.True(CloudIdentity.IsLowS(low));
        Assert.Equal(low, CloudIdentity.NormalizeLowS(low));
    }

    [Fact]
    public void TheFingerprintIsUpperCaseHexOfTheFirstTenDigestBytesInGroupsOfFour()
    {
        var der = RandomNumberGenerator.GetBytes(91);
        var hex = Convert.ToHexString(SHA256.HashData(der)[..10]);
        var fingerprint = CloudIdentity.Fingerprint(der);
        Assert.Matches("^[0-9A-F]{4}(-[0-9A-F]{4}){4}$", fingerprint);
        Assert.Equal(hex, fingerprint.Replace("-", string.Empty, StringComparison.Ordinal));
    }
}
