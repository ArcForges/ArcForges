// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;

namespace ArcForges.Node.CloudLink;

/// <summary>
/// The node's second reviewed composition root of OS-wide stores (16-testing-strategy section 1, guard item 3; AF-CTR-04 CTR4-NODE-06),
/// the only production source that names the CNG key store (<c>ArcForges.Repository.Tests</c> checks this). It follows the
/// <c>--test-mode</c> rule of <see cref="NodeSecretStores"/>:
/// <list type="bullet">
/// <item>Production on Windows: a CNG user key in the Microsoft Software Key Storage Provider, not exportable, for signing.</item>
/// <item>Production on Linux: an owner-only PKCS#8 file in the data root (<see cref="FileNodeKeyBackend"/>).</item>
/// <item><c>--test-mode</c> without the tier's exact opt-in: the file-backed key in the test data root on both systems, and no CNG call.</item>
/// </list>
/// The CNG path asks <see cref="OsSecretStoreGuard"/> first, so a process that denies the OS stores (every test process and every
/// <c>--test-mode</c> node) is refused before any CNG call.
/// </summary>
internal static class NodeKeyStores
{
    /// <summary>The node key store for a data root, following the <c>--test-mode</c> rule.</summary>
    public static NodeKeyStore ForNode(string dataRoot, bool testMode) =>
        ForNode(dataRoot, testMode, Environment.GetEnvironmentVariable(OsSecretStoreGuard.OptInVariable));

    /// <summary>As <see cref="ForNode(string, bool)"/> with the opt-in's value given.</summary>
    internal static NodeKeyStore ForNode(string dataRoot, bool testMode, string? optIn) =>
        new(dataRoot, OperatingSystem.IsWindows() && NodeSecretStores.UsesOsSecretStore(testMode, optIn) ? new CngNodeKeyBackend() : new FileNodeKeyBackend(dataRoot));

    /// <summary>The file-backed key store of a (test) data root.</summary>
    public static NodeKeyStore ForTestDataRoot(string dataRoot) => new(dataRoot, new FileNodeKeyBackend(dataRoot));

    /// <summary>
    /// The creation parameters of a CNG node key, as plain values (so a routine test on any host can assert them without naming CNG):
    /// provider, export policy and usage.
    /// </summary>
    public static (string Provider, bool Exportable, string Usage) CngCreationParameters => ("Microsoft Software Key Storage Provider", false, "signing");

    /// <summary>A CNG user key store (Windows production; the OS secret-store tier creates its keys through this type).</summary>
    [SupportedOSPlatform("windows")]
    internal sealed class CngNodeKeyBackend : INodeKeyBackend
    {
        /// <inheritdoc />
        public string Kind => "cng";

        /// <inheritdoc />
        public INodeKey? Open(string name)
        {
            OsSecretStoreGuard.ThrowIfDenied("a CNG user key store");
            if (!CngKey.Exists(name, CngProvider.MicrosoftSoftwareKeyStorageProvider))
            {
                return null;
            }

            return new CngNodeKey(CngKey.Open(name, CngProvider.MicrosoftSoftwareKeyStorageProvider));
        }

        /// <inheritdoc />
        public INodeKey Create(string name)
        {
            OsSecretStoreGuard.ThrowIfDenied("a CNG user key store");
            var parameters = new CngKeyCreationParameters
            {
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                ExportPolicy = CngExportPolicies.None,
                KeyUsage = CngKeyUsages.Signing,
            };
            return new CngNodeKey(CngKey.Create(CngAlgorithm.ECDsaP256, name, parameters));
        }

        /// <inheritdoc />
        public bool Delete(string name)
        {
            OsSecretStoreGuard.ThrowIfDenied("a CNG user key store");
            if (!CngKey.Exists(name, CngProvider.MicrosoftSoftwareKeyStorageProvider))
            {
                return false;
            }

            using var key = CngKey.Open(name, CngProvider.MicrosoftSoftwareKeyStorageProvider);
            key.Delete();
            return true;
        }

        /// <inheritdoc />
        public IReadOnlyList<string> Names() => [];
    }

    [SupportedOSPlatform("windows")]
    private sealed class CngNodeKey : INodeKey
    {
        private readonly CngKey _handle;
        private readonly ECDsaCng _key;

        public CngNodeKey(CngKey key)
        {
            _handle = key;
            _key = new ECDsaCng(key);
            PublicKey = _key.ExportSubjectPublicKeyInfo();
        }

        public byte[] PublicKey { get; }

        public byte[] Sign(ReadOnlySpan<byte> message) =>
            CloudIdentity.NormalizeLowS(_key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        public void Dispose()
        {
            _key.Dispose();
            _handle.Dispose();
        }
    }
}
