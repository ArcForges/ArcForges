// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Security.Secrets;

/// <summary>Closed local custody dimension; it is not a new wire platform schema.</summary>
public enum InstallationCredentialPlatform
{
    None = 0,
    Windows = 1,
    MacOs = 2,
    Linux = 3,
}

/// <summary>Actual available adapter classification; unsupported is never a working memory/file substitute.</summary>
public enum InstallationCredentialSupport
{
    Unsupported = 0,
    WindowsSameUserShared = 1,
}

/// <summary>Actual pre-authentication owner supplied by the first-party host; no remote user or session is fabricated.</summary>
public sealed class InstallationCredentialScope
{
    public InstallationCredentialScope(RealmId realm, SecretApplicationDimension application,
        InstallationCredentialPlatform platform, InstallationId installation)
    {
        ArgumentNullException.ThrowIfNull(application);
        if (realm.Value == Guid.Empty || installation.Value == Guid.Empty) throw new ArgumentException("Actual realm and installation identities are required.");
        if (platform == InstallationCredentialPlatform.None || !Enum.IsDefined(platform)) throw new ArgumentOutOfRangeException(nameof(platform));
        Realm = realm; Application = application; Platform = platform; Installation = installation;
    }

    public RealmId Realm { get; }
    public SecretApplicationDimension Application { get; }
    public InstallationCredentialPlatform Platform { get; }
    public InstallationId Installation { get; }
}

/// <summary>Immutable expected or received public key metadata. Private key bytes have no public surface.</summary>
public sealed class InstallationCredentialIdentity
{
    private readonly byte[] _publicKey;
    public InstallationCredentialIdentity(long keyVersion, ReadOnlySpan<byte> publicKey)
    {
        if (keyVersion != 1) throw new ArgumentOutOfRangeException(nameof(keyVersion), "Only stable installation key version 1 is supported.");
        if (!IsCanonicalPublicKey(publicKey)) throw new ArgumentException("Canonical P256 DER-SPKI is required.", nameof(publicKey));
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(publicKey, out var consumed);
        if (consumed != publicKey.Length) throw new ArgumentException("Trailing public key bytes are forbidden.", nameof(publicKey));
        _publicKey = publicKey.ToArray(); KeyVersion = keyVersion;
    }

    public long KeyVersion { get; }
    public byte[] GetPublicKey() => (byte[])_publicKey.Clone();
    internal ReadOnlySpan<byte> PublicKey => _publicKey;
    internal bool Matches(InstallationCredentialIdentity other) => KeyVersion == other.KeyVersion
        && CryptographicOperations.FixedTimeEquals(_publicKey, other._publicKey);
    internal static bool IsCanonicalPublicKey(ReadOnlySpan<byte> bytes) => bytes.Length == 91
        && bytes[..27].SequenceEqual((ReadOnlySpan<byte>)[0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
            0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
            0x07, 0x03, 0x42, 0x00, 0x04]);
    public override string ToString() => "InstallationCredentialIdentity:[public metadata]";
}
