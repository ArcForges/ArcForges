// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ArcForges.Security.Secrets;

internal static class InstallationCredentialRecord
{
    private const int HeaderSize = 52;
    private static ReadOnlySpan<byte> Magic => [0x41, 0x46, 0x49, 0x4B, 0, 0, 0, 1];

    internal static byte[] Create(ReadOnlySpan<byte> scopeHash, out InstallationCredentialIdentity identity)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = key.ExportSubjectPublicKeyInfo();
        var privateKey = key.ExportPkcs8PrivateKey();
        try
        {
            identity = new InstallationCredentialIdentity(1, publicKey);
            var record = new byte[checked(HeaderSize + publicKey.Length + privateKey.Length)];
            Magic.CopyTo(record); scopeHash.CopyTo(record.AsSpan(8, 32));
            BinaryPrimitives.WriteInt64BigEndian(record.AsSpan(40, 8), 1);
            BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(48, 2), checked((ushort)publicKey.Length));
            BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(50, 2), checked((ushort)privateKey.Length));
            publicKey.CopyTo(record.AsSpan(HeaderSize)); privateKey.CopyTo(record.AsSpan(HeaderSize + publicKey.Length));
            return record;
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
    }

    internal static ECDsa Open(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> scopeHash, out InstallationCredentialIdentity identity)
    {
        if (bytes.Length < HeaderSize || bytes.Length > 2560 || !bytes[..8].SequenceEqual(Magic)
            || !CryptographicOperations.FixedTimeEquals(bytes.Slice(8, 32), scopeHash)
            || BinaryPrimitives.ReadInt64BigEndian(bytes.Slice(40, 8)) != 1)
            throw new InvalidDataException("Installation credential record header is invalid.");
        int publicLength = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(48, 2));
        int privateLength = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(50, 2));
        if (publicLength != 91 || privateLength is < 1 or > 1024 || bytes.Length != HeaderSize + publicLength + privateLength
            || !InstallationCredentialIdentity.IsCanonicalPublicKey(bytes.Slice(HeaderSize, publicLength)))
            throw new InvalidDataException("Installation credential record lengths are invalid.");
        var key = ECDsa.Create();
        try
        {
            key.ImportPkcs8PrivateKey(bytes[(HeaderSize + publicLength)..], out var consumed);
            if (consumed != privateLength) throw new InvalidDataException("Trailing private key data is forbidden.");
            var actualPublic = key.ExportSubjectPublicKeyInfo();
            if (!CryptographicOperations.FixedTimeEquals(actualPublic, bytes.Slice(HeaderSize, publicLength)))
                throw new InvalidDataException("Installation public and private keys do not match.");
            var canonicalPrivate = key.ExportPkcs8PrivateKey();
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(canonicalPrivate, bytes[(HeaderSize + publicLength)..]))
                    throw new InvalidDataException("Installation private key encoding is not canonical.");
            }
            finally { CryptographicOperations.ZeroMemory(canonicalPrivate); }
            identity = new InstallationCredentialIdentity(1, actualPublic);
            return key;
        }
        catch { key.Dispose(); throw; }
    }
}
