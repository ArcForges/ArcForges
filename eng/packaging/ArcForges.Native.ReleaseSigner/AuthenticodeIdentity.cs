// SPDX-License-Identifier: AGPL-3.0-only
using System.Formats.Asn1;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ArcForges.Native.ReleaseSigner;

/// <summary>Identity extraction after actual OS cryptographic trust, not a substitute for WinVerifyTrust.</summary>
internal static class AuthenticodeIdentity
{
    internal static async Task VerifySignerAsync(string file, string expectedThumbprint, bool requireRfc3161,
        CancellationToken cancellationToken, string? expectedCertificateSha256 = null)
    {
        if (expectedThumbprint.Length != 40 || expectedThumbprint.Any(c => !char.IsAsciiHexDigit(c)))
        {
            throw new ArgumentException("An independently approved signing leaf identity is required.");
        }

        using var stream = new FileStream(ReleaseCommand.CanonicalFilePath(file), FileMode.Open, FileAccess.Read,
            FileShare.Read, 65536, FileOptions.Asynchronous);
        if (stream.Length is 0 or > 256 * 1024 * 1024) { throw new InvalidDataException("Unbounded helper trust input."); }
        int offset, length;
        using (var reader = new PEReader(stream, PEStreamOptions.LeaveOpen))
        {
            var header = reader.PEHeaders.PEHeader ?? throw new InvalidDataException("The helper is not a PE executable.");
            offset = header.CertificateTableDirectory.RelativeVirtualAddress;
            length = header.CertificateTableDirectory.Size;
        }

        if (offset <= 0 || length is < 8 or > 4 * 1024 * 1024 || offset % 8 != 0
            || (long)offset + length > stream.Length)
        {
            throw new CryptographicException("The helper has no bounded embedded signing identity.");
        }

        stream.Position = offset;
        var bytes = new byte[length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        var entryLength = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(bytes);
        if (entryLength < 8 || entryLength > bytes.Length || ((entryLength + 7) & ~7) != bytes.Length
            || System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(4)) != 0x0200
            || System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(6)) != 2)
        {
            throw new CryptographicException("The helper signing table is ambiguous or unsupported.");
        }

        try { VerifyCms(bytes.AsMemory(8, entryLength - 8), expectedThumbprint, requireRfc3161, expectedCertificateSha256); }
        catch (AsnContentException) { throw new CryptographicException("Malformed embedded signing identity."); }
        cancellationToken.ThrowIfCancellationRequested();
    }

    private static void VerifyCms(ReadOnlyMemory<byte> bytes, string expectedThumbprint, bool requireRfc3161, string? expectedCertificateSha256)
    {
        var frame = new AsnReader(bytes, AsnEncodingRules.DER);
        var encodedCms = frame.ReadEncodedValue();
        var padding = bytes.Span[encodedCms.Length..];
        if (padding.Length > 7 || padding.ContainsAnyExcept((byte)0))
        {
            throw new CryptographicException("Foreign data in the signing table alignment padding.");
        }

        var outer = new AsnReader(encodedCms, AsnEncodingRules.DER);
        var content = outer.ReadSequence();
        if (content.ReadObjectIdentifier() != "1.2.840.113549.1.7.2") { throw new CryptographicException("Not embedded SignedData."); }
        var explicitContent = content.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        var signed = explicitContent.ReadSequence();
        _ = signed.ReadInteger();
        _ = signed.ReadSetOf(); // OS policy already verified digest algorithms and signed content.
        _ = signed.ReadSequence();
        var certificates = signed.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        var leaves = new List<X509Certificate2>();
        try
        {
            while (certificates.HasData)
            {
                if (leaves.Count == 32) { throw new CryptographicException("Unbounded embedded certificate inventory."); }
                var encoded = certificates.ReadEncodedValue();
                if (encoded.Length > 65536) { throw new CryptographicException("Unbounded embedded certificate."); }
                leaves.Add(X509CertificateLoader.LoadCertificate(encoded.Span));
            }

            if (signed.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                _ = signed.ReadEncodedValue(); // Optional revocation evidence is evaluated by the real OS policy.
            }

            var signers = signed.ReadSetOf();
            var signer = signers.ReadSequence();
            if (signer.ReadInteger() != 1) { throw new CryptographicException("Unsupported primary signer identity."); }
            var identifier = signer.ReadSequence();
            var issuer = identifier.ReadEncodedValue();
            var serial = identifier.ReadIntegerBytes();
            identifier.ThrowIfNotEmpty();
            signers.ThrowIfNotEmpty(); // No self-selected extra primary signer can waive the approved identity.
            var matches = leaves.Where(certificate => certificate.IssuerName.RawData.AsSpan().SequenceEqual(issuer.Span)
                && Serial(certificate).AsSpan().SequenceEqual(Positive(serial.Span))).ToArray();
            if (matches.Length != 1 || !string.Equals(matches[0].Thumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new CryptographicException("The actual helper signer differs from independently approved authority.");
            }
            if (expectedCertificateSha256 is not null
                && Convert.ToHexStringLower(SHA256.HashData(matches[0].RawData)) != expectedCertificateSha256)
            {
                throw new CryptographicException("The selected private-store signing leaf changed before publication.");
            }

            _ = signer.ReadSequence();
            if (signer.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0))) { _ = signer.ReadEncodedValue(); }
            _ = signer.ReadSequence();
            _ = signer.ReadOctetString();
            var timestamp = false;
            if (signer.HasData)
            {
                var attributes = signer.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
                var count = 0;
                while (attributes.HasData)
                {
                    if (++count > 32) { throw new CryptographicException("Unbounded unsigned signing attributes."); }
                    var attribute = attributes.ReadSequence();
                    var oid = attribute.ReadObjectIdentifier();
                    var values = attribute.ReadSetOf();
                    if (!values.HasData) { throw new CryptographicException("Missing signing attribute value."); }
                    var value = values.ReadEncodedValue();
                    values.ThrowIfNotEmpty();
                    attribute.ThrowIfNotEmpty();
                    if (oid is "1.3.6.1.4.1.311.3.3.1" or "1.2.840.113549.1.9.16.2.14")
                    {
                        if (timestamp || value.IsEmpty) { throw new CryptographicException("Ambiguous RFC3161 signing evidence."); }
                        timestamp = true;
                    }
                }
            }

            if (requireRfc3161 && !timestamp) { throw new CryptographicException("No actual RFC3161 signing evidence."); }
            signer.ThrowIfNotEmpty();
            signed.ThrowIfNotEmpty();
            explicitContent.ThrowIfNotEmpty();
            content.ThrowIfNotEmpty();
            outer.ThrowIfNotEmpty();
        }
        finally { foreach (var certificate in leaves) { certificate.Dispose(); } }
    }

    private static byte[] Serial(X509Certificate2 certificate)
    {
        var serial = certificate.GetSerialNumber();
        Array.Reverse(serial);
        return Positive(serial).ToArray();
    }

    private static ReadOnlySpan<byte> Positive(ReadOnlySpan<byte> value)
    {
        while (value.Length > 1 && value[0] == 0) { value = value[1..]; }
        return value;
    }
}
