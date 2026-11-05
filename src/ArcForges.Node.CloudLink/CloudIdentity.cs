// SPDX-License-Identifier: AGPL-3.0-only
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink;

/// <summary>
/// The node's identity towards a center (AF-CTR-04 CTR4-NODE-06, CTR4-KEY-01/02 as frozen by C0): the node key proof preimage, its
/// low-S normalization and the key fingerprint, as pure functions. fleet.proto, "Node key proof": ES256 over
/// <c>"ArcForges node-key-proof v1\n" (28 bytes ASCII) || purpose (1 byte) || SHA-256(audience) (32 bytes) || node_id (16 bytes) ||
/// binding</c>; "audience = the full canonical center URL the node is configured with"; "IEEE P1363 r||s, 64 bytes, r and s in [1, n-1],
/// low-S (s &lt;= n/2); the node normalizes s, and the center refuses a high-S proof".
/// </summary>
internal static class CloudIdentity
{
    /// <summary>The leading domain string (28 bytes of ASCII).</summary>
    public const string ProofDomain = "ArcForges node-key-proof v1\n";

    /// <summary>The purpose of CompleteNodeSignIn's proof: binding = flow_id (16 bytes) || code (UTF-8, 43 characters).</summary>
    public const byte PurposeComplete = 0x01;

    /// <summary>The purpose of PollDeviceAuthorization's proof: binding = device_code (UTF-8, 43 characters).</summary>
    public const byte PurposePoll = 0x02;

    /// <summary>A node key is the PKIX SubjectPublicKeyInfo DER of a P-256 key: 91 bytes (fleet.proto <c>node_public_key</c>).</summary>
    public const int PublicKeyLength = 91;

    /// <summary>A proof is an IEEE P1363 signature: 64 bytes.</summary>
    public const int ProofLength = 64;

    private static readonly BigInteger Order = BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", System.Globalization.NumberStyles.HexNumber,
        System.Globalization.CultureInfo.InvariantCulture);

    private static readonly BigInteger HalfOrder = Order >> 1;

    /// <summary>
    /// The signed message. The audience is the <paramref name="center"/> the node is configured with, never a value taken from a center's
    /// reply; <paramref name="nodeId"/> is the 16 bytes of <c>Id.value</c> (never a platform GUID byte order).
    /// </summary>
    public static byte[] ProofMessage(byte purpose, CenterEndpoint center, ReadOnlySpan<byte> nodeId, ReadOnlySpan<byte> binding)
    {
        ArgumentNullException.ThrowIfNull(center);
        if (purpose is not (PurposeComplete or PurposePoll))
        {
            throw new ArgumentOutOfRangeException(nameof(purpose), "Other purpose values are reserved.");
        }

        if (nodeId.Length != 16)
        {
            throw new ArgumentException("A node ID is 16 bytes.", nameof(nodeId));
        }

        var audience = SHA256.HashData(Encoding.UTF8.GetBytes(center.Url));
        var message = new byte[ProofDomain.Length + 1 + audience.Length + nodeId.Length + binding.Length];
        var span = message.AsSpan();
        Encoding.ASCII.GetBytes(ProofDomain, span);
        span = span[ProofDomain.Length..];
        span[0] = purpose;
        audience.CopyTo(span[1..]);
        nodeId.CopyTo(span[33..]);
        binding.CopyTo(span[49..]);
        return message;
    }

    /// <summary>CompleteNodeSignIn's binding: the flow ID's 16 bytes, then the code (43 base64url characters), both checked first.</summary>
    public static byte[] CompleteBinding(ReadOnlySpan<byte> flowId, string code)
    {
        if (flowId.Length != 16)
        {
            throw new ArgumentException("A flow ID is 16 bytes.", nameof(flowId));
        }

        RequireBase64Url43(code, nameof(code));
        var binding = new byte[16 + code.Length];
        flowId.CopyTo(binding);
        Encoding.ASCII.GetBytes(code, binding.AsSpan(16));
        return binding;
    }

    /// <summary>PollDeviceAuthorization's binding: the device code (43 base64url characters), checked first.</summary>
    public static byte[] PollBinding(string deviceCode)
    {
        RequireBase64Url43(deviceCode, nameof(deviceCode));
        return Encoding.ASCII.GetBytes(deviceCode);
    }

    /// <summary>
    /// Replaces s by n - s when s &gt; n/2 (the center refuses a high-S proof). <paramref name="signature"/> is a 64-byte P1363 signature;
    /// a new array is returned.
    /// </summary>
    public static byte[] NormalizeLowS(ReadOnlySpan<byte> signature)
    {
        if (signature.Length != ProofLength)
        {
            throw new ArgumentException("A P-256 signature in P1363 form is 64 bytes.", nameof(signature));
        }

        var result = signature.ToArray();
        var s = new BigInteger(signature[32..], isUnsigned: true, isBigEndian: true);
        if (s > HalfOrder)
        {
            var low = Order - s;
            Array.Clear(result, 32, 32);
            var bytes = low.ToByteArray(isUnsigned: true, isBigEndian: true);
            bytes.CopyTo(result.AsSpan(64 - bytes.Length));
        }

        return result;
    }

    /// <summary>True when s of a 64-byte P1363 signature is in the lower half of the order.</summary>
    public static bool IsLowS(ReadOnlySpan<byte> signature) =>
        signature.Length == ProofLength && new BigInteger(signature[32..], isUnsigned: true, isBigEndian: true) <= HalfOrder;

    /// <summary>
    /// The fingerprint people compare (account.proto <c>SignInFlow.node_key_fingerprint</c>): "XXXX-XXXX-XXXX-XXXX-XXXX: upper-case hex of the
    /// first 10 bytes of SHA-256 over the node public key (PKIX DER)".
    /// </summary>
    public static string Fingerprint(ReadOnlySpan<byte> publicKeyDer)
    {
        var hex = Convert.ToHexString(SHA256.HashData(publicKeyDer)[..10]);
        return hex[..4] + "-" + hex[4..8] + "-" + hex[8..12] + "-" + hex[12..16] + "-" + hex[16..20];
    }

    private static void RequireBase64Url43(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length != 43 || !value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
        {
            throw new ArgumentException("The value is not 43 base64url characters.", name);
        }
    }
}
