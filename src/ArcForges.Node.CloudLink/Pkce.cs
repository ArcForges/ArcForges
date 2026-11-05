// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Node.CloudLink;

/// <summary>
/// PKCE and the loopback state of the browser sign-in (AF-CTR-04 CTR4-NODE-12, RFC 7636): a verifier of 48 random bytes in base64url (64
/// characters; fleet.proto <c>code_verifier</c> "43..128 chars"), the S256 challenge (the only method the center admits; 43 characters) and
/// a state of 32 random bytes in base64url (43 characters, within "16..128 chars of [A-Za-z0-9._~-]"). Fresh for every Begin.
/// </summary>
internal static class Pkce
{
    /// <summary>A new code verifier.</summary>
    public static string NewVerifier() => Base64Url(RandomNumberGenerator.GetBytes(48));

    /// <summary>A new loopback state.</summary>
    public static string NewState() => Base64Url(RandomNumberGenerator.GetBytes(32));

    /// <summary>The S256 challenge: <c>BASE64URL(SHA-256(ASCII(verifier)))</c>.</summary>
    public static string Challenge(string verifier)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        return Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
    }

    /// <summary>True for 43 characters of <c>[A-Za-z0-9_-]</c> (a one-use code, a device code, a challenge).</summary>
    public static bool IsBase64Url43(string? value) => value is { Length: 43 } && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>Base64url without padding (RFC 4648 section 5).</summary>
    public static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
