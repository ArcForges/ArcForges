// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.LocalRpc;

/// <summary>
/// The LocalBootstrap confirmation proof of annex 09: <c>HMAC-SHA256(secret, "arcforges.local.bootstrap.v1" || challenge UUID ||
/// client bytes || server bytes || client instance UUID || server instance UUID)</c>, every UUID as its 16 big-endian (RFC 4122)
/// bytes. The parent verifies it and the child computes it; there is no unauthenticated or SHA-only mode.
/// </summary>
internal static class LocalBootstrapProof
{
    internal const int Length = 32;

    private static readonly byte[] Label = Encoding.UTF8.GetBytes("arcforges.local.bootstrap.v1");

    /// <summary>The exact bytes the proof covers.</summary>
    internal static byte[] Transcript(
        Guid challengeId,
        ReadOnlySpan<byte> clientBytes,
        ReadOnlySpan<byte> serverBytes,
        Guid clientInstance,
        Guid serverInstance)
    {
        if (clientBytes.Length != LocalRpcRegistration.ChallengeLength || serverBytes.Length != LocalRpcRegistration.ChallengeLength)
        {
            throw new ArgumentException("Challenge bytes are 32 bytes each.");
        }

        var transcript = new byte[Label.Length + 16 + clientBytes.Length + serverBytes.Length + 16 + 16];
        var span = transcript.AsSpan();
        Label.CopyTo(span);
        span = span[Label.Length..];
        Write(challengeId, ref span);
        clientBytes.CopyTo(span);
        span = span[clientBytes.Length..];
        serverBytes.CopyTo(span);
        span = span[serverBytes.Length..];
        Write(clientInstance, ref span);
        Write(serverInstance, ref span);
        return transcript;
    }

    /// <summary>Computes the proof under <paramref name="secret"/> (32 bytes) into a new array.</summary>
    internal static byte[] Compute(
        ReadOnlySpan<byte> secret,
        Guid challengeId,
        ReadOnlySpan<byte> clientBytes,
        ReadOnlySpan<byte> serverBytes,
        Guid clientInstance,
        Guid serverInstance)
    {
        if (secret.Length != LocalRpcLaunchDescriptor.SecretLength)
        {
            throw new ArgumentException("The launch secret is 32 bytes.", nameof(secret));
        }

        var transcript = Transcript(challengeId, clientBytes, serverBytes, clientInstance, serverInstance);
        try
        {
            return HMACSHA256.HashData(secret, transcript);
        }
        finally
        {
            // The transcript holds no secret, but nothing about a confirmation outlives it.
            CryptographicOperations.ZeroMemory(transcript);
        }
    }

    /// <summary>Compares a presented proof with the expected one in fixed time; a proof of the wrong length never matches.</summary>
    internal static bool Matches(
        ReadOnlySpan<byte> secret,
        Guid challengeId,
        ReadOnlySpan<byte> clientBytes,
        ReadOnlySpan<byte> serverBytes,
        Guid clientInstance,
        Guid serverInstance,
        ReadOnlySpan<byte> presented)
    {
        var expected = Compute(secret, challengeId, clientBytes, serverBytes, clientInstance, serverInstance);
        try
        {
            return presented.Length == Length && CryptographicOperations.FixedTimeEquals(expected, presented);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    private static void Write(Guid value, ref Span<byte> destination)
    {
        _ = value.TryWriteBytes(destination, bigEndian: true, out _);
        destination = destination[16..];
    }
}
