// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.TestLoad;

/// <summary>
/// Platform-independent deterministic values. Every byte TestLoad produces is a pure function of the
/// seed and a position, so equal parameters give equal bytes on every OS, architecture and run.
/// </summary>
internal static class Deterministic
{
    /// <summary>The SplitMix64 finalizer applied to <c>seed + index * golden</c>.</summary>
    public static ulong Mix(ulong seed, ulong index)
    {
        var z = seed + ((index + 1) * 0x9E3779B97F4A7C15UL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }

    /// <summary>Fills <paramref name="destination"/> with the content at byte offset <paramref name="offset"/> (multiple of 8).</summary>
    public static void FillBlocks(ulong seed, long offset, Span<byte> destination)
    {
        if (offset % sizeof(ulong) != 0 || destination.Length % sizeof(ulong) != 0)
        {
            throw new ArgumentException("Block fills must be aligned to 8 bytes.", nameof(destination));
        }

        var block = (ulong)(offset / sizeof(ulong));
        for (var i = 0; i < destination.Length; i += sizeof(ulong), block++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(destination[i..], Mix(seed, block));
        }
    }

    public static string Hex(ReadOnlySpan<byte> hash) => Convert.ToHexStringLower(hash);

    public static IncrementalHash StartDigest(string canonicalParameters)
    {
        var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(canonicalParameters));
        hash.AppendData([0]);
        return hash;
    }

    public static void AppendUInt64(IncrementalHash hash, ulong value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, value);
        hash.AppendData(buffer);
    }
}
