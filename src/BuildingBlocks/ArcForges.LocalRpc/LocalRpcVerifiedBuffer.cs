// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.LocalRpc;

/// <summary>
/// The parent's private copy of a sealed buffer, verified against the sealed digest on the copy itself. Nothing the helper
/// writes afterwards can change it. Dispose it to zero it and to let the session admit its next copy.
/// </summary>
public sealed class LocalRpcVerifiedBuffer : IDisposable
{
    private readonly LocalRpcBrokerSession _session;
    private byte[]? _bytes;

    internal LocalRpcVerifiedBuffer(LocalRpcBrokerSession session, byte[] bytes, uint slotId, ulong sequence, LocalRpcDigest digest)
    {
        _session = session;
        _bytes = bytes;
        SlotId = slotId;
        Sequence = sequence;
        Digest = digest;
        Length = bytes.Length;
    }

    /// <summary>The slot the bytes came from.</summary>
    public uint SlotId { get; }

    /// <summary>The sequence of the grant the bytes came from.</summary>
    public ulong Sequence { get; }

    /// <summary>The verified digest of the bytes.</summary>
    public LocalRpcDigest Digest { get; }

    /// <summary>The number of bytes.</summary>
    public int Length { get; }

    /// <summary>The verified bytes. Reading them after <see cref="Dispose"/> throws.</summary>
    public ReadOnlyMemory<byte> Bytes => _bytes ?? throw new ObjectDisposedException(nameof(LocalRpcVerifiedBuffer));

    /// <summary>Zeroes the private copy and releases the session's copy budget. Safe to repeat.</summary>
    public void Dispose()
    {
        var bytes = Interlocked.Exchange(ref _bytes, null);
        if (bytes is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(bytes);
        _session.ReleaseCopy();
    }
}
