// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.Node.Core.Files;

/// <summary>Counts and hashes the actual content bytes consumed during a removal plan's ownership checks.</summary>
internal sealed class WorkspaceOwnershipInputAudit : IDisposable
{
    internal const ulong MaximumBytes = 67_108_864;
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private ulong _bytes;

    // In-process tests coordinate real filesystem changes after a returned read; production supplies no callback.
    internal Action? AfterReadForTests { get; init; }

    internal int AllowRead(int requested)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(requested);
        var remaining = MaximumBytes - _bytes;
        if (remaining == 0) throw new WorkspaceRemovalPlanException("removal_ownership_input_bytes");
        return (int)Math.Min((ulong)requested, remaining);
    }

    internal void Append(ReadOnlySpan<byte> actualBytes)
    {
        if ((ulong)actualBytes.Length > MaximumBytes - _bytes)
            throw new InvalidOperationException("Ownership input exceeded its read budget.");
        if (actualBytes.IsEmpty) return;
        _hash.AppendData(actualBytes);
        _bytes += (ulong)actualBytes.Length;
        AfterReadForTests?.Invoke();
    }

    internal FileAuditMetadata? Snapshot() => _bytes == 0 ? null : new FileAuditMetadata
    {
        Observations =
        {
            new FileAuditObservation
            {
                Kind = FileAuditKind.InputBytes,
                SizeBytes = _bytes,
                DigestInputBytes = _bytes,
                Sha256 = ByteString.CopyFrom(_hash.GetCurrentHash()),
            },
        },
    };

    public void Dispose() => _hash.Dispose();
}
