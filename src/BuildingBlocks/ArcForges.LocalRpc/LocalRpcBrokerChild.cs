// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.LocalRpc;

/// <summary>
/// The helper's side of one invocation's output slots. The helper mints nothing: it fills only a slot the parent granted,
/// within the granted capacity, seals exactly that grant, and may reuse the slot only after the parent's matching
/// acknowledgement. Cancellation withdraws every slot at once. The calls that reach it (grant, acknowledgement,
/// cancellation) arrive from the parent over the launch-bound stream; this type enforces the slot rules, not who is calling.
/// </summary>
public sealed class LocalRpcBrokerChild : IDisposable
{
    private const long YieldEveryBytes = 4L * 1024 * 1024;

    private readonly object _gate = new();
    private readonly CancellationTokenSource _cancelled = new();
    private readonly ChildSlot[] _slots;
    private bool _isCancelled;

    /// <summary>Creates the helper's slot table from the capacities of the mappings its launch inventory gave it.</summary>
    /// <param name="invocationId">The parent-minted invocation, never zero.</param>
    /// <param name="leaseId">The parent-minted lease, never zero.</param>
    /// <param name="generation">The session generation, positive.</param>
    /// <param name="slotCapacities">The capacity of each slot's mapping, one to three entries of 1 byte through 64 MiB.</param>
    public LocalRpcBrokerChild(Guid invocationId, Guid leaseId, ulong generation, IReadOnlyList<long> slotCapacities)
    {
        ArgumentNullException.ThrowIfNull(slotCapacities);
        if (invocationId == Guid.Empty || leaseId == Guid.Empty)
        {
            throw new ArgumentException("The invocation and lease identifiers are never zero.");
        }

        if (generation == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(generation), generation, "The generation is positive.");
        }

        if (slotCapacities.Count is < 1 or > LocalRpcBrokerLimits.MaxSlots)
        {
            throw new ArgumentException("An invocation has one to three slots.", nameof(slotCapacities));
        }

        if (slotCapacities.Any(capacity => capacity is < 1 or > LocalRpcBrokerLimits.MaxSlotBytes))
        {
            throw new ArgumentException("A slot is 1 byte through 64 MiB.", nameof(slotCapacities));
        }

        InvocationId = invocationId;
        LeaseId = leaseId;
        Generation = generation;
        _slots = [.. slotCapacities.Select(capacity => new ChildSlot(capacity))];
    }

    /// <summary>The invocation this helper serves.</summary>
    public Guid InvocationId { get; }

    /// <summary>The lease this helper serves.</summary>
    public Guid LeaseId { get; }

    /// <summary>The session generation.</summary>
    public ulong Generation { get; }

    /// <summary>Cancelled when the parent cancels the session: the parser stops and nothing more is granted, sealed or acknowledged.</summary>
    public CancellationToken Cancelled => _cancelled.Token;

    /// <summary>Runs just before a seal's digest is computed, outside the lock; only offline fixtures set it.</summary>
    internal Action? BeforeDigest { get; set; }

    /// <summary>The state of each slot.</summary>
    public IReadOnlyList<LocalRpcSlotState> SlotStates
    {
        get
        {
            lock (_gate)
            {
                return [.. _slots.Select(slot => slot.State)];
            }
        }
    }

    /// <summary>
    /// Accepts a grant the parent sent. The slot must be free, the sequence higher than any grant accepted for the slot and
    /// the capacity within the slot's mapping. Receiving the very same grant again is harmless and returns it.
    /// </summary>
    public LocalRpcBrokerResult<LocalRpcSlotGrant> Accept(LocalRpcSlotGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        lock (_gate)
        {
            if (_isCancelled)
            {
                return BrokerResult.Fail<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.Cancelled);
            }

            if (grant.SlotId >= _slots.Length)
            {
                return BrokerResult.Fail<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.UnknownSlot);
            }

            var slot = _slots[grant.SlotId];
            if (slot.State == LocalRpcSlotState.Writing && grant.Sequence == slot.Sequence && grant.Capacity == slot.Capacity)
            {
                return BrokerResult.Ok(grant);
            }

            if (slot.State != LocalRpcSlotState.Free)
            {
                return BrokerResult.Fail<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.SlotBusy);
            }

            if (grant.Sequence <= slot.LastAccepted)
            {
                return BrokerResult.Fail<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.StaleSequence);
            }

            if (grant.Capacity == 0 || grant.Capacity > (ulong)slot.MappingCapacity)
            {
                return BrokerResult.Fail<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.CapacityExceeded);
            }

            slot.State = LocalRpcSlotState.Writing;
            slot.Sequence = grant.Sequence;
            slot.Capacity = grant.Capacity;
            slot.LastAccepted = grant.Sequence;
            return BrokerResult.Ok(grant);
        }
    }

    /// <summary>
    /// Seals the granted slot: <paramref name="written"/> are the bytes the helper wrote at <paramref name="offset"/> inside
    /// the grant. The range must lie inside the granted capacity and the grant must be the slot's outstanding one. The
    /// returned seal carries the SHA-256 of the bytes and is what the helper returns to the parent.
    /// </summary>
    public LocalRpcBrokerResult<LocalRpcBufferSeal> Seal(uint slotId, ulong sequence, ulong offset, ReadOnlySpan<byte> written, ulong rowStride = 0)
    {
        lock (_gate)
        {
            var refusal = CheckSealLocked(slotId, sequence, out var slot);
            if (refusal == LocalRpcBrokerRefusal.None && !LocalRpcBrokerSession.RangeFits(offset, (ulong)written.Length, slot!.Capacity))
            {
                refusal = LocalRpcBrokerRefusal.RangeInvalid;
            }

            if (refusal != LocalRpcBrokerRefusal.None)
            {
                return BrokerResult.Fail<LocalRpcBufferSeal>(refusal);
            }
        }

        // The digest of a large buffer is computed outside the lock: a cancellation must never wait for it.
        BeforeDigest?.Invoke();
        var digest = LocalRpcDigest.Compute(written);
        lock (_gate)
        {
            var refusal = CheckSealLocked(slotId, sequence, out var slot);
            if (refusal != LocalRpcBrokerRefusal.None)
            {
                return BrokerResult.Fail<LocalRpcBufferSeal>(refusal);
            }

            slot!.State = LocalRpcSlotState.Sealed;
            slot.SealedDigest = digest;
            return BrokerResult.Ok(new LocalRpcBufferSeal(InvocationId, LeaseId, Generation, slotId, sequence, offset, (ulong)written.Length, digest, rowStride));
        }
    }

    /// <summary>
    /// Releases a sealed slot for the parent's matching acknowledgement: the session, slot, sequence and the digest of the
    /// parent's private copy must all be those of the seal. The very same acknowledgement again is harmless; a stale sequence
    /// or a different digest is refused.
    /// </summary>
    public LocalRpcBrokerRefusal Acknowledge(LocalRpcBufferAck ack)
    {
        ArgumentNullException.ThrowIfNull(ack);
        ArgumentNullException.ThrowIfNull(ack.Digest);
        lock (_gate)
        {
            if (_isCancelled)
            {
                return LocalRpcBrokerRefusal.Cancelled;
            }

            if (ack.InvocationId != InvocationId || ack.LeaseId != LeaseId || ack.Generation != Generation)
            {
                return LocalRpcBrokerRefusal.WrongSession;
            }

            if (ack.SlotId >= _slots.Length)
            {
                return LocalRpcBrokerRefusal.UnknownSlot;
            }

            var slot = _slots[ack.SlotId];
            switch (slot.State)
            {
                case LocalRpcSlotState.Sealed:
                    if (ack.Sequence != slot.Sequence)
                    {
                        return LocalRpcBrokerRefusal.StaleSequence;
                    }

                    if (!ack.Digest.Equals(slot.SealedDigest))
                    {
                        return LocalRpcBrokerRefusal.DigestMismatch;
                    }

                    slot.State = LocalRpcSlotState.Free;
                    slot.LastAckedSequence = ack.Sequence;
                    slot.LastAckedDigest = slot.SealedDigest;
                    slot.SealedDigest = null;
                    return LocalRpcBrokerRefusal.None;
                case LocalRpcSlotState.Free:
                    if (slot.LastAckedDigest is null || ack.Sequence != slot.LastAckedSequence)
                    {
                        return LocalRpcBrokerRefusal.StaleSequence;
                    }

                    return ack.Digest.Equals(slot.LastAckedDigest) ? LocalRpcBrokerRefusal.None : LocalRpcBrokerRefusal.DigestMismatch;
                default:
                    return LocalRpcBrokerRefusal.NotSealed;
            }
        }
    }

    /// <summary>Withdraws every slot and cancels <see cref="Cancelled"/>. Nothing is granted, sealed or acknowledged afterwards. Safe to repeat.</summary>
    public void Cancel()
    {
        lock (_gate)
        {
            if (_isCancelled)
            {
                return;
            }

            _isCancelled = true;
            foreach (var slot in _slots.Where(slot => slot.State != LocalRpcSlotState.Free))
            {
                slot.State = LocalRpcSlotState.Quarantined;
            }
        }

        // The parser's registrations run here, outside the lock.
        _cancelled.Cancel();
    }

    /// <summary>Cancels, then releases the cancellation source.</summary>
    public void Dispose()
    {
        Cancel();
        _cancelled.Dispose();
    }

    /// <summary>
    /// Checks the helper's read-only input before any parser sees it: the mapping must have exactly the parent-minted length
    /// and the digest, read in bounded chunks that check for cancellation between steps.
    /// </summary>
    /// <param name="input">The read-only input mapping. The caller keeps ownership.</param>
    /// <param name="length">The parent-minted input length, positive.</param>
    /// <param name="digest">The parent-minted SHA-256.</param>
    /// <param name="chunkBytes">The bytes read per step, 4 KiB through 4 MiB.</param>
    /// <param name="cancellationToken">Stops the check.</param>
    public static async ValueTask<LocalRpcBrokerRefusal> VerifyInputAsync(
        ILocalRpcBufferMapping input,
        ulong length,
        LocalRpcDigest digest,
        int chunkBytes = 256 * 1024,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(digest);
        if (chunkBytes is < 4096 or > 4 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkBytes), chunkBytes, "The chunk size is 4 KiB through 4 MiB.");
        }

        if (length == 0 || input.Length != (long)length)
        {
            return LocalRpcBrokerRefusal.InputMismatch;
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[chunkBytes];
        var position = 0L;
        var sinceYield = 0L;
        while (position < (long)length)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return LocalRpcBrokerRefusal.Cancelled;
            }

            var count = (int)Math.Min(chunkBytes, (long)length - position);
            int read;
            try
            {
                read = input.Read(position, buffer.AsSpan(0, count));
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                return LocalRpcBrokerRefusal.MappingFailed;
            }

            if (read != count)
            {
                return LocalRpcBrokerRefusal.MappingFailed;
            }

            hash.AppendData(buffer, 0, count);
            position += count;
            sinceYield += count;
            if (sinceYield >= YieldEveryBytes)
            {
                sinceYield = 0;
                await Task.Yield();
            }
        }

        return digest.Equals(LocalRpcDigest.FromBytes(hash.GetHashAndReset())) ? LocalRpcBrokerRefusal.None : LocalRpcBrokerRefusal.InputMismatch;
    }

    private LocalRpcBrokerRefusal CheckSealLocked(uint slotId, ulong sequence, out ChildSlot? slot)
    {
        slot = null;
        if (_isCancelled)
        {
            return LocalRpcBrokerRefusal.Cancelled;
        }

        if (slotId >= _slots.Length)
        {
            return LocalRpcBrokerRefusal.UnknownSlot;
        }

        slot = _slots[slotId];
        switch (slot.State)
        {
            case LocalRpcSlotState.Free:
                return LocalRpcBrokerRefusal.NotGranted;
            case LocalRpcSlotState.Sealed:
                return LocalRpcBrokerRefusal.AlreadySealed;
            default:
                return sequence == slot.Sequence ? LocalRpcBrokerRefusal.None : LocalRpcBrokerRefusal.StaleSequence;
        }
    }

    private sealed class ChildSlot(long mappingCapacity)
    {
        internal long MappingCapacity { get; } = mappingCapacity;

        internal LocalRpcSlotState State { get; set; }

        internal ulong Sequence { get; set; }

        internal ulong Capacity { get; set; }

        internal ulong LastAccepted { get; set; }

        internal LocalRpcDigest? SealedDigest { get; set; }

        internal ulong LastAckedSequence { get; set; }

        internal LocalRpcDigest? LastAckedDigest { get; set; }
    }
}
