// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace ArcForges.LocalRpc;

/// <summary>What the owner supplies to open a brokered session for one invocation of one helper.</summary>
public sealed class LocalRpcBrokerSessionOptions
{
    /// <summary>The parent-minted invocation, never zero.</summary>
    public Guid InvocationId { get; init; }

    /// <summary>The parent-minted lease, never zero.</summary>
    public Guid LeaseId { get; init; }

    /// <summary>The session generation, positive.</summary>
    public ulong Generation { get; init; }

    /// <summary>The slot mappings, one to three, each 1 byte through 64 MiB and each a distinct object. The session owns them once it is created.</summary>
    public IReadOnlyList<ILocalRpcBufferMapping> Slots { get; init; } = [];

    /// <summary>When cancelled, the parent-child pair is gone and the session closes (for example a launch's <c>Revoked</c> token).</summary>
    public CancellationToken PairGone { get; init; }

    /// <summary>Asked before every lease renewal: false closes the session instead of renewing it. A throwing check counts as false.</summary>
    public Func<bool>? PairLives { get; init; }

    /// <summary>Called once, outside every session lock, when the session ends. An exception it throws is swallowed.</summary>
    public Action<LocalRpcBrokerEnd>? Ended { get; init; }

    /// <summary>The sequence of the first grant of every slot; only offline fixtures change it.</summary>
    internal ulong FirstSequence { get; init; } = 1;
}

/// <summary>
/// The parent's side of one invocation's output slots. The parent is the only authority: it grants a slot, the helper fills
/// only that grant and seals it, the parent verifies the seal, copies the declared bytes into private memory in bounded
/// chunks, checks the digest on that copy and only then acknowledges, which frees the slot. Cancellation, expiry, a lost
/// pair or an integrity failure withdraw every slot and release every mapping; a slot is never silently recycled.
/// </summary>
public sealed class LocalRpcBrokerSession : IDisposable
{
    private const long YieldEveryBytes = 4L * 1024 * 1024;

    private readonly object _gate = new();
    private readonly LocalRpcBrokerRegistry _registry;
    private readonly TimeProvider _time;
    private readonly LocalRpcBrokerLimits _limits;
    private readonly Slot[] _slots;
    private readonly CancellationTokenSource _cancelled = new();
    private readonly Action<LocalRpcBrokerEnd>? _ended;
    private readonly Func<bool>? _pairLives;
    private readonly CancellationToken _pairGone;
    private ITimer? _timer;
    private CancellationTokenRegistration _pairRegistration;
    private LocalRpcBrokerSessionState _state = LocalRpcBrokerSessionState.Open;
    private LocalRpcBrokerEndReason? _endReason;
    private long _leaseStart;
    private long _graceStart;
    private bool _copyActive;
    private bool _copyRunning;
    private bool _mappingsReleased;
    private long _refusals;

    internal LocalRpcBrokerSession(LocalRpcBrokerRegistry registry, LocalRpcBrokerSessionOptions options, ILocalRpcBufferMapping[] mappings, long[] lengths)
    {
        _registry = registry;
        _time = registry.Time;
        _limits = registry.Limits;
        InvocationId = options.InvocationId;
        LeaseId = options.LeaseId;
        Generation = options.Generation;
        _ended = options.Ended;
        _pairLives = options.PairLives;
        _pairGone = options.PairGone;
        _slots = [.. mappings.Select((mapping, index) => new Slot(mapping, lengths[index], options.FirstSequence))];
        _leaseStart = _time.GetTimestamp();
    }

    /// <summary>The invocation this session serves.</summary>
    public Guid InvocationId { get; }

    /// <summary>The lease this session serves.</summary>
    public Guid LeaseId { get; }

    /// <summary>The session generation.</summary>
    public ulong Generation { get; }

    /// <summary>Why the session ended, or null while it has not.</summary>
    public LocalRpcBrokerEndReason? EndReason
    {
        get
        {
            lock (_gate)
            {
                return _endReason;
            }
        }
    }

    /// <summary>The current lifecycle state.</summary>
    public LocalRpcBrokerSessionState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    /// <summary>When the lease runs out unless it is renewed (UTC, from the registry's clock).</summary>
    public DateTimeOffset LeaseExpiresAt
    {
        get
        {
            lock (_gate)
            {
                return _time.GetUtcNow() + LeaseRemainingLocked();
            }
        }
    }

    internal void Start()
    {
        lock (_gate)
        {
            if (_state == LocalRpcBrokerSessionState.Closed)
            {
                return;
            }

            _timer = _time.CreateTimer(OnTimer, null, Max(LeaseRemainingLocked(), TimeSpan.Zero), Timeout.InfiniteTimeSpan);
        }

        var registration = _pairGone.Register(static state => ((LocalRpcBrokerSession)state!).CloseWith(LocalRpcBrokerEndReason.PairGone), this);
        var disposeNow = false;
        lock (_gate)
        {
            if (_state == LocalRpcBrokerSessionState.Closed)
            {
                disposeNow = true;
            }
            else
            {
                _pairRegistration = registration;
            }
        }

        if (disposeNow)
        {
            registration.Dispose();
        }
    }

    /// <summary>
    /// Grants a free slot to the helper: the grant carries the slot's next sequence and the capacity the helper may fill. The
    /// slot is then writing, and only a seal of exactly this grant is honoured.
    /// </summary>
    public LocalRpcBrokerResult<LocalRpcSlotGrant> Grant(uint slotId, ulong capacity) => Counted(GrantCore(slotId, capacity));

    /// <summary>
    /// Verifies the seal the helper returned for a grant: the session identity, the slot's state, the sequence, the range
    /// inside the granted capacity and, when <paramref name="expected"/> is given, the row geometry. A refused seal changes
    /// nothing, so the grant stays outstanding. The digest is not checked here; it is checked on the private copy.
    /// </summary>
    public LocalRpcBrokerRefusal Seal(LocalRpcBufferSeal seal, LocalRpcBufferLayout? expected = null)
    {
        ArgumentNullException.ThrowIfNull(seal);
        ArgumentNullException.ThrowIfNull(seal.Digest);
        if (expected is not null && (expected.Rows == 0 || expected.RowBytes == 0))
        {
            throw new ArgumentOutOfRangeException(nameof(expected), expected, "An expected layout has at least one row of at least one byte.");
        }

        return Counted(SealCore(seal, expected));
    }

    /// <summary>
    /// Copies the sealed buffer of a slot into a private buffer owned by the parent, in bounded chunks, and checks the digest
    /// on that copy. At most one copy (and its undisposed buffer) exists per session. A mapping the helper keeps writing can
    /// only make the digest differ: the bytes returned are the verified private ones. A digest mismatch or a mapping failure
    /// ends the session; the caller's own cancellation only abandons this attempt.
    /// </summary>
    public async ValueTask<LocalRpcBrokerResult<LocalRpcVerifiedBuffer>> CopyAsync(uint slotId, ulong sequence, CancellationToken cancellationToken = default)
    {
        var result = await CopyCoreAsync(slotId, sequence, cancellationToken).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            _ = Interlocked.Increment(ref _refusals);
        }

        return result;
    }

    /// <summary>
    /// Acknowledges a copied and verified buffer: the slot becomes free and its next sequence one higher. The returned
    /// acknowledgement carries the digest of the parent's private copy for the helper to compare. A duplicate request for the
    /// last acknowledged sequence returns the same acknowledgement; any other sequence is stale.
    /// </summary>
    public LocalRpcBrokerResult<LocalRpcBufferAck> Acknowledge(uint slotId, ulong sequence) => Counted(AcknowledgeCore(slotId, sequence));

    /// <summary>
    /// Extends the lease to its full length from now, after asking the pair check. An expired, cancelled or closed session is
    /// not revived, and a failing pair check closes the session.
    /// </summary>
    public LocalRpcBrokerRefusal Renew()
    {
        var pairLives = true;
        if (_pairLives is not null)
        {
            try
            {
                pairLives = _pairLives();
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                pairLives = false;
            }
        }

        PendingClose? pending = null;
        LocalRpcBrokerRefusal refusal;
        lock (_gate)
        {
            refusal = AdmitLocked(ref pending);
            if (refusal == LocalRpcBrokerRefusal.None && !pairLives)
            {
                pending = CloseLocked(LocalRpcBrokerEndReason.PairGone);
                refusal = LocalRpcBrokerRefusal.PairGone;
            }

            if (refusal == LocalRpcBrokerRefusal.None)
            {
                // The armed timer fires at the old due time, finds time left and re-arms for the remainder.
                _leaseStart = _time.GetTimestamp();
            }
        }

        Finish(pending);
        return Counted(refusal);
    }

    /// <summary>
    /// Cancels the invocation: every slot with an outstanding grant, seal or copy is withdrawn for good, a copy in progress is
    /// stopped and no later grant, seal, copy, acknowledgement or renewal is honoured. The owner closes the session once the
    /// helper's disposition is known; if it does not within the cancel grace period the session is closed by itself and
    /// <see cref="LocalRpcBrokerEndReason.CancelUnresponsive"/> asks the owner to terminate the helper. Repeating it changes nothing.
    /// </summary>
    public void Cancel()
    {
        lock (_gate)
        {
            if (_state != LocalRpcBrokerSessionState.Open)
            {
                return;
            }

            _state = LocalRpcBrokerSessionState.Cancelled;
            _graceStart = _time.GetTimestamp();
            foreach (var slot in _slots.Where(slot => slot.State != LocalRpcSlotState.Free))
            {
                slot.State = LocalRpcSlotState.Quarantined;
            }

            ArmLocked();
        }

        CancelSource();
    }

    /// <summary>Ends the session normally: every mapping is released, once no copy is still reading one. Safe to repeat.</summary>
    public void Close() => CloseWith(LocalRpcBrokerEndReason.Closed);

    /// <inheritdoc />
    public void Dispose()
    {
        Close();
        _timer?.Dispose();
    }

    /// <summary>A point-in-time view of the session.</summary>
    public LocalRpcBrokerSnapshot GetSnapshot()
    {
        lock (_gate)
        {
            return new LocalRpcBrokerSnapshot(
                _state,
                [.. _slots.Select(slot => slot.State)],
                [.. _slots.Select(slot => slot.NextSequence)],
                _copyActive,
                Interlocked.Read(ref _refusals));
        }
    }

    internal void CloseWith(LocalRpcBrokerEndReason reason)
    {
        PendingClose? pending;
        lock (_gate)
        {
            pending = CloseLocked(reason);
        }

        Finish(pending);
    }

    internal void ReleaseCopy()
    {
        lock (_gate)
        {
            _copyActive = false;
        }
    }

    internal static bool RangeFits(ulong offset, ulong length, ulong capacity) => length >= 1 && offset <= capacity && length <= capacity - offset;

    internal static bool GeometryFits(ulong length, ulong rowStride, LocalRpcBufferLayout layout)
    {
        // The last row may stop at its end of data: (rows - 1) strides plus one row, up to rows whole strides. A stride shorter
        // than a row makes that interval empty, so no length fits it.
        var minimum = ((UInt128)(layout.Rows - 1) * rowStride) + layout.RowBytes;
        var maximum = (UInt128)layout.Rows * rowStride;
        return length >= minimum && length <= maximum;
    }

    private LocalRpcBrokerResult<T> Counted<T>(LocalRpcBrokerResult<T> result)
        where T : class
    {
        if (!result.IsSuccess)
        {
            _ = Interlocked.Increment(ref _refusals);
        }

        return result;
    }

    private LocalRpcBrokerRefusal Counted(LocalRpcBrokerRefusal refusal)
    {
        if (refusal != LocalRpcBrokerRefusal.None)
        {
            _ = Interlocked.Increment(ref _refusals);
        }

        return refusal;
    }

    private LocalRpcBrokerResult<LocalRpcSlotGrant> GrantCore(uint slotId, ulong capacity)
    {
        PendingClose? pending = null;
        LocalRpcBrokerResult<LocalRpcSlotGrant> result;
        lock (_gate)
        {
            var admit = AdmitLocked(ref pending);
            if (admit != LocalRpcBrokerRefusal.None)
            {
                result = BrokerResult.Fail<LocalRpcSlotGrant>(admit);
            }
            else if (slotId >= _slots.Length)
            {
                result = BrokerResult.Fail<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.UnknownSlot);
            }
            else
            {
                var slot = _slots[slotId];
                if (slot.State != LocalRpcSlotState.Free)
                {
                    result = BrokerResult.Fail<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.SlotBusy);
                }
                else if (capacity == 0 || capacity > (ulong)slot.MappingLength)
                {
                    result = BrokerResult.Fail<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.CapacityExceeded);
                }
                else if (slot.NextSequence == ulong.MaxValue)
                {
                    result = BrokerResult.Fail<LocalRpcSlotGrant>(LocalRpcBrokerRefusal.SequenceExhausted);
                }
                else
                {
                    slot.State = LocalRpcSlotState.Writing;
                    slot.Sequence = slot.NextSequence;
                    slot.Capacity = capacity;
                    slot.Seal = null;
                    slot.CopiedDigest = null;
                    result = BrokerResult.Ok(new LocalRpcSlotGrant(slotId, slot.Sequence, capacity));
                }
            }
        }

        Finish(pending);
        return result;
    }

    private LocalRpcBrokerRefusal SealCore(LocalRpcBufferSeal seal, LocalRpcBufferLayout? expected)
    {
        PendingClose? pending = null;
        LocalRpcBrokerRefusal refusal;
        lock (_gate)
        {
            refusal = AdmitLocked(ref pending);
            if (refusal == LocalRpcBrokerRefusal.None)
            {
                refusal = SealLocked(seal, expected);
            }
        }

        Finish(pending);
        return refusal;
    }

    private LocalRpcBrokerRefusal SealLocked(LocalRpcBufferSeal seal, LocalRpcBufferLayout? expected)
    {
        if (seal.InvocationId != InvocationId || seal.LeaseId != LeaseId || seal.Generation != Generation)
        {
            return LocalRpcBrokerRefusal.WrongSession;
        }

        if (seal.SlotId >= _slots.Length)
        {
            return LocalRpcBrokerRefusal.UnknownSlot;
        }

        var slot = _slots[seal.SlotId];
        if (slot.State != LocalRpcSlotState.Writing)
        {
            return slot.State == LocalRpcSlotState.Free ? LocalRpcBrokerRefusal.NotGranted : LocalRpcBrokerRefusal.AlreadySealed;
        }

        if (seal.Sequence != slot.Sequence)
        {
            return LocalRpcBrokerRefusal.StaleSequence;
        }

        if (!RangeFits(seal.Offset, seal.Length, slot.Capacity))
        {
            return LocalRpcBrokerRefusal.RangeInvalid;
        }

        if (expected is null ? seal.RowStride != 0 : !GeometryFits(seal.Length, seal.RowStride, expected))
        {
            return LocalRpcBrokerRefusal.GeometryInvalid;
        }

        slot.State = LocalRpcSlotState.Sealed;
        slot.Seal = seal;
        return LocalRpcBrokerRefusal.None;
    }

    private LocalRpcBrokerResult<LocalRpcBufferAck> AcknowledgeCore(uint slotId, ulong sequence)
    {
        PendingClose? pending = null;
        LocalRpcBrokerResult<LocalRpcBufferAck> result;
        lock (_gate)
        {
            var admit = AdmitLocked(ref pending);
            if (admit != LocalRpcBrokerRefusal.None)
            {
                result = BrokerResult.Fail<LocalRpcBufferAck>(admit);
            }
            else if (slotId >= _slots.Length)
            {
                result = BrokerResult.Fail<LocalRpcBufferAck>(LocalRpcBrokerRefusal.UnknownSlot);
            }
            else
            {
                result = AcknowledgeLocked(_slots[slotId], slotId, sequence);
            }
        }

        Finish(pending);
        return result;
    }

    private LocalRpcBrokerResult<LocalRpcBufferAck> AcknowledgeLocked(Slot slot, uint slotId, ulong sequence)
    {
        switch (slot.State)
        {
            case LocalRpcSlotState.Reading:
                if (sequence != slot.Sequence)
                {
                    return BrokerResult.Fail<LocalRpcBufferAck>(LocalRpcBrokerRefusal.StaleSequence);
                }

                if (slot.CopiedDigest is null)
                {
                    return BrokerResult.Fail<LocalRpcBufferAck>(LocalRpcBrokerRefusal.CopyPending);
                }

                var ack = new LocalRpcBufferAck(InvocationId, LeaseId, Generation, slotId, sequence, slot.CopiedDigest);
                slot.State = LocalRpcSlotState.Free;
                slot.LastAckedSequence = sequence;
                slot.LastAck = ack;
                slot.NextSequence = sequence + 1;
                slot.Seal = null;
                slot.CopiedDigest = null;
                return BrokerResult.Ok(ack);
            case LocalRpcSlotState.Free:
                return slot.LastAck is not null && slot.LastAckedSequence == sequence
                    ? BrokerResult.Ok(slot.LastAck)
                    : BrokerResult.Fail<LocalRpcBufferAck>(LocalRpcBrokerRefusal.StaleSequence);
            case LocalRpcSlotState.Sealed:
                return BrokerResult.Fail<LocalRpcBufferAck>(LocalRpcBrokerRefusal.CopyPending);
            default:
                return BrokerResult.Fail<LocalRpcBufferAck>(LocalRpcBrokerRefusal.NotSealed);
        }
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the verified buffer passes to the caller through the result; every other path zeroes and drops the private copy.")]
    private async ValueTask<LocalRpcBrokerResult<LocalRpcVerifiedBuffer>> CopyCoreAsync(uint slotId, ulong sequence, CancellationToken cancellationToken)
    {
        PendingClose? pending = null;
        Slot slot;
        LocalRpcBufferSeal seal;
        LocalRpcBrokerRefusal claim;
        lock (_gate)
        {
            (claim, slot, seal) = ClaimLocked(slotId, sequence, ref pending);
        }

        Finish(pending);
        if (claim != LocalRpcBrokerRefusal.None)
        {
            return BrokerResult.Fail<LocalRpcVerifiedBuffer>(claim);
        }

        byte[]? buffer = null;
        CancellationTokenSource? linked = null;
        try
        {
            linked = CancellationTokenSource.CreateLinkedTokenSource(_cancelled.Token, cancellationToken);
            try
            {
                buffer = GC.AllocateUninitializedArray<byte>(checked((int)seal.Length));
            }
            catch (OutOfMemoryException)
            {
                return BrokerResult.Fail<LocalRpcVerifiedBuffer>(EndCopy(slot, seal, LocalRpcBrokerRefusal.OutOfMemory, digest: null));
            }

            var (refusal, digest) = await RunCopyAsync(slot, seal, buffer, linked.Token).ConfigureAwait(false);
            refusal = EndCopy(slot, seal, refusal, digest);
            if (refusal != LocalRpcBrokerRefusal.None)
            {
                CryptographicOperations.ZeroMemory(buffer);
                return BrokerResult.Fail<LocalRpcVerifiedBuffer>(refusal);
            }

            var verified = new LocalRpcVerifiedBuffer(this, buffer, slotId, sequence, digest!);
            buffer = null;
            return BrokerResult.Ok(verified);
        }
        finally
        {
            if (buffer is not null)
            {
                CryptographicOperations.ZeroMemory(buffer);
            }

            linked?.Dispose();
            lock (_gate)
            {
                _copyRunning = false;
            }

            ReleaseMappings();
        }
    }

    private (LocalRpcBrokerRefusal Refusal, Slot Slot, LocalRpcBufferSeal Seal) ClaimLocked(uint slotId, ulong sequence, ref PendingClose? pending)
    {
        var admit = AdmitLocked(ref pending);
        if (admit != LocalRpcBrokerRefusal.None)
        {
            return (admit, null!, null!);
        }

        if (slotId >= _slots.Length)
        {
            return (LocalRpcBrokerRefusal.UnknownSlot, null!, null!);
        }

        var slot = _slots[slotId];
        if (slot.State == LocalRpcSlotState.Reading)
        {
            return (LocalRpcBrokerRefusal.CopyBusy, null!, null!);
        }

        if (slot.State != LocalRpcSlotState.Sealed)
        {
            return (LocalRpcBrokerRefusal.NotSealed, null!, null!);
        }

        if (sequence != slot.Sequence)
        {
            return (LocalRpcBrokerRefusal.StaleSequence, null!, null!);
        }

        if (_copyActive)
        {
            return (LocalRpcBrokerRefusal.CopyBusy, null!, null!);
        }

        slot.State = LocalRpcSlotState.Reading;
        _copyActive = true;
        _copyRunning = true;
        return (LocalRpcBrokerRefusal.None, slot, slot.Seal!);
    }

    private async ValueTask<(LocalRpcBrokerRefusal Refusal, LocalRpcDigest? Digest)> RunCopyAsync(Slot slot, LocalRpcBufferSeal seal, byte[] buffer, CancellationToken token)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var chunk = _limits.ChunkBytes;
        var length = buffer.Length;
        var position = 0;
        var sinceYield = 0L;
        while (position < length)
        {
            if (token.IsCancellationRequested)
            {
                return (LocalRpcBrokerRefusal.Cancelled, null);
            }

            if (LeaseExpired())
            {
                return (LocalRpcBrokerRefusal.Expired, null);
            }

            var count = Math.Min(chunk, length - position);
            int read;
            try
            {
                read = slot.Mapping.Read((long)seal.Offset + position, buffer.AsSpan(position, count));
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                return (LocalRpcBrokerRefusal.MappingFailed, null);
            }

            if (read != count)
            {
                return (LocalRpcBrokerRefusal.MappingFailed, null);
            }

            hash.AppendData(buffer, position, count);
            position += count;
            sinceYield += count;
            if (sinceYield >= YieldEveryBytes)
            {
                sinceYield = 0;
                await Task.Yield();
            }
        }

        var digest = LocalRpcDigest.FromBytes(hash.GetHashAndReset());
        return seal.Digest.Equals(digest) ? (LocalRpcBrokerRefusal.None, digest) : (LocalRpcBrokerRefusal.DigestMismatch, null);
    }

    /// <summary>Settles a finished copy attempt under the lock and returns the refusal the caller sees.</summary>
    private LocalRpcBrokerRefusal EndCopy(Slot slot, LocalRpcBufferSeal seal, LocalRpcBrokerRefusal outcome, LocalRpcDigest? digest)
    {
        PendingClose? pending = null;
        LocalRpcBrokerRefusal refusal;
        lock (_gate)
        {
            if (_state != LocalRpcBrokerSessionState.Open)
            {
                // Cancelled or closed while copying: the slot was withdrawn by that transition. Nothing is released to the caller.
                _copyActive = false;
                refusal = _state == LocalRpcBrokerSessionState.Cancelled ? LocalRpcBrokerRefusal.Cancelled : ClosedRefusalLocked();
            }
            else
            {
                refusal = outcome;
                switch (outcome)
                {
                    case LocalRpcBrokerRefusal.None:
                        slot.CopiedDigest = digest;
                        break;
                    case LocalRpcBrokerRefusal.Cancelled:
                        // The session token did not fire (the state is open), so the caller's token did.
                        AbandonLocked(slot, seal);
                        refusal = LocalRpcBrokerRefusal.Aborted;
                        break;
                    case LocalRpcBrokerRefusal.Expired:
                        pending = CloseLocked(LocalRpcBrokerEndReason.Expired);
                        break;
                    case LocalRpcBrokerRefusal.MappingFailed:
                        pending = CloseLocked(LocalRpcBrokerEndReason.MappingFailed);
                        break;
                    case LocalRpcBrokerRefusal.DigestMismatch:
                        pending = CloseLocked(LocalRpcBrokerEndReason.IntegrityViolation);
                        break;
                    default:
                        AbandonLocked(slot, seal);
                        break;
                }
            }
        }

        Finish(pending);
        return refusal;
    }

    private void AbandonLocked(Slot slot, LocalRpcBufferSeal seal)
    {
        if (slot.State == LocalRpcSlotState.Reading && slot.Sequence == seal.Sequence)
        {
            slot.State = LocalRpcSlotState.Sealed;
        }

        _copyActive = false;
    }

    private LocalRpcBrokerRefusal AdmitLocked(ref PendingClose? pending)
    {
        if (_state == LocalRpcBrokerSessionState.Closed)
        {
            return ClosedRefusalLocked();
        }

        if (LeaseRemainingLocked() <= TimeSpan.Zero)
        {
            pending = CloseLocked(LocalRpcBrokerEndReason.Expired);
            return LocalRpcBrokerRefusal.Expired;
        }

        return _state == LocalRpcBrokerSessionState.Cancelled ? LocalRpcBrokerRefusal.Cancelled : LocalRpcBrokerRefusal.None;
    }

    private LocalRpcBrokerRefusal ClosedRefusalLocked() => _endReason switch
    {
        LocalRpcBrokerEndReason.Expired => LocalRpcBrokerRefusal.Expired,
        LocalRpcBrokerEndReason.PairGone => LocalRpcBrokerRefusal.PairGone,
        LocalRpcBrokerEndReason.CancelUnresponsive => LocalRpcBrokerRefusal.Cancelled,
        _ => LocalRpcBrokerRefusal.Closed,
    };

    private TimeSpan LeaseRemainingLocked() => _limits.SessionLease - _time.GetElapsedTime(_leaseStart);

    private bool LeaseExpired()
    {
        lock (_gate)
        {
            return LeaseRemainingLocked() <= TimeSpan.Zero;
        }
    }

    private void ArmLocked()
    {
        if (_timer is null)
        {
            return;
        }

        var due = LeaseRemainingLocked();
        if (_state == LocalRpcBrokerSessionState.Cancelled)
        {
            var grace = _limits.CancelGrace - _time.GetElapsedTime(_graceStart);
            if (grace < due)
            {
                due = grace;
            }
        }

        _ = _timer.Change(due < TimeSpan.Zero ? TimeSpan.Zero : due, Timeout.InfiniteTimeSpan);
    }

    private void OnTimer(object? state)
    {
        PendingClose? pending = null;
        lock (_gate)
        {
            if (_state == LocalRpcBrokerSessionState.Closed)
            {
                return;
            }

            if (LeaseRemainingLocked() <= TimeSpan.Zero)
            {
                pending = CloseLocked(LocalRpcBrokerEndReason.Expired);
            }
            else if (_state == LocalRpcBrokerSessionState.Cancelled && _limits.CancelGrace - _time.GetElapsedTime(_graceStart) <= TimeSpan.Zero)
            {
                pending = CloseLocked(LocalRpcBrokerEndReason.CancelUnresponsive);
            }
            else
            {
                // A real timer can fire slightly before the clock agrees, and a callback queued by an earlier arming can run after a renewal: wait out the remainder.
                ArmLocked();
            }
        }

        Finish(pending);
    }

    private PendingClose? CloseLocked(LocalRpcBrokerEndReason reason)
    {
        if (_state == LocalRpcBrokerSessionState.Closed)
        {
            return null;
        }

        _state = LocalRpcBrokerSessionState.Closed;
        _endReason = reason;
        _copyActive = false;
        foreach (var slot in _slots.Where(slot => slot.State != LocalRpcSlotState.Free))
        {
            slot.State = LocalRpcSlotState.Quarantined;
        }

        var pending = new PendingClose(new LocalRpcBrokerEnd(InvocationId, reason), _timer, _pairRegistration);
        _pairRegistration = default;
        return pending;
    }

    /// <summary>Runs the work of a close outside every lock: stop a running copy, drop the timer and registration, release the mappings, tell the registry and the owner.</summary>
    private void Finish(PendingClose? pending)
    {
        if (pending is null)
        {
            return;
        }

        CancelSource();
        pending.Timer?.Dispose();
        pending.Registration.Dispose();
        ReleaseMappings();
        _registry.Remove(this);
        try
        {
            _ended?.Invoke(pending.End);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // The owner's callback failing must not undo the close or reach the caller that caused it.
        }
    }

    /// <summary>Disposes the mappings of a closed session once no copy is reading one; whichever of the close and the last copy gets here last does it.</summary>
    private void ReleaseMappings()
    {
        lock (_gate)
        {
            if (_state != LocalRpcBrokerSessionState.Closed || _copyRunning || _mappingsReleased)
            {
                return;
            }

            _mappingsReleased = true;
        }

        foreach (var slot in _slots)
        {
            try
            {
                slot.Mapping.Dispose();
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                // Releasing the rest matters more than reporting one failure.
            }
        }

        _cancelled.Dispose();
    }

    private void CancelSource()
    {
        try
        {
            _cancelled.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The session finished closing first; there is nothing left to cancel.
        }
    }

    private static TimeSpan Max(TimeSpan left, TimeSpan right) => left >= right ? left : right;

    private sealed record PendingClose(LocalRpcBrokerEnd End, ITimer? Timer, CancellationTokenRegistration Registration);

    private sealed class Slot(ILocalRpcBufferMapping mapping, long mappingLength, ulong firstSequence)
    {
        internal ILocalRpcBufferMapping Mapping { get; } = mapping;

        internal long MappingLength { get; } = mappingLength;

        internal LocalRpcSlotState State { get; set; }

        internal ulong NextSequence { get; set; } = firstSequence;

        internal ulong Sequence { get; set; }

        internal ulong Capacity { get; set; }

        internal LocalRpcBufferSeal? Seal { get; set; }

        internal LocalRpcDigest? CopiedDigest { get; set; }

        internal ulong LastAckedSequence { get; set; }

        internal LocalRpcBufferAck? LastAck { get; set; }
    }
}
