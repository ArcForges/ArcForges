// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace ArcForges.LocalRpc;

/// <summary>Why a brokered-transfer operation was refused. A refusal changes no slot unless its documentation says so.</summary>
[SuppressMessage("Design", "CA1027:Mark enums with FlagsAttribute", Justification = "The values are consecutive reason codes, not combinable flags.")]
public enum LocalRpcBrokerRefusal
{
    /// <summary>No refusal: the operation succeeded.</summary>
    None = 0,

    /// <summary>The invocation, lease or generation is not this session's: a resource of another session, never honoured.</summary>
    WrongSession = 1,

    /// <summary>The slot number names no slot of this session.</summary>
    UnknownSlot = 2,

    /// <summary>The slot is not free: it is already granted, sealed or being read.</summary>
    SlotBusy = 3,

    /// <summary>The slot has no outstanding grant, so there is nothing to seal.</summary>
    NotGranted = 4,

    /// <summary>The slot's grant was already sealed.</summary>
    AlreadySealed = 5,

    /// <summary>The slot has no sealed buffer that is ready for this step.</summary>
    NotSealed = 6,

    /// <summary>The sequence is not the slot's current one: a stale, replayed or future grant, seal or acknowledgement.</summary>
    StaleSequence = 7,

    /// <summary>The granted capacity is zero, larger than the slot's mapping or larger than the 64 MiB slot bound.</summary>
    CapacityExceeded = 8,

    /// <summary>The sealed range is empty or does not lie inside the granted capacity.</summary>
    RangeInvalid = 9,

    /// <summary>The declared row geometry does not fit the length, or no expected geometry was given for a geometric seal.</summary>
    GeometryInvalid = 10,

    /// <summary>The digest of the parent's private copy is not the sealed digest, or an acknowledgement carries another digest.</summary>
    DigestMismatch = 11,

    /// <summary>The mapping failed or returned fewer bytes than the sealed range: the invocation is ended.</summary>
    MappingFailed = 12,

    /// <summary>The session's lease ran out. The session is closed and the helper must be terminated.</summary>
    Expired = 13,

    /// <summary>The session was cancelled: no grant, seal or copy is honoured any more.</summary>
    Cancelled = 14,

    /// <summary>The session is closed.</summary>
    Closed = 15,

    /// <summary>A private copy is already in progress or its verified buffer is still held; at most one is admitted per session.</summary>
    CopyBusy = 16,

    /// <summary>The slot's copy has not finished, so it cannot be acknowledged.</summary>
    CopyPending = 17,

    // 18 is unused.

    /// <summary>The slot's sequence numbers are used up; a sequence never wraps.</summary>
    SequenceExhausted = 19,

    /// <summary>The registry already holds the most sessions it admits.</summary>
    TooManySessions = 20,

    /// <summary>The registry already holds a session for this invocation.</summary>
    DuplicateInvocation = 21,

    /// <summary>The parent-child pair is gone; the session was closed.</summary>
    PairGone = 22,

    /// <summary>The caller's own cancellation stopped the copy; the slot is still sealed and the copy may be retried.</summary>
    Aborted = 23,

    /// <summary>The private copy could not be allocated.</summary>
    OutOfMemory = 24,

    /// <summary>The input mapping does not have the length or digest of the parent-minted input.</summary>
    InputMismatch = 25,
}

/// <summary>Why a session ended. Every reason except <see cref="Closed"/> and <see cref="RegistryDisposed"/> asks the owner to terminate the helper.</summary>
[SuppressMessage("Design", "CA1027:Mark enums with FlagsAttribute", Justification = "The values are consecutive reason codes, not combinable flags.")]
public enum LocalRpcBrokerEndReason
{
    /// <summary>The owner closed the session after the helper's disposition was known.</summary>
    Closed = 0,

    /// <summary>The 30 second lease was not renewed in time.</summary>
    Expired = 1,

    /// <summary>The pair-gone token was cancelled or a renewal found the pair no longer lives.</summary>
    PairGone = 2,

    /// <summary>The digest of a private copy did not match the seal: the helper is hostile or raced its own buffer.</summary>
    IntegrityViolation = 3,

    /// <summary>A mapping read failed or fell short.</summary>
    MappingFailed = 4,

    /// <summary>The session was cancelled and the owner did not close it within the cancel grace period.</summary>
    CancelUnresponsive = 5,

    /// <summary>The registry that held the session was disposed.</summary>
    RegistryDisposed = 6,
}

/// <summary>The lifecycle of a brokered session.</summary>
public enum LocalRpcBrokerSessionState
{
    /// <summary>Grants, seals, copies and acknowledgements are honoured.</summary>
    Open = 0,

    /// <summary>Cancelled: nothing is honoured and every slot is withdrawn; the owner closes the session once the helper's disposition is known.</summary>
    Cancelled = 1,

    /// <summary>Ended: every mapping is released and every operation is refused.</summary>
    Closed = 2,
}

/// <summary>The state of one output slot, following the annex 09 order free, writing, sealed, reading, free.</summary>
public enum LocalRpcSlotState
{
    /// <summary>Available for the next grant.</summary>
    Free = 0,

    /// <summary>Granted; the helper may fill only that grant.</summary>
    Writing = 1,

    /// <summary>Sealed by the helper and verified by the parent; waiting for the private copy.</summary>
    Sealed = 2,

    /// <summary>Being copied, or copied and waiting for the acknowledgement that releases it.</summary>
    Reading = 3,

    /// <summary>Withdrawn for the rest of the invocation; never silently recycled.</summary>
    Quarantined = 4,
}

/// <summary>The outcome of an operation that produces a value: either a refusal or the value.</summary>
/// <typeparam name="T">The value type.</typeparam>
/// <param name="Refusal">The refusal, or <see cref="LocalRpcBrokerRefusal.None"/> on success.</param>
/// <param name="Value">The value on success, otherwise null.</param>
public readonly record struct LocalRpcBrokerResult<T>(LocalRpcBrokerRefusal Refusal, T? Value)
    where T : class
{
    /// <summary>True when the operation succeeded and <see cref="Value"/> is set.</summary>
    public bool IsSuccess => Refusal == LocalRpcBrokerRefusal.None && Value is not null;
}

internal static class BrokerResult
{
    internal static LocalRpcBrokerResult<T> Ok<T>(T value)
        where T : class => new(LocalRpcBrokerRefusal.None, value);

    internal static LocalRpcBrokerResult<T> Fail<T>(LocalRpcBrokerRefusal refusal)
        where T : class => new(refusal, null);
}

/// <summary>A SHA-256 digest. On the wire it is exactly 64 lowercase hexadecimal characters.</summary>
public sealed class LocalRpcDigest : IEquatable<LocalRpcDigest>
{
    /// <summary>The digest length in bytes.</summary>
    public const int Length = 32;

    private readonly byte[] _bytes;

    private LocalRpcDigest(byte[] bytes) => _bytes = bytes;

    /// <summary>The bytes of the digest. The span is valid while the digest is.</summary>
    public ReadOnlySpan<byte> AsSpan() => _bytes;

    /// <summary>Digests <paramref name="data"/> with SHA-256.</summary>
    public static LocalRpcDigest Compute(ReadOnlySpan<byte> data) => new(SHA256.HashData(data));

    /// <summary>Wraps a 32-byte digest value (copied).</summary>
    public static LocalRpcDigest FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length)
        {
            throw new ArgumentException("A SHA-256 digest is exactly 32 bytes.", nameof(bytes));
        }

        return new LocalRpcDigest(bytes.ToArray());
    }

    /// <summary>Parses the wire form: exactly 64 lowercase hexadecimal characters; anything else is refused.</summary>
    public static bool TryParse(string? text, [NotNullWhen(true)] out LocalRpcDigest? digest)
    {
        digest = null;
        if (text is null || text.Length != Length * 2)
        {
            return false;
        }

        foreach (var character in text)
        {
            if (character is not ((>= '0' and <= '9') or (>= 'a' and <= 'f')))
            {
                return false;
            }
        }

        digest = new LocalRpcDigest(Convert.FromHexString(text));
        return true;
    }

    /// <summary>The wire form, 64 lowercase hexadecimal characters.</summary>
    public string ToHex() => Convert.ToHexStringLower(_bytes);

    /// <summary>Compares in constant time.</summary>
    public bool Equals(LocalRpcDigest? other) => other is not null && CryptographicOperations.FixedTimeEquals(_bytes, other._bytes);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as LocalRpcDigest);

    /// <inheritdoc />
    public override int GetHashCode() => BitConverter.ToInt32(_bytes, 0);

    /// <inheritdoc />
    public override string ToString() => ToHex();
}

/// <summary>
/// The wire form of an identifier: exactly 16 bytes in canonical UUID order (the first byte is the most significant
/// byte of the first group), never zero, never the little-endian layout of <c>Guid.ToByteArray</c>.
/// </summary>
public static class LocalRpcCanonicalId
{
    /// <summary>The identifier length in bytes.</summary>
    public const int Length = 16;

    /// <summary>Reads an identifier; a value of another length or all zero is refused.</summary>
    public static bool TryRead(ReadOnlySpan<byte> bytes, out Guid id)
    {
        id = Guid.Empty;
        if (bytes.Length != Length)
        {
            return false;
        }

        var candidate = new Guid(bytes, bigEndian: true);
        if (candidate == Guid.Empty)
        {
            return false;
        }

        id = candidate;
        return true;
    }

    /// <summary>Writes an identifier in canonical order into a 16-byte destination.</summary>
    public static void Write(Guid id, Span<byte> destination)
    {
        if (destination.Length != Length)
        {
            throw new ArgumentException("An identifier is exactly 16 bytes.", nameof(destination));
        }

        _ = id.TryWriteBytes(destination, bigEndian: true, out _);
    }
}

/// <summary>What the parent grants for one slot: the slot, its monotonic sequence and the capacity the helper may fill.</summary>
/// <param name="SlotId">The slot, 0 through 2.</param>
/// <param name="Sequence">The positive sequence of this grant; it grows with every grant of the slot.</param>
/// <param name="Capacity">The bytes the helper may fill, positive and at most the slot's mapping and 64 MiB.</param>
public sealed record LocalRpcSlotGrant(uint SlotId, ulong Sequence, ulong Capacity);

/// <summary>
/// What the helper returns to seal a grant. The offset and length name the bytes it wrote inside the granted capacity,
/// and the digest is the SHA-256 it claims for them; the parent verifies the digest on its own copy, never on the mapping.
/// </summary>
/// <param name="InvocationId">The invocation the grant belongs to.</param>
/// <param name="LeaseId">The lease the grant belongs to.</param>
/// <param name="Generation">The session generation.</param>
/// <param name="SlotId">The slot.</param>
/// <param name="Sequence">The sequence of the grant being sealed.</param>
/// <param name="Offset">Where the written bytes start inside the slot.</param>
/// <param name="Length">How many bytes were written.</param>
/// <param name="Digest">The helper's digest of those bytes.</param>
/// <param name="RowStride">The distance between row starts, or zero for a flat byte range.</param>
public sealed record LocalRpcBufferSeal(
    Guid InvocationId,
    Guid LeaseId,
    ulong Generation,
    uint SlotId,
    ulong Sequence,
    ulong Offset,
    ulong Length,
    LocalRpcDigest Digest,
    ulong RowStride);

/// <summary>The geometry the parent expects of a sealed buffer, derived from its own request and never from the helper.</summary>
/// <param name="Rows">The rows of the tile, positive.</param>
/// <param name="RowBytes">The bytes of one row, positive.</param>
public sealed record LocalRpcBufferLayout(ulong Rows, ulong RowBytes);

/// <summary>The acknowledgement the parent sends the helper after it copied and verified a buffer; it releases the slot.</summary>
/// <param name="InvocationId">The invocation.</param>
/// <param name="LeaseId">The lease.</param>
/// <param name="Generation">The session generation.</param>
/// <param name="SlotId">The slot being released.</param>
/// <param name="Sequence">The sequence being released.</param>
/// <param name="Digest">The digest of the parent's verified private copy.</param>
public sealed record LocalRpcBufferAck(
    Guid InvocationId,
    Guid LeaseId,
    ulong Generation,
    uint SlotId,
    ulong Sequence,
    LocalRpcDigest Digest);

/// <summary>Why and which session ended.</summary>
/// <param name="InvocationId">The invocation of the session.</param>
/// <param name="Reason">Why it ended.</param>
public sealed record LocalRpcBrokerEnd(Guid InvocationId, LocalRpcBrokerEndReason Reason);

/// <summary>A point-in-time view of a session, for tests and diagnostics.</summary>
/// <param name="State">The session state.</param>
/// <param name="Slots">The state of each slot.</param>
/// <param name="NextSequences">The sequence the next grant of each slot would carry.</param>
/// <param name="CopyActive">Whether a private copy is in progress or its verified buffer is still held.</param>
/// <param name="Refusals">How many operations the session refused.</param>
public sealed record LocalRpcBrokerSnapshot(
    LocalRpcBrokerSessionState State,
    IReadOnlyList<LocalRpcSlotState> Slots,
    IReadOnlyList<ulong> NextSequences,
    bool CopyActive,
    long Refusals);

/// <summary>
/// The parent's read access to one slot's shared mapping, or a helper's read access to its read-only input. The
/// broker owns what it is given: it disposes the mapping when the session ends.
/// </summary>
public interface ILocalRpcBufferMapping : IDisposable
{
    /// <summary>The bytes the mapping holds.</summary>
    long Length { get; }

    /// <summary>
    /// Reads up to <paramref name="destination"/>.Length bytes starting at <paramref name="offset"/> and returns how many
    /// were read. Whoever else maps the memory may be writing it: the content is never trusted.
    /// </summary>
    int Read(long offset, Span<byte> destination);
}
