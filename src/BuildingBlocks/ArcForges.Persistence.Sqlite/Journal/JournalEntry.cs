// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;

namespace ArcForges.Persistence.Sqlite;

/// <summary>An immutable, checksummed replay record for one owner commit.</summary>
public sealed class JournalEntry
{
    private readonly byte[] payload;
    private readonly byte[] checksum;

    private JournalEntry(JournalSequence sequence, string aggregateKind, Guid aggregateId,
        StoreVersion previous, StoreVersion next, CommandId commandId, string operation,
        int operationVersion, ReadOnlySpan<byte> payload, string? durableReference,
        UserId actorId, Guid correlationId, Guid? causationId, Instant committedAt, long? localSequence)
    {
        sequence.RequireStore(sequence.StoreId);
        ArgumentException.ThrowIfNullOrWhiteSpace(aggregateKind);
        ArgumentException.ThrowIfNullOrWhiteSpace(operation);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(operationVersion);
        if (aggregateId == Guid.Empty || correlationId == Guid.Empty || causationId == Guid.Empty)
            throw new ArgumentException("Aggregate, correlation and any causation identity must be nonempty.");
        _ = commandId.ToWire();
        _ = actorId.ToWire();
        if ((payload.Length > 0) == (durableReference is not null))
            throw new ArgumentException("Exactly one replay payload or durable reference is required.");
        if (durableReference is not null) ArgumentException.ThrowIfNullOrWhiteSpace(durableReference);
        if (!next.IsSuccessorOf(previous))
            throw new ArgumentException("A journal commit must advance the typed source version without changing its domain.");
        if (localSequence is <= 0)
            throw new ArgumentOutOfRangeException(nameof(localSequence));
        if (next.Kind == StoreVersionKind.LocalProjection)
        {
            var oldHead = previous.LocalVersion?.HeadLocalSequence ?? 0;
            var newHead = next.LocalVersion!.Value.HeadLocalSequence;
            long? expectedLocalSequence = newHead > oldHead ? newHead : null;
            if (localSequence != expectedLocalSequence)
                throw new ArgumentException("A local edit must name its per-aggregate sequence; shadow acknowledgement creates no local edit.", nameof(localSequence));
        }
        else if (next.Kind == StoreVersionKind.Cloud && localSequence is not null)
            throw new ArgumentException("A Cloud revision does not allocate a device-local edit identity.", nameof(localSequence));
        Sequence = sequence;
        AggregateKind = aggregateKind;
        AggregateId = aggregateId;
        Previous = previous;
        Next = next;
        CommandId = commandId;
        Operation = operation;
        OperationVersion = operationVersion;
        this.payload = payload.ToArray();
        DurableReference = durableReference;
        ActorId = actorId;
        CorrelationId = correlationId;
        CausationId = causationId;
        CommittedAt = committedAt;
        LocalSequence = localSequence;
        var canonical = CanonicalBytes();
        EncodedLength = canonical.Length;
        checksum = SHA256.HashData(canonical);
    }

    public JournalSequence Sequence { get; }
    public string AggregateKind { get; }
    public Guid AggregateId { get; }
    public StoreVersion Previous { get; }
    public StoreVersion Next { get; }
    public CommandId CommandId { get; }
    public string Operation { get; }
    public int OperationVersion { get; }
    public ReadOnlyMemory<byte> Payload => payload.ToArray();
    public string? DurableReference { get; }
    public UserId ActorId { get; }
    public Guid CorrelationId { get; }
    public Guid? CausationId { get; }
    public Instant CommittedAt { get; }
    /// <summary>Per-aggregate device-local edit identity, independent of journal order and native revision.</summary>
    public long? LocalSequence { get; }
    public ReadOnlyMemory<byte> Checksum => checksum.ToArray();
    internal int EncodedLength { get; }

    public static JournalEntry Create(JournalSequence sequence, string aggregateKind, Guid aggregateId,
        StoreVersion previous, StoreVersion next, CommandId commandId, string operation,
        int operationVersion, ReadOnlySpan<byte> payload, string? durableReference,
        UserId actorId, Guid correlationId, Guid? causationId, Instant committedAt, long? localSequence = null) =>
        new(sequence, aggregateKind, aggregateId, previous, next, commandId, operation,
            operationVersion, payload, durableReference, actorId, correlationId, causationId, committedAt, localSequence);

    internal void Verify(ReadOnlySpan<byte> expected)
    {
        if (expected.Length != 32 || !CryptographicOperations.FixedTimeEquals(checksum, expected))
            throw new InvalidDataException("The journal entry checksum does not match its replay record.");
    }

    private byte[] CanonicalBytes()
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, new UTF8Encoding(false, true), leaveOpen: true);
        writer.Write("ArcForges.Journal.v1");
        writer.Write(Sequence.StoreId.ToString("D"));
        writer.Write(Sequence.Value);
        writer.Write(LocalSequence.HasValue);
        if (LocalSequence.HasValue) writer.Write(LocalSequence.Value);
        writer.Write(AggregateKind);
        writer.Write(AggregateId.ToString("D"));
        writer.Write(Previous.CanonicalText);
        writer.Write(Next.CanonicalText);
        writer.Write(CommandId.Value.ToString("D"));
        writer.Write(Operation);
        writer.Write(OperationVersion);
        writer.Write(payload.Length);
        writer.Write(payload);
        writer.Write(DurableReference is not null);
        if (DurableReference is not null) writer.Write(DurableReference);
        writer.Write(ActorId.Value.ToString("D"));
        writer.Write(CorrelationId.ToString("D"));
        writer.Write(CausationId.HasValue);
        if (CausationId.HasValue) writer.Write(CausationId.Value.ToString("D"));
        writer.Write(CommittedAt.UnixSeconds);
        writer.Write(CommittedAt.Nanoseconds);
        writer.Flush();
        return stream.ToArray();
    }
}
