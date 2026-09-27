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
        UserId actorId, Guid correlationId, Guid? causationId, Instant committedAt)
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
    public ReadOnlyMemory<byte> Checksum => checksum.ToArray();
    internal int EncodedLength { get; }

    public static JournalEntry Create(JournalSequence sequence, string aggregateKind, Guid aggregateId,
        StoreVersion previous, StoreVersion next, CommandId commandId, string operation,
        int operationVersion, ReadOnlySpan<byte> payload, string? durableReference,
        UserId actorId, Guid correlationId, Guid? causationId, Instant committedAt) =>
        new(sequence, aggregateKind, aggregateId, previous, next, commandId, operation,
            operationVersion, payload, durableReference, actorId, correlationId, causationId, committedAt);

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
