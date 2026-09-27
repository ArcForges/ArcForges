// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using Google.Protobuf;

namespace ArcForges.Persistence.Sqlite;

/// <summary>Owner repository boundary. Applications expose their domain DTOs, never this storage port.</summary>
public interface IStore : IDisposable
{
    StoredContent? Read(string aggregateKind, Guid aggregateId);
    CommitReceipt Write(WriteCommand command);
    IReadOnlyList<JournalEntry> ReadJournal(JournalSequence? after, int limit);
}

/// <summary>Immutable content carrier; protobuf unknown fields are retained in the encoded origin.</summary>
public sealed class StoredContent
{
    private readonly byte[] payload;
    private readonly byte[] origin;
    public StoredContent(StoreVersion version, ReadOnlySpan<byte> payload, ContentOrigin origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        _ = version.CanonicalText;
        this.payload = payload.ToArray();
        this.origin = origin.ToByteArray();
        Version = version;
    }
    public StoreVersion Version { get; }
    public ReadOnlyMemory<byte> Payload => payload.ToArray();
    public ContentOrigin Origin => ContentOrigin.Parser.ParseFrom(origin);
    internal byte[] OriginBytes => origin.ToArray();
    public static StoredContent FromJournal(JournalEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        using var stream = new MemoryStream(entry.Payload.ToArray());
        using var reader = new BinaryReader(stream, Encoding.UTF8);
        if (reader.ReadString() != "ArcForges.StoreContent.v1") throw new InvalidDataException("Unsupported store replay payload.");
        var size = reader.ReadInt32();
        if (size < 0 || size > stream.Length - stream.Position) throw new InvalidDataException("Invalid replay payload size.");
        var body = reader.ReadBytes(size);
        var originSize = reader.ReadInt32();
        if (originSize < 0 || originSize > 65536 || originSize != stream.Length - stream.Position) throw new InvalidDataException("Invalid replay origin size.");
        return new(entry.Next, body, ContentOrigin.Parser.ParseFrom(reader.ReadBytes(originSize)));
    }
    internal void ValidateForWrite()
    {
        var value = Origin;
        if (value.Profile != "arcforges.content-origin.v1" || origin.Length > 65536)
            throw new InvalidOperationException("Unsupported content-origin profile is read-only.");
        _ = ContentOriginId.FromWire(value.OriginId);
        _ = ContentUnitId.FromWire(value.ContentUnitId);
        string[] order = ["aiGenerated", "aiManipulated", "nonAi", "unknown"];
        if (value.Kinds.Count == 0 || !value.Kinds.SequenceEqual(order.Where(value.Kinds.Contains)))
            throw new ArgumentException("Origin kinds must be known, unique and canonically ordered.");
        if (value.PayloadSha256 != Convert.ToHexStringLower(SHA256.HashData(payload)))
            throw new ArgumentException("The origin does not identify the exact payload bytes.");
        if (value.ProducerKind is not ("model" or "human" or "deterministic" or "import") ||
            !value.HasOmittedParentCount || value.OmittedParentCount > int.MaxValue || value.ParentOriginIds.Count > 32)
            throw new ArgumentException("Invalid origin producer or bounded lineage.");
        var parents = value.ParentOriginIds.Select(id => ContentOriginId.FromWire(id).Value.ToString("N")).ToArray();
        if (!parents.SequenceEqual(parents.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)))
            throw new ArgumentException("Origin parents must be distinct and canonically ordered.");
        if (value.CreatedAt is not null) _ = WireValues.ReadInstant(value.CreatedAt);
    }
}

public sealed class WriteCommand
{
    public WriteCommand(CommandId commandId, string aggregateKind, Guid aggregateId, StoreVersion expected,
        StoredContent content, string operation, UserId actor, Guid correlationId, ArcForges.Foundation.Instant committedAt, long? localSequence = null)
    {
        _ = commandId.ToWire();
        _ = actor.ToWire();
        ArgumentException.ThrowIfNullOrWhiteSpace(aggregateKind);
        ArgumentException.ThrowIfNullOrWhiteSpace(operation);
        ArgumentNullException.ThrowIfNull(content);
        if (aggregateId == Guid.Empty || correlationId == Guid.Empty) throw new ArgumentException("Nonempty identities required.");
        _ = expected.CanonicalText;
        if (localSequence is <= 0) throw new ArgumentOutOfRangeException(nameof(localSequence));
        LocalSequence = localSequence;
        CommandId = commandId; AggregateKind = aggregateKind; AggregateId = aggregateId; Expected = expected;
        Content = content; Operation = operation; Actor = actor; CorrelationId = correlationId; CommittedAt = committedAt;
    }
    public CommandId CommandId { get; }
    public string AggregateKind { get; }
    public Guid AggregateId { get; }
    public StoreVersion Expected { get; }
    public StoredContent Content { get; }
    public string Operation { get; }
    public UserId Actor { get; }
    public Guid CorrelationId { get; }
    public ArcForges.Foundation.Instant CommittedAt { get; }
    public long? LocalSequence { get; }
}

public sealed record CommitReceipt(CommandId CommandId, StoreVersion Version, JournalSequence Sequence,
    EffectCertainty Effect, bool Replayed);

public sealed class StoreCommittedEventArgs(CommitReceipt receipt) : EventArgs
{
    public CommitReceipt Receipt { get; } = receipt;
}

/// <summary>Authorization is supplied by the owning repository and rechecked before receipt disclosure.</summary>
public interface IStoreAuthorization
{
    bool CanWrite(WriteCommand command);
}

internal enum CommitStage { Applied, Journaled, RevisionAdvanced, OutboxEnqueued, ReceiptRecorded, Committed }
internal sealed class CommitUnit(SqliteCommitContext context)
{
    internal SqliteCommitContext Context { get; } = context;
}
