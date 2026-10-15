// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Events;

/// <summary>How a client's cursor relates to the journal.</summary>
public enum CursorStatus
{
    /// <summary>Resumable: every event after it is still in the journal.</summary>
    Valid = 0,

    /// <summary>From another generation (the node restarted, or the journal was reset): reset with a snapshot.</summary>
    OtherGeneration = 1,

    /// <summary>Older than the journal's retention: reset with a snapshot.</summary>
    Stale = 2,

    /// <summary>Not a position this node issued (ahead of the journal): <c>VALIDATION/invalid_cursor</c>.</summary>
    Invalid = 3,
}

/// <summary>
/// The event journal (architecture 02 section 1; node-store.md <c>event_journal</c>): every state change appends a
/// <see cref="NodeEvent"/> in the same transaction as the change, with a node-wide sequence number that increases strictly within a
/// stream generation. A node start begins a new generation (events.proto: a node restart requires a snapshot), so clients that
/// resume across a restart receive a reset and a fresh snapshot. Retention: 100,000 events or 24 hours, whichever is smaller.
/// </summary>
public sealed class EventJournal
{
    /// <summary>The most events kept.</summary>
    public const int RetainedEvents = 100_000;

    /// <summary>The longest an event is kept.</summary>
    public static readonly TimeSpan RetainedAge = TimeSpan.FromHours(24);

    private ulong _next;
    private ulong _latest;

    private EventJournal(ulong generation, ulong latest)
    {
        Generation = generation;
        _latest = latest;
        _next = latest + 1;
        GenerationStart = latest + 1;
    }

    /// <summary>The current stream generation (<c>store_meta.journal_generation</c>).</summary>
    public ulong Generation { get; }

    /// <summary>The first sequence number of this generation.</summary>
    public ulong GenerationStart { get; }

    /// <summary>The sequence number of the last committed event (published to subscribers).</summary>
    public ulong Latest => Volatile.Read(ref _latest);

    /// <summary>The position after the last committed event.</summary>
    public EventCursor LatestPosition => new(Generation, Latest);

    /// <summary>Begins a new generation: increments <c>store_meta.journal_generation</c> and reads the last sequence number.</summary>
    public static EventJournal Open(NodeStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        return store.Write(transaction =>
        {
            transaction.Execute("UPDATE store_meta SET journal_generation = journal_generation + 1 WHERE singleton = 1;");
            var generation = Convert.ToUInt64(transaction.Scalar("SELECT journal_generation FROM store_meta WHERE singleton = 1;"), CultureInfo.InvariantCulture);
            var latest = Convert.ToUInt64(transaction.Scalar("SELECT coalesce(max(seq), 0) FROM event_journal;"), CultureInfo.InvariantCulture);
            return new EventJournal(generation, latest);
        }, CommitDurability.Full);
    }

    /// <summary>Appends an event in the command's transaction (the command processor's thread only).</summary>
    internal NodeEvent Append(StoreTransaction transaction, EventTopic topic, NodeEvent item)
    {
        var at = transaction.NowMicroseconds;
        item.Seq = _next;
        item.Generation = Generation;
        item.Topic = topic;
        item.At = ArcForges.Client.ProtoTime.ToInstant(StoreTime.FromMicroseconds(at));
        item.ClearFromSnapshot();
        transaction.Execute(
            "INSERT INTO event_journal (seq, generation, at, topic, payload) VALUES ($seq, $generation, $at, $topic, $payload);",
            ("$seq", (long)_next),
            ("$generation", (long)Generation),
            ("$at", at),
            ("$topic", (int)topic),
            ("$payload", item.ToByteArray()));
        _next++;
        return item;
    }

    /// <summary>Marks events up to <paramref name="sequence"/> committed.</summary>
    internal void Committed(ulong sequence) => Volatile.Write(ref _latest, sequence);

    /// <summary>The next sequence number (the processor saves it before a command and restores it on rollback).</summary>
    internal ulong NextSequence
    {
        get => _next;
        set => _next = value;
    }

    /// <summary>Classifies a client's cursor against the journal as it is in <paramref name="reader"/>'s snapshot.</summary>
    public CursorStatus Check(StoreReader reader, EventCursor cursor, ulong latest)
    {
        ArgumentNullException.ThrowIfNull(reader);
        if (cursor.Generation != Generation)
        {
            return cursor.Generation < Generation ? CursorStatus.OtherGeneration : CursorStatus.Invalid;
        }

        if (cursor.Sequence > latest)
        {
            return CursorStatus.Invalid;
        }

        if (cursor.Sequence + 1 < GenerationStart)
        {
            return CursorStatus.Stale;
        }

        var oldest = reader.Scalar("SELECT min(seq) FROM event_journal WHERE generation = $generation;", ("$generation", (long)Generation));
        if (oldest is null)
        {
            return cursor.Sequence >= latest ? CursorStatus.Valid : CursorStatus.Stale;
        }

        return cursor.Sequence + 1 < Convert.ToUInt64(oldest, CultureInfo.InvariantCulture) ? CursorStatus.Stale : CursorStatus.Valid;
    }

    /// <summary>The events of this generation after <paramref name="after"/> up to <paramref name="upTo"/>, of the given topics, in order.</summary>
    public List<NodeEvent> ReadAfter(StoreReader reader, ulong after, ulong upTo, IReadOnlySet<EventTopic> topics, int limit)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(topics);
        var events = new List<NodeEvent>();
        var from = after;
        while (events.Count < limit && from < upTo)
        {
            var scanned = 0;
            using var command = reader.CreateCommand(
                "SELECT seq, topic, payload FROM event_journal WHERE generation = $generation AND seq > $after AND seq <= $upTo ORDER BY seq LIMIT 1000;");
            command.Parameters.AddWithValue("$generation", (long)Generation);
            command.Parameters.AddWithValue("$after", (long)from);
            command.Parameters.AddWithValue("$upTo", (long)upTo);
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                scanned++;
                from = (ulong)rows.GetInt64(0);
                if (topics.Contains((EventTopic)rows.GetInt32(1)))
                {
                    events.Add(NodeEvent.Parser.ParseFrom((byte[])rows.GetValue(2)));
                    if (events.Count == limit)
                    {
                        break;
                    }
                }
            }

            if (scanned == 0)
            {
                break;
            }
        }

        return events;
    }

    /// <summary>Retention (housekeeping): deletes events older than 24 hours and all but the newest 100,000. Returns the number deleted.</summary>
    internal static int Prune(StoreTransaction transaction)
    {
        var cutoff = transaction.NowMicroseconds - (long)(RetainedAge.TotalMilliseconds * 1000);
        var aged = transaction.Execute("DELETE FROM event_journal WHERE at < $cutoff;", ("$cutoff", cutoff));
        var counted = transaction.Execute(
            "DELETE FROM event_journal WHERE seq <= (SELECT max(seq) FROM event_journal) - $keep;", ("$keep", (long)RetainedEvents));
        return aged + counted;
    }
}
