// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Observability;

/// <summary>What <see cref="DiagnosticSpanBuffer.Offer"/> did with one span that head sampling did not select.</summary>
internal enum BufferOutcome
{
    /// <summary>The span, and any spans of its trace held earlier, were released for export.</summary>
    Exported,

    /// <summary>The span is held until its trace is promoted or its retention ends.</summary>
    Held,

    /// <summary>The span's trace had already left the buffer, so the span is dropped and counted.</summary>
    Late,

    /// <summary>The span alone costs more than the buffer holds, so it is dropped and counted.</summary>
    Oversize,
}

/// <summary>The loss and retention counters of the buffer. Every field is cumulative except the last three.</summary>
internal readonly record struct BufferCounters(
    long PromotedTraces,
    long PromotedSpans,
    long ExpiredUnpromotedSpans,
    long SpansLostToOverflow,
    long TracesEvictedForOverflow,
    long LateSpans,
    long OversizeSpans,
    long PurgedSpans,
    long BufferedSpans,
    long BufferedBytes,
    long ClosedTraces);

/// <summary>
/// The bounded diagnostic buffer of observability architecture SG-03. It holds finished, already-scrubbed spans of traces
/// that head sampling did not select, for at most <see cref="Retention"/> per trace and never more than its byte budget.
/// A trace that sees an error or slow span is promoted: the spans still held are released together with the promoting
/// span, and later spans of that trace are released as they arrive. A span that is no longer held cannot be recovered,
/// so a trace may be promoted incomplete, and a trace whose window has closed accepts nothing more. Every such loss is
/// counted; nothing here promises that every error trace is retained.
/// </summary>
/// <remarks>
/// Cost is an accounting model, not a measurement of process memory: a fixed overhead per span, entry and closed-trace
/// marker plus twice the length of each retained string, so the budget is deterministic and testable. Every retained
/// object (held spans, trace entries, promotion state, closed-trace markers) is charged against the one budget. The
/// 30-second window is logical: it is applied when a span is offered or the counters are read, not by a timer.
/// </remarks>
internal sealed class DiagnosticSpanBuffer
{
    internal static readonly TimeSpan Retention = TimeSpan.FromSeconds(30);

    internal const int MaximumClosedTraces = 1024;
    internal const long EntryOverhead = 128;
    internal const long ClosedTraceOverhead = 64;
    private const long SpanOverhead = 256;
    private const long TagOverhead = 64;
    private const long EventOverhead = 96;
    private const long ScalarValueCost = 16;

    private readonly object _gate = new();
    private readonly long _capacity;
    private readonly TimeProvider _time;
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly LinkedList<Entry> _creationOrder = new();
    private readonly LinkedList<Entry> _holding = new();
    private readonly LinkedList<Entry> _promotions = new();
    private readonly HashSet<string> _closed = new(StringComparer.Ordinal);
    private readonly Queue<string> _closedOrder = new();
    private long _bytes;
    private long _bufferedSpans;
    private long _promotedTraces;
    private long _promotedSpans;
    private long _expired;
    private long _lostToOverflow;
    private long _tracesEvicted;
    private long _late;
    private long _oversize;
    private long _purged;

    internal DiagnosticSpanBuffer(long capacityBytes, TimeProvider time)
    {
        if (capacityBytes is < TracePolicyOptions.MinimumBufferBytes or > TracePolicyOptions.HardBufferLimitBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(capacityBytes));
        }

        _capacity = capacityBytes;
        _time = time;
    }

    /// <summary>The accounted cost of holding one span; the same model charges every retained byte against the budget.</summary>
    internal static long Cost(ScrubbedSpan span)
    {
        long cost = SpanOverhead + Text(span.SourceName) + Text(span.Name) + Text(span.TraceId) + Text(span.SpanId) + Text(span.ParentSpanId);
        cost += TagsCost(span.Tags);
        foreach (ScrubbedSpanEvent spanEvent in span.Events)
        {
            cost += EventOverhead + Text(spanEvent.Name) + TagsCost(spanEvent.Tags);
        }

        return cost;
    }

    /// <summary>
    /// Offers a span of an unselected trace. <paramref name="promote"/> says the span is an error or slow. Spans to export
    /// are appended to <paramref name="release"/>, oldest first, for the caller to write outside the buffer's lock.
    /// </summary>
    internal BufferOutcome Offer(ScrubbedSpan span, bool promote, List<ScrubbedSpan> release)
    {
        lock (_gate)
        {
            ExpireDue();
            if (_closed.Contains(span.TraceId))
            {
                _late++;
                return BufferOutcome.Late;
            }

            long cost = Cost(span);
            if (!_entries.TryGetValue(span.TraceId, out Entry? entry))
            {
                if (!promote && cost + EntryOverhead > _capacity)
                {
                    _oversize++;
                    return BufferOutcome.Oversize;
                }

                MakeRoom(EntryOverhead, keep: null);
                entry = new Entry(span.TraceId, _time.GetTimestamp());
                _entries.Add(entry.TraceId, entry);
                entry.OrderNode = _creationOrder.AddLast(entry);
                _bytes += EntryOverhead;
            }

            if (entry.Promoted)
            {
                _promotedSpans++;
                release.Add(span);
                return BufferOutcome.Exported;
            }

            if (promote)
            {
                Promote(entry, release);
                release.Add(span);
                _promotedSpans++;
                return BufferOutcome.Exported;
            }

            if (cost + EntryOverhead > _capacity)
            {
                _oversize++;
                return BufferOutcome.Oversize;
            }

            MakeRoom(cost, keep: entry);
            if (entry.Held is null)
            {
                entry.Held = [];
                entry.HoldingNode = _holding.AddLast(entry);
            }

            entry.Held.Add(new HeldSpan(span, cost));
            entry.HeldBytes += cost;
            _bytes += cost;
            _bufferedSpans++;
            return BufferOutcome.Held;
        }
    }

    /// <summary>Discards everything held and every closed-trace marker, for example when consent is withdrawn.</summary>
    internal void Purge()
    {
        lock (_gate)
        {
            _purged += _bufferedSpans;
            _entries.Clear();
            _creationOrder.Clear();
            _holding.Clear();
            _promotions.Clear();
            _closed.Clear();
            _closedOrder.Clear();
            _bytes = 0;
            _bufferedSpans = 0;
        }
    }

    internal BufferCounters Counters()
    {
        lock (_gate)
        {
            ExpireDue();
            return new BufferCounters(_promotedTraces, _promotedSpans, _expired, _lostToOverflow, _tracesEvicted, _late, _oversize,
                _purged, _bufferedSpans, _bytes, _closed.Count);
        }
    }

    private void Promote(Entry entry, List<ScrubbedSpan> release)
    {
        if (entry.Held is { } held)
        {
            foreach (HeldSpan item in held)
            {
                release.Add(item.Span);
            }

            _promotedSpans += held.Count;
            _bufferedSpans -= held.Count;
            _bytes -= entry.HeldBytes;
            _holding.Remove(entry.HoldingNode!);
            entry.Held = null;
            entry.HoldingNode = null;
            entry.HeldBytes = 0;
        }

        entry.Promoted = true;
        entry.PromotionNode = _promotions.AddLast(entry);
        _promotedTraces++;
    }

    /// <summary>Closes the window of every trace that has been in the buffer for the full retention.</summary>
    private void ExpireDue()
    {
        long now = _time.GetTimestamp();
        while (_creationOrder.First is { Value: Entry oldest }
            && _time.GetElapsedTime(oldest.CreatedAt, now) >= Retention)
        {
            _expired += oldest.Held?.Count ?? 0;
            Remove(oldest);
            Close(oldest.TraceId);
        }
    }

    private void Close(string traceId)
    {
        if (!_closed.Add(traceId))
        {
            return;
        }

        _closedOrder.Enqueue(traceId);
        _bytes += ClosedTraceOverhead;
        while (_closedOrder.Count > MaximumClosedTraces)
        {
            ForgetOldestClosed();
        }
    }

    private void ForgetOldestClosed()
    {
        _closed.Remove(_closedOrder.Dequeue());
        _bytes -= ClosedTraceOverhead;
    }

    /// <summary>
    /// Frees room by evicting, in this order: closed-trace markers, then whole held traces oldest first, then the oldest
    /// spans of the trace being extended, then promotion state oldest first. Spans lost this way are counted.
    /// </summary>
    private void MakeRoom(long needed, Entry? keep)
    {
        while (_bytes + needed > _capacity)
        {
            if (_closedOrder.Count > 0)
            {
                ForgetOldestClosed();
            }
            else if (FirstHoldingOtherThan(keep) is { } victim)
            {
                _lostToOverflow += victim.Held!.Count;
                _tracesEvicted++;
                Remove(victim);
            }
            else if (keep?.Held is { Count: > 0 } own)
            {
                HeldSpan first = own[0];
                own.RemoveAt(0);
                keep.HeldBytes -= first.Cost;
                _bytes -= first.Cost;
                _bufferedSpans--;
                _lostToOverflow++;
            }
            else if (_promotions.First is { Value: Entry promoted } && !ReferenceEquals(promoted, keep))
            {
                _tracesEvicted++;
                Remove(promoted);
            }
            else
            {
                // Nothing is left to evict: the budget is smaller than the one entry being added, which the callers exclude.
                return;
            }
        }
    }

    private Entry? FirstHoldingOtherThan(Entry? keep)
    {
        for (LinkedListNode<Entry>? node = _holding.First; node is not null; node = node.Next)
        {
            if (!ReferenceEquals(node.Value, keep))
            {
                return node.Value;
            }
        }

        return null;
    }

    private void Remove(Entry entry)
    {
        _entries.Remove(entry.TraceId);
        _bytes -= EntryOverhead;
        _creationOrder.Remove(entry.OrderNode!);
        entry.OrderNode = null;
        if (entry.Held is { } held)
        {
            _bufferedSpans -= held.Count;
            _bytes -= entry.HeldBytes;
            _holding.Remove(entry.HoldingNode!);
            entry.Held = null;
            entry.HoldingNode = null;
            entry.HeldBytes = 0;
        }

        if (entry.PromotionNode is { } promotion)
        {
            _promotions.Remove(promotion);
            entry.PromotionNode = null;
        }
    }

    private static long TagsCost(IReadOnlyDictionary<string, object?> tags)
    {
        long cost = 0;
        foreach (KeyValuePair<string, object?> tag in tags)
        {
            cost += TagOverhead + Text(tag.Key) + (tag.Value is string text ? Text(text) : ScalarValueCost);
        }

        return cost;
    }

    private static long Text(string? value) => value is null ? 0 : 2L * value.Length;

    private readonly record struct HeldSpan(ScrubbedSpan Span, long Cost);

    private sealed class Entry(string traceId, long createdAt)
    {
        public string TraceId { get; } = traceId;
        public long CreatedAt { get; } = createdAt;
        public List<HeldSpan>? Held { get; set; }
        public long HeldBytes { get; set; }
        public bool Promoted { get; set; }
        public LinkedListNode<Entry>? OrderNode { get; set; }
        public LinkedListNode<Entry>? HoldingNode { get; set; }
        public LinkedListNode<Entry>? PromotionNode { get; set; }
    }
}
