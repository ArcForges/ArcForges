// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Events;

/// <summary>
/// The stream hub (architecture 02 section 1): the command processor publishes each committed batch of journal events, in sequence
/// order, to every subscription whose topics match. A subscription registers before it reads its snapshot or replay from the
/// journal, so no event committed after that read is missed; events it already sent are dropped by sequence number.
/// </summary>
/// <remarks>
/// Nothing here holds more than the per-subscriber buffer (02 section 1: 2,048 events). While a subscriber's opening frames are written,
/// live events wait in a pending buffer of that size; when it fills, they are dropped and the subscriber catches up from the journal,
/// which holds them. Once attached, each event goes straight to the subscriber's sink (the LocalRpc stream writer, whose own bound of the
/// same size ends the stream with the typed overflow), so a subscriber that stops reading never makes the node hold more.
/// </remarks>
public sealed class StreamHub
{
    private readonly Lock _gate = new();
    private HubSubscription[] _subscriptions = [];
    private int _peakPending;
    private long _overflows;

    /// <summary>The most live events any subscription has held pending (at most its capacity): what the hub itself ever buffered.</summary>
    public int PeakPending => Volatile.Read(ref _peakPending);

    /// <summary>Subscribers whose stream ended because more than the stream buffer waited for them (reported by the stream owner).</summary>
    public long Overflows => Interlocked.Read(ref _overflows);

    /// <summary>The number of open subscriptions.</summary>
    public int Count => Volatile.Read(ref _subscriptions).Length;

    /// <summary>Opens a subscription for <paramref name="topics"/> whose pending buffer holds at most <paramref name="capacity"/> events.</summary>
    public HubSubscription Subscribe(IReadOnlySet<EventTopic> topics, int capacity)
    {
        ArgumentNullException.ThrowIfNull(topics);
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        var subscription = new HubSubscription(this, topics, capacity);
        lock (_gate)
        {
            _subscriptions = [.. _subscriptions, subscription];
        }

        return subscription;
    }

    /// <summary>Publishes committed events (the command processor's thread, in sequence order).</summary>
    public void Publish(IReadOnlyList<NodeEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);
        if (events.Count == 0)
        {
            return;
        }

        foreach (var subscription in Volatile.Read(ref _subscriptions))
        {
            subscription.Offer(events);
        }
    }

    /// <summary>Counts a subscriber that overflowed its stream buffer.</summary>
    public void RecordOverflow() => Interlocked.Increment(ref _overflows);

    internal void RecordPending(int count)
    {
        var peak = Volatile.Read(ref _peakPending);
        while (count > peak)
        {
            var seen = Interlocked.CompareExchange(ref _peakPending, count, peak);
            if (seen == peak)
            {
                return;
            }

            peak = seen;
        }
    }

    internal void Remove(HubSubscription subscription)
    {
        lock (_gate)
        {
            _subscriptions = [.. _subscriptions.Where(existing => !ReferenceEquals(existing, subscription))];
        }
    }
}

/// <summary>
/// One subscriber: a bounded pending buffer while its opening frames are written, then a direct sink. The sink and
/// <see cref="Exclusive"/> run under one lock, so the frames of one stream are written by one thread at a time and in order.
/// </summary>
public sealed class HubSubscription : IDisposable
{
    private readonly StreamHub _hub;
    private readonly Lock _gate = new();
    private readonly Queue<NodeEvent> _pending = new();
    private readonly int _capacity;
    private Func<NodeEvent, bool>? _sink;
    private bool _pendingOverflowed;
    private bool _closed;

    internal HubSubscription(StreamHub hub, IReadOnlySet<EventTopic> topics, int capacity)
    {
        _hub = hub;
        Topics = topics;
        _capacity = capacity;
    }

    /// <summary>The subscribed topics.</summary>
    public IReadOnlySet<EventTopic> Topics { get; }

    /// <summary>
    /// Drops the pending events and buffers anew (call before reading the opening frames from the journal; the events published after
    /// this call are delivered by <see cref="TryAttach"/>).
    /// </summary>
    public void BeginPending()
    {
        lock (_gate)
        {
            _sink = null;
            _pending.Clear();
            _pendingOverflowed = false;
        }
    }

    /// <summary>
    /// Delivers the pending events to <paramref name="sink"/> and then every later event as it is published. False, with nothing
    /// delivered, when more than the capacity arrived meanwhile: they were dropped, and the caller catches up from the journal after
    /// <see cref="BeginPending"/>. The sink returns false when the stream ended; it is then no longer called.
    /// </summary>
    public bool TryAttach(Func<NodeEvent, bool> sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        lock (_gate)
        {
            if (_pendingOverflowed)
            {
                return false;
            }

            var open = true;
            while (open && _pending.TryDequeue(out var item))
            {
                open = sink(item);
            }

            _pending.Clear();
            _sink = open ? sink : null;
            _closed |= !open;
            return true;
        }
    }

    /// <summary>Runs <paramref name="action"/> under the lock the sink runs under (for frames the stream's owner writes itself).</summary>
    public void Exclusive(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (_gate)
        {
            action();
        }
    }

    /// <summary>Closes the subscription.</summary>
    public void Dispose()
    {
        _hub.Remove(this);
        lock (_gate)
        {
            _closed = true;
            _sink = null;
            _pending.Clear();
        }
    }

    internal void Offer(IReadOnlyList<NodeEvent> events)
    {
        lock (_gate)
        {
            foreach (var item in events)
            {
                if (_closed || !Topics.Contains(item.Topic))
                {
                    continue;
                }

                if (_sink is { } sink)
                {
                    if (!sink(item))
                    {
                        _sink = null;
                        _closed = true;
                    }
                }
                else if (!_pendingOverflowed)
                {
                    if (_pending.Count >= _capacity)
                    {
                        _pendingOverflowed = true;
                        _pending.Clear();
                    }
                    else
                    {
                        _pending.Enqueue(item);
                        _hub.RecordPending(_pending.Count);
                    }
                }
            }
        }
    }
}
