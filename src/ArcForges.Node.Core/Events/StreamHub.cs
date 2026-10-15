// SPDX-License-Identifier: AGPL-3.0-only
using System.Threading.Channels;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Events;

/// <summary>
/// The stream hub (architecture 02 section 1): the command processor publishes each committed batch of journal events, in sequence
/// order, to every subscription whose topics match. A subscription registers before it reads its snapshot or replay from the
/// journal, so no event committed after that read is missed; the handler drops what it already sent by sequence number.
/// </summary>
public sealed class StreamHub
{
    /// <summary>Events a subscription may hold before its handler moves them to the stream's own bounded buffer.</summary>
    public const int SubscriptionCapacity = 65_536;

    private readonly Lock _gate = new();
    private HubSubscription[] _subscriptions = [];

    /// <summary>The number of open subscriptions.</summary>
    public int Count => Volatile.Read(ref _subscriptions).Length;

    /// <summary>Opens a subscription for <paramref name="topics"/>.</summary>
    public HubSubscription Subscribe(IReadOnlySet<EventTopic> topics)
    {
        ArgumentNullException.ThrowIfNull(topics);
        var subscription = new HubSubscription(this, topics);
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
            foreach (var item in events)
            {
                subscription.Offer(item);
            }
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

/// <summary>One subscriber's queue of live events.</summary>
public sealed class HubSubscription : IDisposable
{
    private readonly StreamHub _hub;
    private readonly Channel<NodeEvent> _queue = Channel.CreateBounded<NodeEvent>(new BoundedChannelOptions(StreamHub.SubscriptionCapacity)
    {
        SingleReader = true,
        SingleWriter = true,
        FullMode = BoundedChannelFullMode.Wait,
    });

    private int _overflowed;

    internal HubSubscription(StreamHub hub, IReadOnlySet<EventTopic> topics)
    {
        _hub = hub;
        Topics = topics;
    }

    /// <summary>The subscribed topics.</summary>
    public IReadOnlySet<EventTopic> Topics { get; }

    /// <summary>The live events, in sequence order.</summary>
    public ChannelReader<NodeEvent> Reader => _queue.Reader;

    /// <summary>True when the queue filled up and events were lost; the stream must end so that the client resubscribes.</summary>
    public bool Overflowed => Volatile.Read(ref _overflowed) != 0;

    /// <summary>Closes the subscription.</summary>
    public void Dispose()
    {
        _hub.Remove(this);
        _queue.Writer.TryComplete();
    }

    internal void Offer(NodeEvent item)
    {
        if (!Topics.Contains(item.Topic))
        {
            return;
        }

        if (!_queue.Writer.TryWrite(item))
        {
            Volatile.Write(ref _overflowed, 1);
            _queue.Writer.TryComplete();
        }
    }
}
