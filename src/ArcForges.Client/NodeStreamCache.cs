// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using Grpc.Core;

namespace ArcForges.Client;

/// <summary>A keyed collection of one entity type that raises <see cref="Changed"/> for every change.</summary>
public sealed class EntitySet<T>
    where T : class
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, T> _items = new(StringComparer.Ordinal);

    /// <summary>Raised after an entity was added or replaced (or the set was replaced by a snapshot, with a null key).</summary>
    public event EventHandler<EntityChange<T>>? Changed;

    /// <summary>The number of entities.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _items.Count;
            }
        }
    }

    /// <summary>A copy of the entities.</summary>
    public IReadOnlyDictionary<string, T> Snapshot()
    {
        lock (_gate)
        {
            return new Dictionary<string, T>(_items, StringComparer.Ordinal);
        }
    }

    /// <summary>The entity with <paramref name="key"/>, or <see langword="null"/>.</summary>
    public T? Get(string key)
    {
        lock (_gate)
        {
            return _items.GetValueOrDefault(key);
        }
    }

    internal void Set(string key, T item)
    {
        lock (_gate)
        {
            _items[key] = item;
        }

        Changed?.Invoke(this, new EntityChange<T>(key, item));
    }

    internal void Replace(IReadOnlyDictionary<string, T> items)
    {
        lock (_gate)
        {
            _items.Clear();
            foreach (var (key, item) in items)
            {
                _items[key] = item;
            }
        }

        Changed?.Invoke(this, new EntityChange<T>(null, null));
    }
}

/// <summary>One change of an <see cref="EntitySet{T}"/>: a key and its new value, or a null key when a snapshot replaced the set.</summary>
public sealed record EntityChange<T>(string? Key, T? Item)
    where T : class;

/// <summary>
/// <c>NodeStreamCache</c> (architecture 12 section 1; AD-0004 authoritative state 4): subscribes with
/// <c>NodeEventService.Subscribe(topics, cursor)</c>, applies the snapshot and then events in <c>event_seq</c> order, drops
/// duplicates (<c>seq</c> at or below the last applied), and on a reset, a generation change or a stream overflow resubscribes
/// without a cursor and applies a fresh snapshot. After a disconnect it resumes from its last cursor with the reconnect backoff.
/// It holds no authoritative state: every mutation goes through RPCs (R-API-003). Observers use the per-entity sets.
/// </summary>
public sealed class NodeStreamCache : IAsyncDisposable
{
    private readonly Func<CancellationToken, Task<NodeChannel>> _connect;
    private readonly EventTopic[] _topics;
    private readonly ReconnectBackoff _backoff;
    private readonly CancellationTokenSource _stop = new();
    private Task? _loop;
    private Staging? _staging;

    /// <summary>Creates a cache over channels from <paramref name="connect"/> (each call returns a connected channel, or throws).</summary>
    public NodeStreamCache(Func<CancellationToken, Task<NodeChannel>> connect, IEnumerable<EventTopic> topics, ReconnectBackoff? backoff = null)
    {
        _connect = connect ?? throw new ArgumentNullException(nameof(connect));
        _topics = [.. (topics ?? throw new ArgumentNullException(nameof(topics))).Distinct()];
        if (_topics.Length == 0)
        {
            throw new ArgumentException("Subscribe to at least one topic.", nameof(topics));
        }

        _backoff = backoff ?? new ReconnectBackoff();
    }

    /// <summary>The connection state.</summary>
    public ConnectionStateTracker Connection { get; } = new();

    /// <summary>The node's lifecycle state and capabilities (topic NODE).</summary>
    public NodeStatusChanged? NodeStatus { get; private set; }

    /// <summary>Node jobs by job ID (topic JOBS).</summary>
    public EntitySet<JobView> Jobs { get; } = new();

    /// <summary>Notification centre entries by notification ID (topic NOTIFICATIONS).</summary>
    public EntitySet<NodeNotification> Notifications { get; } = new();

    /// <summary>The cursor of the last applied position; the next subscription resumes from it.</summary>
    public string? Cursor { get; private set; }

    /// <summary>The stream generation of the applied state (0 before the first snapshot).</summary>
    public ulong Generation { get; private set; }

    /// <summary>The last applied event sequence number.</summary>
    public ulong LastSequence { get; private set; }

    /// <summary>Snapshots applied (the first one included).</summary>
    public int SnapshotsApplied { get; private set; }

    /// <summary>Resets: a reset frame, a generation change or an overflow that made the cache resubscribe for a snapshot.</summary>
    public int Resets { get; private set; }

    /// <summary>Events dropped as duplicates (sequence at or below the last applied).</summary>
    public int DuplicatesDropped { get; private set; }

    /// <summary>Subscriptions opened (the first, resumes and resubscriptions).</summary>
    public int Subscriptions { get; private set; }

    /// <summary>Subscriptions that resumed from a cursor and received no snapshot.</summary>
    public int Resumes { get; private set; }

    /// <summary>Raised after each applied frame (snapshot completion, event or reset).</summary>
    public event EventHandler? Applied;

    /// <summary>Starts the subscription loop.</summary>
    public void Start()
    {
        if (_loop is not null)
        {
            throw new InvalidOperationException("The cache starts once.");
        }

        _loop = Task.Run(() => RunAsync(_stop.Token));
    }

    /// <summary>Stops the loop.</summary>
    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        if (_loop is not null)
        {
            try
            {
                await _loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        _stop.Dispose();
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        var failures = 0;
        var resetNext = false;
        while (!cancellationToken.IsCancellationRequested)
        {
            NodeChannel? channel = null;
            try
            {
                channel = await _connect(cancellationToken).ConfigureAwait(false);
                Connection.MoveTo(ConnectionState.Connected);
                failures = 0;
                var outcome = await SubscribeOnceAsync(channel, resetNext ? null : Cursor, cancellationToken).ConfigureAwait(false);
                resetNext = outcome == StreamOutcome.ResetRequired;
                if (resetNext)
                {
                    Resets++;
                    continue;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (NodeUnavailableException exception) when (exception.Reason is NodeUnavailableReason.AccessDenied or NodeUnavailableReason.Incompatible)
            {
                Connection.MoveTo(exception.State);
                return;
            }
            catch (Exception exception) when (exception is RpcException or NodeUnavailableException or IOException)
            {
                // Disconnected or not reachable: resume from the cursor after the backoff.
            }
            finally
            {
                if (channel is not null)
                {
                    await channel.DisposeAsync().ConfigureAwait(false);
                }
            }

            failures++;
            Connection.MoveTo(Connection.State == ConnectionState.Connecting ? ConnectionState.NodeStopped : ConnectionState.Reconnecting);
            await Task.Delay(_backoff.Next(failures), cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<StreamOutcome> SubscribeOnceAsync(NodeChannel channel, string? cursor, CancellationToken cancellationToken)
    {
        var request = new NodeEventServiceSubscribeRequest { Topics = { _topics } };
        if (cursor is not null)
        {
            request.Cursor = cursor;
        }
        else
        {
            _staging = new Staging();
        }

        Subscriptions++;
        var resumed = cursor is not null;
        using var call = channel.Events.Subscribe(request, cancellationToken: cancellationToken);
        try
        {
            await foreach (var frame in call.ResponseStream.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                switch (frame.FrameCase)
                {
                    case NodeEventServiceSubscribeFrame.FrameOneofCase.Reset:
                        // A stale cursor or a generation change: a snapshot follows on this stream.
                        Resets++;
                        resumed = false;
                        _staging = new Staging();
                        break;
                    case NodeEventServiceSubscribeFrame.FrameOneofCase.Event:
                        if (Apply(frame) == StreamOutcome.ResetRequired)
                        {
                            return StreamOutcome.ResetRequired;
                        }

                        if (resumed && !frame.Event.FromSnapshot && _staging is null)
                        {
                            resumed = false;
                            Resumes++;
                        }

                        break;
                    case NodeEventServiceSubscribeFrame.FrameOneofCase.SnapshotComplete:
                        CompleteSnapshot(frame);
                        break;
                    case NodeEventServiceSubscribeFrame.FrameOneofCase.Error:
                        throw new RpcException(new Status(StatusCode.Unavailable, $"The stream ended with {frame.Error.Category}/{frame.Error.Code}."));
                }

                if (resumed && frame.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.Heartbeat && _staging is null)
                {
                    // A resumed stream that is caught up starts with heartbeats or live events, never a snapshot.
                    resumed = false;
                    Resumes++;
                }
            }
        }
        catch (RpcException exception) when (LocalRpcStreamEnd.TryRead(exception, out var end) && end == LocalRpcStreamEndReason.Overflow)
        {
            // The node's per-subscriber buffer overflowed (02 section 1): resubscribe for a snapshot.
            return StreamOutcome.ResetRequired;
        }

        throw new RpcException(new Status(StatusCode.Unavailable, "The node ended the stream."));
    }

    private StreamOutcome Apply(NodeEventServiceSubscribeFrame frame)
    {
        var item = frame.Event;
        if (item.FromSnapshot)
        {
            (_staging ??= new Staging()).Add(item);
            return StreamOutcome.Continue;
        }

        if (_staging is not null)
        {
            // An incremental event before the snapshot completed would mix states; resubscribe.
            return StreamOutcome.ResetRequired;
        }

        if (Generation != 0 && item.Generation != Generation)
        {
            return StreamOutcome.ResetRequired;
        }

        if (item.Seq <= LastSequence)
        {
            DuplicatesDropped++;
            return StreamOutcome.Continue;
        }

        ApplyEvent(item);
        LastSequence = item.Seq;
        Cursor = frame.Position?.Cursor is { Length: > 0 } next ? next : Cursor;
        Applied?.Invoke(this, EventArgs.Empty);
        return StreamOutcome.Continue;
    }

    private void CompleteSnapshot(NodeEventServiceSubscribeFrame frame)
    {
        var staging = _staging ?? new Staging();
        _staging = null;
        NodeStatus = staging.Node ?? NodeStatus;
        Jobs.Replace(staging.Jobs);
        Notifications.Replace(staging.Notifications);
        Generation = frame.Position.Generation;
        LastSequence = frame.SnapshotComplete.Seq;
        Cursor = frame.Position.Cursor;
        SnapshotsApplied++;
        Applied?.Invoke(this, EventArgs.Empty);
    }

    private void ApplyEvent(NodeEvent item)
    {
        switch (item.PayloadCase)
        {
            case NodeEvent.PayloadOneofCase.Node:
                NodeStatus = item.Node;
                break;
            case NodeEvent.PayloadOneofCase.Job:
                Jobs.Set(IdText.Format(item.Job.JobId), item.Job);
                break;
            case NodeEvent.PayloadOneofCase.Notification:
                Notifications.Set(IdText.Format(item.Notification.NotificationId), item.Notification);
                break;
        }
    }

    private enum StreamOutcome
    {
        Continue,
        ResetRequired,
    }

    private sealed class Staging
    {
        public NodeStatusChanged? Node { get; private set; }

        public Dictionary<string, JobView> Jobs { get; } = new(StringComparer.Ordinal);

        public Dictionary<string, NodeNotification> Notifications { get; } = new(StringComparer.Ordinal);

        public void Add(NodeEvent item)
        {
            switch (item.PayloadCase)
            {
                case NodeEvent.PayloadOneofCase.Node:
                    Node = item.Node;
                    break;
                case NodeEvent.PayloadOneofCase.Job:
                    Jobs[IdText.Format(item.Job.JobId)] = item.Job;
                    break;
                case NodeEvent.PayloadOneofCase.Notification:
                    Notifications[IdText.Format(item.Notification.NotificationId)] = item.Notification;
                    break;
            }
        }
    }
}
