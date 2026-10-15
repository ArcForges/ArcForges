// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Store;
using Grpc.Core;

namespace ArcForges.Node.Api;

/// <summary>
/// <c>arcforges.node.v1.NodeEventService</c> (events.proto; AD-0004 authoritative state 4; architecture 02 section 1):
/// <list type="bullet">
/// <item><c>Subscribe</c>: a snapshot of the requested topics, then events in sequence order. A valid cursor resumes after it with no
/// snapshot; a cursor from another generation or beyond retention gets <c>reset{snapshot_follows}</c> and a snapshot; a malformed
/// one a terminal <c>VALIDATION/invalid_cursor</c> frame. Heartbeats every 15 s. The stream runs in LocalRpc's stream lane. Live events
/// go straight from the hub to the stream writer, whose per-subscriber buffer of 2,048 events is the only place they wait: one more ends
/// the stream with <c>RESOURCE_EXHAUSTED</c> and the <c>x-af-stream-end: overflow</c> trailer, so the client resubscribes and gets a
/// reset. Opening frames are written as the client reads; live events that arrive meanwhile wait in a pending buffer of the same size,
/// and when it fills the subscriber catches up from the journal instead.</item>
/// <item><c>ListEvents</c>: the events after a cursor, or <c>reset_required</c>.</item>
/// </list>
/// The topics with event sources in this build are NODE, JOBS and NOTIFICATIONS; the other topics are valid and carry nothing yet.
/// </summary>
public sealed class NodeEventServiceHandler : NodeEventService.NodeEventServiceBase
{
    /// <summary>The heartbeat interval (R-API-006).</summary>
    public static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(15);

    private readonly NodeRuntime _node;
    private readonly int _streamBuffer;
    private readonly int _replayHighWater;

    /// <summary>Creates the service over the running node; <paramref name="streamBuffer"/> is the per-subscriber buffer (02 section 1: 2,048).</summary>
    public NodeEventServiceHandler(NodeRuntime node, int streamBuffer = 2048)
    {
        _node = node ?? throw new ArgumentNullException(nameof(node));
        ArgumentOutOfRangeException.ThrowIfLessThan(streamBuffer, 1);
        _streamBuffer = streamBuffer;

        // Opening frames (snapshot, replay, catch-up) are written as the client reads and never fill the buffer themselves.
        _replayHighWater = Math.Max(1, streamBuffer / 2);
    }

    /// <inheritdoc />
    public override async Task Subscribe(NodeEventServiceSubscribeRequest request, IServerStreamWriter<NodeEventServiceSubscribeFrame> responseStream,
        ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        _node.CountCall();
        var writer = context.OpenLocalRpcStream(responseStream);
        await using (writer.ConfigureAwait(false))
        {
            var invalidTopics = Validation.Topics(request.Topics, unique: true, out var topics);
            var invalidCursor = Validation.Cursor(request.HasCursor, request.Cursor, out var cursor);
            var refused = (_node.Lifecycle.IsStopping ? NodeErrors.NodeStopping(_node.Clock.GetUtcNow()) : null) ?? invalidTopics ?? invalidCursor;
            if (refused is null && request.HasResourcesIntervalMs && request.ResourcesIntervalMs is < 1_000 or > 60_000)
            {
                refused = NodeErrors.InvalidArgument("resources_interval_ms: 1,000..60,000");
            }

            using var stop = CancellationTokenSource.CreateLinkedTokenSource(writer.Ended, context.CancellationToken, _node.Stopping);
            if (refused is not null)
            {
                writer.TryWrite(new NodeEventServiceSubscribeFrame { Meta = new ResponseMeta(), Error = refused });
                await writer.CompleteAsync().ConfigureAwait(false);
                return;
            }

            using var subscription = _node.Hub.Subscribe(topics, _streamBuffer);
            var start = _node.Store.Read(reader => Start(reader, topics, cursor));
            if (start.Error is not null)
            {
                writer.TryWrite(new NodeEventServiceSubscribeFrame { Meta = new ResponseMeta(), Error = start.Error });
                await writer.CompleteAsync().ConfigureAwait(false);
                return;
            }

            try
            {
                var live = new LiveState(_node.Clock.GetTimestamp());
                while (true)
                {
                    foreach (var frame in start.Frames)
                    {
                        await WaitForRoomAsync(writer, stop.Token).ConfigureAwait(false);
                        if (!writer.TryWrite(frame))
                        {
                            break;
                        }
                    }

                    live.LastSent = start.LastSent;
                    live.LastWrite = _node.Clock.GetTimestamp();
                    if (subscription.TryAttach(item => Deliver(writer, live, item)))
                    {
                        break;
                    }

                    // More live events than the stream buffer arrived while the opening frames were written; they are in the journal.
                    subscription.BeginPending();
                    var after = new EventCursor(_node.Journal.Generation, live.LastSent);
                    start = _node.Store.Read(reader => Start(reader, topics, after));
                }

                await HeartbeatsAsync(writer, subscription, live, stop.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
            }

            // Detach before completing: an overflow (more than the stream buffer waiting for this subscriber) ends the stream through
            // CompleteAsync with RESOURCE_EXHAUSTED and the x-af-stream-end trailer, so the client resubscribes and gets a reset.
            subscription.Dispose();
            await writer.CompleteAsync().ConfigureAwait(false);
        }
    }
    /// <inheritdoc />
    public override Task<NodeEventServiceListEventsResponse> ListEvents(NodeEventServiceListEventsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        _node.CountCall();
        var response = new NodeEventServiceListEventsResponse { Meta = new ResponseMeta() };
        var invalidTopics = Validation.Topics(request.Topics, unique: false, out var topics);
        var refused = (_node.Lifecycle.IsStopping ? NodeErrors.NodeStopping(_node.Clock.GetUtcNow()) : null) ?? invalidTopics;
        EventCursor? cursor = null;
        if (refused is null)
        {
            refused = !request.HasCursor || request.Cursor.Length == 0
                ? NodeErrors.InvalidArgument("cursor: required")
                : Validation.Cursor(true, request.Cursor, out cursor);
        }

        var limit = request.HasLimit ? (int)request.Limit : 200;
        if (refused is null && (limit < 1 || limit > 1000))
        {
            refused = NodeErrors.InvalidArgument("limit: 1..1000");
        }

        if (refused is not null)
        {
            response.Error = refused;
            return Task.FromResult(response);
        }

        response.Value = _node.Store.Read(reader =>
        {
            var latest = Latest(reader);
            var value = new NodeEventServiceListEventsValue();
            switch (_node.Journal.Check(reader, cursor!.Value, latest))
            {
                case CursorStatus.Invalid:
                    return null;
                case CursorStatus.OtherGeneration:
                case CursorStatus.Stale:
                    value.ResetRequired = true;
                    value.Position = new StreamPosition { Generation = _node.Journal.Generation, Sequence = latest };
                    return value;
            }

            var events = _node.Journal.ReadAfter(reader, cursor.Value.Sequence, latest, topics, limit);
            value.Events.Add(events);
            var position = events.Count == limit ? events[^1].Seq : latest;
            value.Position = Position(position);
            return value;
        });
        if (response.Value is null)
        {
            response.Error = NodeErrors.InvalidCursor();
        }

        return Task.FromResult(response);
    }

    private static ulong Latest(StoreReader reader) =>
        Convert.ToUInt64(reader.Scalar("SELECT coalesce(max(seq), 0) FROM event_journal;"), CultureInfo.InvariantCulture);

    private async Task WaitForRoomAsync(LocalRpcStreamWriter<NodeEventServiceSubscribeFrame> writer, CancellationToken cancellationToken)
    {
        // Replays and snapshots can be larger than the stream's buffer; they are written as the client reads.
        while (writer.Buffered >= _replayHighWater)
        {
            await Task.Delay(5, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>The opening frames of a subscription, read in one store snapshot after the hub subscription was registered.</summary>
    private StartFrames Start(StoreReader reader, HashSet<EventTopic> topics, EventCursor? cursor)
    {
        var latest = Latest(reader);
        var frames = new List<NodeEventServiceSubscribeFrame>();
        if (cursor is { } position)
        {
            var status = _node.Journal.Check(reader, position, latest);
            if (status == CursorStatus.Invalid)
            {
                return new StartFrames([], 0, NodeErrors.InvalidCursor());
            }

            if (status == CursorStatus.Valid)
            {
                var replay = _node.Journal.ReadAfter(reader, position.Sequence, latest, topics, int.MaxValue);
                frames.AddRange(replay.Select(EventFrame));
                return new StartFrames(frames, Math.Max(position.Sequence, latest), null);
            }

            frames.Add(new NodeEventServiceSubscribeFrame
            {
                Meta = new ResponseMeta(),
                Position = new StreamPosition { Generation = _node.Journal.Generation, Sequence = latest },
                Reset = new StreamReset
                {
                    Reason = status == CursorStatus.OtherGeneration ? "generation_changed" : "cursor_expired",
                    SnapshotFollows = true,
                },
            });
        }

        var now = ProtoTime.ToInstant(_node.Clock.GetUtcNow());
        void Add(EventTopic topic, NodeEvent item)
        {
            item.Seq = latest;
            item.Generation = _node.Journal.Generation;
            item.At = now;
            item.Topic = topic;
            item.FromSnapshot = true;
            frames.Add(new NodeEventServiceSubscribeFrame
            {
                Meta = new ResponseMeta(),
                Position = new StreamPosition { Generation = _node.Journal.Generation, Sequence = latest },
                Event = item,
            });
        }

        if (topics.Contains(EventTopic.Node))
        {
            Add(EventTopic.Node, new NodeEvent { Node = _node.Status() });
        }

        if (topics.Contains(EventTopic.Jobs))
        {
            foreach (var job in Jobs.All(reader))
            {
                Add(EventTopic.Jobs, new NodeEvent { Job = job });
            }
        }

        if (topics.Contains(EventTopic.Notifications))
        {
            foreach (var notification in Notifications.All(reader))
            {
                Add(EventTopic.Notifications, new NodeEvent { Notification = notification });
            }
        }

        var complete = new SnapshotComplete { Seq = latest };
        complete.Topics.Add(topics.Order());
        frames.Add(new NodeEventServiceSubscribeFrame { Meta = new ResponseMeta(), Position = Position(latest), SnapshotComplete = complete });
        return new StartFrames(frames, latest, null);
    }

    /// <summary>
    /// Writes one live event (the command processor's thread, under the subscription's lock). False when the stream ended: an overflow of
    /// the stream buffer ends it in LocalRpc with the typed overflow, and the handler's wait wakes through <c>writer.Ended</c>.
    /// </summary>
    private bool Deliver(LocalRpcStreamWriter<NodeEventServiceSubscribeFrame> writer, LiveState live, NodeEvent item)
    {
        if (item.Seq <= live.LastSent)
        {
            return true;
        }

        if (!writer.TryWrite(EventFrame(item)))
        {
            if (writer.EndReason == LocalRpcStreamEndReason.Overflow)
            {
                _node.Hub.RecordOverflow();
            }

            return false;
        }

        live.LastSent = item.Seq;
        live.LastWrite = _node.Clock.GetTimestamp();
        return true;
    }

    /// <summary>Sends a heartbeat when the stream carried nothing for the heartbeat interval, until the stream ends.</summary>
    private async Task HeartbeatsAsync(LocalRpcStreamWriter<NodeEventServiceSubscribeFrame> writer, HubSubscription subscription, LiveState live,
        CancellationToken cancellationToken)
    {
        // The wait wakes on a cancellation raised by the writer on the publishing thread; continuations run asynchronously, so the
        // command processor never runs this handler inline.
        var ended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = cancellationToken.Register(static state => ((TaskCompletionSource)state!).TrySetResult(), ended);
        while (!cancellationToken.IsCancellationRequested)
        {
            TimeSpan due = TimeSpan.Zero;
            subscription.Exclusive(() => due = HeartbeatInterval - _node.Clock.GetElapsedTime(live.LastWrite));
            if (due > TimeSpan.Zero)
            {
                try
                {
                    await ended.Task.WaitAsync(due, CancellationToken.None).ConfigureAwait(false);
                    return;
                }
                catch (TimeoutException)
                {
                    // The heartbeat may be due.
                }

                continue;
            }

            var open = true;
            subscription.Exclusive(() =>
            {
                if (_node.Clock.GetElapsedTime(live.LastWrite) < HeartbeatInterval)
                {
                    return;
                }

                open = writer.TryWrite(new NodeEventServiceSubscribeFrame
                {
                    Meta = new ResponseMeta(),
                    Position = Position(live.LastSent),
                    Heartbeat = new Heartbeat { At = ProtoTime.ToInstant(_node.Clock.GetUtcNow()) },
                });
                live.LastWrite = _node.Clock.GetTimestamp();
            });
            if (!open)
            {
                return;
            }
        }
    }
    private NodeEventServiceSubscribeFrame EventFrame(NodeEvent item) => new()
    {
        Meta = new ResponseMeta(),
        Position = Position(item.Seq),
        Event = item,
    };

    private StreamPosition Position(ulong sequence) => new()
    {
        Cursor = new EventCursor(_node.Journal.Generation, sequence).ToString(),
        Sequence = sequence,
        Generation = _node.Journal.Generation,
    };

    /// <summary>What the stream sent last and when; read and written under the subscription's lock.</summary>
    private sealed class LiveState(long lastWrite)
    {
        public ulong LastSent { get; set; }

        public long LastWrite { get; set; } = lastWrite;
    }

    private sealed record StartFrames(IReadOnlyList<NodeEventServiceSubscribeFrame> Frames, ulong LastSent, ArcError? Error);
}
