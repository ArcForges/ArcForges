// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Store;
using Grpc.Core;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// NodeEventService and the client's NodeStreamCache against a real node in the test process (R-API-004; AD-0004 authoritative
/// state 4): snapshot then ordered events, resume by cursor without a snapshot, reset with a snapshot on a generation change, on a
/// stale or foreign cursor and on overflow, and many subscribers resetting at once.
/// </summary>
[Collection(SerialNodeTests.Name)]
public sealed class EventStreamTests
{
    private static readonly EventTopic[] Topics = [EventTopic.Node, EventTopic.Jobs, EventTopic.Notifications];

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 60_000)]
    public async Task ASubscriptionStartsWithASnapshotThenDeliversEventsInOrder()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create(seed: transaction =>
            InProcessNode.SeedJob(transaction, JobKind.Doctor, JobState.Running, transaction.NowMicroseconds)).StartAsync();
        await using var channel = await node.ChannelAsync();
        using var call = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest { Topics = { Topics } }, cancellationToken: ct);
        var reader = call.ResponseStream;

        var snapshot = await ReadUntilAsync(reader, frame => frame.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.SnapshotComplete);
        var complete = snapshot[^1];
        Assert.All(snapshot[..^1], frame => Assert.True(frame.Event.FromSnapshot));
        Assert.Contains(snapshot, frame => frame.Event?.Node?.State == NodeLifecycleState.Degraded);
        Assert.Contains(snapshot, frame => frame.Event?.Job?.Kind == JobKind.Doctor);
        Assert.Equal(node.Runtime.Journal.Generation, complete.Position.Generation);
        Assert.True(EventCursor.TryParse(complete.Position.Cursor, out var cursor));
        Assert.Equal(complete.SnapshotComplete.Seq, cursor.Sequence);

        await Rename(channel, "one");
        await Rename(channel, "two");
        var live = await ReadAsync(reader, 2);
        Assert.Equal([complete.SnapshotComplete.Seq + 1, complete.SnapshotComplete.Seq + 2], live.Select(frame => frame.Event.Seq));
        Assert.All(live, frame => Assert.Equal(("renamed", false), (frame.Event.Node.Reason, frame.Event.FromSnapshot)));
        Assert.Equal(live[1].Event.Seq, live[1].Position.Sequence);
    }

    [Fact(Timeout = 60_000)]
    public async Task ResumingFromACursorDeliversOnlyTheMissedEvents()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        string cursor;
        using (var first = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest { Topics = { Topics } }, cancellationToken: ct))
        {
            cursor = (await ReadUntilAsync(first.ResponseStream, frame => frame.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.SnapshotComplete))[^1].Position.Cursor;
        }

        // Missed while disconnected.
        await Rename(channel, "missed one");
        await Rename(channel, "missed two");
        using var resumed = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest { Topics = { Topics }, Cursor = cursor }, cancellationToken: ct);
        var frames = await ReadAsync(resumed.ResponseStream, 2);
        Assert.All(frames, frame => Assert.Equal(NodeEventServiceSubscribeFrame.FrameOneofCase.Event, frame.FrameCase));
        Assert.All(frames, frame => Assert.False(frame.Event.FromSnapshot));
        Assert.True(EventCursor.TryParse(cursor, out var position));
        Assert.Equal([position.Sequence + 1, position.Sequence + 2], frames.Select(frame => frame.Event.Seq));

        // ListEvents (polling clients) resumes the same way.
        var listed = await channel.Events.ListEventsAsync(new NodeEventServiceListEventsRequest { Topics = { Topics }, Cursor = cursor, Limit = 1 },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: ct);
        Assert.Equal([position.Sequence + 1], listed.Value.Events.Select(item => item.Seq));
        var rest = await channel.Events.ListEventsAsync(new NodeEventServiceListEventsRequest { Topics = { Topics }, Cursor = listed.Value.Position.Cursor },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: ct);
        Assert.Equal([position.Sequence + 2], rest.Value.Events.Select(item => item.Seq));
        Assert.False(rest.Value.ResetRequired);
    }

    [Fact(Timeout = 90_000)]
    public async Task AGenerationChangeResetsWithAFreshSnapshot()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = InProcessNode.Create();
        await node.StartAsync();
        string cursor;
        ulong generation;
        await using (var channel = await node.ChannelAsync())
        {
            using var call = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest { Topics = { Topics } }, cancellationToken: ct);
            var complete = (await ReadUntilAsync(call.ResponseStream, frame => frame.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.SnapshotComplete))[^1];
            (cursor, generation) = (complete.Position.Cursor, complete.Position.Generation);
        }

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        await using var again = await node.ChannelAsync();
        Assert.Equal(generation + 1, node.Runtime.Journal.Generation);

        using var resumed = again.Events.Subscribe(new NodeEventServiceSubscribeRequest { Topics = { Topics }, Cursor = cursor }, cancellationToken: ct);
        var frames = await ReadUntilAsync(resumed.ResponseStream, frame => frame.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.SnapshotComplete);
        Assert.Equal(NodeEventServiceSubscribeFrame.FrameOneofCase.Reset, frames[0].FrameCase);
        Assert.Equal(("generation_changed", true), (frames[0].Reset.Reason, frames[0].Reset.SnapshotFollows));
        Assert.All(frames[1..^1], frame => Assert.True(frame.Event.FromSnapshot));
        Assert.Equal(generation + 1, frames[^1].Position.Generation);

        var listed = await again.Events.ListEventsAsync(new NodeEventServiceListEventsRequest { Topics = { Topics }, Cursor = cursor }, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: ct);
        Assert.True(listed.Value.ResetRequired);
    }

    [Fact(Timeout = 60_000)]
    public async Task MalformedAndFutureCursorsEndWithInvalidCursor()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();

        foreach (var cursor in (string[])["garbage", new EventCursor(node.Runtime.Journal.Generation, node.Runtime.Journal.Latest + 1000).ToString(),
            new EventCursor(node.Runtime.Journal.Generation + 1, 1).ToString()])
        {
            using var call = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest { Topics = { Topics }, Cursor = cursor }, cancellationToken: ct);
            var frames = await ReadAsync(call.ResponseStream, 1);
            Assert.Equal("invalid_cursor", frames[0].Error.Code);
            Assert.False(await call.ResponseStream.MoveNext(ct));
        }

        using var empty = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest(), cancellationToken: ct);
        Assert.Equal("topics: non-empty", (await ReadAsync(empty.ResponseStream, 1))[0].Error.Details.State.Reason);
        using var duplicate = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest { Topics = { EventTopic.Node, EventTopic.Node } }, cancellationToken: ct);
        Assert.Equal("topics: unique", (await ReadAsync(duplicate.ResponseStream, 1))[0].Error.Details.State.Reason);
    }

    [Fact(Timeout = 120_000)]
    public async Task TheStreamCacheResumesAfterADisconnectAndResetsOnARestart()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = InProcessNode.Create();
        await node.StartAsync();
        var connections = 0;
        NodeChannel? current = null;
        await using var cache = new NodeStreamCache(async _ =>
        {
            connections++;
            current = await node.ChannelAsync();
            return current;
        }, Topics, new ReconnectBackoff(() => 0));
        cache.Start();
        await WaitAsync(() => cache.SnapshotsApplied == 1 && cache.NodeStatus is not null);
        Assert.Equal(NodeLifecycleState.Degraded, cache.NodeStatus!.State);
        Assert.Equal(ConnectionState.Connected, cache.Connection.State);

        // A disconnect (the channel closes under the subscription), events while away, then a resume from the cursor.
        await using (var writer = await node.ChannelAsync())
        {
            var before = cache.LastSequence;
            await current!.DisposeAsync();
            await Rename(writer, "while away");
            await WaitAsync(() => cache.LastSequence > before && cache.Subscriptions >= 2);
            Assert.Equal(1, cache.SnapshotsApplied);
            Assert.Equal("renamed", cache.NodeStatus!.Reason);
        }

        // A node restart is a new generation: the cache resets and applies a fresh snapshot.
        var generation = cache.Generation;
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        await WaitAsync(() => cache.Generation == generation + 1 && cache.SnapshotsApplied == 2);
        Assert.True(cache.Resets >= 1);
        Assert.Equal(ConnectionState.Connected, cache.Connection.State);
        Assert.True(connections >= 3);
    }

    [Fact(Timeout = 180_000)]
    public async Task ManySubscribersResetTogetherAfterARestart()
    {
        var ct = TestContext.Current.CancellationToken;
        // Plan risk: "stream reset storms on generation change overload clients" - snapshot plus cursor with many subscribers.
        // LocalRpc's stream lane admits 32 streams per client process (MaxStreamCallsPerProcess); this test is one process.
        const int Subscribers = 30;
        await using var node = InProcessNode.Create();
        await node.StartAsync();
        var caches = Enumerable.Range(0, Subscribers)
            .Select(_ => new NodeStreamCache(_ => node.ChannelAsync(), Topics, new ReconnectBackoff())).ToList();
        try
        {
            caches.ForEach(cache => cache.Start());
            await WaitAsync(() => caches.All(cache => cache.SnapshotsApplied == 1), TimeSpan.FromSeconds(60));
            var generation = caches[0].Generation;

            Assert.Equal(0, await node.StopAsync());
            await node.StartAsync();
            await WaitAsync(() => caches.All(cache => cache.Generation == generation + 1 && cache.SnapshotsApplied == 2), TimeSpan.FromSeconds(90));
            Assert.All(caches, cache => Assert.True(cache.Resets >= 1));

            // After the reset every cache follows the live stream again.
            await using (var writer = await node.ChannelAsync())
            {
                await Rename(writer, "after restart");
            }

            await WaitAsync(() => caches.All(cache => cache.NodeStatus?.Reason == "renamed"), TimeSpan.FromSeconds(30));
            Assert.All(caches, cache => Assert.Equal(caches[0].LastSequence, cache.LastSequence));
        }
        finally
        {
            foreach (var cache in caches)
            {
                await cache.DisposeAsync();
            }
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task AnOverflowingSubscriberIsEndedAndTheCacheResubscribesForASnapshot()
    {
        var ct = TestContext.Current.CancellationToken;
        // The per-subscriber buffer is 2,048 events (02 section 1); a small buffer reaches overflow with few events.
        await using var node = await InProcessNode.Create(streamBuffer: 8).StartAsync();
        var stall = new ManualResetEventSlim(true);
        await using var cache = new NodeStreamCache(_ => node.ChannelAsync(), [EventTopic.Node], new ReconnectBackoff(() => 0));
        cache.Applied += (_, _) => stall.Wait(TimeSpan.FromSeconds(10));
        cache.Start();
        await WaitAsync(() => cache.SnapshotsApplied == 1);

        stall.Reset();
        await using (var writer = await node.ChannelAsync())
        {
            await Rename(writer, "start");
            // Stalled reader: the HTTP/2 window and then the stream's buffer fill up.
            for (var i = 0; i < 600 && node.Runtime.ServerMetrics!().All(metric => metric.Name != "rpc.streams_ended" || metric.Labels["reason"] != "Overflow" || metric.Value == 0); i++)
            {
                await Rename(writer, "filler " + i);
            }
        }

        stall.Set();
        await WaitAsync(() => cache.Resets >= 1 && cache.SnapshotsApplied >= 2, TimeSpan.FromSeconds(60));
        Assert.Contains(node.Runtime.ServerMetrics!(), metric => metric.Name == "rpc.streams_ended" && metric.Labels["reason"] == "Overflow" && metric.Value >= 1);
    }

    [Fact(Timeout = 60_000)]
    public async Task OverflowIsReportedToARawSubscriberAsTheTypedStreamEnd()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create(streamBuffer: 8).StartAsync();
        await using var channel = await node.ChannelAsync();
        using var call = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest { Topics = { EventTopic.Node } }, cancellationToken: ct);
        await ReadUntilAsync(call.ResponseStream, frame => frame.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.SnapshotComplete);
        await using (var writer = await node.ChannelAsync())
        {
            for (var i = 0; i < 600; i++)
            {
                await Rename(writer, "filler " + i);
                if (node.Runtime.ServerMetrics!().Any(metric => metric.Name == "rpc.streams_ended" && metric.Labels["reason"] == "Overflow" && metric.Value > 0))
                {
                    break;
                }
            }
        }

        var exception = await Assert.ThrowsAsync<RpcException>(async () =>
        {
            while (await call.ResponseStream.MoveNext(ct))
            {
            }
        });
        Assert.Equal(StatusCode.ResourceExhausted, exception.StatusCode);
        Assert.True(LocalRpcStreamEnd.TryRead(exception, out var end));
        Assert.Equal(LocalRpcStreamEndReason.Overflow, end);
    }

    [Theory(Timeout = 240_000)]
    [InlineData(6_000)]
    [InlineData(70_000)]
    public async Task AtTheProductionBufferAStalledSubscriberIsEndedWithTheTypedOverflowAndTheNodeHoldsNoMore(int events)
    {
        var ct = TestContext.Current.CancellationToken;
        // 02 section 1 / events.proto: the per-subscriber buffer is 2,048 events and overflow ends the stream with a reset.
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.Equal(2048, node.StreamBuffer);
        await using var channel = await node.ChannelAsync();
        using var call = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest { Topics = { EventTopic.Node } }, cancellationToken: ct);
        await ReadUntilAsync(call.ResponseStream, frame => frame.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.SnapshotComplete);

        // The subscriber stops reading; the node keeps committing events.
        await EmitAsync(node, events);
        // The overflow is signalled when it happens; the typed status follows once the client takes the frame already on its way.
        await WaitAsync(() => node.Runtime.Hub.Overflows >= 1, TimeSpan.FromSeconds(60));
        Assert.InRange(node.Runtime.Hub.PeakPending, 0, node.StreamBuffer);

        // Reading again: what the transport already carried, then RESOURCE_EXHAUSTED with the x-af-stream-end trailer, far before the end.
        var received = 0;
        var exception = await Assert.ThrowsAsync<RpcException>(async () =>
        {
            while (await call.ResponseStream.MoveNext(ct))
            {
                received++;
            }
        });
        Assert.Equal(StatusCode.ResourceExhausted, exception.StatusCode);
        Assert.True(LocalRpcStreamEnd.TryRead(exception, out var end));
        Assert.Equal(LocalRpcStreamEndReason.Overflow, end);
        Assert.True(received < events, $"{received} of {events} frames arrived before the overflow");
        await WaitAsync(() => OverflowCount(node) == 1, TimeSpan.FromSeconds(30));
        TestContext.Current.TestOutputHelper?.WriteLine($"{events} events: {received} frames reached the stalled subscriber before the typed overflow.");
    }

    [Theory(Timeout = 240_000)]
    [InlineData(6_000)]
    [InlineData(70_000)]
    public async Task AtTheProductionBufferAStalledCacheIsResetAndCatchesUp(int events)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        using var stall = new ManualResetEventSlim(true);
        await using var cache = new NodeStreamCache(_ => node.ChannelAsync(), [EventTopic.Node], new ReconnectBackoff(() => 0));
        cache.Applied += (_, _) => stall.Wait(TimeSpan.FromSeconds(60));
        cache.Start();
        await WaitAsync(() => cache.SnapshotsApplied == 1);

        stall.Reset();
        var latest = await EmitAsync(node, events);
        await WaitAsync(() => node.Runtime.Hub.Overflows >= 1, TimeSpan.FromSeconds(60));
        stall.Set();

        await WaitAsync(() => cache.Resets >= 1 && cache.SnapshotsApplied >= 2 && cache.LastSequence >= latest, TimeSpan.FromSeconds(120));
        await WaitAsync(() => OverflowCount(node) == 1, TimeSpan.FromSeconds(30));
        Assert.InRange(node.Runtime.Hub.PeakPending, 0, node.StreamBuffer);
        Assert.Equal(ConnectionState.Connected, cache.Connection.State);
    }

    [Fact(Timeout = 120_000)]
    public async Task LiveEventsBeyondTheBufferDuringAReplayAreCaughtUpFromTheJournal()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create(streamBuffer: 64).StartAsync();
        await using var channel = await node.ChannelAsync();
        var first = await EmitAsync(node, 1);

        // A resume replays 5,000 events, written as the client reads (32 at a time with a buffer of 64), while 1,000 more arrive.
        var replayed = await EmitAsync(node, 5_000);
        using var call = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest
        {
            Topics = { EventTopic.Node },
            Cursor = new EventCursor(node.Runtime.Journal.Generation, first).ToString(),
        }, cancellationToken: ct);
        Assert.True(await call.ResponseStream.MoveNext(ct));
        var live = EmitAsync(node, 1_000);
        var expected = first + 1;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        var current = call.ResponseStream.Current;
        var last = await live;
        while (true)
        {
            if (current.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.Event)
            {
                Assert.Equal(expected, current.Event.Seq);
                expected++;
                if (current.Event.Seq == last)
                {
                    break;
                }
            }
            else
            {
                Assert.Equal(NodeEventServiceSubscribeFrame.FrameOneofCase.Heartbeat, current.FrameCase);
            }

            Assert.True(await call.ResponseStream.MoveNext(timeout.Token));
            current = call.ResponseStream.Current;
        }

        Assert.True(replayed < last);
        // The pending buffer filled (64) and the rest of the 1,000 overflowed it, yet every event arrived once and in order.
        Assert.Equal(64, node.Runtime.Hub.PeakPending);
    }

    /// <summary>Commits <paramref name="count"/> NODE events through the command processor (1,000 per command); returns the last sequence.</summary>
    private static async Task<ulong> EmitAsync(InProcessNode node, int count)
    {
        ulong last = 0;
        for (var done = 0; done < count; done += 1000)
        {
            var batch = Math.Min(1000, count - done);
            last = await node.Runtime.Processor.ExecuteAsync(context =>
            {
                NodeEvent? item = null;
                for (var i = 0; i < batch; i++)
                {
                    item = context.Emit(EventTopic.Node, new NodeEvent { Node = node.Runtime.Status() });
                }

                return item!.Seq;
            });
        }

        return last;
    }

    private static double OverflowCount(InProcessNode node) => node.Runtime.ServerMetrics!()
        .Where(metric => metric.Name == "rpc.streams_ended" && metric.Labels["reason"] == "Overflow").Sum(metric => metric.Value);

    private static async Task Rename(NodeChannel channel, string name)
    {
        var response = await channel.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Meta = InProcessNode.Command(), Name = name },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
        Assert.Null(response.Error);
    }

    private static async Task<List<NodeEventServiceSubscribeFrame>> ReadAsync(IAsyncStreamReader<NodeEventServiceSubscribeFrame> reader, int count)
    {
        var frames = new List<NodeEventServiceSubscribeFrame>();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        while (frames.Count < count && await reader.MoveNext(timeout.Token))
        {
            if (reader.Current.FrameCase != NodeEventServiceSubscribeFrame.FrameOneofCase.Heartbeat)
            {
                frames.Add(reader.Current);
            }
        }

        return frames;
    }

    private static async Task<List<NodeEventServiceSubscribeFrame>> ReadUntilAsync(IAsyncStreamReader<NodeEventServiceSubscribeFrame> reader,
        Func<NodeEventServiceSubscribeFrame, bool> last)
    {
        var frames = new List<NodeEventServiceSubscribeFrame>();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        while (await reader.MoveNext(timeout.Token))
        {
            frames.Add(reader.Current);
            if (last(reader.Current))
            {
                break;
            }
        }

        return frames;
    }

    private static async Task WaitAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        var limit = timeout ?? TimeSpan.FromSeconds(30);
        var started = TimeProvider.System.GetTimestamp();
        while (!condition())
        {
            Assert.True(TimeProvider.System.GetElapsedTime(started) < limit, "The condition was not reached in time.");
            await Task.Delay(20, Ct);
        }
    }
}
