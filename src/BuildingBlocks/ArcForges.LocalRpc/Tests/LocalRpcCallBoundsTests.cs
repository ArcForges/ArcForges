// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// The 16-active/64-queued data bound, the two reserved control slots, deadlines and typed refusals, proved against
/// real Kestrel HTTP/2 and Grpc.Net.Client over in-memory duplex streams. These are offline admission fixtures, not
/// OS-stream evidence.
/// </summary>
// One collection: the hosting-URL test changes process-wide environment variables, so no other test may run beside it.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcCallBoundsTests
{
    private const int Active = LocalRpcLimits.DefaultMaxActiveCalls;
    private const int Queued = LocalRpcLimits.DefaultMaxQueuedCalls;
    private static readonly TimeSpan Patience = BoundsHarness.Patience;

    [Fact]
    public async Task TheDataLaneHoldsSixteenActiveAndSixtyFourQueuedAndRefusesTheRestBeforeDispatch()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);

        var calls = await SaturateAsync(harness, client, ct);
        var refused = new List<RpcException>();
        for (var id = Active + Queued; id < Active + Queued + 10; id++)
        {
            refused.Add(await ProbeClient.FailureAsync(client.Work(id, deadline: DateTime.UtcNow + Patience)));
        }

        Assert.All(refused, failure =>
        {
            Assert.Equal(StatusCode.ResourceExhausted, failure.StatusCode);
            Assert.True(LocalRpcRefusal.TryRead(failure, out var refusal));
            Assert.Equal(LocalRpcRefusalReason.DataQueueFull, refusal!.Reason);
        });
        var snapshot = harness.Server.GetBoundsSnapshot();
        Assert.Equal(Active, snapshot.DataActive);
        Assert.Equal(Queued, snapshot.DataQueued);
        Assert.Equal(10, snapshot.Refused[LocalRpcRefusalReason.DataQueueFull]);
        Assert.Equal(Active, harness.Probe.Started.Count);
        Assert.Equal(Active, harness.Probe.Running);
        Assert.Equal(Active, harness.Probe.PeakRunning);

        await DrainAsync(harness, calls, ct);
    }

    [Fact]
    public async Task QueuedCallsStartInArrivalOrderAsSlotsFree()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var calls = await SaturateAsync(harness, client, ct);

        for (var released = 0; released < Active + Queued; released++)
        {
            Assert.True(harness.Probe.Release(released));
            if (released + Active < Active + Queued)
            {
                var nextToStart = released + Active;
                await BoundsHarness.WaitUntilAsync(() => harness.Probe.Started.Count == nextToStart + 1, "the next queued call", ct);
                Assert.Equal(nextToStart, harness.Probe.Started[nextToStart]);
                Assert.Equal(Active, harness.Probe.Running);
            }
        }

        await Task.WhenAll(calls.Select(call => call.ResponseAsync)).WaitAsync(Patience, ct);
        // The first sixteen start in whatever order the server schedules them; every later call starts in arrival order.
        Assert.Equal(Enumerable.Range(0, Active).Order(), harness.Probe.Started.Take(Active).Order());
        Assert.Equal(Enumerable.Range(Active, Queued), harness.Probe.Started.Skip(Active));
        Assert.Equal(Active + Queued, harness.Server.GetBoundsSnapshot().DataAdmitted);
    }

    [Fact]
    public async Task QueuedCallsBufferAtMostAStreamWindowAndNeverStarveAControlCall()
    {
        var ct = TestContext.Current.CancellationToken;
        const int padding = 256 * 1024;
        var read = 0L;
        await using var harness = await BoundsHarness.StartAsync(
            wrapServerStream: stream => new CountingStream(stream, bytes => Interlocked.Add(ref read, bytes)),
            cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var calls = new List<AsyncUnaryCall<byte[]>>();

        for (var id = 0; id < Active + Queued; id++)
        {
            calls.Add(client.Work(id, padding, DateTime.UtcNow + Patience));
            if (id < Active)
            {
                await BoundsHarness.WaitUntilAsync(() => harness.Probe.Running == id + 1, "an active call", ct);
            }
            else
            {
                var queuedNow = id - Active + 1;
                await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataQueued == queuedNow, "a queued call", ct);
            }
        }

        // Let the client push everything flow control allows, then measure what the server actually took off the wire.
        await Task.Delay(500, ct);
        var offeredToQueue = (long)Queued * padding;
        var consumedByActiveCalls = (long)Active * (padding + 64);
        var queuedBudget = (long)Queued * LocalRpcLimits.StreamWindowBytes;

        // Each waiting call holds at most its stream window of body, far less than it offered.
        Assert.Equal(Active + Queued, harness.Server.GetBoundsSnapshot().DataActive + harness.Server.GetBoundsSnapshot().DataQueued);
        Assert.InRange(Interlocked.Read(ref read), consumedByActiveCalls, consumedByActiveCalls + queuedBudget + 512 * 1024);
        Assert.True(queuedBudget < offeredToQueue / 3);

        // The queued bodies hold flow-control credit but cannot exhaust the connection window: a control call still gets through.
        var health = await client.Health().ResponseAsync.WaitAsync(TimeSpan.FromSeconds(5), ct);
        Assert.Equal(Active, health[0]);
        await DrainAsync(harness, calls, ct);
    }

    [Theory]
    [InlineData(256 * 1024)]
    [InlineData(2 * 1024 * 1024)]
    public async Task ABurstOfLargeConcurrentCallsAdmitsSixteenAndNeverBlocksAControlCall(int padding)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);

        // All 80 calls are submitted back to back, so every admitted body is still arriving while the queued ones start.
        var calls = Enumerable.Range(0, Active + Queued)
            .Select(id => client.Work(id, padding, DateTime.UtcNow + Patience)).ToList();
        await BoundsHarness.WaitUntilAsync(
            () => harness.Probe.Running == Active && harness.Server.GetBoundsSnapshot().DataQueued == Queued,
            "sixteen running and sixty-four queued calls", ct);
        var health = await client.Health().ResponseAsync.WaitAsync(TimeSpan.FromSeconds(5), ct);

        Assert.Equal(Active, health[0]);
        Assert.Equal(Active, harness.Server.GetBoundsSnapshot().DataActive);
        await DrainAsync(harness, calls, ct);
    }

    [Fact]
    public async Task AllFourControlOperationsStayServiceableWhileTheDataLaneIsSaturated()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var calls = await SaturateAsync(harness, client, ct);
        var deadline = DateTime.UtcNow + Patience;

        // Bootstrap (challenge and confirm), lease renewal and health, each while 16 + 64 data calls are held.
        AssertSaturated(harness);
        var challenge = await client.Bootstrap.ChallengeAsync(Requests.Challenge(32), deadline: deadline, cancellationToken: ct);
        AssertSaturated(harness);
        var confirm = await client.Bootstrap.ConfirmAsync(Requests.Confirm(), deadline: deadline, cancellationToken: ct);
        AssertSaturated(harness);
        var renew = await client.Bootstrap.RenewAsync(Requests.Renew(), deadline: deadline, cancellationToken: ct);
        AssertSaturated(harness);
        var health = await client.Health().ResponseAsync.WaitAsync(Patience, ct);
        AssertSaturated(harness);

        Assert.Equal(32, challenge.Value.ServerChallenge.Length);
        Assert.NotNull(confirm.Value);
        Assert.NotNull(renew.Value);
        Assert.Equal(Active, health[0]);
        Assert.Equal(1, harness.Bootstrap.Dispatched);
        Assert.Equal(1, harness.Bootstrap.Confirmed);
        Assert.Equal(1, harness.Bootstrap.Renewed);

        // Cancellation: a control call that cancels a held data call frees its slot, and the oldest queued call takes it.
        Assert.Equal(new byte[] { 1 }, await client.Cancel(0).ResponseAsync.WaitAsync(Patience, ct));
        var cancelled = await ProbeClient.FailureAsync(calls[0]);
        Assert.Equal(StatusCode.Cancelled, cancelled.StatusCode);
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Started.Count == Active + 1, "the oldest queued call", ct);
        Assert.Equal(Active, harness.Probe.Started[Active]);

        var snapshot = harness.Server.GetBoundsSnapshot();
        Assert.Equal(Active, snapshot.DataActive);
        Assert.Equal(Queued - 1, snapshot.DataQueued);
        Assert.Equal(2, snapshot.ControlAdmitted[LocalRpcControlOperation.Bootstrap]);
        Assert.Equal(1, snapshot.ControlAdmitted[LocalRpcControlOperation.LeaseRenewal]);
        Assert.Equal(1, snapshot.ControlAdmitted[LocalRpcControlOperation.Cancellation]);
        Assert.Equal(1, snapshot.ControlAdmitted[LocalRpcControlOperation.Health]);
        Assert.Equal(0, snapshot.Refused.Values.Sum());
        await DrainAsync(harness, calls.Skip(1).ToList(), ct);
    }

    [Fact]
    public async Task TheTwoControlSlotsAreOutsideTheDataBudgetAndANeverQueuedThirdControlCallIsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var calls = await SaturateAsync(harness, client, ct);

        var firstHeld = client.Health(hold: true);
        var secondHeld = client.Health(hold: true);
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.HealthHeld == 2, "both control slots", ct);

        // Sixteen data calls and two control calls run at the same time: the control slots are not part of the data budget.
        Assert.Equal(Active + 2, harness.Probe.Running);
        Assert.Equal(Active + 2, harness.Probe.PeakRunning);
        var snapshot = harness.Server.GetBoundsSnapshot();
        Assert.Equal(2, snapshot.ControlActive);
        Assert.Equal(Active, snapshot.DataActive);
        Assert.Equal(Queued, snapshot.DataQueued);

        // A third control call finds both slots taken and is refused at once; it does not wait and does not use a data slot.
        var thirdTimer = System.Diagnostics.Stopwatch.StartNew();
        var third = await ProbeClient.FailureAsync(client.Health());
        thirdTimer.Stop();
        Assert.Equal(StatusCode.ResourceExhausted, third.StatusCode);
        Assert.True(LocalRpcRefusal.TryRead(third, out var refusal));
        Assert.Equal(LocalRpcRefusalReason.ControlBusy, refusal!.Reason);
        Assert.True(thirdTimer.Elapsed < TimeSpan.FromSeconds(5));
        var afterRefusal = harness.Server.GetBoundsSnapshot();
        Assert.Equal(Active, afterRefusal.DataActive);
        Assert.Equal(Queued, afterRefusal.DataQueued);
        Assert.Equal(1, afterRefusal.Refused[LocalRpcRefusalReason.ControlBusy]);

        harness.Probe.ReleaseHealth();
        _ = await firstHeld.ResponseAsync.WaitAsync(Patience, ct);
        _ = await secondHeld.ResponseAsync.WaitAsync(Patience, ct);
        var renew = await client.Bootstrap.RenewAsync(Requests.Renew(), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);
        Assert.NotNull(renew.Value);
        await DrainAsync(harness, calls, ct);
    }

    [Fact]
    public async Task ADataCallIsRefusedWhenOnlyTheControlSlotsAreFree()
    {
        var ct = TestContext.Current.CancellationToken;
        var limits = new LocalRpcLimits { MaxActiveCalls = 2, MaxQueuedCalls = 1 };
        await using var harness = await BoundsHarness.StartAsync(limits, cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var held = new List<AsyncUnaryCall<byte[]>> { client.Work(0, deadline: DateTime.UtcNow + Patience), client.Work(1, deadline: DateTime.UtcNow + Patience) };
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Running == 2, "two active calls", ct);
        held.Add(client.Work(2, deadline: DateTime.UtcNow + Patience));
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataQueued == 1, "one queued call", ct);

        var refused = await ProbeClient.FailureAsync(client.Work(3, deadline: DateTime.UtcNow + Patience));

        Assert.True(LocalRpcRefusal.TryRead(refused, out var refusal));
        Assert.Equal(LocalRpcRefusalReason.DataQueueFull, refusal!.Reason);
        Assert.Equal(0, harness.Server.GetBoundsSnapshot().ControlActive);
        await DrainAsync(harness, held, ct);
    }

    [Fact]
    public async Task OnePeerSaturatingItsLanesDoesNotSlowAnotherPeer()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var noisy = harness.NewChannel();
        await using var quiet = harness.NewChannel();
        var noisyClient = new ProbeClient(noisy.CallInvoker);
        var quietClient = new ProbeClient(quiet.CallInvoker);
        var calls = await SaturateAsync(harness, noisyClient, ct);

        var other = quietClient.Work(1000, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Started.Contains(1000), "the second peer's call to start", ct);
        var snapshot = harness.Server.GetBoundsSnapshot();

        Assert.Equal(2, snapshot.Peers);
        Assert.Equal(Active + 1, snapshot.DataActive);
        Assert.Equal(Queued, snapshot.DataQueued);
        Assert.True(harness.Probe.Release(1000));
        _ = await other.ResponseAsync.WaitAsync(Patience, ct);
        await DrainAsync(harness, calls, ct);
    }

    [Fact]
    public async Task ACallWithoutADeadlineGetsTheDefaultAndALongerOneIsShortenedToTheMaximum()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);

        var none = client.Work(1);
        var longer = client.Work(2, deadline: DateTime.UtcNow.AddHours(1));
        var shorter = client.Work(3, deadline: DateTime.UtcNow.AddSeconds(4));
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Started.Count == 3, "three calls", ct);
        var remaining = harness.Probe.RemainingAtStart;

        Assert.InRange(remaining[1], TimeSpan.FromSeconds(8), TimeSpan.FromSeconds(10.5));
        Assert.InRange(remaining[2], TimeSpan.FromSeconds(28), TimeSpan.FromSeconds(30.5));
        Assert.InRange(remaining[3], TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4.5));
        foreach (var id in new[] { 1, 2, 3 })
        {
            Assert.True(harness.Probe.Release(id));
        }

        _ = await Task.WhenAll(none.ResponseAsync, longer.ResponseAsync, shorter.ResponseAsync).WaitAsync(Patience, ct);
    }

    [Fact]
    public async Task TheDefaultAndMaximumDeadlinesEndARunningCallAndFreeItsSlot()
    {
        var ct = TestContext.Current.CancellationToken;
        var limits = new LocalRpcLimits
        {
            DefaultCallDeadline = TimeSpan.FromMilliseconds(300),
            MaxCallDeadline = TimeSpan.FromMilliseconds(600),
        };
        await using var harness = await BoundsHarness.StartAsync(limits, cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);

        var byDefault = await ProbeClient.FailureAsync(client.Work(1));
        var byMaximum = await ProbeClient.FailureAsync(client.Work(2, deadline: DateTime.UtcNow.AddHours(1)));

        Assert.Equal(StatusCode.DeadlineExceeded, byDefault.StatusCode);
        Assert.Equal(StatusCode.DeadlineExceeded, byMaximum.StatusCode);
        Assert.False(LocalRpcRefusal.TryRead(byDefault, out _));
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Interrupted.Count == 2, "both handlers to observe the deadline", ct);
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataActive == 0, "the slots to free", ct);
    }

    [Fact]
    public async Task AControlCallIsHeldToTheControlDeadlineNotTheDataDeadline()
    {
        var ct = TestContext.Current.CancellationToken;
        var limits = new LocalRpcLimits { ControlCallDeadline = TimeSpan.FromMilliseconds(300) };
        await using var harness = await BoundsHarness.StartAsync(limits, cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);

        var expired = await ProbeClient.FailureAsync(client.Health(hold: true, deadline: DateTime.UtcNow + Patience));

        Assert.Equal(StatusCode.DeadlineExceeded, expired.StatusCode);
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().ControlActive == 0, "the control slot to free", ct);
        Assert.Equal(1, harness.Server.GetBoundsSnapshot().ControlAdmitted[LocalRpcControlOperation.Health]);
    }

    [Fact]
    public async Task WaitingInTheQueueCountsAgainstTheDeadlineAndAnExpiredWaiterIsRefusedWithoutDispatch()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        var limits = new LocalRpcLimits { MaxActiveCalls = 1, MaxQueuedCalls = 2 };
        await using var harness = await BoundsHarness.StartAsync(limits, time, cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var holder = client.Work(0, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Running == 1, "the holder", ct);
        var waiter = client.Work(1, deadline: DateTime.UtcNow + TimeSpan.FromSeconds(20));
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataQueued == 1, "the waiter", ct);

        time.Advance(TimeSpan.FromSeconds(19));
        await Task.Delay(100, ct);
        Assert.Equal(1, harness.Server.GetBoundsSnapshot().DataQueued);
        Assert.False(waiter.ResponseAsync.IsCompleted);
        time.Advance(TimeSpan.FromSeconds(1));
        var expired = await ProbeClient.FailureAsync(waiter);

        Assert.Equal(StatusCode.DeadlineExceeded, expired.StatusCode);
        Assert.True(LocalRpcRefusal.TryRead(expired, out var refusal));
        Assert.Equal(LocalRpcRefusalReason.DeadlineBeforeDispatch, refusal!.Reason);
        Assert.Equal([0], harness.Probe.Started);
        var snapshot = harness.Server.GetBoundsSnapshot();
        Assert.Equal(0, snapshot.DataQueued);
        Assert.Equal(1, snapshot.Refused[LocalRpcRefusalReason.DeadlineBeforeDispatch]);
        Assert.True(harness.Probe.Release(0));
        _ = await holder.ResponseAsync.WaitAsync(Patience, ct);
    }

    [Fact]
    public async Task ACallThatWaitedStartsWithTheTimeThatRemains()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        var limits = new LocalRpcLimits { MaxActiveCalls = 1, MaxQueuedCalls = 2 };
        await using var harness = await BoundsHarness.StartAsync(limits, time, cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var holder = client.Work(0, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Running == 1, "the holder", ct);
        var waiter = client.Work(1, deadline: DateTime.UtcNow + TimeSpan.FromSeconds(25));
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataQueued == 1, "the waiter", ct);

        time.Advance(TimeSpan.FromSeconds(15));
        Assert.True(harness.Probe.Release(0));
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Started.Count == 2, "the waiter to start", ct);

        Assert.InRange(harness.Probe.RemainingAtStart[1], TimeSpan.FromSeconds(8), TimeSpan.FromSeconds(10.5));
        Assert.True(harness.Probe.Release(1));
        _ = await Task.WhenAll(holder.ResponseAsync, waiter.ResponseAsync).WaitAsync(Patience, ct);
    }

    [Fact]
    public async Task ACancelledQueuedCallLeavesTheQueue()
    {
        var ct = TestContext.Current.CancellationToken;
        var limits = new LocalRpcLimits { MaxActiveCalls = 1, MaxQueuedCalls = 2 };
        await using var harness = await BoundsHarness.StartAsync(limits, cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var holder = client.Work(0, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Running == 1, "the holder", ct);
        using var cancel = new CancellationTokenSource();
        var waiter = client.WorkUntilCancelled(1, DateTime.UtcNow + Patience, cancel.Token);
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataQueued == 1, "the waiter", ct);

        await cancel.CancelAsync();
        var cancelled = await ProbeClient.FailureAsync(waiter);

        Assert.Equal(StatusCode.Cancelled, cancelled.StatusCode);
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataQueued == 0, "the queue to empty", ct);
        Assert.Equal([0], harness.Probe.Started);
        Assert.True(harness.Probe.Release(0));
        _ = await holder.ResponseAsync.WaitAsync(Patience, ct);
        Assert.Equal(0, harness.Server.GetBoundsSnapshot().DataActive);
    }

    [Fact]
    public async Task AUnaryCallOutsideAnyHandlerIsNeverMarkedAsACallbackAndQueues()
    {
        var ct = TestContext.Current.CancellationToken;
        var limits = new LocalRpcLimits { MaxActiveCalls = 1, MaxQueuedCalls = 3 };
        await using var harness = await BoundsHarness.StartAsync(limits, cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var holder = client.Work(0, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Running == 1, "the holder", ct);

        var queued = client.Work(1, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataQueued == 1, "a queued call", ct);

        Assert.Null(LocalRpcCallbackGuard.CurrentDepth);
        Assert.True(harness.Probe.Release(0));
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Started.Count == 2, "the queued call", ct);
        Assert.True(harness.Probe.Release(1));
        _ = await Task.WhenAll(holder.ResponseAsync, queued.ResponseAsync).WaitAsync(Patience, ct);
    }

    private static async Task<List<AsyncUnaryCall<byte[]>>> SaturateAsync(BoundsHarness harness, ProbeClient client, CancellationToken ct)
    {
        var calls = new List<AsyncUnaryCall<byte[]>>();
        for (var id = 0; id < Active; id++)
        {
            calls.Add(client.Work(id, deadline: DateTime.UtcNow + Patience));
        }

        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Running == Active, "sixteen active calls", ct);
        for (var id = Active; id < Active + Queued; id++)
        {
            calls.Add(client.Work(id, deadline: DateTime.UtcNow + Patience));
            var expected = id - Active + 1;
            await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataQueued == expected, "queued call " + expected, ct);
        }

        return calls;
    }

    private static void AssertSaturated(BoundsHarness harness)
    {
        var snapshot = harness.Server.GetBoundsSnapshot();
        Assert.Equal(Active, snapshot.DataActive);
        Assert.Equal(Queued, snapshot.DataQueued);
    }

    private static async Task DrainAsync(BoundsHarness harness, List<AsyncUnaryCall<byte[]>> calls, CancellationToken ct)
    {
        // Release every held call in arrival order until all have finished; queued calls start as slots free.
        var pending = calls.Select(call => call.ResponseAsync).ToList();
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bounded.CancelAfter(Patience);
        while (pending.Any(task => !task.IsCompleted))
        {
            for (var id = 0; id < Active + Queued + 16; id++)
            {
                _ = harness.Probe.Release(id);
            }

            await Task.Delay(10, bounded.Token);
        }

        foreach (var task in pending)
        {
            try
            {
                _ = await task;
            }
            catch (RpcException)
            {
                // A call the test cancelled or refused.
            }
        }

        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().DataActive == 0, "the data lane to drain", ct);
    }
}

internal sealed class CountingStream(Stream inner, Action<int> counted) : Stream
{
    public override bool CanRead => true;

    public override bool CanWrite => true;

    public override bool CanSeek => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var read = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        counted(read);
        return read;
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => inner.WriteAsync(buffer, cancellationToken);

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    public override void Flush() => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
