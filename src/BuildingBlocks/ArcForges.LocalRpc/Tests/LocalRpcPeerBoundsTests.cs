// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>The per-peer registry and watchdog in isolation, driven by a manual clock.</summary>
// One collection: the hosting-URL test changes process-wide environment variables, so no other test may run beside it.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcPeerBoundsTests
{
    [Fact]
    public void ATimerCallbackQueuedByAnEarlierArmingNeverClosesAConnectionThatRestartedItsClock()
    {
        var time = new ManualTimeProvider();
        var registry = new LocalRpcBoundsRegistry(new LocalRpcLimits(), time);
        var peer = registry.Add("p");
        var aborts = 0;
        peer.Start(() => aborts++);

        peer.CallStarted();
        peer.CallFinished();
        // The handshake timer's callback was already queued when the call began and ended: it runs now, at the start of the idle clock.
        peer.OnTimer(null);

        Assert.Equal(0, aborts);
        time.Advance(TimeSpan.FromSeconds(59));
        Assert.Equal(0, aborts);
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(1, aborts);
        registry.Remove(peer);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ATimerThatFiresEarlyWaitsOutTheRemainderInsteadOfDroppingTheLimit(bool handshake)
    {
        var time = new ManualTimeProvider();
        var registry = new LocalRpcBoundsRegistry(new LocalRpcLimits(), time);
        var peer = registry.Add("p");
        var aborts = 0;
        peer.Start(() => aborts++);
        if (!handshake)
        {
            peer.CallStarted();
            peer.CallFinished();
        }

        var limit = handshake ? TimeSpan.FromSeconds(10) : TimeSpan.FromSeconds(60);
        time.Advance(limit - TimeSpan.FromMilliseconds(5));
        time.FireNextEarly(TimeSpan.FromMilliseconds(2));

        // The one-shot timer is spent and the limit is not yet due: it must be armed again for what remains.
        Assert.Equal(0, aborts);
        Assert.Equal(1, time.ArmedTimers);
        time.Advance(TimeSpan.FromMilliseconds(3));
        Assert.Equal(1, aborts);
        registry.Remove(peer);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EveryPeerOfALargeBatchIsClosedOnTheRealClock(bool handshake)
    {
        var ct = TestContext.Current.CancellationToken;
        var limits = new LocalRpcLimits { HandshakeTimeout = TimeSpan.FromMilliseconds(100), IdleTimeout = TimeSpan.FromMilliseconds(100) };
        var registry = new LocalRpcBoundsRegistry(limits, TimeProvider.System);
        var aborted = 0;
        const int peers = 3000;

        // Thousands of timers armed in the same instant come due together, so some fire before the stopwatch agrees.
        for (var index = 0; index < peers; index++)
        {
            var peer = registry.Add("p" + index);
            peer.Start(() => Interlocked.Increment(ref aborted));
            if (!handshake)
            {
                peer.CallStarted();
                peer.CallFinished();
            }
        }

        await BoundsHarness.WaitUntilAsync(() => Volatile.Read(ref aborted) == peers, "every peer to be closed", ct);
        Assert.Equal(peers, registry.Snapshot().Peers);
    }

    [Fact]
    public void ATimerCallbackThatRunsWhileACallIsInFlightNeverClosesTheConnection()
    {
        var time = new ManualTimeProvider();
        var registry = new LocalRpcBoundsRegistry(new LocalRpcLimits(), time);
        var peer = registry.Add("p");
        var aborts = 0;
        peer.Start(() => aborts++);
        peer.CallStarted();
        time.Advance(TimeSpan.FromMinutes(5));

        peer.OnTimer(null);

        Assert.Equal(0, aborts);
        peer.CallFinished();
        time.Advance(TimeSpan.FromSeconds(60));
        Assert.Equal(1, aborts);
        registry.Remove(peer);
    }

    [Fact]
    public void ARemovedPeerNeverArmsOrClosesAnything()
    {
        var time = new ManualTimeProvider();
        var registry = new LocalRpcBoundsRegistry(new LocalRpcLimits(), time);
        var peer = registry.Add("p");
        var aborts = 0;
        peer.Start(() => aborts++);
        Assert.Equal(1, time.ArmedTimers);

        registry.Remove(peer);
        peer.CallStarted();
        peer.CallFinished();
        peer.Start(() => aborts++);
        time.Advance(TimeSpan.FromHours(1));

        Assert.Equal(0, aborts);
        Assert.Equal(0, time.ArmedTimers);
        Assert.False(registry.TryGet("p", out _));
    }

    [Fact]
    public void TheRegistryFindsLivePeersAndRemovesOnlyTheOneItWasGiven()
    {
        var registry = new LocalRpcBoundsRegistry(new LocalRpcLimits(), TimeProvider.System);
        var first = registry.Add("a");
        var second = registry.Add("b");

        Assert.True(registry.TryGet("a", out var found));
        Assert.Same(first, found);
        registry.Remove(first);
        Assert.False(registry.TryGet("a", out _));
        Assert.True(registry.TryGet("b", out found));
        Assert.Same(second, found);
        Assert.Equal(1, registry.Snapshot().Peers);
        registry.Remove(second);
        Assert.Equal(0, registry.Snapshot().Peers);
    }

    [Fact]
    public void AStalePeerWithTheSameIdIsNotRemovedByAnOlderInstance()
    {
        var registry = new LocalRpcBoundsRegistry(new LocalRpcLimits(), TimeProvider.System);
        var older = registry.Add("same");
        var newer = registry.Add("same");

        registry.Remove(older);

        Assert.True(registry.TryGet("same", out var found));
        Assert.Same(newer, found);
        registry.Remove(newer);
    }

    [Fact]
    public async Task EachPeerGetsItsOwnLanesSizedFromTheLimits()
    {
        var registry = new LocalRpcBoundsRegistry(new LocalRpcLimits { MaxActiveCalls = 3, MaxQueuedCalls = 5 }, TimeProvider.System);
        var first = registry.Add("a");
        var second = registry.Add("b");

        for (var taken = 0; taken < 3; taken++)
        {
            Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(first.Data, false));
        }

        Assert.Equal(LocalRpcGateOutcome.Refused, await Immediate(first.Data, false));
        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(second.Data, false));
        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(first.Control, false));
        Assert.Equal(LocalRpcGateOutcome.Admitted, await Immediate(first.Control, true));
        Assert.Equal(LocalRpcGateOutcome.Refused, await Immediate(first.Control, true));
        registry.Remove(first);
        registry.Remove(second);
    }

    /// <summary>Enters a gate that must answer at once; a gate that wrongly queues the caller fails the test instead of hanging it.</summary>
    private static async Task<LocalRpcGateOutcome> Immediate(LocalRpcCallGate gate, bool mayQueue) =>
        await gate.EnterAsync(mayQueue, TestContext.Current.CancellationToken).AsTask()
            .WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
}
