// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// The handshake and idle limits that stop a silent or stalled peer from holding a connection slot, driven by a
/// manual clock so no test sleeps for a limit.
/// </summary>
// One collection: the hosting-URL test changes process-wide environment variables, so no other test may run beside it.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcPeerLimitTests
{
    private static readonly TimeSpan Patience = BoundsHarness.Patience;

    [Fact]
    public async Task APeerThatConnectsAndSaysNothingIsClosedAtTheHandshakeLimitAndItsSlotIsReused()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        await using var harness = await BoundsHarness.StartAsync(new LocalRpcLimits { MaxConnections = 1 }, time, cancellationToken: ct);
        await using var silent = harness.NewClientStream();
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 1, "the silent peer to be accepted", ct);
        var closed = silent.ReadAsync(new byte[1], ct).AsTask();
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var waiting = client.Health().ResponseAsync;
        await BoundsHarness.WaitUntilAsync(() => harness.Connects == 2, "the second peer to connect", ct);

        time.Advance(TimeSpan.FromSeconds(9));
        await Task.Delay(200, ct);
        Assert.False(closed.IsCompleted);
        Assert.False(waiting.IsCompleted);
        time.Advance(TimeSpan.FromSeconds(1));

        Assert.Equal(0, await closed.WaitAsync(Patience, ct));
        _ = await waiting.WaitAsync(Patience, ct);
        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Peers);
    }

    [Fact]
    [SuppressMessage("Reliability", "CA2025", Justification = "The drain task is awaited in the test body before the stream is disposed.")]
    public async Task APeerThatSendsTheHttp2PrefaceAndStallsIsClosedAtTheHandshakeLimit()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        await using var harness = await BoundsHarness.StartAsync(new LocalRpcLimits { HandshakeTimeout = TimeSpan.FromSeconds(3) }, time, cancellationToken: ct);
        await using var raw = harness.NewClientStream();
        await raw.WriteAsync(RawFrames.Preface, ct);
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 1, "the stalled peer to be accepted", ct);
        var drained = RawFrames.ReadUntilClosedAsync(raw, Patience, ct);

        time.Advance(TimeSpan.FromSeconds(2));
        await Task.Delay(200, ct);
        Assert.False(drained.IsCompleted);
        time.Advance(TimeSpan.FromSeconds(1));
        _ = await drained;

        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 0, "the stalled peer to be dropped", ct);
    }

    [Fact]
    public async Task AConnectionWithNoCallInFlightIsClosedAfterTheIdleLimitAndEachCallRestartsTheClock()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct, time: time);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        _ = await client.Health().ResponseAsync.WaitAsync(Patience, ct);

        time.Advance(TimeSpan.FromSeconds(59));
        await Task.Delay(200, ct);
        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Peers);
        _ = await client.Health().ResponseAsync.WaitAsync(Patience, ct);
        Assert.Equal(1, harness.Connects);

        // The second call restarted the 60 s clock: 118 s after the first call but 59 s after the second, still open.
        time.Advance(TimeSpan.FromSeconds(59));
        await Task.Delay(200, ct);
        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Peers);
        time.Advance(TimeSpan.FromSeconds(2));
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 0, "the idle connection to close", ct);

        await RetryAsync(async () => await client.Health().ResponseAsync.WaitAsync(Patience, ct), ct);
        Assert.Equal(2, harness.Connects);
    }

    [Fact]
    public async Task EverySilentPeerIsClosedOnTheRealClock()
    {
        var ct = TestContext.Current.CancellationToken;
        var limits = new LocalRpcLimits { MaxConnections = 64, HandshakeTimeout = TimeSpan.FromMilliseconds(150) };
        await using var harness = await BoundsHarness.StartAsync(limits, cancellationToken: ct);
        var streams = new List<Stream>();
        try
        {
            for (var round = 0; round < 3; round++)
            {
                for (var peer = 0; peer < 40; peer++)
                {
                    streams.Add(await SupplyAsync(harness, ct));
                }

                // A real timer may fire before the stopwatch agrees that the limit has passed; none may keep its slot.
                await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 0 && harness.Connects == (round + 1) * 40, "every silent peer to be closed", ct);
            }
        }
        finally
        {
            foreach (var stream in streams)
            {
                await stream.DisposeAsync();
            }
        }
    }

    [Fact]
    public async Task EveryIdleConnectionIsClosedOnTheRealClock()
    {
        var ct = TestContext.Current.CancellationToken;
        var limits = new LocalRpcLimits { MaxConnections = 64, IdleTimeout = TimeSpan.FromMilliseconds(150) };
        await using var harness = await BoundsHarness.StartAsync(limits, cancellationToken: ct);
        var channels = new List<LocalRpcClientChannel>();
        try
        {
            for (var peer = 0; peer < 40; peer++)
            {
                var channel = harness.NewChannel();
                channels.Add(channel);
                _ = await new ProbeClient(channel.CallInvoker).Health().ResponseAsync.WaitAsync(Patience, ct);
            }

            await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 0, "every idle connection to be closed", ct);
        }
        finally
        {
            foreach (var channel in channels)
            {
                await channel.DisposeAsync();
            }
        }
    }

    [Fact]
    public async Task ACallInFlightKeepsTheConnectionOpenHoweverLongItRuns()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct, time: time);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);
        var held = client.Work(1, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Running == 1, "the call", ct);

        time.Advance(TimeSpan.FromMinutes(10));
        await Task.Delay(200, ct);

        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Peers);
        Assert.Equal(1, harness.Probe.Running);
        Assert.True(harness.Probe.Release(1));
        _ = await held.ResponseAsync.WaitAsync(Patience, ct);
        // Once it ends the idle clock starts from that moment.
        time.Advance(TimeSpan.FromSeconds(59));
        await Task.Delay(200, ct);
        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Peers);
        time.Advance(TimeSpan.FromSeconds(1));
        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 0, "the idle connection to close", ct);
    }

    [Fact]
    public async Task ACallStartingAsTheHandshakeLimitPassesIsNotCutOff()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        await using var harness = await BoundsHarness.StartAsync(new LocalRpcLimits { HandshakeTimeout = TimeSpan.FromSeconds(5) }, time, cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new ProbeClient(channel.CallInvoker);

        var held = client.Work(1, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => harness.Probe.Running == 1, "the first call", ct);
        time.Advance(TimeSpan.FromSeconds(30));
        await Task.Delay(200, ct);

        Assert.Equal(1, harness.Server.GetBoundsSnapshot().Peers);
        Assert.True(harness.Probe.Release(1));
        _ = await held.ResponseAsync.WaitAsync(Patience, ct);
    }

    [Fact]
    public async Task NoTimerOutlivesAConnection()
    {
        var ct = TestContext.Current.CancellationToken;
        var time = new ManualTimeProvider();
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct, time: time);
        await using (var channel = harness.NewChannel())
        {
            var client = new ProbeClient(channel.CallInvoker);
            _ = await client.Health().ResponseAsync.WaitAsync(Patience, ct);
            Assert.True(time.ArmedTimers >= 1);
        }

        await BoundsHarness.WaitUntilAsync(() => harness.Server.GetBoundsSnapshot().Peers == 0, "the connection to end", ct);
        await BoundsHarness.WaitUntilAsync(() => time.ArmedTimers == 0, "every timer to be released", ct);
    }

    [Fact]
    public async Task ConnectionLimitsOutsideTheProfileAreRefused()
    {
        LocalRpcLimits[] invalid =
        [
            new() { MaxActiveCalls = 0 },
            new() { MaxActiveCalls = 17 },
            new() { MaxQueuedCalls = -1 },
            new() { MaxQueuedCalls = 65 },
            new() { MaxCallDeadline = TimeSpan.Zero },
            new() { MaxCallDeadline = TimeSpan.FromSeconds(31) },
            new() { DefaultCallDeadline = TimeSpan.Zero },
            new() { DefaultCallDeadline = TimeSpan.FromSeconds(31) },
            new() { DefaultCallDeadline = TimeSpan.FromSeconds(20), MaxCallDeadline = TimeSpan.FromSeconds(10) },
            new() { ControlCallDeadline = TimeSpan.Zero },
            new() { ControlCallDeadline = TimeSpan.FromSeconds(31) },
            new() { HandshakeTimeout = TimeSpan.Zero },
            new() { HandshakeTimeout = TimeSpan.FromMinutes(2) },
            new() { IdleTimeout = TimeSpan.Zero },
            new() { IdleTimeout = TimeSpan.FromMinutes(11) },
        ];
        var builder = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new RecordingBootstrapService());

        foreach (var limits in invalid)
        {
            builder.Limits = limits;
            Assert.Throws<ArgumentOutOfRangeException>(builder.Build);
        }

        builder.Limits = new LocalRpcLimits { MaxActiveCalls = 1, MaxQueuedCalls = 0, DefaultCallDeadline = TimeSpan.FromMilliseconds(1), MaxCallDeadline = TimeSpan.FromSeconds(30) };
        await using var built = builder.Build();
    }

    /// <summary>The supplier holds only a few streams that were not yet accepted: wait for room.</summary>
    private static async Task<Stream> SupplyAsync(BoundsHarness harness, CancellationToken ct)
    {
        for (var tries = 0; ; tries++)
        {
            try
            {
                return harness.NewClientStream();
            }
            catch (InvalidOperationException) when (tries < 2000)
            {
                await Task.Delay(2, ct);
            }
        }
    }

    private static async Task RetryAsync(Func<Task> attempt, CancellationToken ct)
    {
        // The client may notice the closed connection only when it next sends: allow a few attempts.
        for (var tries = 0; ; tries++)
        {
            try
            {
                await attempt();
                return;
            }
            catch (RpcException) when (tries < 5)
            {
                await Task.Delay(50, ct);
            }
        }
    }
}
