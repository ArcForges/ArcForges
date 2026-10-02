// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Deterministic offline fixtures for the connection decision: real Kestrel HTTP/2 over in-memory streams with an
/// asynchronous, cancellable, time-bounded authorizer, and a server whose decision is a launch. Framing and authorization
/// fixtures only, never OS-stream evidence.
/// </summary>
// One collection: these tests start servers, and the hosting-URL test changes process-wide environment variables.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcLaunchTransportTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);
    private static readonly LocalRpcLaunchIdentity Standard = Launches.Identity();

    [Fact]
    public async Task AnAsynchronousDecisionSeesTheConnectionAndAdmitsIt()
    {
        var ct = TestContext.Current.CancellationToken;
        var seen = new List<LocalRpcConnectionInfo>();
        await using var harness = await SuppliedHarness.StartAsync(b => b.AuthorizeConnectionsAsync(async (connection, token) =>
        {
            await Task.Yield();
            Assert.False(token.IsCancellationRequested);
            lock (seen)
            {
                seen.Add(connection);
            }

            return true;
        }), ct);
        await using var channel = harness.NewChannel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);

        var response = await client.ChallengeAsync(Requests.Challenge(16), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);

        Assert.Equal(16, response.Value.ServerChallenge.Length);
        var info = Assert.Single(seen);
        Assert.Equal(1, info.Sequence);
        Assert.Null(info.Endpoint);
    }

    [Fact]
    public async Task ADecisionThatIgnoresItsTokenIsDeniedAtTheTimeoutAndLaterPeersAreStillServed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(b =>
        {
            b.Limits = new LocalRpcLimits { AuthorizationTimeout = TimeSpan.FromMilliseconds(300) };
            _ = b.AuthorizeConnectionsAsync(async (connection, _) =>
            {
                if (connection.Sequence == 1)
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, CancellationToken.None);
                }

                return true;
            });
        }, ct);

        await using var silent = harness.NewClientStream();
        var started = System.Diagnostics.Stopwatch.StartNew();
        var frames = await RawFrames.ReadUntilClosedAsync(silent, Patience, ct);

        Assert.Empty(frames);
        Assert.InRange(started.Elapsed, TimeSpan.FromMilliseconds(250), TimeSpan.FromSeconds(10));
        await using var channel = harness.NewChannel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
        var response = await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);
        Assert.Equal(8, response.Value.ServerChallenge.Length);
        Assert.Equal(1, harness.Service.Dispatched);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ADecisionThatBlocksItsThreadIsStillDeniedAtTheTimeout(bool useAsync)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(b =>
        {
            b.Limits = new LocalRpcLimits { AuthorizationTimeout = TimeSpan.FromMilliseconds(300) };
            _ = useAsync
                ? b.AuthorizeConnectionsAsync((connection, _) => ValueTask.FromResult(BlockFirst(connection)))
                : b.AuthorizeConnections(BlockFirst);
        }, ct);

        await using var blocked = harness.NewClientStream();
        var started = System.Diagnostics.Stopwatch.StartNew();
        var frames = await RawFrames.ReadUntilClosedAsync(blocked, Patience, ct);

        Assert.Empty(frames);
        Assert.InRange(started.Elapsed, TimeSpan.FromMilliseconds(250), TimeSpan.FromMilliseconds(2500));
    }

    private static bool BlockFirst(LocalRpcConnectionInfo connection)
    {
        if (connection.Sequence == 1)
        {
            Thread.Sleep(3000);
        }

        return true;
    }

    [Fact]
    public async Task ADecisionThatHonorsItsTokenIsCancelledAtTheTimeoutAndDenies()
    {
        var ct = TestContext.Current.CancellationToken;
        var observed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var harness = await SuppliedHarness.StartAsync(b =>
        {
            b.Limits = new LocalRpcLimits { AuthorizationTimeout = TimeSpan.FromMilliseconds(300) };
            _ = b.AuthorizeConnectionsAsync(async (connection, token) =>
            {
                if (connection.Sequence == 1)
                {
                    try
                    {
                        await Task.Delay(Timeout.InfiniteTimeSpan, token);
                    }
                    catch (OperationCanceledException)
                    {
                        observed.TrySetResult();
                        throw;
                    }
                }

                return true;
            });
        }, ct);

        await using var silent = harness.NewClientStream();
        var frames = await RawFrames.ReadUntilClosedAsync(silent, Patience, ct);

        Assert.Empty(frames);
        await observed.Task.WaitAsync(Patience, ct);
    }

    [Fact]
    public async Task AFailingDecisionDeniesEvenWhenItFaultsAfterTheTimeout()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(b =>
        {
            b.Limits = new LocalRpcLimits { AuthorizationTimeout = TimeSpan.FromMilliseconds(200) };
            _ = b.AuthorizeConnectionsAsync(async (connection, _) =>
            {
                switch (connection.Sequence)
                {
                    case 1:
                        await Task.Yield();
                        throw new InvalidOperationException("an authorizer that fails must deny");
                    case 2:
                        await Task.Delay(TimeSpan.FromMilliseconds(600), CancellationToken.None);
                        throw new InvalidOperationException("a late failure must not crash the server");
                    default:
                        return true;
                }
            });
        }, ct);

        foreach (var attempt in new[] { 1, 2 })
        {
            await using var raw = harness.NewClientStream();
            var frames = await RawFrames.ReadUntilClosedAsync(raw, Patience, ct);
            Assert.Empty(frames);
        }

        await Task.Delay(TimeSpan.FromMilliseconds(800), ct);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        await using var channel = harness.NewChannel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
        var response = await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);
        Assert.Equal(8, response.Value.ServerChallenge.Length);
    }

    [Fact]
    public async Task StoppingTheServerCancelsAPendingDecisionAndDropsTheStreamUnread()
    {
        var ct = TestContext.Current.CancellationToken;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var harness = await SuppliedHarness.StartAsync(b =>
        {
            b.Limits = new LocalRpcLimits { AuthorizationTimeout = TimeSpan.FromSeconds(30), ShutdownTimeout = TimeSpan.FromSeconds(2) };
            _ = b.AuthorizeConnectionsAsync(async (_, token) =>
            {
                entered.TrySetResult();
                try
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, token);
                }
                catch (OperationCanceledException)
                {
                    cancelled.TrySetResult();
                    throw;
                }

                return true;
            });
        }, ct);
        await using var pending = harness.NewClientStream();
        await entered.Task.WaitAsync(Patience, ct);

        await harness.Server.StopAsync(ct);

        await cancelled.Task.WaitAsync(Patience, ct);
        var frames = await RawFrames.ReadUntilClosedAsync(pending, Patience, ct);
        Assert.Empty(frames);
    }

    [Fact]
    public void TheAuthorizationTimeoutIsBounded()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcLimits { AuthorizationTimeout = TimeSpan.Zero }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcLimits { AuthorizationTimeout = TimeSpan.FromTicks(-1) }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcLimits { AuthorizationTimeout = TimeSpan.FromSeconds(30) + TimeSpan.FromTicks(1) }.Validated());
        _ = new LocalRpcLimits { AuthorizationTimeout = TimeSpan.FromTicks(1) }.Validated();
        _ = new LocalRpcLimits { AuthorizationTimeout = TimeSpan.FromSeconds(30) }.Validated();
        Assert.Equal(TimeSpan.FromSeconds(2), new LocalRpcLimits().AuthorizationTimeout);
    }

    [Fact]
    public async Task TheLastDecisionSetOnABuilderWinsAndTheAsynchronousOneValidatesItsArguments()
    {
        var ct = TestContext.Current.CancellationToken;
        var builder = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new RecordingBootstrapService());
        Assert.Throws<ArgumentNullException>(() => builder.AuthorizeConnectionsAsync(null!));
        await using (var server = builder.Build())
        {
            Assert.Throws<InvalidOperationException>(() => builder.AuthorizeConnectionsAsync((_, _) => ValueTask.FromResult(true)));
        }

        await using (var harness = await SuppliedHarness.StartAsync(b => b.AuthorizeConnections(_ => false).AuthorizeConnectionsAsync((_, _) => ValueTask.FromResult(true)), ct))
        {
            await using var channel = harness.NewChannel();
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
            _ = await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);
        }

        await using var denying = await SuppliedHarness.StartAsync(b => b.AuthorizeConnectionsAsync((_, _) => ValueTask.FromResult(true)).AuthorizeConnections(_ => false), ct);
        await using var raw = denying.NewClientStream();
        Assert.Empty(await RawFrames.ReadUntilClosedAsync(raw, Patience, ct));
    }

    [Fact]
    public async Task AServerOverALaunchAdmitsConnectionsOnlyWhileTheLaunchAuthorizes()
    {
        var ct = TestContext.Current.CancellationToken;
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        var child = world.SpawnFake(5150);
        launch.BindChild(child);
        await using var harness = await SuppliedHarness.StartAsync(b => b.AuthorizeConnectionsAsync(launch.AuthorizeConnectionAsync), ct);

        await using (var channel = harness.NewChannel())
        {
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
            _ = await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);
        }

        world.Processes.Set(child, ProcessLiveness.Dead);
        await using (var stale = harness.NewClientStream())
        {
            Assert.Empty(await RawFrames.ReadUntilClosedAsync(stale, Patience, ct));
        }

        world.Processes.Set(child, ProcessLiveness.Live);
        launch.Revoke();
        await using (var revoked = harness.NewClientStream())
        {
            Assert.Empty(await RawFrames.ReadUntilClosedAsync(revoked, Patience, ct));
        }

        Assert.Equal(1, harness.Service.Dispatched);
    }

    [Fact]
    public async Task ASupersededLaunchStopsAdmittingEvenThoughItsServerKeepsRunning()
    {
        var ct = TestContext.Current.CancellationToken;
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var old = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);
        await using var harness = await SuppliedHarness.StartAsync(b => b.AuthorizeConnectionsAsync(old.AuthorizeConnectionAsync), ct);
        _ = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        await using var raw = harness.NewClientStream();

        Assert.Empty(await RawFrames.ReadUntilClosedAsync(raw, Patience, ct));
        Assert.Equal(0, harness.Service.Dispatched);
        Assert.True(old.Revoked.IsCancellationRequested);
    }

    [Fact]
    public async Task TheListenerGivesTheDecisionTheEndpointAndAnIncreasingSequence()
    {
        var ct = TestContext.Current.CancellationToken;
        var endpoint = LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.NamedPipe, "af-listener-info");
        var seen = new List<LocalRpcConnectionInfo>();
        await using var source = new QueueAcceptSource(3);
        var listenEndPoint = new LocalRpcListenEndPoint(endpoint, null, new LocalRpcLimits(), (connection, _) =>
        {
            seen.Add(connection);
            return ValueTask.FromResult(connection.Sequence != 2);
        });
        await using var listener = new LocalRpcConnectionListener(listenEndPoint, source);

        var first = await listener.AcceptAsync(ct);
        var third = await listener.AcceptAsync(ct);

        Assert.NotNull(first);
        Assert.NotNull(third);
        Assert.Equal([1L, 2L, 3L], seen.Select(connection => connection.Sequence));
        Assert.All(seen, connection =>
        {
            Assert.Same(endpoint, connection.Endpoint);
            Assert.Equal(LocalRpcTransport.NamedPipe, connection.Transport);
        });
        Assert.Equal(1, source.Disposed);
    }

    private sealed class QueueAcceptSource : IStreamAcceptSource
    {
        private readonly Queue<Stream> _streams = new();
        private int _disposed;

        [SuppressMessage("Reliability", "CA2000", Justification = "Streams created here are owned by the queue and disposed by the listener under test.")]
        internal QueueAcceptSource(int count)
        {
            for (var index = 0; index < count; index++)
            {
                var (client, server) = InMemoryDuplexStream.CreatePair();
                client.Dispose();
                _streams.Enqueue(new CountingStream(server, () => Interlocked.Increment(ref _disposed)));
            }
        }

        internal int Disposed => Volatile.Read(ref _disposed);

        public ValueTask<Stream?> AcceptAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult<Stream?>(_streams.Count > 0 ? _streams.Dequeue() : null);

        public ValueTask UnbindAsync() => ValueTask.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class CountingStream(Stream inner, Action disposed) : Stream
    {
        private int _done;

        public override bool CanRead => inner.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => inner.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => inner.Flush();

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        public override async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _done, 1) == 0)
            {
                disposed();
            }

            await inner.DisposeAsync();
            await base.DisposeAsync();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && Interlocked.Exchange(ref _done, 1) == 0)
            {
                disposed();
            }

            inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
