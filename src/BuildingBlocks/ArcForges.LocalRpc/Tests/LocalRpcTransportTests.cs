// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Net;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.Core;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Deterministic offline fixtures: real Kestrel HTTP/2, the custom listener factory and Grpc.Net.Client over
/// in-memory duplex streams. These are framing and authorization fixtures, not OS-stream evidence.
/// </summary>
// One collection: the hosting-URL test changes process-wide environment variables, so no other test may run beside it.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcTransportTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    [Fact]
    public async Task GeneratedUnaryCallRoundTripsOverASuppliedStream()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);

        var response = await client.ChallengeAsync(Requests.Challenge(1024 * 1024), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);

        Assert.Equal(1024 * 1024, response.Value.ServerChallenge.Length);
        Assert.Equal(1, harness.Service.Dispatched);
    }

    [Fact]
    public async Task OneHttp2ConnectionServesConcurrentCallsAndIsNeverRecycled()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);

        var calls = Enumerable.Range(0, 12).Select(_ => client.ChallengeAsync(
            Requests.Challenge(2048), deadline: DateTime.UtcNow + Patience, cancellationToken: ct).ResponseAsync).ToArray();
        _ = await Task.WhenAll(calls);
        _ = await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);

        Assert.Equal(13, harness.Service.Dispatched);
        Assert.Equal(1, harness.Connects);
    }

    [Fact]
    public async Task MessagesAboveTheBoundAreRefusedByTheClientAndByTheServer()
    {
        var ct = TestContext.Current.CancellationToken;
        var limits = new LocalRpcLimits { MaxMessageBytes = 64 * 1024 };
        await using var harness = await SuppliedHarness.StartAsync(b => b.Limits = limits, ct);
        await using var channel = harness.NewChannel(limits);
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);

        var small = await client.ChallengeAsync(Requests.Challenge(32 * 1024), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);
        var clientRefusal = await Assert.ThrowsAsync<RpcException>(async () =>
            await client.ChallengeAsync(Requests.Challenge(80 * 1024), deadline: DateTime.UtcNow + Patience, cancellationToken: ct));
        var serverRefusal = await RawGrpc.PostAsync(
            _ => ValueTask.FromResult(harness.NewClientStream()),
            Requests.ChallengePath,
            RawFrames.GrpcMessage(0, declaredLength: 64 * 1024 + 1, actualBytes: 16),
            encoding: null,
            ct);

        Assert.Equal(32 * 1024, small.Value.ServerChallenge.Length);
        Assert.Equal(StatusCode.ResourceExhausted, clientRefusal.StatusCode);
        Assert.Equal(StatusCode.ResourceExhausted, serverRefusal);
        Assert.Equal(1, harness.Service.Dispatched);
    }

    [Theory]
    [InlineData("truncated", 13)]
    [InlineData("invalid-flag", 2)]
    [InlineData("compressed-without-encoding", 13)]
    [InlineData("compressed-with-gzip", 12)]
    public async Task MalformedGrpcFramesAreRefusedBeforeServiceDispatch(string fixture, int expectedStatus)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(cancellationToken: ct);
        var (flag, declared, actual, encoding) = fixture switch
        {
            "truncated" => ((byte)0, 100u, 10, (string?)null),
            "invalid-flag" => ((byte)2, 8u, 8, (string?)null),
            "compressed-without-encoding" => ((byte)1, 8u, 8, (string?)null),
            _ => ((byte)1, 8u, 8, "gzip"),
        };

        var status = await RawGrpc.PostAsync(
            _ => ValueTask.FromResult(harness.NewClientStream()),
            Requests.ChallengePath,
            RawFrames.GrpcMessage(flag, declared, actual),
            encoding,
            ct);

        Assert.Equal((StatusCode)expectedStatus, status);
        Assert.Equal(0, harness.Service.Dispatched);
    }

    [Theory]
    [InlineData("http1-text", null)]
    [InlineData("settings-on-stream-one", 1)]
    [InlineData("frame-over-the-size-limit", 6)]
    [InlineData("invalid-hpack-block", 9)]
    public async Task MalformedHttp2BytesCloseOnlyTheirConnectionAndTheServerKeepsServing(string fixture, int? goAwayCode)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(cancellationToken: ct);
        var bytes = fixture switch
        {
            "http1-text" => "GET / HTTP/1.1\r\nHost: arcforges.invalid\r\n\r\n"u8.ToArray(),
            "settings-on-stream-one" => RawFrames.Concat(RawFrames.Preface, RawFrames.Frame(0, 0x4, 0, 1)),
            "frame-over-the-size-limit" => RawFrames.Concat(RawFrames.Preface, RawFrames.Frame(65535, 0x0, 0, 1)),
            _ => RawFrames.Concat(RawFrames.Preface, RawFrames.Frame(4, 0x1, 0x4, 1, [0xFF, 0xFF, 0xFF, 0xFF])),
        };

        await using (var raw = harness.NewClientStream())
        {
            await raw.WriteAsync(bytes, ct);
            var frames = await RawFrames.ReadUntilClosedAsync(raw, Patience, ct);
            if (goAwayCode is { } expected)
            {
                Assert.Equal(expected, RawFrames.GoAwayCode(frames));
            }
        }

        await using var channel = harness.NewChannel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
        var response = await client.ChallengeAsync(Requests.Challenge(64), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);

        Assert.Equal(64, response.Value.ServerChallenge.Length);
        Assert.Equal(1, harness.Service.Dispatched);
    }

    [Fact]
    public async Task AConnectionTheAuthorizerDeniesReceivesNoByteAndNeverReachesHttp2()
    {
        var ct = TestContext.Current.CancellationToken;
        var decisions = new List<LocalRpcConnectionInfo>();
        await using var harness = await SuppliedHarness.StartAsync(b => b.AuthorizeConnections(connection =>
        {
            lock (decisions)
            {
                decisions.Add(connection);
            }

            return connection.Sequence switch
            {
                1 => false,
                2 => throw new InvalidOperationException("An authorizer that fails must deny."),
                _ => true,
            };
        }), ct);

        foreach (var attempt in new[] { 1, 2 })
        {
            await using var raw = harness.NewClientStream();
            try
            {
                await raw.WriteAsync(RawFrames.Preface, ct);
            }
            catch (IOException)
            {
                // The denial may close the stream before the preface is written; that is the expected outcome.
            }

            var frames = await RawFrames.ReadUntilClosedAsync(raw, Patience, ct);
            Assert.Empty(frames);
        }

        await using var channel = harness.NewChannel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
        var response = await client.ChallengeAsync(Requests.Challenge(16), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);

        Assert.Equal(16, response.Value.ServerChallenge.Length);
        Assert.Equal(1, harness.Service.Dispatched);
        lock (decisions)
        {
            Assert.Equal([1L, 2L, 3L], decisions.Select(decision => decision.Sequence));
        }
    }

    [Fact]
    public async Task OnlyExplicitlyRegisteredServicesAreServed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(cancellationToken: ct);

        var unknown = await RawGrpc.PostAsync(
            _ => ValueTask.FromResult(harness.NewClientStream()),
            "/arcforges.local.unregistered.v1.NotRegistered/Call",
            RawFrames.GrpcMessage(0, 0, 0),
            encoding: null,
            ct);

        Assert.Equal(StatusCode.Unimplemented, unknown);
        Assert.Equal(0, harness.Service.Dispatched);
    }

    [Fact]
    public async Task RegistrationIsExplicitSingleUseAndRequiresAService()
    {
        var service = new RecordingBootstrapService();
        var builder = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier());

        Assert.Throws<InvalidOperationException>(builder.Build);
        _ = builder.AddService(service);
        Assert.Throws<InvalidOperationException>(() => builder.AddService(new RecordingBootstrapService()));
        Assert.Throws<ArgumentNullException>(() => builder.AuthorizeConnections(null!));
        Assert.Throws<ArgumentNullException>(() => builder.AddService<RecordingBootstrapService>(null!));
        await using var server = builder.Build();
        Assert.Throws<InvalidOperationException>(builder.Build);
        Assert.Throws<InvalidOperationException>(() => builder.AddService(service));
        Assert.Throws<InvalidOperationException>(() => builder.AuthorizeConnections(_ => true));
    }

    [Fact]
    public void LimitsOutsideTheProfileAreRefused()
    {
        var supplier = new LocalRpcStreamSupplier();
        var builder = LocalRpcServer.CreateBuilder(supplier).AddService(new RecordingBootstrapService());
        LocalRpcLimits[] invalid =
        [
            new() { MaxMessageBytes = 512 },
            new() { MaxMessageBytes = LocalRpcLimits.DefaultMaxMessageBytes + 1 },
            new() { MaxConnections = 0 },
            new() { MaxConnections = 65 },
            new() { ConnectTimeout = TimeSpan.Zero },
            new() { ShutdownTimeout = TimeSpan.FromMinutes(2) },
        ];

        foreach (var limits in invalid)
        {
            builder.Limits = limits;
            Assert.Throws<ArgumentOutOfRangeException>(builder.Build);
            Assert.Throws<ArgumentOutOfRangeException>(() => LocalRpcClientChannel.CreateFromStreams(_ => ValueTask.FromResult<Stream>(Stream.Null), limits));
        }
    }

    [Fact]
    public async Task TheServerListensOnNoIpAddressAndIgnoresEnvironmentUrls()
    {
        var ct = TestContext.Current.CancellationToken;
        var previousAspNet = Environment.GetEnvironmentVariable("ASPNETCORE_URLS");
        var previousDotnet = Environment.GetEnvironmentVariable("DOTNET_URLS");
        try
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_URLS", "http://127.0.0.1:0");
            Environment.SetEnvironmentVariable("DOTNET_URLS", "http://127.0.0.1:0");
            await using var harness = await SuppliedHarness.StartAsync(cancellationToken: ct);
            var services = harness.Server.Services;

            var factories = services.GetServices<IConnectionListenerFactory>().ToArray();
            var addresses = services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>();

            Assert.Single(factories);
            var factory = Assert.IsAssignableFrom<IConnectionListenerFactorySelector>(factories[0]);
            Assert.False(factory.CanBind(new IPEndPoint(IPAddress.Loopback, 0)));
            Assert.False(factory.CanBind(new IPEndPoint(IPAddress.IPv6Any, 5000)));
            await Assert.ThrowsAsync<NotSupportedException>(async () =>
                await factories[0].BindAsync(new IPEndPoint(IPAddress.Loopback, 0), ct));
            Assert.NotNull(addresses);
            Assert.All(addresses.Addresses, address => Assert.StartsWith("http://localrpc:", address, StringComparison.Ordinal));
        }
        finally
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_URLS", previousAspNet);
            Environment.SetEnvironmentVariable("DOTNET_URLS", previousDotnet);
        }
    }

    [Fact]
    public async Task TheClientNeverFallsBackToDnsOrTcpWhenTheStreamFails()
    {
        var ct = TestContext.Current.CancellationToken;
        var attempts = 0;
        await using var channel = LocalRpcClientChannel.CreateFromStreams(_ =>
        {
            Interlocked.Increment(ref attempts);
            throw new IOException("verified-stream-unavailable");
        });
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);

        var failure = await Assert.ThrowsAsync<RpcException>(async () =>
            await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct));

        Assert.Equal(StatusCode.Unavailable, failure.StatusCode);
        Assert.True(attempts >= 1);
        Assert.Contains("verified-stream-unavailable", Describe(failure), StringComparison.Ordinal);
        Assert.Equal("http://arcforges.invalid", LocalRpcClientChannel.Authority);
    }

    [Fact]
    public async Task CancellationAndDeadlinesReachTheServerHandler()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);

        using var cancel = new CancellationTokenSource();
        var pending = client.ChallengeAsync(Requests.Challenge(8, first: 0xEE), cancellationToken: cancel.Token);
        var observed = harness.Service.CancellationObserved.Task;
        using var dispatchWait = CancellationTokenSource.CreateLinkedTokenSource(ct);
        dispatchWait.CancelAfter(Patience);
        while (harness.Service.Dispatched == 0)
        {
            await Task.Delay(10, dispatchWait.Token);
        }

        await cancel.CancelAsync();
        var cancelled = await Assert.ThrowsAsync<RpcException>(async () => await pending.ResponseAsync);
        await observed.WaitAsync(Patience, ct);

        Assert.Equal(StatusCode.Cancelled, cancelled.StatusCode);
        var deadline = await Assert.ThrowsAsync<RpcException>(async () =>
            await client.ChallengeAsync(Requests.Challenge(8, first: 0xEE), deadline: DateTime.UtcNow + TimeSpan.FromMilliseconds(300), cancellationToken: ct));
        Assert.Equal(StatusCode.DeadlineExceeded, deadline.StatusCode);
    }

    [Fact]
    [SuppressMessage("Reliability", "CA2000", Justification = "The test disposes the harness explicitly, twice, to prove disposal is idempotent.")]
    public async Task StoppingAndDisposingTheServerClosesConnectionsAndDropsUnacceptedStreams()
    {
        var ct = TestContext.Current.CancellationToken;
        var harness = await SuppliedHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
        _ = await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);

        await harness.Server.StopAsync(ct);
        var (unaccepted, server) = InMemoryDuplexStream.CreatePair();
        Assert.False(harness.Supplier.TrySupply(server));
        await server.DisposeAsync();
        await harness.DisposeAsync();
        await harness.DisposeAsync();

        var refused = await Assert.ThrowsAsync<RpcException>(async () =>
            await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + TimeSpan.FromSeconds(5), cancellationToken: ct));
        var buffer = new byte[1];
        var read = await unaccepted.ReadAsync(buffer, ct);

        Assert.True(refused.StatusCode is StatusCode.Unavailable or StatusCode.Cancelled or StatusCode.Internal);
        Assert.Equal(0, read);
        await unaccepted.DisposeAsync();
    }

    [Fact]
    public async Task ASupplierServesOneServerAndRefusesStreamsOnceCompleted()
    {
        var ct = TestContext.Current.CancellationToken;
        var supplier = new LocalRpcStreamSupplier();
        var service = new RecordingBootstrapService();
        var first = LocalRpcServer.CreateBuilder(supplier).AddService(service).Build();
        Assert.Throws<InvalidOperationException>(() => LocalRpcServer.CreateBuilder(supplier).AddService(new RecordingBootstrapService()).Build());
        await using var firstLifetime = first;
        await first.StartAsync(ct);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await first.StartAsync(ct));

        var (client, server) = InMemoryDuplexStream.CreatePair();
        using (client)
        using (server)
        using (var readOnly = new MemoryStream([], writable: false))
        {
            Assert.Throws<ArgumentException>(() => supplier.TrySupply(readOnly));
            Assert.Throws<ArgumentNullException>(() => supplier.TrySupply(null!));
            supplier.Complete();
            Assert.False(supplier.TrySupply(server));
        }
    }

    [Fact]
    public async Task BuildersOverAnEndpointBuildWithoutBindingAnythingAndChannelsConnectLazily()
    {
        var ct = TestContext.Current.CancellationToken;
        var endpoint = OperatingSystem.IsWindows()
            ? LocalRpcEndpoint.NamedPipe("af-ci-unbound-" + Guid.NewGuid().ToString("N"))
            : LocalRpcEndpoint.UnixDomainSocket(Path.Combine(Path.GetTempPath(), "afrpc-" + Guid.NewGuid().ToString("N")[..8] + ".sock"));

        var server = LocalRpcServer.CreateBuilder(endpoint).AddService(new RecordingBootstrapService()).Build();
        await using var channel = LocalRpcClientChannel.Create(endpoint);
        await using var serverLifetime = server;
        await server.StopAsync(ct);

        Assert.Equal(endpoint.Transport, OperatingSystem.IsWindows() ? LocalRpcTransport.NamedPipe : LocalRpcTransport.UnixDomainSocket);
        Assert.NotNull(channel.CallInvoker);
        Assert.Throws<ArgumentNullException>(() => LocalRpcServer.CreateBuilder((LocalRpcEndpoint)null!));
        Assert.Throws<ArgumentNullException>(() => LocalRpcServer.CreateBuilder((LocalRpcStreamSupplier)null!));
        Assert.Throws<ArgumentNullException>(() => LocalRpcClientChannel.Create(null!));
        Assert.Throws<ArgumentNullException>(() => LocalRpcClientChannel.CreateFromStreams(null!));
    }

    [Fact]
    public async Task ACompressedRequestIsRefusedWithoutDecompressionOrDispatch()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(cancellationToken: ct);

        var small = await RawGrpc.PostAsync(_ => ValueTask.FromResult(harness.NewClientStream()), Requests.ChallengePath, Requests.Frame(64, gzip: true), "gzip", ct);
        // 32 MiB of payload compresses to a few dozen KiB: far over the 4 MiB cap once decoded.
        var large = await RawGrpc.PostAsync(_ => ValueTask.FromResult(harness.NewClientStream()), Requests.ChallengePath, Requests.Frame(32 * 1024 * 1024, gzip: true), "gzip", ct);
        var deflate = await RawGrpc.PostAsync(_ => ValueTask.FromResult(harness.NewClientStream()), Requests.ChallengePath, Requests.Frame(64, gzip: true), "deflate", ct);
        var identity = await RawGrpc.PostAsync(_ => ValueTask.FromResult(harness.NewClientStream()), Requests.ChallengePath, Requests.Frame(64, gzip: false), "identity", ct);

        Assert.Equal(StatusCode.Unimplemented, small);
        Assert.Equal(StatusCode.Unimplemented, large);
        Assert.Equal(StatusCode.Unimplemented, deflate);
        Assert.Equal(StatusCode.OK, identity);
        Assert.Equal(1, harness.Service.Dispatched);
    }

    [Fact]
    public async Task TheServerAndClientBoundsAreAppliedToBothDirections()
    {
        var ct = TestContext.Current.CancellationToken;
        var small = new LocalRpcLimits { MaxMessageBytes = 64 * 1024 };

        // Server send bound: the handler answers 128 KiB, the 64 KiB server must refuse to send it.
        await using (var narrowServer = await SuppliedHarness.StartAsync(b => b.Limits = small, ct))
        {
            await using var channel = narrowServer.NewChannel();
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
            var refused = await Assert.ThrowsAsync<RpcException>(async () =>
                await client.ChallengeAsync(Requests.Challenge(16, first: 0xAA), deadline: DateTime.UtcNow + Patience, cancellationToken: ct));
            Assert.NotEqual(StatusCode.OK, refused.StatusCode);
            var options = narrowServer.Server.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<Grpc.AspNetCore.Server.GrpcServiceOptions>>().Value;
            Assert.Equal(64 * 1024, options.MaxSendMessageSize);
            Assert.Equal(64 * 1024, options.MaxReceiveMessageSize);
            Assert.False(options.EnableDetailedErrors);
            Assert.False(options.IgnoreUnknownServices);
            Assert.Empty(options.CompressionProviders);
            Assert.Null(options.ResponseCompressionAlgorithm);
        }

        // Client receive bound: the server (4 MiB) answers 128 KiB, the 64 KiB client must refuse to read it.
        await using (var wideServer = await SuppliedHarness.StartAsync(cancellationToken: ct))
        {
            await using var channel = wideServer.NewChannel(small);
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
            var refused = await Assert.ThrowsAsync<RpcException>(async () =>
                await client.ChallengeAsync(Requests.Challenge(16, first: 0xAA), deadline: DateTime.UtcNow + Patience, cancellationToken: ct));
            Assert.Equal(StatusCode.ResourceExhausted, refused.StatusCode);
            Assert.Equal(1, wideServer.Service.Dispatched);

            // Client send bound: an 80 KiB request never leaves a 64 KiB client although the server would take it.
            var tooLarge = await Assert.ThrowsAsync<RpcException>(async () =>
                await client.ChallengeAsync(Requests.Challenge(80 * 1024), deadline: DateTime.UtcNow + Patience, cancellationToken: ct));
            Assert.Equal(StatusCode.ResourceExhausted, tooLarge.StatusCode);
            Assert.Equal(1, wideServer.Service.Dispatched);
        }
    }

    [Fact]
    public async Task HandlerExceptionTextNeverCrossesTheTransport()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(cancellationToken: ct);
        await using var channel = harness.NewChannel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);

        var failure = await Assert.ThrowsAsync<RpcException>(async () =>
            await client.ChallengeAsync(Requests.Challenge(16, first: 0xBB), deadline: DateTime.UtcNow + Patience, cancellationToken: ct));

        Assert.Equal(StatusCode.Unknown, failure.StatusCode);
        Assert.DoesNotContain("secret-detail", failure.Status.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExtraConnectionsWaitForAFreeSlotInsteadOfBeingReset()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(b => b.Limits = new LocalRpcLimits { MaxConnections = 1 }, ct);
        await using var first = harness.NewChannel();
        var firstClient = new LocalBootstrapService.LocalBootstrapServiceClient(first.CallInvoker);
        _ = await firstClient.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);

        await using var second = harness.NewChannel();
        var secondClient = new LocalBootstrapService.LocalBootstrapServiceClient(second.CallInvoker);
        var waiting = secondClient.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct).ResponseAsync;
        using var connectWait = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connectWait.CancelAfter(Patience);
        while (harness.Connects < 2)
        {
            await Task.Delay(10, connectWait.Token);
        }

        await Task.Delay(500, ct);
        Assert.False(waiting.IsCompleted);
        Assert.Equal(1, harness.Service.Dispatched);

        await first.DisposeAsync();
        var served = await waiting;
        Assert.NotNull(served);
        Assert.Equal(2, harness.Service.Dispatched);
    }

    [Fact]
    public async Task ManyQuickReconnectsAreAllServedAtASmallConnectionBound()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await SuppliedHarness.StartAsync(b => b.Limits = new LocalRpcLimits { MaxConnections = 2 }, ct);

        for (var index = 0; index < 60; index++)
        {
            await using var channel = harness.NewChannel();
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
            _ = await client.ChallengeAsync(Requests.Challenge(8), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);
        }

        Assert.Equal(60, harness.Service.Dispatched);
    }

    [Fact]
    public async Task HostingUrlSettingsNeverCreateAnAddress()
    {
        var ct = TestContext.Current.CancellationToken;
        var names = new[] { "ASPNETCORE_URLS", "ASPNETCORE_HTTP_PORTS", "ASPNETCORE_HTTPS_PORTS", "ASPNETCORE_PREFERHOSTINGURLS", "DOTNET_URLS" };
        var previous = names.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        try
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_URLS", "http://127.0.0.1:0");
            Environment.SetEnvironmentVariable("ASPNETCORE_HTTP_PORTS", "0");
            Environment.SetEnvironmentVariable("ASPNETCORE_HTTPS_PORTS", "0");
            Environment.SetEnvironmentVariable("ASPNETCORE_PREFERHOSTINGURLS", "true");
            Environment.SetEnvironmentVariable("DOTNET_URLS", "http://127.0.0.1:0");
            var supplier = new LocalRpcStreamSupplier();
            await using var server = LocalRpcServer.CreateBuilder(supplier).AddService(new RecordingBootstrapService()).Build();
            // Either the host ignores the URL settings or it refuses to start; no outcome may bind an IP address.
            try
            {
                await server.StartAsync(ct);
                var addresses = server.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>();
                Assert.NotNull(addresses);
                Assert.All(addresses.Addresses, address => Assert.StartsWith("http://localrpc:", address, StringComparison.Ordinal));
            }
            catch (InvalidOperationException)
            {
                // Refused to start: nothing was bound.
            }
        }
        finally
        {
            foreach (var (name, value) in previous)
            {
                Environment.SetEnvironmentVariable(name, value);
            }
        }
    }

    private static string Describe(Exception exception)
    {
        var text = new System.Text.StringBuilder();
        for (var current = exception; current is not null; current = current.InnerException!)
        {
            text.Append(current.Message).Append('|');
            if (current.InnerException is null)
            {
                break;
            }
        }

        return text.ToString();
    }
}
