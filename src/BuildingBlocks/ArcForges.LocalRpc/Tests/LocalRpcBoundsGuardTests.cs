// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.AspNetCore.Server;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Every guard of the bounds layer and of the transport profile it builds on, each with a test that fails when the
/// guard is removed: control registration and start-up checks, the private-transport guards, deadline parsing, typed
/// refusals, the callback marker, the pinned Kestrel limits and the client's refusal of compression.
/// </summary>
// One collection: the hosting-URL test changes process-wide environment variables, so no other test may run beside it.
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcBoundsGuardTests
{
    private static readonly TimeSpan Patience = BoundsHarness.Patience;
    private static readonly string[] TwoTimeouts = ["5S", "6S"];

    [Fact]
    public async Task ControlRegistrationIsValidatedSingleUseAndClosedAtBuild()
    {
        var builder = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ProbeService());
        const string service = BoundsProbe.ServiceName;

        Assert.Throws<ArgumentNullException>(() => builder.RegisterControl(LocalRpcControlOperation.Health, null!, "Health"));
        Assert.Throws<ArgumentNullException>(() => builder.RegisterControl(LocalRpcControlOperation.Health, service, null!));
        Assert.Throws<ArgumentNullException>(() => builder.RegisterControl(LocalRpcControlOperation.Health, null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => builder.RegisterControl((LocalRpcControlOperation)99, service, "Health"));
        Assert.Throws<ArgumentOutOfRangeException>(() => builder.RegisterControl(LocalRpcControlOperation.None, service, "Health"));
        foreach (var badService in new[] { string.Empty, "1abc", "a b", "a..b", ".a", "a.", "a/b" })
        {
            Assert.Throws<ArgumentException>(() => builder.RegisterControl(LocalRpcControlOperation.Health, badService, "Health"));
        }

        foreach (var badMethod in new[] { string.Empty, "1abc", "a b", "Do.It", "a/b" })
        {
            Assert.Throws<ArgumentException>(() => builder.RegisterControl(LocalRpcControlOperation.Health, service, badMethod));
        }

        _ = builder.RegisterControl(LocalRpcControlOperation.Health, service, "Health");
        Assert.Throws<InvalidOperationException>(() => builder.RegisterControl(LocalRpcControlOperation.Health, service, "Health"));
        Assert.Throws<InvalidOperationException>(() => builder.RegisterControl(LocalRpcControlOperation.Cancellation, BoundsProbe.Health));
        _ = builder.RegisterControl(LocalRpcControlOperation.Cancellation, BoundsProbe.Cancel);
        await using var server = builder.Build();
        Assert.Throws<InvalidOperationException>(() => builder.RegisterControl(LocalRpcControlOperation.Bootstrap, service, "Work"));
        Assert.Throws<InvalidOperationException>(() => builder.UseTimeProvider(TimeProvider.System));
        Assert.Throws<InvalidOperationException>(() => builder.ConfigureHostServices(_ => { }));
        Assert.Throws<ArgumentNullException>(() => LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).UseTimeProvider(null!));
        Assert.Throws<ArgumentNullException>(() => LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).ConfigureHostServices(null!));
    }

    [Theory]
    [InlineData("a", true)]
    [InlineData("a.b", true)]
    [InlineData("_a1", true)]
    [InlineData("A.B_c9.d", true)]
    [InlineData("", false)]
    [InlineData(".", false)]
    [InlineData("a.", false)]
    [InlineData(".a", false)]
    [InlineData("a..b", false)]
    [InlineData("1a", false)]
    [InlineData("a.1b", false)]
    [InlineData("a b", false)]
    [InlineData("a-b", false)]
    [InlineData("a/b", false)]
    [InlineData("é", false)]
    public void ProtobufNamesAreDotSeparatedAsciiIdentifiers(string name, bool valid)
    {
        Assert.Equal(valid, LocalRpcServerBuilder.IsProtoName(name));
    }

    [Theory]
    [InlineData(BoundsProbe.ServiceName, "Helth")]
    [InlineData("arcforges.test.missing.v1.Missing", "Cancel")]
    public async Task AControlMethodNoRegisteredServiceServesFailsStartInsteadOfRunningAsADataCall(string service, string method)
    {
        var ct = TestContext.Current.CancellationToken;
        var supplier = new LocalRpcStreamSupplier();
        await using var server = LocalRpcServer.CreateBuilder(supplier)
            .AddService(new ProbeService())
            .RegisterControl(LocalRpcControlOperation.Health, service, method)
            .Build();

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () => await server.StartAsync(ct));

        Assert.Contains(service + "/" + method, failure.Message, StringComparison.Ordinal);
        Assert.Contains("data call", failure.Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await server.StartAsync(ct));
    }

    [Fact]
    public async Task TheServerRefusesToStartIfAnIpAddressIsBoundAfterTheHostStarted()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var server = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier())
            .AddService(new ProbeService())
            .ViewReportedAddresses(addresses => (addresses ?? []).Append("http://127.0.0.1:5999"))
            .Build();

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () => await server.StartAsync(ct));

        Assert.Contains("127.0.0.1:5999", failure.Message, StringComparison.Ordinal);
        Assert.Contains("never listens on TCP", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheServerRefusesToStartIfAnotherConnectionListenerFactoryIsRegistered()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var server = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier())
            .AddService(new ProbeService())
            .ConfigureHostServices(services => services.AddSingleton<IConnectionListenerFactory, AlienListenerFactory>())
            .Build();

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () => await server.StartAsync(ct));

        Assert.Contains("Only the private stream transport may listen", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void OnlyThePrivateTransportAddressIsAcceptableAfterStart()
    {
        Assert.Null(LocalRpcServer.PrivateTransportViolation(["http://localrpc:NamedPipe:x", "http://localrpc:supplied-streams"]));
        Assert.NotNull(LocalRpcServer.PrivateTransportViolation(null));
        Assert.Null(LocalRpcServer.PrivateTransportViolation([]));
        Assert.Contains("127.0.0.1", LocalRpcServer.PrivateTransportViolation(["http://localrpc:x", "http://127.0.0.1:80"]), StringComparison.Ordinal);
        Assert.NotNull(LocalRpcServer.PrivateTransportViolation(["https://localhost:5001"]));
        Assert.NotNull(LocalRpcServer.PrivateTransportViolation(["http://localrpcx:80"]));
    }

    [Fact]
    public async Task TheKestrelLimitsThatBoundQueuedMemoryAreExplicit()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct);

        var limits = harness.Server.Services.GetRequiredService<IOptions<KestrelServerOptions>>().Value.Limits;

        Assert.Equal(LocalRpcLimits.MaxStreamsPerConnection, limits.Http2.MaxStreamsPerConnection);
        Assert.True(limits.Http2.MaxStreamsPerConnection > LocalRpcLimits.DefaultMaxActiveCalls + LocalRpcLimits.DefaultMaxQueuedCalls + LocalRpcLimits.ControlSlots);
        Assert.Equal(3 * 100 * 64 * 1024, limits.Http2.InitialConnectionWindowSize);
        Assert.Equal(64 * 1024, limits.Http2.InitialStreamWindowSize);
        Assert.Equal(16, LocalRpcLimits.DefaultMaxActiveCalls);
        Assert.Equal(64, LocalRpcLimits.DefaultMaxQueuedCalls);
        Assert.Equal(2, LocalRpcLimits.ControlSlots);
    }

    [Theory]
    [InlineData("1H", 3_600_000_000_0L)]
    [InlineData("2M", 1_200_000_000L)]
    [InlineData("3S", 30_000_000L)]
    [InlineData("4m", 40_000L)]
    [InlineData("5u", 50L)]
    [InlineData("700n", 7L)]
    [InlineData("12345678S", 123_456_780_000_000L)]
    [InlineData("0S", 0L)]
    public void GrpcTimeoutsParseInEveryUnit(string text, long ticks)
    {
        Assert.True(LocalRpcCallAdmission.TryParseTimeout(text, out var timeout));
        Assert.Equal(ticks, timeout.Ticks);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("S")]
    [InlineData("1")]
    [InlineData("1x")]
    [InlineData("-1S")]
    [InlineData("1.5S")]
    [InlineData("123456789S")]
    [InlineData("1 S")]
    public void MalformedGrpcTimeoutsAreRejected(string? text)
    {
        Assert.False(LocalRpcCallAdmission.TryParseTimeout(text, out _));
    }

    [Fact]
    public void TheRemainingTimeIsHandedOnInWholeMillisecondsRoundedUpAndNeverBelowOne()
    {
        Assert.Equal("1m", LocalRpcCallAdmission.ToTimeoutHeader(TimeSpan.FromTicks(1)));
        Assert.Equal("2m", LocalRpcCallAdmission.ToTimeoutHeader(TimeSpan.FromMilliseconds(1.2)));
        Assert.Equal("10000m", LocalRpcCallAdmission.ToTimeoutHeader(TimeSpan.FromSeconds(10)));
        Assert.Equal("99999999m", LocalRpcCallAdmission.ToTimeoutHeader(TimeSpan.FromDays(30)));
    }

    [Fact]
    public void ADeclaredDeadlineIsTheLaneDefaultWhenAbsentOrMalformedAndNeverAboveTheLaneMaximum()
    {
        var limits = new LocalRpcLimits
        {
            DefaultCallDeadline = TimeSpan.FromSeconds(7),
            MaxCallDeadline = TimeSpan.FromSeconds(20),
            ControlCallDeadline = TimeSpan.FromSeconds(3),
        };

        Assert.Equal(TimeSpan.FromSeconds(7), Window(null, limits, control: false));
        Assert.Equal(TimeSpan.FromSeconds(3), Window(null, limits, control: true));
        Assert.Equal(TimeSpan.FromSeconds(7), Window("junk", limits, control: false));
        Assert.Equal(TimeSpan.FromSeconds(3), Window("junk", limits, control: true));
        Assert.Equal(TimeSpan.FromSeconds(5), Window("5S", limits, control: false));
        Assert.Equal(TimeSpan.FromSeconds(2), Window("2S", limits, control: true));
        Assert.Equal(TimeSpan.FromSeconds(20), Window("100H", limits, control: false));
        Assert.Equal(TimeSpan.FromSeconds(3), Window("100H", limits, control: true));
        Assert.Equal(TimeSpan.Zero, Window("0m", limits, control: false));
        Assert.Equal(TimeSpan.FromSeconds(7), Window(TwoTimeouts, limits, control: false));
    }

    [Fact]
    public async Task ARoutedCallOnAnUntrackedConnectionIsAnsweredInternalAndNeverDispatched()
    {
        var registry = new LocalRpcBoundsRegistry(new LocalRpcLimits(), TimeProvider.System);
        var admission = new LocalRpcCallAdmission(registry, new Dictionary<string, LocalRpcControlOperation>());
        var context = RoutedContext(connectionId: "nobody", BoundsProbe.Work);
        var dispatched = false;

        await admission.InvokeAsync(context, _ =>
        {
            dispatched = true;
            return Task.CompletedTask;
        });

        Assert.False(dispatched);
        Assert.Equal(((int)StatusCode.Internal).ToString(System.Globalization.CultureInfo.InvariantCulture), context.Response.Headers["grpc-status"].ToString());
        Assert.False(context.Response.Headers.ContainsKey(LocalRpcRefusal.ReasonTrailer));
    }

    [Fact]
    public async Task ARequestThatIsNotARoutedGrpcMethodPassesThroughWithoutAdmission()
    {
        var registry = new LocalRpcBoundsRegistry(new LocalRpcLimits(), TimeProvider.System);
        var admission = new LocalRpcCallAdmission(registry, new Dictionary<string, LocalRpcControlOperation>());
        var context = new DefaultHttpContext();
        context.Connection.Id = "nobody";
        var dispatched = false;

        await admission.InvokeAsync(context, _ =>
        {
            dispatched = true;
            return Task.CompletedTask;
        });

        Assert.True(dispatched);
        Assert.False(context.Response.Headers.ContainsKey("grpc-status"));
        Assert.Equal(0, registry.Snapshot().DataAdmitted);
    }

    [Fact]
    public async Task ARoutedCallTakesTheControlGateOnlyWhenItsMethodWasDeclaredControl()
    {
        var registry = new LocalRpcBoundsRegistry(new LocalRpcLimits { MaxActiveCalls = 1, MaxQueuedCalls = 0 }, TimeProvider.System);
        var peer = registry.Add("peer");
        var control = new Dictionary<string, LocalRpcControlOperation> { [BoundsProbe.ServiceName + "/Cancel"] = LocalRpcControlOperation.Cancellation };
        var admission = new LocalRpcCallAdmission(registry, control);
        Assert.Equal(LocalRpcGateOutcome.Admitted, await peer.Data.EnterAsync(false, TestContext.Current.CancellationToken));
        int? seenControl = null;
        int? seenData = null;

        var controlContext = RoutedContext("peer", BoundsProbe.Cancel);
        await admission.InvokeAsync(controlContext, _ =>
        {
            seenControl = peer.Control.Active;
            return Task.CompletedTask;
        });
        var dataContext = RoutedContext("peer", BoundsProbe.Work);
        await admission.InvokeAsync(dataContext, _ =>
        {
            seenData = peer.Data.Active;
            return Task.CompletedTask;
        });

        // The data lane is full, so a data call is refused; the control call ran in its own gate and was counted as control.
        Assert.Equal(1, seenControl);
        Assert.Null(seenData);
        Assert.Equal(LocalRpcRefusalReason.DataQueueFull, ReasonOf(dataContext));
        Assert.Equal(1, registry.Snapshot().ControlAdmitted[LocalRpcControlOperation.Cancellation]);
        Assert.Equal(0, registry.Snapshot().DataAdmitted);
        Assert.Equal(0, peer.Control.Active);
    }

    [Fact]
    public void ARefusalIsReadOnlyWhenItWasMarkedAsNotDispatched()
    {
        foreach (var reason in Enum.GetValues<LocalRpcRefusalReason>().Where(known => known != LocalRpcRefusalReason.None))
        {
            var failure = Failure(new Metadata { { LocalRpcRefusal.ReasonTrailer, LocalRpcRefusal.NameOf(reason) }, { LocalRpcRefusal.DispatchedTrailer, "0" } });
            Assert.True(LocalRpcRefusal.TryRead(failure, out var refusal));
            Assert.Equal(reason, refusal!.Reason);
        }

        Assert.False(LocalRpcRefusal.TryRead(Failure([]), out _));
        Assert.False(LocalRpcRefusal.TryRead(Failure(new Metadata { { LocalRpcRefusal.ReasonTrailer, "data-queue-full" } }), out _));
        Assert.False(LocalRpcRefusal.TryRead(Failure(new Metadata { { LocalRpcRefusal.ReasonTrailer, "data-queue-full" }, { LocalRpcRefusal.DispatchedTrailer, "1" } }), out _));
        Assert.False(LocalRpcRefusal.TryRead(Failure(new Metadata { { LocalRpcRefusal.ReasonTrailer, "something-new" }, { LocalRpcRefusal.DispatchedTrailer, "0" } }), out _));
        Assert.False(LocalRpcRefusal.TryRead(Failure(new Metadata { { LocalRpcRefusal.ReasonTrailer + "-bin", [1, 2] }, { LocalRpcRefusal.DispatchedTrailer, "0" } }), out _));
        Assert.Throws<ArgumentNullException>(() => LocalRpcRefusal.TryRead(null!, out _));
        Assert.Equal(StatusCode.DeadlineExceeded, LocalRpcRefusal.StatusOf(LocalRpcRefusalReason.DeadlineBeforeDispatch));
        Assert.Equal(StatusCode.FailedPrecondition, LocalRpcRefusal.StatusOf(LocalRpcRefusalReason.RecursiveCallback));
        Assert.All(
            new[] { LocalRpcRefusalReason.DataQueueFull, LocalRpcRefusalReason.ControlBusy, LocalRpcRefusalReason.CallbackNotQueued },
            reason => Assert.Equal(StatusCode.ResourceExhausted, LocalRpcRefusal.StatusOf(reason)));
    }

    [Fact]
    public async Task TheSnapshotNamesEveryOperationAndReasonAndStartsAtZero()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct);

        var snapshot = harness.Server.GetBoundsSnapshot();

        Assert.Equal(0, snapshot.Peers + snapshot.DataActive + snapshot.DataQueued + snapshot.ControlActive);
        Assert.Equal(0, snapshot.DataAdmitted);
        Assert.Equal(Enum.GetValues<LocalRpcControlOperation>().Where(operation => operation != LocalRpcControlOperation.None).Order(), snapshot.ControlAdmitted.Keys.Order());
        Assert.Equal(Enum.GetValues<LocalRpcRefusalReason>().Where(reason => reason != LocalRpcRefusalReason.None).Order(), snapshot.Refused.Keys.Order());
        Assert.All(snapshot.ControlAdmitted.Values, count => Assert.Equal(0, count));
        Assert.All(snapshot.Refused.Values, count => Assert.Equal(0, count));
    }

    [Fact]
    public async Task TheCallbackMarkIsAddedInsideAHandlerAndOnlyThere()
    {
        var plain = await Intercept(depth: null);
        var inHandler = await Intercept(depth: 0, new Metadata { { "keep", "me" } });

        Assert.Null(plain.Headers);
        Assert.Equal("1", inHandler.Headers!.GetValue(LocalRpcRefusal.NestedHeader));
        Assert.Equal("me", inHandler.Headers.GetValue("keep"));
        Assert.True(inHandler.Passed);
    }

    [Fact]
    public async Task ACallFromInsideACallbackHandlerIsRefusedBeforeItIsSentOnEveryCallShape()
    {
        using var scope = LocalRpcCallbackGuard.Enter(1);
        var interceptor = new LocalRpcCallbackInterceptor();
        var context = new ClientInterceptorContext<byte[], byte[]>(BoundsProbe.Work, null, new CallOptions());
        var sent = false;

        var asyncCall = interceptor.AsyncUnaryCall([], context, (_, _) =>
        {
            sent = true;
            throw new InvalidOperationException();
        });
        var asyncFailure = await Assert.ThrowsAsync<RpcException>(async () => await asyncCall.ResponseAsync);
        var blocking = Assert.Throws<RpcException>(() => interceptor.BlockingUnaryCall([], context, (_, _) =>
        {
            sent = true;
            return [];
        }));
        var clientStream = Assert.Throws<RpcException>(() => interceptor.AsyncClientStreamingCall(context, _ =>
        {
            sent = true;
            throw new InvalidOperationException();
        }));
        var serverStream = Assert.Throws<RpcException>(() => interceptor.AsyncServerStreamingCall([], context, (_, _) =>
        {
            sent = true;
            throw new InvalidOperationException();
        }));
        var duplex = Assert.Throws<RpcException>(() => interceptor.AsyncDuplexStreamingCall(context, _ =>
        {
            sent = true;
            throw new InvalidOperationException();
        }));

        Assert.False(sent);
        Assert.Equal(StatusCode.FailedPrecondition, asyncCall.GetStatus().StatusCode);
        foreach (var failure in new[] { asyncFailure, blocking, clientStream, serverStream, duplex })
        {
            Assert.Equal(StatusCode.FailedPrecondition, failure.StatusCode);
            Assert.True(LocalRpcRefusal.TryRead(failure, out var refusal));
            Assert.Equal(LocalRpcRefusalReason.RecursiveCallback, refusal!.Reason);
        }

        Assert.Equal(LocalRpcRefusal.NameOf(LocalRpcRefusalReason.RecursiveCallback), asyncCall.GetTrailers().GetValue(LocalRpcRefusal.ReasonTrailer));
        Assert.Empty(await asyncCall.ResponseHeadersAsync);
        asyncCall.Dispose();
    }

    [Fact]
    public async Task EveryCallShapePassesThroughOutsideAHandlerAndIsMarkedInsideOne()
    {
        var interceptor = new LocalRpcCallbackInterceptor();
        var context = new ClientInterceptorContext<byte[], byte[]>(BoundsProbe.Work, null, new CallOptions());
        var marks = new List<string?>();
        void Record(ClientInterceptorContext<byte[], byte[]> seen) => marks.Add(seen.Options.Headers?.GetValue(LocalRpcRefusal.NestedHeader));
        AsyncUnaryCall<byte[]> Unary(ClientInterceptorContext<byte[], byte[]> seen)
        {
            Record(seen);
            return new AsyncUnaryCall<byte[]>(Task.FromResult(Array.Empty<byte>()), Task.FromResult(new Metadata()), () => Status.DefaultSuccess, () => [], () => { });
        }

        foreach (var depth in new int?[] { null, 0 })
        {
            using var scope = depth is { } value ? LocalRpcCallbackGuard.Enter(value) : default;
            using var unary = interceptor.AsyncUnaryCall([], context, (_, seen) => Unary(seen));
            _ = await unary.ResponseAsync;
            _ = interceptor.BlockingUnaryCall([], context, (_, seen) =>
            {
                Record(seen);
                return [];
            });
            _ = interceptor.AsyncClientStreamingCall(context, seen =>
            {
                Record(seen);
                return default!;
            });
            _ = interceptor.AsyncServerStreamingCall([], context, (_, seen) =>
            {
                Record(seen);
                return default!;
            });
            _ = interceptor.AsyncDuplexStreamingCall(context, seen =>
            {
                Record(seen);
                return default!;
            });
        }

        Assert.Equal(new string?[] { null, null, null, null, null, "1", "1", "1", "1", "1" }, marks);
        Assert.Null(LocalRpcCallbackGuard.CurrentDepth);
    }

    [Fact]
    public async Task TheClientNeverAdvertisesOrAcceptsCompression()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await BoundsHarness.StartAsync(cancellationToken: ct);
        var sent = new StringBuilder();
        await using var channel = LocalRpcClientChannel.CreateFromStreams(cancellation =>
            ValueTask.FromResult<Stream>(new RecordingWriteStream(harness.NewClientStream(), bytes =>
            {
                lock (sent)
                {
                    _ = sent.Append(Encoding.Latin1.GetString(bytes));
                }
            })));
        var client = new ProbeClient(channel.CallInvoker);

        _ = await client.Bootstrap.RenewAsync(Requests.Renew(), deadline: DateTime.UtcNow + Patience, cancellationToken: ct);

        string text;
        lock (sent)
        {
            text = sent.ToString();
        }

        // Positive control: the call's headers are visible in the captured bytes, so their absence means something.
        Assert.Contains("application/grpc", text, StringComparison.Ordinal);
        Assert.DoesNotContain("gzip", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("deflate", text, StringComparison.OrdinalIgnoreCase);
    }

    private static TimeSpan Window(object? header, LocalRpcLimits limits, bool control)
    {
        var context = new DefaultHttpContext();
        switch (header)
        {
            case string text:
                context.Request.Headers["grpc-timeout"] = text;
                break;
            case string[] many:
                context.Request.Headers["grpc-timeout"] = many;
                break;
        }

        return LocalRpcCallAdmission.DeadlineWindow(context, limits, control);
    }

    private static DefaultHttpContext RoutedContext(string connectionId, Method<byte[], byte[]> method)
    {
        var context = new DefaultHttpContext();
        context.Connection.Id = connectionId;
        var metadata = new EndpointMetadataCollection(new GrpcMethodMetadata(typeof(ProbeService), method));
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, metadata, method.Name));
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static LocalRpcRefusalReason? ReasonOf(HttpContext context)
    {
        var failure = new RpcException(Status.DefaultCancelled, Trailers(context.Response.Headers));
        return LocalRpcRefusal.TryRead(failure, out var refusal) ? refusal!.Reason : null;
    }

    private static Metadata Trailers(IHeaderDictionary headers)
    {
        var metadata = new Metadata();
        foreach (var name in new[] { LocalRpcRefusal.ReasonTrailer, LocalRpcRefusal.DispatchedTrailer })
        {
            if (headers.TryGetValue(name, out var value))
            {
                metadata.Add(name, value.ToString());
            }
        }

        return metadata;
    }

    private static RpcException Failure(Metadata trailers) => new(Status.DefaultCancelled, trailers);

    private static async Task<(Metadata? Headers, bool Passed)> Intercept(int? depth, Metadata? headers = null)
    {
        using var scope = depth is { } value ? LocalRpcCallbackGuard.Enter(value) : default;
        var interceptor = new LocalRpcCallbackInterceptor();
        var context = new ClientInterceptorContext<byte[], byte[]>(BoundsProbe.Work, null, new CallOptions(headers: headers));
        Metadata? seen = null;
        var passed = false;
        using var call = interceptor.AsyncUnaryCall([], context, (_, forwarded) =>
        {
            seen = forwarded.Options.Headers;
            passed = true;
            return new AsyncUnaryCall<byte[]>(Task.FromResult(Array.Empty<byte>()), Task.FromResult(new Metadata()), () => Status.DefaultSuccess, () => [], () => { });
        });
        _ = await call.ResponseAsync;
        return (seen, passed);
    }

    [SuppressMessage("Performance", "CA1812", Justification = "Instantiated by the host.")]
    private sealed class AlienListenerFactory : IConnectionListenerFactory, IConnectionListenerFactorySelector
    {
        public bool CanBind(EndPoint endpoint) => false;

        public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    [SuppressMessage("Performance", "CA1812", Justification = "Instantiated in the test body.")]
    private sealed class RecordingWriteStream(Stream inner, Action<byte[]> written) : Stream
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

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            written(buffer.ToArray());
            return inner.WriteAsync(buffer, cancellationToken);
        }

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
}
