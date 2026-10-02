// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.Core;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// A server over supplied in-memory streams that serves the real generated LocalBootstrap service and the test probe,
/// with the four control operations declared the way an owner declares them.
/// </summary>
internal sealed class BoundsHarness : IAsyncDisposable
{
    internal static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    private readonly Func<Stream, Stream>? _wrapServerStream;
    private int _connects;

    private BoundsHarness(
        LocalRpcStreamSupplier supplier,
        ProbeService probe,
        RecordingBootstrapService bootstrap,
        LocalRpcServer server,
        Func<Stream, Stream>? wrapServerStream)
    {
        _wrapServerStream = wrapServerStream;
        Supplier = supplier;
        Probe = probe;
        Bootstrap = bootstrap;
        Server = server;
    }

    internal LocalRpcStreamSupplier Supplier { get; }

    internal ProbeService Probe { get; }

    internal RecordingBootstrapService Bootstrap { get; }

    internal LocalRpcServer Server { get; }

    internal int Connects => Volatile.Read(ref _connects);

    internal static async Task<BoundsHarness> StartAsync(
        LocalRpcLimits? limits = null,
        TimeProvider? time = null,
        Action<LocalRpcServerBuilder>? configure = null,
        Func<Stream, Stream>? wrapServerStream = null,
        CancellationToken cancellationToken = default)
    {
        var supplier = new LocalRpcStreamSupplier();
        var probe = new ProbeService();
        var bootstrap = new RecordingBootstrapService();
        var builder = LocalRpcServer.CreateBuilder(supplier)
            .AddService(probe)
            .AddService(bootstrap)
            .RegisterControl(LocalRpcControlOperation.Bootstrap, LocalBootstrapService.Descriptor.FullName, "Challenge")
            .RegisterControl(LocalRpcControlOperation.Bootstrap, LocalBootstrapService.Descriptor.FullName, "Confirm")
            .RegisterControl(LocalRpcControlOperation.LeaseRenewal, LocalBootstrapService.Descriptor.FullName, "Renew")
            .RegisterControl(LocalRpcControlOperation.Cancellation, BoundsProbe.Cancel)
            .RegisterControl(LocalRpcControlOperation.Health, BoundsProbe.Health);
        if (limits is not null)
        {
            builder.Limits = limits;
        }

        if (time is not null)
        {
            _ = builder.UseTimeProvider(time);
        }

        configure?.Invoke(builder);
        var server = builder.Build();
        await server.StartAsync(cancellationToken).ConfigureAwait(false);
        return new BoundsHarness(supplier, probe, bootstrap, server, wrapServerStream);
    }

    /// <summary>Supplies a fresh connected pair to the server and returns the client end.</summary>
    internal Stream NewClientStream()
    {
        var (client, server) = InMemoryDuplexStream.CreatePair();
        if (!Supplier.TrySupply(_wrapServerStream is null ? server : _wrapServerStream(server)))
        {
            server.Dispose();
            client.Dispose();
            throw new InvalidOperationException("The supplier refused a stream.");
        }

        Interlocked.Increment(ref _connects);
        return client;
    }

    internal LocalRpcClientChannel NewChannel(LocalRpcLimits? limits = null) =>
        LocalRpcClientChannel.CreateFromStreams(_ => ValueTask.FromResult(NewClientStream()), limits);

    internal static async Task WaitUntilAsync(Func<bool> condition, string what, CancellationToken cancellationToken)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(Patience);
        while (!condition())
        {
            try
            {
                await Task.Delay(5, bounded.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("Timed out waiting for " + what + ".");
            }
        }
    }

    public ValueTask DisposeAsync() => Server.DisposeAsync();
}

/// <summary>Calls the probe service and the generated bootstrap service over one channel.</summary>
internal sealed class ProbeClient(CallInvoker invoker)
{
    internal CallInvoker Invoker { get; } = invoker;

    internal LocalBootstrapService.LocalBootstrapServiceClient Bootstrap { get; } = new(invoker);

    internal AsyncUnaryCall<byte[]> Work(int id, int padding = 0, DateTime? deadline = null) =>
        Invoker.AsyncUnaryCall(BoundsProbe.Work, null, new CallOptions(deadline: deadline), ProbeService.Request(id, padding));

    internal AsyncUnaryCall<byte[]> WorkUntilCancelled(int id, DateTime deadline, CancellationToken cancellation) =>
        Invoker.AsyncUnaryCall(BoundsProbe.Work, null, new CallOptions(deadline: deadline, cancellationToken: cancellation), ProbeService.Request(id));

    internal AsyncUnaryCall<byte[]> Cancel(int id) =>
        Invoker.AsyncUnaryCall(BoundsProbe.Cancel, null, new CallOptions(deadline: DateTime.UtcNow + BoundsHarness.Patience), ProbeService.Request(id));

    internal AsyncUnaryCall<byte[]> Health(bool hold = false, DateTime? deadline = null) =>
        Invoker.AsyncUnaryCall(BoundsProbe.Health, null, new CallOptions(deadline: deadline ?? DateTime.UtcNow + BoundsHarness.Patience), hold ? [0xEE] : [0x00]);

    internal AsyncUnaryCall<byte[]> Relay() =>
        Invoker.AsyncUnaryCall(BoundsProbe.Relay, null, new CallOptions(deadline: DateTime.UtcNow + BoundsHarness.Patience), [0]);

    internal AsyncUnaryCall<byte[]> Callback() =>
        Invoker.AsyncUnaryCall(BoundsProbe.Callback, null, new CallOptions(deadline: DateTime.UtcNow + BoundsHarness.Patience), [0]);

    internal static async Task<RpcException> FailureAsync(AsyncUnaryCall<byte[]> call)
    {
        try
        {
            _ = await call.ResponseAsync.WaitAsync(BoundsHarness.Patience).ConfigureAwait(false);
        }
        catch (RpcException exception)
        {
            return exception;
        }

        throw new InvalidOperationException("The call was expected to fail.");
    }
}
