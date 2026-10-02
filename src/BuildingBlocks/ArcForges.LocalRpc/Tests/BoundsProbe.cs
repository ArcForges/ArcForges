// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Collections.Concurrent;
using Grpc.Core;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// A hand-written, test-only unary service shaped like generated code. The pinned Platform contract has no Health or
/// Cancel method (cancellation is in the Sandbox package, which this repository does not admit), and the bounds layer
/// is contract-agnostic, so the probe stands in for those control methods and for a data method that can be held.
/// It proves bounds behavior only, never the contract of any real service.
/// </summary>
internal static class BoundsProbe
{
    internal const string ServiceName = "arcforges.test.bounds.v1.BoundsProbe";

    private static readonly Marshaller<byte[]> Bytes = Marshallers.Create(value => value, value => value);

    internal static readonly Method<byte[], byte[]> Work = Unary("Work");

    internal static readonly Method<byte[], byte[]> Cancel = Unary("Cancel");

    internal static readonly Method<byte[], byte[]> Health = Unary("Health");

    internal static readonly Method<byte[], byte[]> Relay = Unary("Relay");

    internal static readonly Method<byte[], byte[]> Callback = Unary("Callback");

    public static void BindService(ServiceBinderBase binder, BoundsProbeBase? service)
    {
        ArgumentNullException.ThrowIfNull(binder);
        binder.AddMethod(Work, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Work));
        binder.AddMethod(Cancel, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Cancel));
        binder.AddMethod(Health, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Health));
        binder.AddMethod(Relay, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Relay));
        binder.AddMethod(Callback, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Callback));
    }

    private static Method<byte[], byte[]> Unary(string name) => new(MethodType.Unary, ServiceName, name, Bytes, Bytes);

    [BindServiceMethod(typeof(BoundsProbe), nameof(BindService))]
    internal abstract class BoundsProbeBase
    {
        public virtual Task<byte[]> Work(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> Cancel(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> Health(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> Relay(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> Callback(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));
    }
}

/// <summary>
/// The probe's behavior. A Work call (first four bytes: a big-endian id) is held until released, cancelled by id or
/// cancelled by its own deadline or client, which lets a test fill every slot and then free them one at a time.
/// </summary>
internal sealed class ProbeService : BoundsProbe.BoundsProbeBase
{
    private readonly ConcurrentDictionary<int, Held> _held = new();
    private readonly object _sync = new();
    private readonly List<int> _started = [];
    private readonly List<int> _cancelledByDeadlineOrClient = [];
    private readonly TaskCompletionSource _healthGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentDictionary<int, TimeSpan> _remainingAtStart = new();
    private int _running;
    private int _peakRunning;
    private int _healthHeld;
    private int _callbackRuns;
    private long _bytesReceived;

    /// <summary>What a Relay call does inside its handler: the callback a handler makes to the peer.</summary>
    public Func<CancellationToken, Task<string>>? RelayAction { get; set; }

    /// <summary>What a Callback call does inside its handler.</summary>
    public Func<CancellationToken, Task<string>>? CallbackAction { get; set; }

    /// <summary>The deadline the handler saw when its call started, per id; <see cref="TimeSpan.MaxValue"/> when there was none.</summary>
    public IReadOnlyDictionary<int, TimeSpan> RemainingAtStart => _remainingAtStart;

    public int CallbackRuns => Volatile.Read(ref _callbackRuns);

    public int Running => Volatile.Read(ref _running);

    public int PeakRunning => Volatile.Read(ref _peakRunning);

    public int HealthHeld => Volatile.Read(ref _healthHeld);

    public long BytesReceived => Interlocked.Read(ref _bytesReceived);

    public IReadOnlyList<int> Started
    {
        get
        {
            lock (_sync)
            {
                return [.. _started];
            }
        }
    }

    public IReadOnlyList<int> Interrupted
    {
        get
        {
            lock (_sync)
            {
                return [.. _cancelledByDeadlineOrClient];
            }
        }
    }

    public static byte[] Request(int id, int padding = 0)
    {
        var request = new byte[4 + padding];
        BinaryPrimitives.WriteInt32BigEndian(request, id);
        return request;
    }

    public bool Release(int id) => _held.TryGetValue(id, out var held) && held.Completion.TrySetResult();

    public void ReleaseHealth() => _healthGate.TrySetResult();

    public override async Task<byte[]> Work(byte[] request, ServerCallContext context)
    {
        Interlocked.Add(ref _bytesReceived, request.Length);
        var id = BinaryPrimitives.ReadInt32BigEndian(request);
        var held = new Held();
        _held[id] = held;
        _remainingAtStart[id] = context.Deadline == DateTime.MaxValue ? TimeSpan.MaxValue : context.Deadline - DateTime.UtcNow;
        lock (_sync)
        {
            _started.Add(id);
        }

        EnterRunning();
        try
        {
            using var registration = context.CancellationToken.Register(() => held.Completion.TrySetCanceled(context.CancellationToken));
            await held.Completion.Task.ConfigureAwait(false);
            return request[..4];
        }
        catch (OperationCanceledException)
        {
            lock (_sync)
            {
                _cancelledByDeadlineOrClient.Add(id);
            }

            if (context.CancellationToken.IsCancellationRequested)
            {
                throw;
            }

            // A call ended by the probe's cancel method (not by its own deadline or client) reports Cancelled.
            throw new RpcException(new Status(StatusCode.Cancelled, "Cancelled by the control operation."));
        }
        finally
        {
            Interlocked.Decrement(ref _running);
            _ = _held.TryRemove(id, out _);
        }
    }

    /// <summary>The probe's cancellation method: cancels the held Work call whose id the request names.</summary>
    public override Task<byte[]> Cancel(byte[] request, ServerCallContext context)
    {
        var id = BinaryPrimitives.ReadInt32BigEndian(request);
        var found = _held.TryGetValue(id, out var held) && held.Completion.TrySetCanceled();
        return Task.FromResult(new[] { found ? (byte)1 : (byte)0 });
    }

    /// <summary>The probe's health method; a request starting with 0xEE holds its control slot until released.</summary>
    public override async Task<byte[]> Health(byte[] request, ServerCallContext context)
    {
        if (request.Length > 0 && request[0] == 0xEE)
        {
            Interlocked.Increment(ref _healthHeld);
            EnterRunning();
            try
            {
                using var registration = context.CancellationToken.Register(() => _healthGate.TrySetCanceled(context.CancellationToken));
                await _healthGate.Task.ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Decrement(ref _running);
            }
        }

        return [(byte)Running];
    }

    public override async Task<byte[]> Relay(byte[] request, ServerCallContext context)
    {
        var action = RelayAction ?? throw new InvalidOperationException("No relay action.");
        return System.Text.Encoding.ASCII.GetBytes(await action(context.CancellationToken).ConfigureAwait(false));
    }

    public override async Task<byte[]> Callback(byte[] request, ServerCallContext context)
    {
        Interlocked.Increment(ref _callbackRuns);
        var action = CallbackAction ?? throw new InvalidOperationException("No callback action.");
        return System.Text.Encoding.ASCII.GetBytes(await action(context.CancellationToken).ConfigureAwait(false));
    }

    private void EnterRunning()
    {
        var now = Interlocked.Increment(ref _running);
        int peak;
        while (now > (peak = Volatile.Read(ref _peakRunning)) && Interlocked.CompareExchange(ref _peakRunning, now, peak) != peak)
        {
        }
    }

    private sealed class Held
    {
        internal TaskCompletionSource Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
