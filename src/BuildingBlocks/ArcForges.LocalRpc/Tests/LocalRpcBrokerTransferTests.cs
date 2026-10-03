#pragma warning disable CA2000 // Test mappings and the helper side are handed to the rig, which disposes them.
// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.Core;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// The broker over real Kestrel HTTP/2 and Grpc.Net.Client on in-memory duplex streams, with the bounds layer of PLT.13 in
/// front of a hand-written test-only helper service (the generated sandbox contract is not admitted here). These are offline
/// fixtures: they are not OS-stream evidence and no real helper, mapping or process takes part.
/// </summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcBrokerTransferTests
{
    private const int Active = LocalRpcLimits.DefaultMaxActiveCalls;
    private const int Queued = LocalRpcLimits.DefaultMaxQueuedCalls;
    private static readonly TimeSpan Patience = BoundsHarness.Patience;

    [Fact]
    public async Task ALargeBufferCrossesAsAGrantASealAndAnAcknowledgementNeverAsMessageBytes()
    {
        var ct = TestContext.Current.CancellationToken;
        const int size = 3 * 1024 * 1024;
        await using var rig = await TransferRig.StartAsync(cancelIsControl: true, slotBytes: size, ct);

        for (var round = 1UL; round <= 2; round++)
        {
            var grant = await rig.GrantAsync(0, size, ct);
            Assert.Equal(round, grant.Sequence);
            var (refusal, seal) = BrokerCodec.DecodeSeal(await rig.Fill(grant, 0, size, seed: (byte)(10 + round), hold: false).ResponseAsync.WaitAsync(Patience, ct));
            Assert.Equal(LocalRpcBrokerRefusal.None, refusal);
            Assert.Equal(LocalRpcBrokerRefusal.None, rig.Session.Seal(seal!));

            var copy = await rig.Session.CopyAsync(0, grant.Sequence, ct);
            Assert.True(copy.IsSuccess);
            using var buffer = copy.Value!;
            Assert.Equal(size, buffer.Length);
            Assert.True(buffer.Bytes.Span.SequenceEqual(BrokerRig.Pattern(size, (byte)(10 + round))));

            var ack = rig.Session.Acknowledge(0, grant.Sequence).Value!;
            var reply = await rig.Invoker.AsyncUnaryCall(BrokerProbe.AckBuffer, null, TransferRig.Options(), BrokerCodec.Encode(ack)).ResponseAsync.WaitAsync(Patience, ct);
            Assert.Equal((byte)LocalRpcBrokerRefusal.None, reply[0]);
        }

        // Six MiB moved, and no message was ever larger than a descriptor.
        Assert.True(rig.Service.LargestMessage < 256, "largest message " + rig.Service.LargestMessage);
        Assert.Equal(LocalRpcSlotState.Free, rig.Service.Child.SlotStates[0]);
        Assert.Equal(LocalRpcSlotState.Free, rig.Session.GetSnapshot().Slots[0]);
        Assert.Equal(3UL, rig.Session.GetSnapshot().NextSequences[0]);
    }

    [Fact]
    public async Task AGrantOrAcknowledgementOfAnotherSessionIsRefusedOnBothSides()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var rig = await TransferRig.StartAsync(cancelIsControl: true, slotBytes: 4096, ct);
        var grant = await rig.GrantAsync(0, 4096, ct);
        var (_, seal) = BrokerCodec.DecodeSeal(await rig.Fill(grant, 0, 100, seed: 1, hold: false).ResponseAsync.WaitAsync(Patience, ct));

        // A second session of the same registry (another invocation) never accepts the first one's seal.
        var otherMap = new MemoryMapping(4096);
        var other = rig.Registry.CreateSession(new LocalRpcBrokerSessionOptions { InvocationId = Guid.NewGuid(), LeaseId = BrokerRig.Lease, Generation = BrokerRig.GenerationValue, Slots = [otherMap] }).Value!;
        Assert.Equal(grant, other.Grant(0, 4096).Value);
        Assert.Equal(LocalRpcBrokerRefusal.WrongSession, other.Seal(seal!));
        Assert.Equal(LocalRpcSlotState.Writing, other.GetSnapshot().Slots[0]);

        // And the helper never accepts an acknowledgement minted by it.
        var foreignAck = new LocalRpcBufferAck(other.InvocationId, BrokerRig.Lease, BrokerRig.GenerationValue, 0, grant.Sequence, seal!.Digest);
        var reply = await rig.Invoker.AsyncUnaryCall(BrokerProbe.AckBuffer, null, TransferRig.Options(), BrokerCodec.Encode(foreignAck)).ResponseAsync.WaitAsync(Patience, ct);
        Assert.Equal((byte)LocalRpcBrokerRefusal.WrongSession, reply[0]);
        Assert.Equal(LocalRpcSlotState.Sealed, rig.Service.Child.SlotStates[0]);
    }

    [Fact]
    public async Task CancellationProgressesThroughAReservedControlSlotWhileTheDataLaneIsSaturated()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var rig = await TransferRig.StartAsync(cancelIsControl: true, slotBytes: 64 * 1024, ct);
        var grant = await rig.GrantAsync(0, 64 * 1024, ct);

        // One data slot is held by a transfer in progress, fifteen more and sixty-four queued by other work.
        var fill = rig.Fill(grant, 0, 32 * 1024, seed: 4, hold: true);
        await BoundsHarness.WaitUntilAsync(() => rig.Service.Holding == 1, "the held transfer", ct);
        var work = await rig.SaturateAsync(ct);
        var snapshot = rig.Harness.Server.GetBoundsSnapshot();
        Assert.Equal(Active, snapshot.DataActive);
        Assert.Equal(Queued, snapshot.DataQueued);

        // Ordinary data dispatch really is full: one more data call is refused before dispatch.
        var refused = await ProbeClient.FailureAsync(rig.Invoker.AsyncUnaryCall(BrokerProbe.GrantSlot, null, TransferRig.Options(), BrokerCodec.Encode(new LocalRpcSlotGrant(1, 1, 10))));
        Assert.Equal(StatusCode.ResourceExhausted, refused.StatusCode);
        Assert.True(LocalRpcRefusal.TryRead(refused, out var refusal));
        Assert.Equal(LocalRpcRefusalReason.DataQueueFull, refusal!.Reason);

        var cancelBefore = snapshot.ControlAdmitted[LocalRpcControlOperation.Cancellation];
        var renewBefore = snapshot.ControlAdmitted[LocalRpcControlOperation.LeaseRenewal];
        var timer = Stopwatch.StartNew();
        rig.Session.Cancel();
        var cancelReply = await rig.Invoker.AsyncUnaryCall(BrokerProbe.CancelSession, null, TransferRig.Options(), []).ResponseAsync.WaitAsync(Patience, ct);
        var cancelTook = timer.Elapsed;

        Assert.Equal(1, cancelReply[0]);
        Assert.True(cancelTook < TimeSpan.FromSeconds(5), "cancel took " + cancelTook);
        var after = rig.Harness.Server.GetBoundsSnapshot();
        Assert.Equal(cancelBefore + 1, after.ControlAdmitted[LocalRpcControlOperation.Cancellation]);
        Assert.Equal(0, after.Refused[LocalRpcRefusalReason.ControlBusy]);

        // The held transfer was stopped by the helper's cancellation, and nothing is recyclable.
        var failure = await ProbeClient.FailureAsync(fill);
        Assert.Equal(StatusCode.Cancelled, failure.StatusCode);
        Assert.True(rig.Service.Child.Cancelled.IsCancellationRequested);
        Assert.Equal(LocalRpcSlotState.Quarantined, rig.Service.Child.SlotStates[0]);
        Assert.Equal(LocalRpcBrokerSessionState.Cancelled, rig.Session.State);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, rig.Session.Grant(1, 10).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, (await rig.Session.CopyAsync(0, grant.Sequence, ct)).Refusal);
        Assert.Equal(LocalRpcBrokerRefusal.Cancelled, rig.Service.Child.Accept(new LocalRpcSlotGrant(1, 1, 10)).Refusal);

        // Lease renewal takes a control slot as well while the lane stays full.
        var stillSaturated = rig.Harness.Server.GetBoundsSnapshot();
        Assert.Equal(Active, stillSaturated.DataActive);
        var renewReply = await rig.Invoker.AsyncUnaryCall(BrokerProbe.RenewSession, null, TransferRig.Options(), []).ResponseAsync.WaitAsync(Patience, ct);
        Assert.Equal(1, renewReply[0]);
        Assert.Equal(renewBefore + 1, rig.Harness.Server.GetBoundsSnapshot().ControlAdmitted[LocalRpcControlOperation.LeaseRenewal]);

        rig.Session.Close();
        Assert.All(rig.Maps, map => Assert.Equal(1, map.Disposals));
        Assert.Equal(LocalRpcBrokerEndReason.Closed, Assert.Single(rig.Ends).Reason);
        await rig.DrainAsync(work, ct);
    }

    [Fact]
    public async Task WithoutTheControlDeclarationTheSameCancelIsRefusedBehindTheSaturatedLane()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var rig = await TransferRig.StartAsync(cancelIsControl: false, slotBytes: 64 * 1024, ct);
        var grant = await rig.GrantAsync(0, 64 * 1024, ct);
        var fill = rig.Fill(grant, 0, 1024, seed: 4, hold: true);
        await BoundsHarness.WaitUntilAsync(() => rig.Service.Holding == 1, "the held transfer", ct);
        var work = await rig.SaturateAsync(ct);
        var cancelBefore = rig.Harness.Server.GetBoundsSnapshot().ControlAdmitted[LocalRpcControlOperation.Cancellation];

        var failure = await ProbeClient.FailureAsync(rig.Invoker.AsyncUnaryCall(BrokerProbe.CancelSession, null, TransferRig.Options(), []));

        // A cancel that is only an ordinary data call cannot get through: this is what the control slot is for.
        Assert.Equal(StatusCode.ResourceExhausted, failure.StatusCode);
        Assert.True(LocalRpcRefusal.TryRead(failure, out var refusal));
        Assert.Equal(LocalRpcRefusalReason.DataQueueFull, refusal!.Reason);
        Assert.Equal(cancelBefore, rig.Harness.Server.GetBoundsSnapshot().ControlAdmitted[LocalRpcControlOperation.Cancellation]);
        Assert.False(rig.Service.Child.Cancelled.IsCancellationRequested);
        Assert.Equal(1, rig.Service.Holding);

        rig.Service.Child.Cancel();
        _ = await ProbeClient.FailureAsync(fill);
        await rig.DrainAsync(work, ct);
    }

    [Fact]
    public async Task AReaderThatStopsReadingMultiMegabyteResponsesNeverBlocksAnotherPeerAndTheWireStaysWithinFlowControl()
    {
        var ct = TestContext.Current.CancellationToken;
        const int response = (4 * 1024 * 1024) - 1024;
        var written = 0L;
        await using var rig = await TransferRig.StartAsync(cancelIsControl: true, slotBytes: 4096, ct, wrapServerStream: stream => new WriteCountingStream(stream, count => Interlocked.Add(ref written, count)));
        var stallable = default(StallableStream);
        await using var stalled = LocalRpcClientChannel.CreateFromStreams(
            _ => ValueTask.FromResult<Stream>(stallable = new StallableStream(rig.Harness.NewClientStream())));
        await using var healthy = rig.Harness.NewChannel();
        var stalledInvoker = stalled.CallInvoker;
        _ = await stalledInvoker.AsyncUnaryCall(BrokerProbe.RenewSession, null, TransferRig.Options(), []).ResponseAsync.WaitAsync(Patience, ct);
        var before = GC.GetTotalMemory(true);

        stallable!.Stall();
        var calls = Enumerable.Range(0, Active).Select(_ =>
            stalledInvoker.AsyncUnaryCall(BrokerProbe.Big, null, new CallOptions(deadline: DateTime.UtcNow + Patience), BigRequest(response))).ToList();
        await BoundsHarness.WaitUntilAsync(() => rig.Harness.Server.GetBoundsSnapshot().DataAdmitted >= Active, "sixteen big responses to be produced", ct);
        await Task.Delay(500, ct);
        var writtenWhileStalled = Interlocked.Read(ref written);
        var heldWhileStalled = GC.GetTotalMemory(true) - before;
        var whileStalled = rig.Harness.Server.GetBoundsSnapshot();

        // Another peer is served at once, control calls included, while the first peer is not reading.
        var probe = new ProbeClient(healthy.CallInvoker);
        _ = await probe.Health().ResponseAsync.WaitAsync(TimeSpan.FromSeconds(5), ct);
        var peerWork = probe.Work(1000, deadline: DateTime.UtcNow + Patience);
        await BoundsHarness.WaitUntilAsync(() => rig.Harness.Probe.Running == 1, "another peer's data call", ct);
        Assert.True(rig.Harness.Probe.Release(1000));
        _ = await peerWork.ResponseAsync.WaitAsync(Patience, ct);

        stallable.Resume();
        foreach (var call in calls)
        {
            Assert.Equal(response, (await call.ResponseAsync.WaitAsync(Patience, ct)).Length);
        }

        // What this characterizes (measured, not designed): the wire stays within the client's flow-control windows, the handlers
        // finished at once so no admission slot is pinned, and the server holds one response per call in memory until the peer reads
        // it. That memory is outside the 16/64 admission bounds; it is bounded only by the stream cap, which the README states.
        Assert.True(writtenWhileStalled < 1024 * 1024, "server wrote " + writtenWhileStalled + " bytes to a reader that was not reading");
        Assert.Equal(0, whileStalled.DataActive);
        Assert.Equal(0, whileStalled.DataQueued);
        Assert.True(heldWhileStalled < Active * (response + (256 * 1024)), "server held " + heldWhileStalled + " bytes for " + Active + " unread responses");
        var end = rig.Harness.Server.GetBoundsSnapshot();
        Assert.Equal(0, end.DataActive);
        Assert.Equal(0, end.DataQueued);
        Assert.Equal(0, end.ControlActive);
    }

    private static byte[] BigRequest(int size)
    {
        var bytes = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(bytes, size);
        return bytes;
    }

    /// <summary>The parent and helper sides of one invocation over one in-memory connection.</summary>
    private sealed class TransferRig : IAsyncDisposable
    {
        private readonly List<LocalRpcBrokerEnd> _ends;
        private readonly LocalRpcClientChannel _channel;

        private TransferRig(BoundsHarness harness, LocalRpcClientChannel channel, BrokerProbeService service, MemoryMapping[] maps, LocalRpcBrokerRegistry registry, LocalRpcBrokerSession session, List<LocalRpcBrokerEnd> ends)
        {
            Harness = harness;
            _channel = channel;
            Service = service;
            Maps = maps;
            Registry = registry;
            Session = session;
            _ends = ends;
        }

        internal BoundsHarness Harness { get; }

        internal BrokerProbeService Service { get; }

        internal MemoryMapping[] Maps { get; }

        internal LocalRpcBrokerRegistry Registry { get; }

        internal LocalRpcBrokerSession Session { get; }

        internal CallInvoker Invoker => _channel.CallInvoker;

        internal IReadOnlyList<LocalRpcBrokerEnd> Ends
        {
            get
            {
                lock (_ends)
                {
                    return [.. _ends];
                }
            }
        }

        internal static async Task<TransferRig> StartAsync(
            bool cancelIsControl,
            int slotBytes,
            CancellationToken cancellationToken,
            LocalRpcLimits? limits = null,
            Func<Stream, Stream>? wrapServerStream = null)
        {
            var maps = Enumerable.Range(0, 3).Select(_ => new MemoryMapping(slotBytes)).ToArray();
            var child = new LocalRpcBrokerChild(BrokerRig.Invocation, BrokerRig.Lease, BrokerRig.GenerationValue, [slotBytes, slotBytes, slotBytes]);
            var service = new BrokerProbeService(child, maps);
            var harness = await BoundsHarness.StartAsync(
                limits,
                configure: builder =>
                {
                    _ = builder.AddService(service).RegisterControl(LocalRpcControlOperation.LeaseRenewal, BrokerProbe.RenewSession);
                    if (cancelIsControl)
                    {
                        _ = builder.RegisterControl(LocalRpcControlOperation.Cancellation, BrokerProbe.CancelSession);
                    }
                },
                wrapServerStream: wrapServerStream,
                cancellationToken: cancellationToken);
            var registry = new LocalRpcBrokerRegistry();
            var ends = new List<LocalRpcBrokerEnd>();
            var session = registry.CreateSession(new LocalRpcBrokerSessionOptions
            {
                InvocationId = BrokerRig.Invocation,
                LeaseId = BrokerRig.Lease,
                Generation = BrokerRig.GenerationValue,
                Slots = maps,
                Ended = end =>
                {
                    lock (ends)
                    {
                        ends.Add(end);
                    }
                },
            }).Value!;
            return new TransferRig(harness, harness.NewChannel(), service, maps, registry, session, ends);
        }

        internal static CallOptions Options() => new(deadline: DateTime.UtcNow + Patience);

        internal async Task<LocalRpcSlotGrant> GrantAsync(uint slot, ulong capacity, CancellationToken cancellationToken)
        {
            var grant = Session.Grant(slot, capacity).Value!;
            var reply = await Invoker.AsyncUnaryCall(BrokerProbe.GrantSlot, null, Options(), BrokerCodec.Encode(grant)).ResponseAsync.WaitAsync(Patience, cancellationToken);
            Assert.Equal((byte)LocalRpcBrokerRefusal.None, reply[0]);
            return grant;
        }

        internal AsyncUnaryCall<byte[]> Fill(LocalRpcSlotGrant grant, ulong offset, int length, byte seed, bool hold) =>
            Invoker.AsyncUnaryCall(BrokerProbe.Fill, null, Options(), BrokerCodec.EncodeFill(grant.SlotId, grant.Sequence, offset, (uint)length, seed, hold));

        /// <summary>Fills the rest of the data lane with ordinary held calls: the active slots, then the whole queue.</summary>
        internal async Task<List<AsyncUnaryCall<byte[]>>> SaturateAsync(CancellationToken cancellationToken)
        {
            var client = new ProbeClient(Invoker);
            var calls = new List<AsyncUnaryCall<byte[]>>();
            for (var id = 0; id < Active - 1; id++)
            {
                calls.Add(client.Work(id, deadline: DateTime.UtcNow + Patience));
                var running = id + 1;
                await BoundsHarness.WaitUntilAsync(() => Harness.Probe.Running == running, "an active call", cancellationToken);
            }

            for (var id = Active - 1; id < Active - 1 + Queued; id++)
            {
                calls.Add(client.Work(id, deadline: DateTime.UtcNow + Patience));
                var queuedNow = id - (Active - 1) + 1;
                await BoundsHarness.WaitUntilAsync(() => Harness.Server.GetBoundsSnapshot().DataQueued == queuedNow, "a queued call", cancellationToken);
            }

            return calls;
        }

        internal async Task DrainAsync(List<AsyncUnaryCall<byte[]>> calls, CancellationToken cancellationToken)
        {
            using var stop = new CancellationTokenSource();
            var releaser = Task.Run(
                async () =>
                {
                    while (!stop.IsCancellationRequested)
                    {
                        foreach (var id in Harness.Probe.Started)
                        {
                            _ = Harness.Probe.Release(id);
                        }

                        await Task.Delay(5, CancellationToken.None);
                    }
                },
                CancellationToken.None);
            await Task.WhenAll(calls.Select(call => call.ResponseAsync)).WaitAsync(Patience, cancellationToken);
            await stop.CancelAsync();
            await releaser;
        }

        public async ValueTask DisposeAsync()
        {
            Service.Child.Dispose();
            Session.Dispose();
            Registry.Dispose();
            await _channel.DisposeAsync();
            await Harness.DisposeAsync();
        }
    }

    /// <summary>A client stream that stops delivering bytes to the HTTP/2 client when told to, like a peer that stopped reading.</summary>
    private sealed class StallableStream(Stream inner) : Stream
    {
        private TaskCompletionSource? _stall;

        public override bool CanRead => true;

        public override bool CanWrite => true;

        public override bool CanSeek => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        internal void Stall() => Volatile.Write(ref _stall, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));

        internal void Resume() => Volatile.Read(ref _stall)?.TrySetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var gate = Volatile.Read(ref _stall);
            if (gate is not null)
            {
                await gate.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            return await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
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

    /// <summary>Counts the bytes written through a stream: what the server pushed at a peer.</summary>
    private sealed class WriteCountingStream(Stream inner, Action<int> counted) : Stream
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

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            counted(buffer.Length);
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
