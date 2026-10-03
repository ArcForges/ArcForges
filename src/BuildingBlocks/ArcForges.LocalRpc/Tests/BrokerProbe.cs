// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using Grpc.Core;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// A hand-written, test-only unary service that stands in for the helper side of the grant, seal, acknowledge and cancel
/// calls of a sandbox helper. The generated ContentSandboxService contract is not admitted in this repository, so this is
/// not that contract and proves nothing about its wire shapes: it carries the records of <see cref="LocalRpcBrokerChild"/> and
/// <see cref="LocalRpcBrokerSession"/> in a fixed binary layout so the bounds layer and the broker are exercised together.
/// </summary>
internal static class BrokerProbe
{
    internal const string ServiceName = "arcforges.test.broker.v1.BrokerProbe";

    private static readonly Marshaller<byte[]> Bytes = Marshallers.Create(value => value, value => value);

    internal static readonly Method<byte[], byte[]> GrantSlot = Unary("GrantSlot");

    internal static readonly Method<byte[], byte[]> Fill = Unary("Fill");

    internal static readonly Method<byte[], byte[]> AckBuffer = Unary("AckBuffer");

    internal static readonly Method<byte[], byte[]> CancelSession = Unary("CancelSession");

    internal static readonly Method<byte[], byte[]> RenewSession = Unary("RenewSession");

    internal static readonly Method<byte[], byte[]> Big = Unary("Big");

    public static void BindService(ServiceBinderBase binder, BrokerProbeBase? service)
    {
        ArgumentNullException.ThrowIfNull(binder);
        binder.AddMethod(GrantSlot, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.GrantSlot));
        binder.AddMethod(Fill, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Fill));
        binder.AddMethod(AckBuffer, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.AckBuffer));
        binder.AddMethod(CancelSession, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.CancelSession));
        binder.AddMethod(RenewSession, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.RenewSession));
        binder.AddMethod(Big, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Big));
    }

    private static Method<byte[], byte[]> Unary(string name) => new(MethodType.Unary, ServiceName, name, Bytes, Bytes);

    [BindServiceMethod(typeof(BrokerProbe), nameof(BindService))]
    internal abstract class BrokerProbeBase
    {
        public virtual Task<byte[]> GrantSlot(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> Fill(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> AckBuffer(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> CancelSession(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> RenewSession(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> Big(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));
    }
}

/// <summary>The fixed binary layout the probe uses for the broker records.</summary>
internal static class BrokerCodec
{
    internal const int FillRequestLength = 26;

    internal static byte[] Encode(LocalRpcSlotGrant grant)
    {
        var bytes = new byte[20];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, grant.SlotId);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(4), grant.Sequence);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(12), grant.Capacity);
        return bytes;
    }

    internal static LocalRpcSlotGrant DecodeGrant(byte[] bytes) =>
        new(BinaryPrimitives.ReadUInt32BigEndian(bytes), BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(4)), BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(12)));

    internal static byte[] EncodeFill(uint slot, ulong sequence, ulong offset, uint length, byte seed, bool hold)
    {
        var bytes = new byte[FillRequestLength];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, slot);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(4), sequence);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(12), offset);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(20), length);
        bytes[24] = seed;
        bytes[25] = hold ? (byte)1 : (byte)0;
        return bytes;
    }

    internal static byte[] Encode(LocalRpcBufferSeal seal)
    {
        var bytes = new byte[1 + 16 + 16 + 8 + 4 + 8 + 8 + 8 + 32 + 8];
        var span = bytes.AsSpan(1);
        LocalRpcCanonicalId.Write(seal.InvocationId, span[..16]);
        LocalRpcCanonicalId.Write(seal.LeaseId, span.Slice(16, 16));
        BinaryPrimitives.WriteUInt64BigEndian(span.Slice(32, 8), seal.Generation);
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(40, 4), seal.SlotId);
        BinaryPrimitives.WriteUInt64BigEndian(span.Slice(44, 8), seal.Sequence);
        BinaryPrimitives.WriteUInt64BigEndian(span.Slice(52, 8), seal.Offset);
        BinaryPrimitives.WriteUInt64BigEndian(span.Slice(60, 8), seal.Length);
        seal.Digest.AsSpan().CopyTo(span.Slice(68, 32));
        BinaryPrimitives.WriteUInt64BigEndian(span.Slice(100, 8), seal.RowStride);
        return bytes;
    }

    /// <summary>Reads a fill response: the refusal byte, and the seal when there was none.</summary>
    internal static (LocalRpcBrokerRefusal Refusal, LocalRpcBufferSeal? Seal) DecodeSeal(byte[] bytes)
    {
        var refusal = (LocalRpcBrokerRefusal)bytes[0];
        if (refusal != LocalRpcBrokerRefusal.None)
        {
            return (refusal, null);
        }

        var span = bytes.AsSpan(1);
        _ = LocalRpcCanonicalId.TryRead(span[..16], out var invocation);
        _ = LocalRpcCanonicalId.TryRead(span.Slice(16, 16), out var lease);
        return (
            refusal,
            new LocalRpcBufferSeal(
                invocation,
                lease,
                BinaryPrimitives.ReadUInt64BigEndian(span.Slice(32, 8)),
                BinaryPrimitives.ReadUInt32BigEndian(span.Slice(40, 4)),
                BinaryPrimitives.ReadUInt64BigEndian(span.Slice(44, 8)),
                BinaryPrimitives.ReadUInt64BigEndian(span.Slice(52, 8)),
                BinaryPrimitives.ReadUInt64BigEndian(span.Slice(60, 8)),
                LocalRpcDigest.FromBytes(span.Slice(68, 32)),
                BinaryPrimitives.ReadUInt64BigEndian(span.Slice(100, 8))));
    }

    internal static byte[] Encode(LocalRpcBufferAck ack)
    {
        var bytes = new byte[16 + 16 + 8 + 4 + 8 + 32];
        LocalRpcCanonicalId.Write(ack.InvocationId, bytes.AsSpan(0, 16));
        LocalRpcCanonicalId.Write(ack.LeaseId, bytes.AsSpan(16, 16));
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(32, 8), ack.Generation);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(40, 4), ack.SlotId);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(44, 8), ack.Sequence);
        ack.Digest.AsSpan().CopyTo(bytes.AsSpan(52, 32));
        return bytes;
    }

    internal static LocalRpcBufferAck DecodeAck(byte[] bytes)
    {
        _ = LocalRpcCanonicalId.TryRead(bytes.AsSpan(0, 16), out var invocation);
        _ = LocalRpcCanonicalId.TryRead(bytes.AsSpan(16, 16), out var lease);
        return new LocalRpcBufferAck(
            invocation,
            lease,
            BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(32, 8)),
            BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(40, 4)),
            BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(44, 8)),
            LocalRpcDigest.FromBytes(bytes.AsSpan(52, 32)));
    }
}

/// <summary>
/// The helper side behind the probe: it fills the mapping it was granted (the test shares the parent's mapping objects) and
/// seals through a real <see cref="LocalRpcBrokerChild"/>. A fill can be held, to keep one data slot busy mid-transfer.
/// </summary>
internal sealed class BrokerProbeService(LocalRpcBrokerChild child, MemoryMapping[] maps) : BrokerProbe.BrokerProbeBase
{
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _holding;
    private int _largestMessage;

    internal LocalRpcBrokerChild Child { get; } = child;

    /// <summary>Fill calls currently held.</summary>
    internal int Holding => Volatile.Read(ref _holding);

    /// <summary>The largest request or response message the probe handled, in bytes: bulk data never crosses as a message.</summary>
    internal int LargestMessage => Volatile.Read(ref _largestMessage);

    internal void ReleaseHeldFills() => _release.TrySetResult();

    public override Task<byte[]> GrantSlot(byte[] request, ServerCallContext context)
    {
        Note(request.Length);
        var refusal = Child.Accept(BrokerCodec.DecodeGrant(request)).Refusal;
        return Task.FromResult(Respond([(byte)refusal]));
    }

    public override async Task<byte[]> Fill(byte[] request, ServerCallContext context)
    {
        Note(request.Length);
        var slot = BinaryPrimitives.ReadUInt32BigEndian(request);
        var sequence = BinaryPrimitives.ReadUInt64BigEndian(request.AsSpan(4));
        var offset = BinaryPrimitives.ReadUInt64BigEndian(request.AsSpan(12));
        var length = BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(20));
        var content = BrokerRig.Pattern((int)length, request[24]);
        content.CopyTo(maps[slot].Bytes.AsSpan((int)offset));
        if (request[25] == 1)
        {
            _ = Interlocked.Increment(ref _holding);
            try
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(Child.Cancelled, context.CancellationToken);
                await _release.Task.WaitAsync(linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (Child.Cancelled.IsCancellationRequested)
            {
                throw new RpcException(new Status(StatusCode.Cancelled, "The invocation was cancelled."));
            }
            finally
            {
                _ = Interlocked.Decrement(ref _holding);
            }
        }

        var result = Child.Seal(slot, sequence, offset, content);
        return Respond(result.IsSuccess ? BrokerCodec.Encode(result.Value!) : [(byte)result.Refusal]);
    }

    public override Task<byte[]> AckBuffer(byte[] request, ServerCallContext context)
    {
        Note(request.Length);
        return Task.FromResult(Respond([(byte)Child.Acknowledge(BrokerCodec.DecodeAck(request))]));
    }

    public override Task<byte[]> CancelSession(byte[] request, ServerCallContext context)
    {
        Note(request.Length);
        Child.Cancel();
        return Task.FromResult(Respond([1]));
    }

    public override Task<byte[]> RenewSession(byte[] request, ServerCallContext context)
    {
        Note(request.Length);
        return Task.FromResult(Respond([1]));
    }

    public override Task<byte[]> Big(byte[] request, ServerCallContext context)
    {
        Note(request.Length);
        return Task.FromResult(new byte[BinaryPrimitives.ReadInt32BigEndian(request)]);
    }

    private byte[] Respond(byte[] response)
    {
        Note(response.Length);
        return response;
    }

    private void Note(int length)
    {
        int largest;
        while (length > (largest = Volatile.Read(ref _largestMessage)) && Interlocked.CompareExchange(ref _largestMessage, length, largest) != largest)
        {
        }
    }
}
