// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using ArcForges.LocalRpc;
using Google.Protobuf;

namespace ArcForges.ContentSandbox.Contracts;

/// <summary>The geometry of an image or page tile that a sealed buffer carries; the parent derives its expectation from its own request.</summary>
/// <param name="Format">1 for 8-bit RGBA, 2 for 32-bit float RGBA.</param>
/// <param name="FullWidth">The full image or page width in pixels.</param>
/// <param name="FullHeight">The full image or page height in pixels.</param>
/// <param name="TileX">The tile origin.</param>
/// <param name="TileY">The tile origin.</param>
/// <param name="TileWidth">The tile width.</param>
/// <param name="TileHeight">The tile height.</param>
internal readonly record struct TileGeometry(uint Format, uint FullWidth, uint FullHeight, uint TileX, uint TileY, uint TileWidth, uint TileHeight)
{
    /// <summary>Bytes per pixel of the format, or zero for an unknown format.</summary>
    internal uint PixelBytes => Format switch { 1 => 4u, 2 => 16u, _ => 0u };

    /// <summary>The geometry the parent expects of a seal: tile rows and bytes of one row.</summary>
    internal LocalRpcBufferLayout? Layout() =>
        PixelBytes == 0 || TileWidth == 0 || TileHeight == 0
            ? null
            : new LocalRpcBufferLayout(TileHeight, (ulong)TileWidth * PixelBytes);
}

/// <summary>
/// The mapping between the generated sandbox slot records and the LocalRpc brokered-data records. It is only a mapping:
/// every wire value is range-checked on the way in, and the brokered-data session still owns the sequence, capacity, digest
/// and geometry decisions.
/// </summary>
internal static class SandboxRecords
{
    internal static Id ToWireId(Guid value)
    {
        Span<byte> bytes = stackalloc byte[LocalRpcCanonicalId.Length];
        LocalRpcCanonicalId.Write(value, bytes);
        return new Id { Value = ByteString.CopyFrom(bytes) };
    }

    internal static bool TryReadId(Id? wire, out Guid id)
    {
        id = Guid.Empty;
        return wire is { HasValue: true } && LocalRpcCanonicalId.TryRead(wire.Value.Span, out id);
    }

    internal static Instant ToInstant(DateTimeOffset value) => new()
    {
        UnixSeconds = value.ToUnixTimeSeconds(),
        Nanos = (uint)(value.UtcTicks % TimeSpan.TicksPerSecond * 100),
    };

    internal static DateTimeOffset FromInstant(Instant? value) =>
        value is null
            ? DateTimeOffset.MinValue
            : DateTimeOffset.FromUnixTimeSeconds(value.UnixSeconds).AddTicks(value.Nanos / 100);

    internal static SandboxSlotGrant ToWire(LocalRpcSlotGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        return new SandboxSlotGrant { SlotId = grant.SlotId, Sequence = grant.Sequence, Capacity = grant.Capacity };
    }

    internal static bool TryReadGrant(SandboxSlotGrant? wire, out LocalRpcSlotGrant grant)
    {
        grant = new LocalRpcSlotGrant(0, 0, 0);
        if (wire is null || !wire.HasSlotId || !wire.HasSequence || !wire.HasCapacity)
        {
            return false;
        }

        grant = new LocalRpcSlotGrant(wire.SlotId, wire.Sequence, wire.Capacity);
        return true;
    }

    internal static SandboxBufferAck ToWire(LocalRpcBufferAck ack)
    {
        ArgumentNullException.ThrowIfNull(ack);
        return new SandboxBufferAck
        {
            InvocationId = ToWireId(ack.InvocationId),
            LeaseId = ToWireId(ack.LeaseId),
            Generation = ack.Generation,
            SlotId = ack.SlotId,
            Sequence = ack.Sequence,
            Digest = ack.Digest.ToHex(),
        };
    }

    internal static bool TryReadAck(SandboxBufferAck? wire, out LocalRpcBufferAck ack)
    {
        ack = null!;
        if (wire is null || !wire.HasGeneration || !wire.HasSlotId || !wire.HasSequence || !wire.HasDigest
            || !TryReadId(wire.InvocationId, out var invocation) || !TryReadId(wire.LeaseId, out var lease)
            || !LocalRpcDigest.TryParse(wire.Digest, out var digest))
        {
            return false;
        }

        ack = new LocalRpcBufferAck(invocation, lease, wire.Generation, wire.SlotId, wire.Sequence, digest);
        return true;
    }

    internal static SandboxBufferDescriptor ToWire(LocalRpcBufferSeal seal, TileGeometry geometry)
    {
        ArgumentNullException.ThrowIfNull(seal);
        return new SandboxBufferDescriptor
        {
            Version = 1,
            InvocationId = ToWireId(seal.InvocationId),
            LeaseId = ToWireId(seal.LeaseId),
            Generation = seal.Generation,
            SlotId = seal.SlotId,
            Sequence = seal.Sequence,
            Kind = 1,
            Format = geometry.Format,
            FullWidth = geometry.FullWidth,
            FullHeight = geometry.FullHeight,
            TileX = geometry.TileX,
            TileY = geometry.TileY,
            TileWidth = geometry.TileWidth,
            TileHeight = geometry.TileHeight,
            SampleStart = 0,
            SampleCount = 0,
            Offset = seal.Offset,
            Length = seal.Length,
            RowStride = seal.RowStride,
            Sha256 = seal.Digest.ToHex(),
        };
    }

    /// <summary>Reads a seal descriptor; a missing or malformed field is refused. The geometry it states is returned for the caller to compare with its own request.</summary>
    internal static bool TryReadSeal(SandboxBufferDescriptor? wire, out LocalRpcBufferSeal seal, out TileGeometry geometry)
    {
        seal = null!;
        geometry = default;
        if (wire is null || !wire.HasVersion || wire.Version != 1 || !wire.HasGeneration || !wire.HasSlotId || !wire.HasSequence
            || !wire.HasKind || wire.Kind != 1 || !wire.HasFormat || !wire.HasFullWidth || !wire.HasFullHeight
            || !wire.HasTileX || !wire.HasTileY || !wire.HasTileWidth || !wire.HasTileHeight
            || !wire.HasOffset || !wire.HasLength || !wire.HasRowStride || !wire.HasSha256
            || !TryReadId(wire.InvocationId, out var invocation) || !TryReadId(wire.LeaseId, out var lease)
            || !LocalRpcDigest.TryParse(wire.Sha256, out var digest))
        {
            return false;
        }

        seal = new LocalRpcBufferSeal(invocation, lease, wire.Generation, wire.SlotId, wire.Sequence, wire.Offset, wire.Length, digest, wire.RowStride);
        geometry = new TileGeometry(wire.Format, wire.FullWidth, wire.FullHeight, wire.TileX, wire.TileY, wire.TileWidth, wire.TileHeight);
        return true;
    }
}
