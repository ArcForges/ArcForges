// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using Xunit;

namespace ArcForges.Persistence.Resources.Tests;

public sealed class AppendFrameCodecTests
{
    [Fact]
    public void EveryByteTruncationReturnsOnlyVerifiedPrefixAndPreservesEvidence()
    {
        using var complete = new MemoryStream();
        var first = AppendFrameCodec.Write(complete, AppendFrameKind.Chunk, 1, "first"u8);
        var second = AppendFrameCodec.Write(complete, AppendFrameKind.Gap, 2, "loss"u8);
        AppendFrameCodec.Write(complete, AppendFrameKind.Seal, 3, []);
        var bytes = complete.ToArray();
        for (var length = 0; length <= bytes.Length; length++)
        {
            var prefix = bytes[..length];
            using var interrupted = new MemoryStream(prefix, writable: false);
            var result = AppendFrameCodec.Scan(interrupted);
            var expected = length >= second.EndOffset ? second.EndOffset : length >= first.EndOffset ? first.EndOffset : 0;
            Assert.Equal(length == bytes.Length ? bytes.Length : expected, result.VerifiedEndOffset);
            Assert.Equal(length == bytes.Length, result.Sealed);
            Assert.Equal(result.VerifiedEndOffset, result.FailureOffset);
            if (length < bytes.Length) Assert.NotEqual(AppendScanFailure.None, result.Failure);
            Assert.Equal(prefix, interrupted.ToArray());
        }
    }

    [Theory]
    [InlineData(10)] // Another valid kind: metadata must be checksum-bound.
    [InlineData(32)]
    [InlineData(64)]
    public void MetadataAndPayloadDamageCannotEnterTheVerifiedPrefix(int offset)
    {
        using var stream = Capture();
        var bytes = stream.ToArray();
        bytes[offset] ^= offset == 10 ? (byte)2 : (byte)1;
        using var damaged = new MemoryStream(bytes);
        var result = AppendFrameCodec.Scan(damaged);
        Assert.Equal(AppendScanFailure.ChecksumMismatch, result.Failure);
        Assert.Empty(result.Frames);
        Assert.Equal(0, result.VerifiedEndOffset);
    }

    [Fact]
    public void BoundsVersionsSequenceAndPostSealDamageAreExplicit()
    {
        using var stream = Capture();
        var bytes = stream.ToArray();
        AssertFailure(bytes, 8, 2, AppendScanFailure.UnsupportedVersion);
        AssertFailure(bytes, 0, 0, AppendScanFailure.InvalidMagic);
        AssertFailure(bytes, 11, 1, AppendScanFailure.InvalidMetadata);
        AssertFailure(bytes, 12, 2, AppendScanFailure.SequenceMismatch);
        var oversized = (byte[])bytes.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(oversized.AsSpan(20), AppendFrameCodec.MaximumPayloadLength + 1u);
        using (var invalid = new MemoryStream(oversized))
            Assert.Equal(AppendScanFailure.PayloadTooLarge, AppendFrameCodec.Scan(invalid).Failure);
        using (var limited = new MemoryStream(bytes))
            Assert.Equal(AppendScanFailure.FrameLimitExceeded, AppendFrameCodec.Scan(limited, 1).Failure);
        using var trailing = new MemoryStream();
        trailing.Write(bytes); trailing.WriteByte(0);
        var result = AppendFrameCodec.Scan(trailing);
        Assert.Equal(AppendScanFailure.DataAfterSeal, result.Failure);
        Assert.False(result.Sealed);
        Assert.Equal(bytes.Length, result.VerifiedEndOffset);
    }

    [Fact]
    public void RangePayloadReadVerifiesTheWholeTouchedFrameAndDescriptor()
    {
        using var stream = Capture();
        var frame = AppendFrameCodec.Scan(stream).Frames[0];
        Assert.Equal("payload"u8.ToArray(), AppendFrameCodec.ReadVerifiedPayload(stream, frame));
        Assert.Throws<InvalidDataException>(() => AppendFrameCodec.ReadVerifiedPayload(stream, frame with { Kind = AppendFrameKind.Gap }));
        stream.Position = frame.EndOffset - 1;
        stream.WriteByte(0);
        Assert.Throws<InvalidDataException>(() => AppendFrameCodec.ReadVerifiedPayload(stream, frame));
    }

    [Fact]
    public void WriteRejectsInvalidBoundsWithoutChangingBytesAndScanPropagatesIoFailure()
    {
        using var stream = new MemoryStream();
        Assert.Throws<ArgumentOutOfRangeException>(() => AppendFrameCodec.Write(stream, AppendFrameKind.Chunk, 0, "x"u8));
        Assert.Throws<ArgumentException>(() => AppendFrameCodec.Write(stream, AppendFrameKind.Seal, 1, "x"u8));
        Assert.Throws<ArgumentException>(() => AppendFrameCodec.Write(stream, AppendFrameKind.Chunk, 1, []));
        Assert.Throws<ArgumentOutOfRangeException>(() => AppendFrameCodec.Write(stream, AppendFrameKind.Chunk, 1, new byte[AppendFrameCodec.MaximumPayloadLength + 1]));
        Assert.Equal(0, stream.Length);
        stream.WriteByte(0); stream.Position = 0;
        Assert.Throws<InvalidOperationException>(() => AppendFrameCodec.Write(stream, AppendFrameKind.Chunk, 1, "x"u8));
        using var broken = new FailingReadStream();
        Assert.Throws<IOException>(() => AppendFrameCodec.Scan(broken));
    }

    private static MemoryStream Capture()
    {
        var stream = new MemoryStream();
        AppendFrameCodec.Write(stream, AppendFrameKind.Chunk, 1, "payload"u8);
        AppendFrameCodec.Write(stream, AppendFrameKind.Seal, 2, []);
        return stream;
    }

    private static void AssertFailure(byte[] original, int offset, byte value, AppendScanFailure failure)
    {
        var bytes = (byte[])original.Clone(); bytes[offset] = value;
        using var stream = new MemoryStream(bytes);
        Assert.Equal(failure, AppendFrameCodec.Scan(stream).Failure);
    }

    private sealed class FailingReadStream() : MemoryStream(new byte[AppendFrameCodec.HeaderLength])
    {
        public override int Read(Span<byte> buffer) => throw new IOException("Injected read failure.");
    }
}
