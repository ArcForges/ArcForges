// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ArcForges.Persistence.Resources;

internal enum AppendFrameKind : byte { Chunk = 1, Segment = 2, Gap = 3, Seal = 4 }
internal enum AppendScanFailure
{
    None, MissingSeal, TruncatedHeader, InvalidMagic, UnsupportedVersion, InvalidMetadata,
    SequenceMismatch, PayloadTooLarge, TruncatedPayload, ChecksumMismatch, FrameLimitExceeded, DataAfterSeal
}
internal sealed record AppendFrame(long Offset, long PayloadOffset, int PayloadLength, long EndOffset,
    AppendFrameKind Kind, long Sequence);
internal sealed record AppendScanResult(IReadOnlyList<AppendFrame> Frames, long VerifiedEndOffset,
    bool Sealed, AppendScanFailure Failure, long FailureOffset);

/// <summary>Bounded framing only. The owner flushes before acknowledgement and records recovery loss separately.</summary>
internal static class AppendFrameCodec
{
    internal const int HeaderLength = 64;
    internal const int MaximumPayloadLength = 4 * 1024 * 1024;
    private const int MaximumFrameCount = 1_000_000;

    internal static AppendFrame Write(Stream stream, AppendFrameKind kind, long sequence, ReadOnlySpan<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanWrite || !stream.CanSeek) throw new ArgumentException("A seekable writable stream is required.", nameof(stream));
        if (stream.Position != stream.Length) throw new InvalidOperationException("Frames may only append at the physical end.");
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        if (kind is < AppendFrameKind.Chunk or > AppendFrameKind.Seal) throw new ArgumentOutOfRangeException(nameof(kind));
        if (payload.Length > MaximumPayloadLength) throw new ArgumentOutOfRangeException(nameof(payload));
        if ((kind == AppendFrameKind.Seal) != payload.IsEmpty) throw new ArgumentException("Only the seal has an empty payload.", nameof(payload));
        var offset = stream.Position;
        var end = checked(offset + HeaderLength + payload.Length);
        Span<byte> header = stackalloc byte[HeaderLength];
        header.Clear();
        "AFAPPEND"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt16LittleEndian(header[8..], 1);
        header[10] = (byte)kind;
        BinaryPrimitives.WriteInt64LittleEndian(header[12..], sequence);
        BinaryPrimitives.WriteUInt32LittleEndian(header[20..], (uint)payload.Length);
        ComputeChecksum(header[..32], payload).CopyTo(header[32..]);
        stream.Write(header);
        stream.Write(payload);
        return new(offset, offset + HeaderLength, payload.Length, end, kind, sequence);
    }

    internal static AppendScanResult Scan(Stream stream, int maximumFrames = MaximumFrameCount)
    {
        RequireReadable(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumFrames);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumFrames, MaximumFrameCount);
        stream.Position = 0;
        var frames = new List<AppendFrame>();
        long boundary = 0;
        while (boundary < stream.Length)
        {
            if (frames.Count == maximumFrames) return Result(AppendScanFailure.FrameLimitExceeded);
            var failure = ReadOne(stream, frames.Count + 1L, out var frame, out _);
            if (failure != AppendScanFailure.None) return Result(failure);
            frames.Add(frame!);
            boundary = frame!.EndOffset;
            if (frame.Kind == AppendFrameKind.Seal)
                return Result(boundary == stream.Length ? AppendScanFailure.None : AppendScanFailure.DataAfterSeal, true);
        }
        return Result(AppendScanFailure.MissingSeal);

        AppendScanResult Result(AppendScanFailure failure, bool sealedCapture = false) =>
            new(frames.AsReadOnly(), boundary, sealedCapture && failure == AppendScanFailure.None, failure, boundary);
    }

    internal static byte[] ReadVerifiedPayload(Stream stream, AppendFrame frame)
    {
        RequireReadable(stream);
        ArgumentNullException.ThrowIfNull(frame);
        if (frame.Offset < 0 || frame.Sequence <= 0 || frame.PayloadLength < 0 || frame.PayloadLength > MaximumPayloadLength ||
            frame.PayloadOffset != checked(frame.Offset + HeaderLength) || frame.EndOffset != checked(frame.PayloadOffset + frame.PayloadLength))
            throw new ArgumentException("Invalid frame descriptor.", nameof(frame));
        stream.Position = frame.Offset;
        var failure = ReadOne(stream, frame.Sequence, out var actual, out var payload);
        if (failure != AppendScanFailure.None || actual != frame)
            throw new InvalidDataException($"The requested frame no longer verifies: {failure}.");
        return payload!;
    }

    private static AppendScanFailure ReadOne(Stream stream, long expectedSequence, out AppendFrame? frame, out byte[]? payload)
    {
        frame = null;
        payload = null;
        var offset = stream.Position;
        if (stream.Length - offset < HeaderLength) return AppendScanFailure.TruncatedHeader;
        Span<byte> header = stackalloc byte[HeaderLength];
        try { stream.ReadExactly(header); }
        catch (EndOfStreamException) { return AppendScanFailure.TruncatedHeader; }
        if (!header[..8].SequenceEqual("AFAPPEND"u8)) return AppendScanFailure.InvalidMagic;
        if (BinaryPrimitives.ReadUInt16LittleEndian(header[8..]) != 1) return AppendScanFailure.UnsupportedVersion;
        var kind = (AppendFrameKind)header[10];
        if (kind is < AppendFrameKind.Chunk or > AppendFrameKind.Seal || header[11] != 0 ||
            BinaryPrimitives.ReadUInt64LittleEndian(header[24..]) != 0) return AppendScanFailure.InvalidMetadata;
        var sequence = BinaryPrimitives.ReadInt64LittleEndian(header[12..]);
        if (sequence != expectedSequence || sequence <= 0) return AppendScanFailure.SequenceMismatch;
        var size = BinaryPrimitives.ReadUInt32LittleEndian(header[20..]);
        if (size > MaximumPayloadLength) return AppendScanFailure.PayloadTooLarge;
        if ((kind == AppendFrameKind.Seal) != (size == 0)) return AppendScanFailure.InvalidMetadata;
        if (stream.Length - stream.Position < size) return AppendScanFailure.TruncatedPayload;
        payload = new byte[(int)size];
        try { stream.ReadExactly(payload); }
        catch (EndOfStreamException) { payload = null; return AppendScanFailure.TruncatedPayload; }
        if (!CryptographicOperations.FixedTimeEquals(header[32..], ComputeChecksum(header[..32], payload)))
        {
            payload = null;
            return AppendScanFailure.ChecksumMismatch;
        }
        frame = new(offset, offset + HeaderLength, (int)size, stream.Position, kind, sequence);
        return AppendScanFailure.None;
    }

    private static byte[] ComputeChecksum(ReadOnlySpan<byte> header, ReadOnlySpan<byte> payload)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(header);
        hash.AppendData(payload);
        return hash.GetHashAndReset();
    }

    private static void RequireReadable(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("A seekable readable stream is required.", nameof(stream));
    }
}
