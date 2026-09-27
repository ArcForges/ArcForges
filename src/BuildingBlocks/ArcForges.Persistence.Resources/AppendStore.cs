// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Persistence.Resources;

/// <summary>A physical chunk slice. Segment identities are independent of chunk sequence numbers.</summary>
public sealed record ChunkSlice(long Chunk, int Offset, int Length);

public enum CaptureGapCause { None = 0, Overflow = 1, Dropped = 2, BackPressure = 3 }

/// <summary>Explicit lost acquisition interval in caller-defined monotonic timestamp units.</summary>
public sealed record CaptureGap(CaptureGapCause Cause, long StartTimestamp, long EndTimestamp, long? LostSamples);

/// <summary>Durably recorded recovery uncertainty. Unknown counts and acquisition times stay unknown.</summary>
public sealed record CaptureLoss(long ObservedBytes, long VerifiedBytes, string Cause)
{
    public EffectCertainty Effect { get; } = EffectCertainty.Unknown;
    public long? LostSamples { get; }
    public long? StartTimestamp { get; }
    public long? EndTimestamp { get; }
}

/// <summary>Single writer of immutable raw evidence. Each operation returns only after a stable-storage flush.</summary>
public sealed class AppendStore : IDisposable
{
    public const int MaximumChunkBytes = 4 * 1024 * 1024;
    public const int MaximumSegmentSlices = 1024;
    internal const int MaximumFrames = 1_000_000;
    private readonly FileStream _stream;
    private readonly object _gate = new();
    private readonly Dictionary<long, AppendFrame> _chunks = [];
    private readonly HashSet<Guid> _segments = [];
    private long _sequence;
    private bool _closed;
    private bool _faulted;

    internal AppendStore(FileStream stream) => _stream = stream;

    /// <summary>Never replaces or resumes existing raw evidence.</summary>
    public static AppendStore Create(string path) => new(new FileStream(path, FileMode.CreateNew,
        FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough));

    public long AppendChunk(ReadOnlySpan<byte> bytes)
    {
        lock (_gate)
        {
            if (bytes.Length is < 1 or > MaximumChunkBytes) throw new ArgumentOutOfRangeException(nameof(bytes));
            var frame = Append(AppendFrameKind.Chunk, bytes);
            _chunks.Add(frame.Sequence, frame);
            return frame.Sequence;
        }
    }

    /// <summary>Maps a domain segment to any ordered selection of committed physical chunk slices.</summary>
    public void MapSegment(Guid segment, IReadOnlyList<ChunkSlice> slices)
    {
        lock (_gate)
        {
            ArgumentNullException.ThrowIfNull(slices);
            EnsureWritable();
            if (segment == Guid.Empty || _segments.Contains(segment)) throw new ArgumentException("Segment must be new and nonempty.", nameof(segment));
            if (slices.Count is < 1 or > MaximumSegmentSlices) throw new ArgumentOutOfRangeException(nameof(slices));
            var stable = slices.ToArray();
            if (stable.Length is < 1 or > MaximumSegmentSlices) throw new ArgumentOutOfRangeException(nameof(slices));
            ValidateSlices(stable, _chunks);
            var payload = new byte[20 + stable.Length * 16];
            segment.TryWriteBytes(payload);
            BinaryPrimitives.WriteInt32LittleEndian(payload.AsSpan(16), stable.Length);
            for (int index = 0; index < stable.Length; index++)
            {
                var part = payload.AsSpan(20 + index * 16);
                BinaryPrimitives.WriteInt64LittleEndian(part, stable[index].Chunk);
                BinaryPrimitives.WriteInt32LittleEndian(part[8..], stable[index].Offset);
                BinaryPrimitives.WriteInt32LittleEndian(part[12..], stable[index].Length);
            }
            Append(AppendFrameKind.Segment, payload);
            _segments.Add(segment);
        }
    }

    public void RecordGap(CaptureGap gap)
    {
        lock (_gate)
        {
            ArgumentNullException.ThrowIfNull(gap);
            ValidateGap(gap);
            var payload = new byte[25];
            payload[0] = (byte)gap.Cause;
            BinaryPrimitives.WriteInt64LittleEndian(payload.AsSpan(1), gap.StartTimestamp);
            BinaryPrimitives.WriteInt64LittleEndian(payload.AsSpan(9), gap.EndTimestamp);
            BinaryPrimitives.WriteInt64LittleEndian(payload.AsSpan(17), gap.LostSamples ?? -1);
            Append(AppendFrameKind.Gap, payload);
        }
    }

    public void Seal()
    {
        lock (_gate)
        {
            Append(AppendFrameKind.Seal, []);
            _closed = true;
        }
    }

    private AppendFrame Append(AppendFrameKind kind, ReadOnlySpan<byte> payload)
    {
        EnsureWritable();
        if (_sequence >= MaximumFrames - (kind == AppendFrameKind.Seal ? 0 : 1))
            throw new InvalidOperationException("Capture frame limit reached; seal and start a new capture.");
        try
        {
            var frame = AppendFrameCodec.Write(_stream, kind, _sequence + 1, payload);
            _stream.Flush(flushToDisk: true);
            _sequence++;
            return frame;
        }
        catch
        {
            _faulted = true;
            throw;
        }
    }

    private void EnsureWritable()
    {
        if (_closed || _faulted) throw new InvalidOperationException("Capture is sealed, closed or has an uncertain failed write.");
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _closed = true;
            _stream.Dispose();
        }
    }

    internal static void ValidateSlices(IReadOnlyList<ChunkSlice> slices, IReadOnlyDictionary<long, AppendFrame> chunks)
    {
        foreach (var slice in slices)
        {
            if (slice is null || !chunks.TryGetValue(slice.Chunk, out var chunk) || slice.Offset < 0
                || slice.Length <= 0 || slice.Offset > chunk.PayloadLength - slice.Length)
                throw new InvalidDataException("Segment slice does not belong to a committed chunk range.");
        }
    }

    internal static void ValidateGap(CaptureGap gap)
    {
        if (gap.Cause == CaptureGapCause.None || !Enum.IsDefined(gap.Cause) || gap.StartTimestamp < 0 || gap.EndTimestamp < gap.StartTimestamp || gap.LostSamples < 0)
            throw new ArgumentException("Gap cause, interval or count is invalid.", nameof(gap));
    }
}

/// <summary>Verified immutable view. Recovery never rewrites capture bytes or permits resuming them.</summary>
public sealed class CaptureSnapshot : IDisposable
{
    private readonly FileStream _stream;
    private readonly object _gate = new();
    private readonly Dictionary<long, AppendFrame> _chunks = [];
    private readonly Dictionary<Guid, ChunkSlice[]> _segments = [];
    private readonly List<CaptureGap> _gaps = [];
    private bool _disposed;

    private CaptureSnapshot(FileStream stream) => _stream = stream;
    public bool IsSealed { get; private set; }
    public CaptureLoss? Loss { get; private set; }
    public IReadOnlyList<CaptureGap> Gaps => _gaps.AsReadOnly();
    public IReadOnlyCollection<Guid> Segments => new ReadOnlyCollection<Guid>(_segments.Keys.ToArray());

    /// <summary>Refuses to return an incomplete capture until its separate loss receipt is durable.</summary>
    public static CaptureSnapshot Open(string path)
    {
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var snapshot = new CaptureSnapshot(stream);
        try
        {
            var scan = AppendFrameCodec.Scan(stream, AppendStore.MaximumFrames);
            long verified = 0;
            string cause = scan.Failure.ToString();
            bool semanticFailure = false;
            foreach (var frame in scan.Frames)
            {
                try { snapshot.Accept(frame); }
                catch (Exception error) when (error is InvalidDataException or ArgumentException or OverflowException)
                {
                    cause = "InvalidManifest";
                    semanticFailure = true;
                    break;
                }
                verified = frame.EndOffset;
            }
            snapshot.IsSealed = scan.Sealed && !semanticFailure && scan.Failure == AppendScanFailure.None;
            if (!snapshot.IsSealed)
            {
                snapshot.Loss = new CaptureLoss(stream.Length, verified, cause);
                snapshot.PersistLoss(path + ".loss");
            }
            return snapshot;
        }
        catch
        {
            snapshot.Dispose();
            throw;
        }
    }

    private void Accept(AppendFrame frame)
    {
        if (frame.Kind == AppendFrameKind.Chunk)
        {
            if (frame.PayloadLength == 0) throw new InvalidDataException("Empty chunk.");
            _chunks.Add(frame.Sequence, frame);
            return;
        }
        var payload = AppendFrameCodec.ReadVerifiedPayload(_stream, frame);
        if (frame.Kind == AppendFrameKind.Segment)
        {
            if (payload.Length < 20) throw new InvalidDataException("Short segment manifest.");
            var id = new Guid(payload.AsSpan(0, 16));
            int count = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(16));
            if (id == Guid.Empty || _segments.ContainsKey(id) || count is < 1 or > AppendStore.MaximumSegmentSlices
                || payload.Length != 20 + count * 16) throw new InvalidDataException("Invalid segment manifest.");
            var slices = new ChunkSlice[count];
            for (int index = 0; index < count; index++)
            {
                var part = payload.AsSpan(20 + index * 16);
                slices[index] = new ChunkSlice(BinaryPrimitives.ReadInt64LittleEndian(part),
                    BinaryPrimitives.ReadInt32LittleEndian(part[8..]), BinaryPrimitives.ReadInt32LittleEndian(part[12..]));
            }
            AppendStore.ValidateSlices(slices, _chunks);
            _segments.Add(id, slices);
        }
        else if (frame.Kind == AppendFrameKind.Gap)
        {
            if (payload.Length != 25) throw new InvalidDataException("Invalid gap record.");
            long count = BinaryPrimitives.ReadInt64LittleEndian(payload.AsSpan(17));
            if (count < -1) throw new InvalidDataException("Invalid loss count.");
            var gap = new CaptureGap((CaptureGapCause)payload[0], BinaryPrimitives.ReadInt64LittleEndian(payload.AsSpan(1)),
                BinaryPrimitives.ReadInt64LittleEndian(payload.AsSpan(9)), count == -1 ? null : count);
            AppendStore.ValidateGap(gap);
            _gaps.Add(gap);
        }
    }

    public long SegmentLength(Guid segment)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _segments[segment].Sum(slice => (long)slice.Length);
        }
    }

    /// <summary>Reads at most one chunk-sized range, verifying every touched physical chunk in full.</summary>
    public byte[] ReadRange(Guid segment, long offset, int length)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (offset < 0 || length < 0 || length > AppendStore.MaximumChunkBytes || offset > SegmentLength(segment) - length)
                throw new ArgumentOutOfRangeException(nameof(offset));
            var result = new byte[length];
            int written = 0;
            foreach (var slice in _segments[segment])
            {
                if (offset >= slice.Length) { offset -= slice.Length; continue; }
                if (written == length) break;
                var bytes = AppendFrameCodec.ReadVerifiedPayload(_stream, _chunks[slice.Chunk]);
                int take = Math.Min(slice.Length - (int)offset, length - written);
                bytes.AsSpan(slice.Offset + (int)offset, take).CopyTo(result.AsSpan(written));
                written += take;
                offset = 0;
            }
            return result;
        }
    }

    private void PersistLoss(string path)
    {
        var loss = Loss!;
        _stream.Position = 0;
        byte[] identity = SHA256.HashData(_stream);
        byte[] reason = System.Text.Encoding.UTF8.GetBytes(loss.Cause);
        var receipt = new byte[60 + reason.Length + 32];
        "AFLOSS01"u8.CopyTo(receipt);
        BinaryPrimitives.WriteInt64LittleEndian(receipt.AsSpan(8), loss.ObservedBytes);
        BinaryPrimitives.WriteInt64LittleEndian(receipt.AsSpan(16), loss.VerifiedBytes);
        identity.CopyTo(receipt, 24);
        BinaryPrimitives.WriteInt32LittleEndian(receipt.AsSpan(56), reason.Length);
        reason.CopyTo(receipt, 60);
        SHA256.HashData(receipt.AsSpan(0, receipt.Length - 32), receipt.AsSpan(receipt.Length - 32));
        if (File.Exists(path))
        {
            using var existing = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (existing.Length != receipt.Length) throw new InvalidDataException("Recovery receipt does not match capture evidence.");
            var actual = new byte[receipt.Length];
            existing.ReadExactly(actual);
            if (!CryptographicOperations.FixedTimeEquals(actual, receipt)) throw new InvalidDataException("Recovery receipt integrity failure.");
            return;
        }
        // Incomplete pending receipts remain separate evidence and never replace a valid final receipt.
        string pending = path + ".pending." + Guid.NewGuid().ToString("N");
        using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            output.Write(receipt);
            output.Flush(flushToDisk: true);
        }
        try { File.Move(pending, path, overwrite: false); }
        catch (IOException) when (File.Exists(path)) { PersistLoss(path); }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _stream.Dispose();
        }
    }
}
