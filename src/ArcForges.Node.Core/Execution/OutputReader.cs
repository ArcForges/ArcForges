// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using ContractIndexRecord = ArcForges.Contracts.Node.V1.OutputIndexRecord;
using IndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.Node.Core.Execution;

/// <summary>A slice of captured output: bytes of one stream with their index record.</summary>
/// <param name="Stream">The stream.</param>
/// <param name="Offset">The offset in the stream's file.</param>
/// <param name="Data">The bytes.</param>
/// <param name="UnixNanos">When the tailer saw them.</param>
/// <param name="Approximate">Written while the node was down.</param>
public sealed record OutputSlice(OutputStreamKind Stream, long Offset, byte[] Data, long UnixNanos, bool Approximate);

/// <summary>
/// Reads an attempt's captured output (04 section 4): one stream by its own offsets, or the merged view, which interleaves the two
/// streams in index order with offsets that count the merged bytes. Only indexed bytes are visible, so every reader sees the same
/// output whether the attempt is running or finished.
/// </summary>
public static class OutputReader
{
    /// <summary>The largest output chunk in a stream frame (tasks.proto: 64 KiB).</summary>
    public const int ChunkBytes = 64 * 1024;

    /// <summary>
    /// <c>ReadTaskOutput</c>: up to <paramref name="maxBytes"/> from <paramref name="from"/> of <paramref name="stream"/> (MERGED by default),
    /// with the index records of what was returned; <c>eof</c> once the attempt finished and nothing more is indexed.
    /// </summary>
    public static TaskServiceReadTaskOutputValue Read(AttemptFiles files, OutputStream stream, ulong from, int maxBytes, bool finished)
    {
        ArgumentNullException.ThrowIfNull(files);
        var records = OutputIndexFile.Read(files.IndexPath, 0, out _);
        var value = new TaskServiceReadTaskOutputValue();
        var data = new MemoryStream();
        long position;
        bool more;
        if (stream is OutputStream.Stdout or OutputStream.Stderr)
        {
            var kind = stream == OutputStream.Stdout ? OutputStreamKind.Stdout : OutputStreamKind.Stderr;
            var mine = records.Where(record => record.Stream == kind).ToList();
            var end = mine.Count == 0 ? 0 : mine.Max(record => record.End);
            position = (long)Math.Min(from, (ulong)end);
            var stop = Math.Min(end, position + maxBytes);
            if (stop > position)
            {
                data.Write(ReadRange(files.OutputPath(kind), position, (int)(stop - position)));
                foreach (var record in mine.Where(record => record.End > position && record.Offset < stop))
                {
                    var start = Math.Max(record.Offset, position);
                    value.Index.Add(Contract(record, start, (uint)(Math.Min(record.End, stop) - start)));
                }
            }

            position = stop;
            more = position < end;
        }
        else
        {
            long merged = 0;
            position = 0;
            var target = (long)from;
            foreach (var record in records)
            {
                if (data.Length >= maxBytes)
                {
                    break;
                }

                var recordEnd = merged + record.Length;
                if (recordEnd > target)
                {
                    var skip = Math.Max(0, target - merged);
                    var take = (int)Math.Min(record.Length - skip, maxBytes - data.Length);
                    data.Write(ReadRange(files.OutputPath(record.Stream), record.Offset + skip, take));
                    value.Index.Add(Contract(record, record.Offset + skip, (uint)take));
                    position = merged + skip + take;
                }

                merged = recordEnd;
            }

            position = Math.Max(position, Math.Min(target, merged));
            more = position < merged;
        }

        value.Data = Google.Protobuf.ByteString.CopyFrom(data.ToArray());
        value.NextOffset = (ulong)position;
        value.Eof = finished && !more;
        return value;
    }

    /// <summary>The last <paramref name="bytes"/> of the merged output, and whether earlier output was left out.</summary>
    public static (byte[] Data, bool Truncated) Tail(AttemptFiles files, int bytes)
    {
        ArgumentNullException.ThrowIfNull(files);
        var records = OutputIndexFile.Read(files.IndexPath, 0, out _);
        var total = records.Sum(record => (long)record.Length);
        if (bytes <= 0 || total == 0)
        {
            return ([], total > 0);
        }

        var from = Math.Max(0, total - bytes);
        var read = Read(files, OutputStream.Merged, (ulong)from, bytes, finished: true);
        return (read.Data.ToByteArray(), from > 0);
    }

    /// <summary>
    /// Reads index records from record number <paramref name="firstRecord"/> and the bytes they name, split into chunks of at most
    /// 64 KiB, skipping bytes before the per-stream start offsets. Returns the slices and the next record number.
    /// </summary>
    public static (List<OutputSlice> Slices, long NextRecord) Follow(AttemptFiles files, long firstRecord, long stdoutFrom, long stderrFrom, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(files);
        var slices = new List<OutputSlice>();
        var records = OutputIndexFile.Read(files.IndexPath, firstRecord, out _);
        var next = firstRecord;
        long total = 0;
        foreach (var record in records)
        {
            if (total >= maxBytes)
            {
                break;
            }

            next++;
            var from = record.Stream == OutputStreamKind.Stdout ? stdoutFrom : stderrFrom;
            if (record.End <= from)
            {
                continue;
            }

            var start = Math.Max(record.Offset, from);
            var remaining = record.End - start;
            var path = files.OutputPath(record.Stream);
            while (remaining > 0)
            {
                var take = (int)Math.Min(remaining, ChunkBytes);
                slices.Add(new OutputSlice(record.Stream, start, ReadRange(path, start, take), record.UnixNanos,
                    (record.Marks & OutputChunkMarks.ApproximateTime) != 0));
                start += take;
                remaining -= take;
                total += take;
            }
        }

        return (slices, next);
    }

    private static ContractIndexRecord Contract(IndexRecord record, long offset, uint length) => new()
    {
        Stream = record.Stream == OutputStreamKind.Stdout ? OutputStream.Stdout : OutputStream.Stderr,
        Offset = (ulong)offset,
        Length = length,
        UnixNanos = record.UnixNanos,
        ApproximateTime = (record.Marks & OutputChunkMarks.ApproximateTime) != 0,
    };

    private static byte[] ReadRange(string path, long offset, int length)
    {
        var buffer = new byte[length];
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var read = 0;
        while (read < length)
        {
            var count = RandomAccess.Read(handle, buffer.AsSpan(read), offset + read);
            if (count == 0)
            {
                break;
            }

            read += count;
        }

        return read == length ? buffer : buffer[..read];
    }
}
