// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;

namespace ArcForges.Node.Platform;

/// <summary>Flags of an output index record.</summary>
[Flags]
public enum OutputChunkMarks : byte
{
    /// <summary>None.</summary>
    None = 0,

    /// <summary>The chunk was written while the node was down; its time is the re-attach time (04 section 4).</summary>
    ApproximateTime = 1,
}

/// <summary>
/// One record of <c>index.bin</c> (04 section 4): <c>{stream:u8, offset:u64, length:u32, unix_nanos:i64, flags:u8}</c>, little-endian,
/// 22 bytes. The node's tailer appends one record per stream and read; the merged view interleaves the streams in record order.
/// </summary>
/// <param name="Stream">The stream.</param>
/// <param name="Offset">The chunk's offset in the stream's file.</param>
/// <param name="Length">The chunk's length.</param>
/// <param name="UnixNanos">When the tailer saw the chunk.</param>
/// <param name="Marks">The marks.</param>
public readonly record struct OutputIndexRecord(OutputStreamKind Stream, long Offset, uint Length, long UnixNanos, OutputChunkMarks Marks)
{
    /// <summary>The encoded size.</summary>
    public const int Size = 22;

    /// <summary>The offset after the chunk.</summary>
    public long End => Offset + Length;

    /// <summary>Encodes the record into <paramref name="destination"/> (22 bytes).</summary>
    public void Write(Span<byte> destination)
    {
        destination[0] = (byte)Stream;
        BinaryPrimitives.WriteUInt64LittleEndian(destination[1..], checked((ulong)Offset));
        BinaryPrimitives.WriteUInt32LittleEndian(destination[9..], Length);
        BinaryPrimitives.WriteInt64LittleEndian(destination[13..], UnixNanos);
        destination[21] = (byte)Marks;
    }

    /// <summary>Decodes a record; false for a malformed one.</summary>
    public static bool TryRead(ReadOnlySpan<byte> source, out OutputIndexRecord record)
    {
        record = default;
        if (source.Length < Size || source[0] is not ((byte)OutputStreamKind.Stdout or (byte)OutputStreamKind.Stderr))
        {
            return false;
        }

        var offset = BinaryPrimitives.ReadUInt64LittleEndian(source[1..]);
        if (offset > long.MaxValue)
        {
            return false;
        }

        record = new OutputIndexRecord((OutputStreamKind)source[0], (long)offset, BinaryPrimitives.ReadUInt32LittleEndian(source[9..]),
            BinaryPrimitives.ReadInt64LittleEndian(source[13..]), (OutputChunkMarks)source[21]);
        return true;
    }
}

/// <summary>Reads an attempt's <c>index.bin</c>.</summary>
public static class OutputIndexFile
{
    /// <summary>
    /// Reads every complete record of <paramref name="path"/> from record number <paramref name="first"/>. A torn record at the end (a
    /// crash during an append) is ignored; <paramref name="completeBytes"/> is the length of the complete records.
    /// </summary>
    public static List<OutputIndexRecord> Read(string path, long first, out long completeBytes)
    {
        var records = new List<OutputIndexRecord>();
        completeBytes = 0;
        FileStream stream;
        try
        {
            stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return records;
        }

        using (stream)
        {
            var length = stream.Length - (stream.Length % OutputIndexRecord.Size);
            completeBytes = length;
            var start = Math.Min(first * OutputIndexRecord.Size, length);
            stream.Position = start;
            var buffer = new byte[OutputIndexRecord.Size * 4096];
            var remaining = length - start;
            while (remaining > 0)
            {
                var want = (int)Math.Min(buffer.Length, remaining);
                stream.ReadExactly(buffer, 0, want);
                for (var position = 0; position < want; position += OutputIndexRecord.Size)
                {
                    if (OutputIndexRecord.TryRead(buffer.AsSpan(position, OutputIndexRecord.Size), out var record))
                    {
                        records.Add(record);
                    }
                }

                remaining -= want;
            }
        }

        return records;
    }
}
