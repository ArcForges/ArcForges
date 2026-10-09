// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Native.Image;

// Bytes of one image, read synchronously by native code through the arc_io_v1 callback. The source is
// fixed for the life of an ImageReader. ReadAt runs on the thread that is executing the native call, so it
// must not block on UI work or on the same reader. Implementations are serialised by the reader.
public abstract class ImageByteSource
{
    // Total byte length. Must not change while a reader is open.
    public abstract long Length { get; }

    // Copies up to destination.Length bytes starting at offset and returns the count copied. A short count
    // is allowed only at the end of the source. Returning zero at or after the end is end of input.
    public abstract int ReadAt(long offset, Span<byte> destination);

    // Wraps a seekable stream. The caller keeps ownership of the stream and must not use it while a reader
    // is reading from it.
    public static ImageByteSource FromStream(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek || !stream.CanRead)
        {
            throw new ArgumentException("The image stream must be readable and seekable.", nameof(stream));
        }

        return new StreamByteSource(stream);
    }

    private sealed class StreamByteSource(Stream stream) : ImageByteSource
    {
        public override long Length => stream.Length;

        public override int ReadAt(long offset, Span<byte> destination)
        {
            if (offset < 0 || offset >= stream.Length || destination.IsEmpty)
            {
                return 0;
            }

            stream.Position = offset;
            int total = 0;
            while (total < destination.Length)
            {
                int read = stream.Read(destination[total..]);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            return total;
        }
    }
}
