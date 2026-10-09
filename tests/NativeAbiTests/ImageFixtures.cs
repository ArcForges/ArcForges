// SPDX-License-Identifier: AGPL-3.0-only

using System.IO.Compression;
using System.Text;

namespace ArcForges.Tests.NativeAbiTests;

// Generates PNG and TIFF bytes in test code (decision D1): no image file is shipped with the tests.
internal static class ImageFixtures
{
    private static readonly byte[] PngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    private static readonly uint[] CrcTable = BuildCrcTable();

    // 8-bit RGBA, straight (unassociated) alpha, one filter byte per scanline.
    internal static byte[] PngRgba8(int width, int height, byte[] rgba)
    {
        int stride = width * 4;
        var raw = new byte[height * (stride + 1)];
        for (int row = 0; row < height; row++)
        {
            Buffer.BlockCopy(rgba, row * stride, raw, row * (stride + 1) + 1, stride);
        }

        using var file = new MemoryStream();
        file.Write(PngSignature);

        using var header = new MemoryStream();
        WriteBigEndian(header, (uint)width);
        WriteBigEndian(header, (uint)height);
        header.WriteByte(8); // bit depth
        header.WriteByte(6); // colour type RGBA
        header.WriteByte(0); // compression
        header.WriteByte(0); // filter method
        header.WriteByte(0); // no interlace
        WriteChunk(file, "IHDR", header.ToArray());
        WriteChunk(file, "IDAT", Deflate(raw));
        WriteChunk(file, "IEND", []);
        return file.ToArray();
    }

    // Uncompressed 8-bit RGBA TIFF with ExtraSamples = unassociated alpha, little endian, one strip.
    internal static byte[] TiffRgba8(int width, int height, byte[] rgba)
    {
        int dataLength = width * height * 4;
        int bitsOffset = 8 + dataLength;
        int directoryOffset = bitsOffset + 8;

        using var file = new MemoryStream();
        file.Write("II"u8);
        WriteLittle16(file, 42);
        WriteLittle32(file, (uint)directoryOffset);
        file.Write(rgba);
        for (int channel = 0; channel < 4; channel++)
        {
            WriteLittle16(file, 8);
        }

        const ushort shortType = 3;
        const ushort longType = 4;
        Entry[] entries =
        [
            new(256, shortType, 1, (uint)width),
            new(257, shortType, 1, (uint)height),
            new(258, shortType, 4, (uint)bitsOffset),
            new(259, shortType, 1, 1),
            new(262, shortType, 1, 2),
            new(273, longType, 1, 8),
            new(277, shortType, 1, 4),
            new(278, longType, 1, (uint)height),
            new(279, longType, 1, (uint)dataLength),
            new(284, shortType, 1, 1),
            new(338, shortType, 1, 2),
        ];
        WriteLittle16(file, (ushort)entries.Length);
        foreach (Entry entry in entries)
        {
            WriteLittle16(file, entry.Tag);
            WriteLittle16(file, entry.Type);
            WriteLittle32(file, entry.Count);
            WriteLittle32(file, entry.Value);
        }

        WriteLittle32(file, 0);
        return file.ToArray();
    }

    private static byte[] Deflate(byte[] raw)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(raw);
        }

        return output.ToArray();
    }

    private static void WriteChunk(Stream file, string type, byte[] data)
    {
        byte[] typeBytes = Encoding.ASCII.GetBytes(type);
        WriteBigEndian(file, (uint)data.Length);
        file.Write(typeBytes);
        file.Write(data);

        uint crc = 0xFFFFFFFFU;
        foreach (byte value in typeBytes.Concat(data))
        {
            crc = CrcTable[(crc ^ value) & 0xFF] ^ (crc >> 8);
        }

        WriteBigEndian(file, crc ^ 0xFFFFFFFFU);
    }

    private static uint[] BuildCrcTable()
    {
        var table = new uint[256];
        for (uint index = 0; index < 256; index++)
        {
            uint value = index;
            for (int bit = 0; bit < 8; bit++)
            {
                value = (value & 1) != 0 ? 0xEDB88320U ^ (value >> 1) : value >> 1;
            }

            table[index] = value;
        }

        return table;
    }

    private static void WriteBigEndian(Stream stream, uint value)
    {
        stream.WriteByte((byte)(value >> 24));
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static void WriteLittle16(Stream stream, ushort value)
    {
        stream.WriteByte((byte)value);
        stream.WriteByte((byte)(value >> 8));
    }

    private static void WriteLittle32(Stream stream, uint value)
    {
        WriteLittle16(stream, (ushort)value);
        WriteLittle16(stream, (ushort)(value >> 16));
    }

    private readonly record struct Entry(ushort Tag, ushort Type, uint Count, uint Value);
}
