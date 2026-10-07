// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>Authored 2x2 opaque red images. The generators are test data, never replacement decoders.</summary>
internal static class FirstPartyImageFixtures
{
    internal static byte[] Create(string codec) => codec switch
    {
        "png" => Png(),
        "tiff" => Tiff(),
        "exr" => Exr(),
        _ => throw new ArgumentOutOfRangeException(nameof(codec)),
    };

    private static byte[] Png()
    {
        using var result = new MemoryStream();
        result.Write([137, 80, 78, 71, 13, 10, 26, 10]);
        byte[] header = [0, 0, 0, 2, 0, 0, 0, 2, 8, 6, 0, 0, 0];
        Chunk(result, "IHDR"u8, header);
        using var compressed = new MemoryStream();
        using (var zlib = new ZLibStream(compressed, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            for (var y = 0; y < 2; y++) { zlib.Write([0, 255, 0, 0, 255, 255, 0, 0, 255]); }
        }

        Chunk(result, "IDAT"u8, compressed.ToArray());
        Chunk(result, "IEND"u8, []);
        return result.ToArray();
    }

    private static void Chunk(Stream output, ReadOnlySpan<byte> type, ReadOnlySpan<byte> data)
    {
        Span<byte> number = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(number, data.Length);
        output.Write(number); output.Write(type); output.Write(data);
        var crc = uint.MaxValue;
        foreach (var value in type) { crc = Crc(crc, value); }
        foreach (var value in data) { crc = Crc(crc, value); }
        BinaryPrimitives.WriteUInt32BigEndian(number, ~crc);
        output.Write(number);
    }

    private static uint Crc(uint crc, byte value)
    {
        crc ^= value;
        for (var bit = 0; bit < 8; bit++) { crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0u : 0xedb88320u); }
        return crc;
    }

    private static byte[] Tiff()
    {
        const uint bitsOffset = 8 + 2 + (11 * 12) + 4;
        const uint pixelsOffset = bitsOffset + 8;
        using var result = new MemoryStream();
        using var writer = new BinaryWriter(result, Encoding.ASCII, leaveOpen: true);
        writer.Write((byte)'I'); writer.Write((byte)'I'); writer.Write((ushort)42); writer.Write(8u);
        writer.Write((ushort)11);
        Entry(writer, 256, 4, 1, 2); Entry(writer, 257, 4, 1, 2);
        Entry(writer, 258, 3, 4, bitsOffset); Entry(writer, 259, 3, 1, 1);
        Entry(writer, 262, 3, 1, 2); Entry(writer, 273, 4, 1, pixelsOffset);
        Entry(writer, 277, 3, 1, 4); Entry(writer, 278, 4, 1, 2);
        Entry(writer, 279, 4, 1, 16); Entry(writer, 284, 3, 1, 1);
        Entry(writer, 338, 3, 1, 2); writer.Write(0u);
        for (var i = 0; i < 4; i++) { writer.Write((ushort)8); }
        for (var i = 0; i < 4; i++) { writer.Write(new byte[] { 255, 0, 0, 255 }); }
        return result.ToArray();
    }

    private static void Entry(BinaryWriter writer, ushort tag, ushort type, uint count, uint value)
    {
        writer.Write(tag); writer.Write(type); writer.Write(count); writer.Write(value);
    }

    private static byte[] Exr()
    {
        using var result = new MemoryStream();
        using var writer = new BinaryWriter(result, Encoding.ASCII, leaveOpen: true);
        writer.Write(20000630u); writer.Write(2u);
        using var channels = new MemoryStream();
        using (var channel = new BinaryWriter(channels, Encoding.ASCII, leaveOpen: true))
        {
            foreach (var name in new[] { "A", "B", "G", "R" })
            {
                Text(channel, name); channel.Write(1); channel.Write(0u); channel.Write(1); channel.Write(1);
            }

            channel.Write((byte)0);
        }

        Attribute(writer, "channels", "chlist", channels.ToArray());
        Attribute(writer, "compression", "compression", [0]);
        byte[] box = [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0];
        Attribute(writer, "dataWindow", "box2i", box); Attribute(writer, "displayWindow", "box2i", box);
        Attribute(writer, "lineOrder", "lineOrder", [0]);
        Attribute(writer, "pixelAspectRatio", "float", [0, 0, 128, 63]);
        Attribute(writer, "screenWindowCenter", "v2f", new byte[8]);
        Attribute(writer, "screenWindowWidth", "float", [0, 0, 128, 63]);
        writer.Write((byte)0);
        var first = checked((ulong)result.Position + 16);
        writer.Write(first); writer.Write(first + 24);
        for (var y = 0; y < 2; y++)
        {
            writer.Write(y); writer.Write(16);
            foreach (var value in new ushort[] { 0x3c00, 0, 0, 0x3c00 }) { writer.Write(value); writer.Write(value); }
        }

        return result.ToArray();
    }

    private static void Attribute(BinaryWriter writer, string name, string type, byte[] bytes)
    {
        Text(writer, name); Text(writer, type); writer.Write(bytes.Length); writer.Write(bytes);
    }

    private static void Text(BinaryWriter writer, string text)
    {
        writer.Write(Encoding.ASCII.GetBytes(text)); writer.Write((byte)0);
    }
}
