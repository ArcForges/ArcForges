// SPDX-License-Identifier: AGPL-3.0-only

using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;

namespace ArcForges.Native.Image;

public enum ImageSourceFormat
{
    Png,
    Tiff,
    Exr,
}

public enum ImageAlphaKind
{
    None,
    Straight,
    Premultiplied,
}

public enum ImageChannelMapping
{
    Named,
    Positional,
}

// One source channel as the file declares it. Type is the closed OpenImageIO type name.
public sealed record ImageChannel(string Name, string Type);

// Immutable description of the selected level. Conversions and Losses list every change applied to pixels
// that a region read returns, so callers can see bit-depth reduction, clamping and dropped channels.
public sealed record ImageMetadata(
    ImageSourceFormat Format,
    uint Subimage,
    uint Subimages,
    uint Mip,
    uint Mips,
    uint Width,
    uint Height,
    int OriginX,
    int OriginY,
    bool Tiled,
    uint TileWidth,
    uint TileHeight,
    IReadOnlyList<ImageChannel> Channels,
    ImageChannelMapping ChannelMapping,
    ImageAlphaKind Alpha,
    string ColorSpace,
    uint SourceBitsMax,
    ImageOutputFormat OutputFormat,
    uint OutputChannels,
    uint BytesPerPixel,
    IReadOnlyList<string> Conversions,
    IReadOnlyList<string> Losses)
{
    internal const string Schema = "arc.image.metadata.v1";

    // Parses the closed arc.image.metadata.v1 document. Any missing field, unknown name or inconsistent
    // size is refused, because the native library always writes this exact shape.
    internal static ImageMetadata Parse(ReadOnlySpan<byte> utf8)
    {
        try
        {
            string text = new UTF8Encoding(false, true).GetString(utf8);
            using JsonDocument document = JsonDocument.Parse(text);
            JsonElement root = document.RootElement;
            if (root.GetProperty("schema").GetString() != Schema)
            {
                throw new InvalidDataException("Image metadata schema is not arc.image.metadata.v1.");
            }

            var channels = new List<ImageChannel>();
            foreach (JsonElement channel in root.GetProperty("channels").EnumerateArray())
            {
                channels.Add(new ImageChannel(channel.GetProperty("name").GetString() ?? string.Empty,
                    channel.GetProperty("type").GetString() ?? string.Empty));
            }

            ImageOutputFormat output = ParseOutput(root.GetProperty("outputFormat").GetString());
            uint outputChannels = root.GetProperty("outputChannels").GetUInt32();
            uint bytesPerPixel = root.GetProperty("bytesPerPixel").GetUInt32();
            ValidatePixelSize(output, outputChannels, bytesPerPixel);

            return new ImageMetadata(
                ParseFormat(root.GetProperty("format").GetString()),
                root.GetProperty("subimage").GetUInt32(),
                root.GetProperty("subimages").GetUInt32(),
                root.GetProperty("mip").GetUInt32(),
                root.GetProperty("mips").GetUInt32(),
                root.GetProperty("width").GetUInt32(),
                root.GetProperty("height").GetUInt32(),
                root.GetProperty("originX").GetInt32(),
                root.GetProperty("originY").GetInt32(),
                root.GetProperty("tiled").GetBoolean(),
                root.GetProperty("tileWidth").GetUInt32(),
                root.GetProperty("tileHeight").GetUInt32(),
                channels.AsReadOnly(),
                root.GetProperty("channelMapping").GetString() switch
                {
                    "named" => ImageChannelMapping.Named,
                    "positional" => ImageChannelMapping.Positional,
                    _ => throw new InvalidDataException("Image channel mapping is not known."),
                },
                root.GetProperty("alpha").GetString() switch
                {
                    "none" => ImageAlphaKind.None,
                    "straight" => ImageAlphaKind.Straight,
                    "premultiplied" => ImageAlphaKind.Premultiplied,
                    _ => throw new InvalidDataException("Image alpha kind is not known."),
                },
                root.GetProperty("colorSpace").GetString() ?? string.Empty,
                root.GetProperty("sourceBitsMax").GetUInt32(),
                output,
                outputChannels,
                bytesPerPixel,
                ReadStrings(root.GetProperty("conversions")),
                ReadStrings(root.GetProperty("loss")));
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException
                                       or FormatException or ArgumentException)
        {
            throw new InvalidDataException("Image metadata is malformed.", ex);
        }
    }

    private static ImageSourceFormat ParseFormat(string? value) => value switch
    {
        "png" => ImageSourceFormat.Png,
        "tiff" => ImageSourceFormat.Tiff,
        "exr" => ImageSourceFormat.Exr,
        _ => throw new InvalidDataException("Image source format is not known."),
    };

    private static ImageOutputFormat ParseOutput(string? value) => value switch
    {
        "rgba8" => ImageOutputFormat.Rgba8,
        "rgba32fLinearPremultiplied" => ImageOutputFormat.Rgba32fLinearPremultiplied,
        "float32Interleaved" => ImageOutputFormat.Float32Interleaved,
        _ => throw new InvalidDataException("Image output format is not known."),
    };

    private static void ValidatePixelSize(ImageOutputFormat output, uint channels, uint bytesPerPixel)
    {
        bool consistent = output switch
        {
            ImageOutputFormat.Rgba8 => channels == 4 && bytesPerPixel == 4,
            ImageOutputFormat.Rgba32fLinearPremultiplied => channels == 4 && bytesPerPixel == 16,
            _ => channels is > 0 and <= 64 && bytesPerPixel == channels * 4U,
        };
        if (!consistent)
        {
            throw new InvalidDataException("Image pixel size is inconsistent with its output format.");
        }
    }

    private static ReadOnlyCollection<string> ReadStrings(JsonElement array)
    {
        var values = new List<string>();
        foreach (JsonElement item in array.EnumerateArray())
        {
            values.Add(item.GetString() ?? string.Empty);
        }

        return values.AsReadOnly();
    }
}
