// SPDX-License-Identifier: AGPL-3.0-only

using System.Text.Json;

namespace ArcForges.Native.Pdf;

/// <summary>
/// Reads the closed text encoding of arc_pdf_text: <c>{version,page,start,next?,text,boxes:[{start,length,x,y,width,height}]}</c>. Reading is
/// strict and independent of the native engine's own checks: an unknown or repeated member, a wrong type, a box outside the chunk window or a
/// non-finite number refuses the whole chunk.
/// </summary>
internal static class PdfTextJson
{
    internal static PdfTextChunk Parse(ReadOnlySpan<byte> utf8, uint expectedPage, uint expectedStart)
    {
        var reader = new Utf8JsonReader(utf8, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = 8 });
        try
        {
            return Read(ref reader, expectedPage, expectedStart);
        }
        catch (JsonException exception)
        {
            throw new PdfNativeException("The native text encoding is malformed.", exception);
        }
        catch (InvalidOperationException exception)
        {
            throw new PdfNativeException("The native text encoding is malformed.", exception);
        }
        catch (FormatException exception)
        {
            throw new PdfNativeException("The native text encoding is malformed.", exception);
        }
    }

    private static PdfTextChunk Read(ref Utf8JsonReader reader, uint expectedPage, uint expectedStart)
    {
        Expect(ref reader, JsonTokenType.StartObject);
        uint? version = null;
        uint? page = null;
        uint? start = null;
        uint? next = null;
        string? text = null;
        List<PdfTextBox>? boxes = null;
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            var name = reader.GetString();
            _ = reader.Read();
            switch (name)
            {
                case "version" when version is null:
                    version = reader.GetUInt32();
                    break;
                case "page" when page is null:
                    page = reader.GetUInt32();
                    break;
                case "start" when start is null:
                    start = reader.GetUInt32();
                    break;
                case "next" when next is null:
                    next = reader.GetUInt32();
                    break;
                case "text" when text is null:
                    text = reader.GetString() ?? throw new PdfNativeException("The native text is null.");
                    break;
                case "boxes" when boxes is null:
                    boxes = ReadBoxes(ref reader);
                    break;
                default:
                    throw new PdfNativeException("The native text encoding has an unknown or repeated member.");
            }
        }

        if (reader.TokenType != JsonTokenType.EndObject || reader.Read() || version != 1 || page != expectedPage || start != expectedStart || text is null || boxes is null)
        {
            throw new PdfNativeException("The native text encoding is incomplete or answers another request.");
        }

        var end = (ulong)start.Value + (ulong)text.Length;
        if (next is not null && (next.Value != end || next.Value <= start.Value))
        {
            throw new PdfNativeException("The native text chunk makes no progress.");
        }

        foreach (var box in boxes)
        {
            if (box.Start < start.Value || (ulong)box.Start + box.Length > end || box.Length == 0)
            {
                throw new PdfNativeException("A native text box lies outside its chunk.");
            }
        }

        return new PdfTextChunk(page.Value, start.Value, next, text, boxes);
    }

    private static List<PdfTextBox> ReadBoxes(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.StartArray)
        {
            throw new PdfNativeException("The native box list has the wrong shape.");
        }

        var boxes = new List<PdfTextBox>();
        while (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
        {
            uint? start = null;
            uint? length = null;
            double? x = null;
            double? y = null;
            double? width = null;
            double? height = null;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var name = reader.GetString();
                _ = reader.Read();
                switch (name)
                {
                    case "start" when start is null:
                        start = reader.GetUInt32();
                        break;
                    case "length" when length is null:
                        length = reader.GetUInt32();
                        break;
                    case "x" when x is null:
                        x = Finite(reader.GetDouble());
                        break;
                    case "y" when y is null:
                        y = Finite(reader.GetDouble());
                        break;
                    case "width" when width is null:
                        width = Finite(reader.GetDouble());
                        break;
                    case "height" when height is null:
                        height = Finite(reader.GetDouble());
                        break;
                    default:
                        throw new PdfNativeException("A native text box has an unknown or repeated member.");
                }
            }

            if (reader.TokenType != JsonTokenType.EndObject || start is null || length is null || x is null || y is null || width is null || height is null || width < 0 || height < 0)
            {
                throw new PdfNativeException("A native text box is incomplete.");
            }

            boxes.Add(new PdfTextBox(start.Value, length.Value, x.Value, y.Value, width.Value, height.Value));
        }

        if (reader.TokenType != JsonTokenType.EndArray)
        {
            throw new PdfNativeException("The native box list is malformed.");
        }

        return boxes;
    }

    private static double Finite(double value) => double.IsFinite(value) ? value : throw new PdfNativeException("A native number is not finite.");

    private static void Expect(ref Utf8JsonReader reader, JsonTokenType type)
    {
        if (!reader.Read() || reader.TokenType != type)
        {
            throw new PdfNativeException("The native text encoding has the wrong shape.");
        }
    }
}
