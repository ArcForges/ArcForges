// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using ArcForges.ContentSandbox.Native;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ContentSandbox.HostileFixture;

/// <summary>
/// TEST ONLY: the composition of the hostile first-party parser. It parses no real format. Its input is a small script, written by the test,
/// that says what the parser does when it is opened or asked for a tile: attack the operating-system boundary and report each outcome as a
/// bounded string, crash, hang, exhaust memory or overrun its output. Nothing here is a parser, a codec or a fallback for either.
/// </summary>
internal sealed class HostileProfile : IContentParserProfile
{
    /// <summary>The identifier a launch names to select this composition.</summary>
    internal const string ProfileId = "hostile-test-parser";

    /// <inheritdoc />
    public string Id => ProfileId;

    /// <inheritdoc />
    public IImageParser? CreateImageParser() => new HostileImageParser();

    /// <inheritdoc />
    public IPdfParser? CreatePdfParser() => new HostilePdfParser();
}

/// <summary>The script a hostile test document carries: line-oriented, first line the magic, the rest commands.</summary>
internal sealed class HostileScript
{
    private const int MaxBytes = 1024 * 1024;
    private readonly List<string[]> _lines;

    private HostileScript(List<string[]> lines) => _lines = lines;

    internal IReadOnlyList<string[]> Lines => _lines;

    internal static HostileScript Read(ParserInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.Length > MaxBytes)
        {
            throw new ContentParserException("The script is too large.");
        }

        var bytes = new byte[input.Length];
        var read = 0;
        while (read < bytes.Length)
        {
            var count = input.Read(read, bytes.AsSpan(read));
            if (count == 0)
            {
                throw new ContentParserException("The script ended early.");
            }

            read += count;
        }

        var lines = Encoding.UTF8.GetString(bytes)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.TrimEnd('\r').Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Where(parts => parts.Length > 0)
            .ToList();
        if (lines.Count == 0 || lines[0][0] != "HOSTILE1")
        {
            throw new ContentParserException("Not a hostile fixture script.");
        }

        return new HostileScript(lines);
    }

    internal bool Has(string command) => _lines.Any(line => line[0] == command);

    internal string[]? Find(string command) => _lines.FirstOrDefault(line => line[0] == command);

    internal uint Number(string command, int index, uint fallback)
    {
        var line = Find(command);
        return line is not null && line.Length > index && uint.TryParse(line[index], NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : fallback;
    }
}

/// <summary>The image side of the hostile fixture.</summary>
internal sealed class HostileImageParser : IImageParser
{
    private HostileScript? _script;
    private uint _width;
    private uint _height;

    /// <inheritdoc />
    public SandboxImageInfo Open(ParserInput input, uint subimage, uint mip, uint outputFormat, ParserContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var script = _script = HostileScript.Read(input);
        _width = script.Number("image", 1, 64);
        _height = script.Number("image", 2, 64);
        var warnings = new List<string>();
        foreach (var line in script.Lines.Where(line => line[0] == "attack"))
        {
            warnings.Add(HostileAttacks.Run(line));
        }

        HostileBehaviors.OnOpen(script, context);
        var info = new SandboxImageInfo { Width = _width, Height = _height, SubimageCount = 1, MipCount = 1 };
        foreach (var (name, type) in new[] { ("R", "uint8"), ("G", "uint8"), ("B", "uint8"), ("A", "uint8") })
        {
            info.Channels.Add(new SandboxImageChannel { Name = name, SampleType = type });
        }

        info.Tags.Add(new SandboxTag { Key = "source", Value = "hostile-fixture" });
        info.Warnings.AddRange(warnings);
        return info;
    }

    /// <inheritdoc />
    public int ReadTile(SandboxRegion region, uint format, Span<byte> destination, ParserContext context)
    {
        ArgumentNullException.ThrowIfNull(region);
        ArgumentNullException.ThrowIfNull(context);
        var script = _script ?? throw new ContentParserException("Not open.");
        HostileBehaviors.OnTile(script, context);
        if (script.Has("overflow-on-tile"))
        {
            return destination.Length + 1;
        }

        return TilePattern.Fill(region, format, _width, _height, destination);
    }

    /// <inheritdoc />
    public void Dispose()
    {
    }
}

/// <summary>The PDF side of the hostile fixture: pages and text come from the script, never from a real document.</summary>
internal sealed class HostilePdfParser : IPdfParser
{
    private readonly List<(double Width, double Height, string Text)> _pages = [];

    /// <inheritdoc />
    public uint Open(ParserInput input, ParserContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var script = HostileScript.Read(input);
        foreach (var line in script.Lines)
        {
            if (line[0] == "page" && line.Length >= 3
                && double.TryParse(line[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var width)
                && double.TryParse(line[2], NumberStyles.Float, CultureInfo.InvariantCulture, out var height))
            {
                _pages.Add((width, height, string.Join(' ', line.Skip(3))));
            }
            else if (line[0] == "longpage" && line.Length >= 2 && int.TryParse(line[1], NumberStyles.None, CultureInfo.InvariantCulture, out var chars))
            {
                _pages.Add((612, 792, LongText(chars)));
            }
        }

        HostileBehaviors.OnOpen(script, context);
        return (uint)_pages.Count;
    }

    /// <inheritdoc />
    public SandboxPdfPage GetPage(uint pageIndex, ParserContext context)
    {
        var page = _pages[(int)pageIndex];
        return new SandboxPdfPage { PageIndex = pageIndex, Rotation = 0, WidthPoints = page.Width, HeightPoints = page.Height };
    }

    /// <inheritdoc />
    public PdfPageText GetPageText(uint pageIndex, ParserContext context)
    {
        var text = _pages[(int)pageIndex].Text;
        var boxes = new List<SandboxTextBox>();
        var start = 0;
        while (start < text.Length)
        {
            var end = text.IndexOf(' ', start);
            end = end < 0 ? text.Length : end;
            if (end > start)
            {
                boxes.Add(new SandboxTextBox { Start = (uint)start, Length = (uint)(end - start), X = start, Y = 0, Width = end - start, Height = 10 });
            }

            start = end + 1;
        }

        return new PdfPageText(text, boxes);
    }

    /// <inheritdoc />
    public int RenderTile(SandboxPdfPage page, SandboxRegion region, uint fullWidth, uint fullHeight, Span<byte> destination, ParserContext context) =>
        TilePattern.Fill(region, 1, fullWidth, fullHeight, destination);

    /// <inheritdoc />
    public void Dispose()
    {
    }

    private static string LongText(int chars)
    {
        var builder = new StringBuilder(chars);
        var word = 0;
        while (builder.Length < chars)
        {
            // Words of letters, a four-byte character (a surrogate pair) every few words, and spaces, so that a cut can land inside a pair.
            builder.Append("word").Append(word.ToString(CultureInfo.InvariantCulture)).Append(' ');
            if (word % 5 == 0)
            {
                builder.Append(char.ConvertFromUtf32(0x1F600)).Append(' ');
            }

            word++;
        }

        return builder.ToString(0, chars).TrimEnd(char.ConvertFromUtf32(0x1F600)[0]);
    }
}

/// <summary>The deterministic tile content: it makes a wrong tile, a wrong slot or a stale buffer visible.</summary>
internal static class TilePattern
{
    internal static int Fill(SandboxRegion region, uint format, uint fullWidth, uint fullHeight, Span<byte> destination)
    {
        var pixelBytes = format == 1 ? 4 : 16;
        var rowBytes = (int)region.Width * pixelBytes;
        var stride = (int)region.RowStride;
        for (var row = 0; row < region.Height; row++)
        {
            var offset = row * stride;
            for (var column = 0; column < region.Width; column++)
            {
                var x = region.X + (uint)column;
                var y = region.Y + (uint)row;
                var pixel = destination.Slice(offset + (column * pixelBytes), pixelBytes);
                if (format == 1)
                {
                    pixel[0] = (byte)(x & 0xFF);
                    pixel[1] = (byte)(y & 0xFF);
                    pixel[2] = (byte)((x + y) & 0xFF);
                    pixel[3] = 0xFF;
                }
                else
                {
                    _ = BitConverter.TryWriteBytes(pixel[..4], (float)x / Math.Max(1, fullWidth));
                    _ = BitConverter.TryWriteBytes(pixel.Slice(4, 4), (float)y / Math.Max(1, fullHeight));
                    _ = BitConverter.TryWriteBytes(pixel.Slice(8, 4), 0.5f);
                    _ = BitConverter.TryWriteBytes(pixel.Slice(12, 4), 1.0f);
                }
            }
        }

        return ((int)(region.Height - 1) * stride) + rowBytes;
    }
}

/// <summary>The misbehavior a script asks for at open and at tile time: crash, hang, memory exhaustion, slowness.</summary>
internal static class HostileBehaviors
{
    internal static void OnOpen(HostileScript script, ParserContext context)
    {
        Misbehave(script, "crash-on-open", "hang-on-open", "polite-hang-on-open", "oom-on-open", "slow-on-open", context);
    }

    internal static void OnTile(HostileScript script, ParserContext context)
    {
        Misbehave(script, "crash-on-tile", "hang-on-tile", "polite-hang-on-tile", "oom-on-tile", "slow-on-tile", context);
    }

    [SuppressMessage("Design", "CA1031", Justification = "TEST ONLY: the fixture misbehaves on purpose.")]
    private static void Misbehave(HostileScript script, string crash, string hang, string politeHang, string oom, string slow, ParserContext context)
    {
        if (script.Has(crash))
        {
            // A write to an address that is not mapped: a native access violation, which no managed handler can catch.
            Marshal.WriteInt32((nint)0x1000, 1);
        }

        if (script.Has(hang))
        {
            while (true)
            {
                _ = Environment.TickCount64;
            }
        }

        if (script.Has(politeHang))
        {
            context.Cancelled.WaitHandle.WaitOne();
            context.Cancelled.ThrowIfCancellationRequested();
        }

        if (script.Has(oom))
        {
            var blocks = new List<nint>();
            while (true)
            {
                var block = Marshal.AllocHGlobal(16 * 1024 * 1024);
                for (var offset = 0; offset < 16 * 1024 * 1024; offset += 4096)
                {
                    Marshal.WriteByte(block, offset, 1);
                }

                blocks.Add(block);
            }
        }

        var delay = script.Number(slow, 1, 0);
        if (delay > 0)
        {
            context.Cancelled.WaitHandle.WaitOne((int)delay);
            context.Cancelled.ThrowIfCancellationRequested();
        }
    }
}

/// <summary>
/// The attacks a script can ask for. Each runs the real operation against the real boundary and reports <c>name:DENIED:cause</c> or
/// <c>name:ALLOWED:detail</c>. A report is bounded text with no path, no secret and no exception message.
/// </summary>
[SuppressMessage("Design", "CA1031", Justification = "TEST ONLY: every attack reports its own failure as a denial.")]
internal static class HostileAttacks
{
    internal static string Run(string[] line)
    {
        ArgumentNullException.ThrowIfNull(line);
        if (line.Length < 2)
        {
            return "attack:DENIED:malformed";
        }

        return line[1] switch
        {
            "file" when line.Length >= 3 => ReadFile(string.Join(' ', line.Skip(2))),
            "tcp" when line.Length >= 4 => Tcp(line[2], line[3]),
            "udp" when line.Length >= 4 => Udp(line[2], line[3]),
            "process" when line.Length >= 3 => OpenProcess(line[2]),
            "spawn" when line.Length >= 3 => Spawn(string.Join(' ', line.Skip(2))),
            "input-write" => InputWritable(),
            "env" => Environment(),
            "identity" => Identity(),
            _ => "attack:DENIED:unknown",
        };
    }

    private static string ReadFile(string path)
    {
        try
        {
            var length = File.ReadAllBytes(path).Length;
            return "file:ALLOWED:" + length.ToString(CultureInfo.InvariantCulture);
        }
        catch (Exception exception)
        {
            return "file:DENIED:" + exception.GetType().Name;
        }
    }

    private static string Tcp(string address, string port)
    {
        try
        {
            using var client = new TcpClient();
            client.ConnectAsync(IPAddress.Parse(address), int.Parse(port, CultureInfo.InvariantCulture)).Wait(TimeSpan.FromSeconds(5));
            return client.Connected ? "tcp:ALLOWED:" + address : "tcp:DENIED:NotConnected";
        }
        catch (Exception exception)
        {
            var cause = exception is AggregateException { InnerException: { } inner } ? inner : exception;
            return "tcp:DENIED:" + cause.GetType().Name + (cause is SocketException socket ? "." + socket.SocketErrorCode : string.Empty);
        }
    }

    private static string Udp(string address, string port)
    {
        try
        {
            using var client = new UdpClient();
            var sent = client.Send("arcforges"u8, new IPEndPoint(IPAddress.Parse(address), int.Parse(port, CultureInfo.InvariantCulture)));
            return "udp:ALLOWED:" + sent.ToString(CultureInfo.InvariantCulture);
        }
        catch (Exception exception)
        {
            return "udp:DENIED:" + exception.GetType().Name + (exception is SocketException socket ? "." + socket.SocketErrorCode : string.Empty);
        }
    }

    private static string OpenProcess(string id)
    {
        try
        {
            using var process = Process.GetProcessById(int.Parse(id, CultureInfo.InvariantCulture));
            _ = process.Handle;
            return "process:ALLOWED:" + process.ProcessName;
        }
        catch (Exception exception)
        {
            return "process:DENIED:" + exception.GetType().Name;
        }
    }

    private static string Spawn(string executable)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true });
            if (process is null)
            {
                return "spawn:DENIED:NoProcess";
            }

            process.Kill(true);
            return "spawn:ALLOWED:started";
        }
        catch (Exception exception)
        {
            return "spawn:DENIED:" + exception.GetType().Name;
        }
    }

    /// <summary>The input section arrived read-only: mapping it writable must fail.</summary>
    private static string InputWritable()
    {
        if (!OperatingSystem.IsWindows() || !HelperFacts.TryGetInputHandle(out var handle))
        {
            return "input-write:DENIED:NotApplicable";
        }

        var address = HelperWindowsNative.MapViewOfFile((nint)handle, HelperWindowsNative.FileMapWrite, 0, 0, 1);
        if (address != 0)
        {
            _ = HelperWindowsNative.UnmapViewOfFile(address);
            return "input-write:ALLOWED:mapped";
        }

        return "input-write:DENIED:AccessDenied";
    }

    private static string Environment()
    {
        var names = System.Environment.GetEnvironmentVariables().Keys.Cast<string>().Order(StringComparer.OrdinalIgnoreCase).ToArray();
        var unexpected = names.Where(name => !name.Equals("SystemRoot", StringComparison.OrdinalIgnoreCase)
            && !name.Equals("windir", StringComparison.OrdinalIgnoreCase)
            && !name.Equals("LOCALAPPDATA", StringComparison.OrdinalIgnoreCase) && !name.Equals("TEMP", StringComparison.OrdinalIgnoreCase)
            && !name.Equals("TMP", StringComparison.OrdinalIgnoreCase)
            && !name.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase)).ToArray();
        return unexpected.Length == 0 ? "env:DENIED:OnlySystemRoot" : "env:ALLOWED:" + string.Join('/', unexpected.Take(8));
    }

    [SupportedOSPlatform("windows")]
    private static string WindowsIdentityReport()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var low = identity.Groups?.Any(group => group.Value == "S-1-16-4096") == true;
            return "identity:INFO:" + (low ? "low-integrity" : "not-low-integrity");
        }
        catch (Exception exception)
        {
            return "identity:INFO:" + exception.GetType().Name;
        }
    }

    private static string Identity() => OperatingSystem.IsWindows() ? WindowsIdentityReport() : "identity:INFO:NotApplicable";
}
