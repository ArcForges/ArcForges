// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Text;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// The browser of the sign-in tests (the Plan's AF-CTR-04 fakes_allowed: "ScriptedBrowser (system browser)"): it replaces the opener seam,
/// records every URL the node asked it to open (the node's URL check runs before the seam), and plays the browser's part: it asks
/// FakeCenter to decide as the account would and sends the center's redirect to the node's real loopback receiver over a real socket.
/// </summary>
internal sealed class ScriptedBrowser : IBrowserOpener
{
    private readonly List<string> _opened = [];
    private TaskCompletionSource<string> _next = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Whether <see cref="OpenAsync"/> reports success.</summary>
    public bool Opens { get; set; } = true;

    /// <summary>The URLs opened, in order.</summary>
    public IReadOnlyList<string> Opened
    {
        get
        {
            lock (_opened)
            {
                return [.. _opened];
            }
        }
    }

    /// <summary>Completes with the next URL opened.</summary>
    public Task<string> NextAsync()
    {
        lock (_opened)
        {
            return _next.Task;
        }
    }

    /// <inheritdoc />
    public Task<bool> OpenAsync(DerivedUrl url, TimeSpan wait, CancellationToken cancellationToken)
    {
        lock (_opened)
        {
            _opened.Add(url.Value);
            var next = _next;
            _next = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            next.TrySetResult(url.Value);
        }

        return Task.FromResult(Opens);
    }

    /// <summary>Sends <c>GET</c> of <paramref name="url"/> (an <c>http://host:port/path?query</c> loopback URL) as a browser does; the reply's status line.</summary>
    public static Task<string> GetAsync(string url, string? host = null, string method = "GET", string extraHeaders = "", string body = "")
    {
        var uri = new Uri(url);
        var target = url[(url.IndexOf('/', "http://".Length))..];
        var request = method + " " + target + " HTTP/1.1\r\nHost: " + (host ?? uri.Authority) + "\r\n" + extraHeaders
            + (body.Length > 0 ? "Content-Length: " + body.Length + "\r\n" : string.Empty) + "Connection: close\r\n\r\n" + body;
        return RawAsync(uri.Host.Trim('[', ']'), uri.Port, request);
    }

    /// <summary>Sends raw bytes to a loopback port; the reply's first line (or "" when the connection closed without a reply).</summary>
    public static async Task<string> RawAsync(string host, int port, string request, TimeSpan? timeout = null)
    {
        using var client = new TcpClient(host.Contains(':', StringComparison.Ordinal) ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
        using var cancel = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(10));
        await client.ConnectAsync(host, port, cancel.Token);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.Latin1.GetBytes(request), cancel.Token);
        var buffer = new byte[16384];
        var total = 0;
        try
        {
            while (total < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(total), cancel.Token);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }
        }
        catch (IOException)
        {
        }

        var text = Encoding.Latin1.GetString(buffer, 0, total);
        return text.Contains("\r\n", StringComparison.Ordinal) ? text[..text.IndexOf("\r\n", StringComparison.Ordinal)] : text;
    }

    /// <summary>Sends raw bytes and returns the whole reply (headers and body).</summary>
    public static async Task<string> FullAsync(string url)
    {
        var uri = new Uri(url);
        using var client = new TcpClient();
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await client.ConnectAsync(uri.Host, uri.Port, cancel.Token);
        var stream = client.GetStream();
        var target = url[(url.IndexOf('/', "http://".Length))..];
        await stream.WriteAsync(Encoding.ASCII.GetBytes("GET " + target + " HTTP/1.1\r\nHost: " + uri.Authority + "\r\n\r\n"), cancel.Token);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync(cancel.Token);
    }
}
