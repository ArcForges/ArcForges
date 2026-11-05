// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink;

/// <summary>What the browser brought back to the loopback receiver.</summary>
internal enum LoopbackOutcome
{
    /// <summary>The approval: a one-use code.</summary>
    Code,

    /// <summary>The denial (<c>error=access_denied</c>).</summary>
    Denied,
}

/// <summary>The one valid request the receiver accepted.</summary>
/// <param name="Outcome">Code or denial.</param>
/// <param name="Code">The one-use code (43 base64url characters; never logged), for <see cref="LoopbackOutcome.Code"/>.</param>
internal sealed record LoopbackResult(LoopbackOutcome Outcome, string? Code);

/// <summary>
/// The browser sign-in's loopback receiver (AF-CTR-04 CTR4-NODE-12 as amended by node-14, P-10 and N2 decision R-1). It listens on the
/// literal <c>127.0.0.1</c> (<c>[::1]</c> only when IPv4 cannot bind) on a port the center admits (1024..65535), before
/// <c>BeginNodeSignIn</c> (the port is part of <c>redirect_uri</c>), and accepts exactly one valid request:
/// <c>GET /callback?code=&lt;43 base64url&gt;&amp;state=&lt;state&gt;</c> or <c>GET /callback?error=access_denied&amp;state=&lt;state&gt;</c>, in that
/// order, with exactly one <c>Host</c> equal to its own authority (the DNS-rebinding guard), no other or repeated key, no <c>%</c>, no
/// body, the state compared in constant time. There is no Origin or <c>Sec-Fetch-*</c> rule: the browser's top-level navigation carries no
/// Origin, and the 256-bit state is the secret. Any other request is answered 400 and never ends the flow; idle connections are closed
/// silently at their 5 s deadline (one total deadline per connection for its whole request, not per read). Once 8 connections are idle
/// (no complete request line, nothing waiting to be read, older than one second), a new connection closes the OLDEST idle one (N2 decision R-1), so idle
/// connections cannot lock the browser out (a browser sends its request at once). Every open connection counts against a hard cap of 256
/// (N2 review FX-4): at the cap a new connection closes the oldest one that has not completed its request, whatever it sent (those with
/// bytes waiting to be read last; when every one completed, the oldest of all), so connections that send a request line and stall never
/// hold more than 256 sockets. The valid request ends the flow before its
/// answer is written (a static page without script, best effort); then the receiver stops. It logs a count of refused requests, nothing
/// request-derived.
/// </summary>
internal sealed class LoopbackReceiver : IAsyncDisposable
{
    /// <summary>Idle connections (no complete request line, nothing waiting to be read) from which a new one closes the oldest idle one (R-1).</summary>
    public const int Capacity = 8;

    /// <summary>The most connections open at once, of any kind: at it, a new one closes the oldest that has not completed its request.</summary>
    public const int HardCapacity = 256;

    /// <summary>
    /// How long a new connection does not count as idle (below the hard cap): a browser connects and then sends, and a flood of new idle
    /// connections must not close the browser's in between (<c>AFreshConnectionOutlivesAFloodOfIdleOnesBelowTheHardCap</c> fails without it).
    /// </summary>
    public static readonly TimeSpan Grace = TimeSpan.FromSeconds(1);

    /// <summary>The longest request line.</summary>
    public const int MaxRequestLine = 2048;

    /// <summary>The longest header block (after the request line).</summary>
    public const int MaxHeaderBytes = 8192;

    /// <summary>The most header lines.</summary>
    public const int MaxHeaderLines = 32;

    /// <summary>The deadline of one connection's whole request.</summary>
    public static readonly TimeSpan RequestDeadline = TimeSpan.FromSeconds(5);

    private const string Page = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>ArcForges</title></head><body>"
        + "<p>The sign-in result reached this computer's ArcForges node. You can close this tab.</p></body></html>";

    private const string BadRequest = "This is not a sign-in result for this node.\n";

    private readonly TcpListener _listener;
    private readonly NodeLog? _log;
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource<LoopbackResult> _result = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Lock _lock = new();
    private readonly List<Connection> _connections = [];
    private byte[] _state;
    private int _refused;
    private int _served;
    private long _lastLog;
    private int _stopped;
    private int _peak;

    private LoopbackReceiver(TcpListener listener, IPAddress address, int port, string state, NodeLog? log)
    {
        _listener = listener;
        Address = address;
        Port = port;
        RedirectUri = SignInUrls.RedirectUri(address, port)!;
        Authority = SignInUrls.Authority(address, port);
        _state = Encoding.ASCII.GetBytes(state);
        _log = log;
        Closed = Task.Run(AcceptLoopAsync);
    }

    /// <summary>The bound address (<c>127.0.0.1</c> or <c>::1</c>).</summary>
    public IPAddress Address { get; }

    /// <summary>The bound port.</summary>
    public int Port { get; }

    /// <summary>The <c>redirect_uri</c> the center is told.</summary>
    public string RedirectUri { get; }

    /// <summary>The authority a browser names in <c>Host</c>.</summary>
    public string Authority { get; }

    /// <summary>Completes with the one valid request.</summary>
    public Task<LoopbackResult> Result => _result.Task;

    /// <summary>Completes when the accept loop ended and the listener is closed.</summary>
    public Task Closed { get; }

    /// <summary>The requests refused so far.</summary>
    public int Refused => Volatile.Read(ref _refused);

    /// <summary>The valid requests served (0 or 1).</summary>
    public int Served => Volatile.Read(ref _served);

    /// <summary>The bound endpoint, as the socket reports it (tests: loopback only, N2 review FX-8).</summary>
    internal IPEndPoint LocalEndpoint => (IPEndPoint)_listener.LocalEndpoint;

    /// <summary>The connections open now (tests).</summary>
    internal int Open
    {
        get
        {
            lock (_lock)
            {
                return _connections.Count;
            }
        }
    }

    /// <summary>The most connections that were open at once (tests: the hard cap holds).</summary>
    internal int Peak => Volatile.Read(ref _peak);

    /// <summary>
    /// Binds the receiver: IPv4 loopback first (a port outside 1024..65535 is released and another one drawn, three times at most), then IPv6
    /// loopback; <see langword="null"/> when neither binds (the flow then falls back to device code). <paramref name="listen"/> replaces the
    /// listener construction in tests (a bind failure).
    /// </summary>
    public static LoopbackReceiver? TryStart(string state, NodeLog? log, Func<IPAddress, TcpListener>? listen = null)
    {
        ArgumentNullException.ThrowIfNull(state);
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        {
            for (var attempt = 0; attempt < 3; attempt++)
            {
                TcpListener? listener = null;
                try
                {
                    listener = listen?.Invoke(address) ?? new TcpListener(address, 0);
                    if (OperatingSystem.IsWindows())
                    {
                        // Defence in depth (node-14 corrected item 3): no other socket may bind this address and port.
                        listener.ExclusiveAddressUse = true;
                    }

                    listener.Start(16);
                    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                    if (port is >= SignInUrls.LowestPort and <= SignInUrls.HighestPort)
                    {
                        return new LoopbackReceiver(listener, address, port, state, log);
                    }

                    listener.Stop();
                }
                catch (SocketException)
                {
                    listener?.Stop();
                    break;
                }
            }
        }

        return null;
    }

    /// <summary>The state a valid request must carry (a new Begin of the same flow draws a new one).</summary>
    public void Expect(string state)
    {
        ArgumentNullException.ThrowIfNull(state);
        lock (_lock)
        {
            _state = Encoding.ASCII.GetBytes(state);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        Stop();
        try
        {
            await Closed.ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is ObjectDisposedException or SocketException or OperationCanceledException)
        {
        }

        _stop.Dispose();
    }

    /// <summary>Stops listening and drops every connection.</summary>
    public void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0)
        {
            return;
        }

        try
        {
            _stop.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        _listener.Stop();
        lock (_lock)
        {
            // The connection that brought the valid request finishes its answer within its own deadline (N2 review sec N-3).
            foreach (var connection in _connections.Where(open => !open.Answering))
            {
                connection.Close();
            }

            _connections.RemoveAll(open => !open.Answering);
        }

        if (Refused > 0)
        {
            _log?.Info("cloud.sign_in.loopback_closed", new LogField("refused", (long)Refused));
        }
    }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or SocketException or InvalidOperationException)
                {
                    return;
                }

                var connection = new Connection(client);
                lock (_lock)
                {
                    if (_stop.IsCancellationRequested)
                    {
                        connection.Close();
                        return;
                    }

                    // N2 decision R-1: never refuse the new connection; close the oldest that has not sent its request line. At the hard
                    // cap (N2 review FX-4) the oldest that has not completed its request goes whatever it sent, so the count never exceeds it.
                    if (Evicted() is { } oldest)
                    {
                        oldest.Close();
                        _connections.Remove(oldest);
                    }

                    _connections.Add(connection);
                    if (_connections.Count > _peak)
                    {
                        Volatile.Write(ref _peak, _connections.Count);
                    }
                }

                _ = Task.Run(() => ServeAsync(connection));
            }
        }
        finally
        {
            _listener.Stop();
        }
    }

    /// <summary>
    /// The connection a new one closes (the caller holds the lock), or <see langword="null"/>. R-1: once <see cref="Capacity"/> connections
    /// are idle (no complete request line read, no bytes waiting to be read, older than <see cref="Grace"/>), the oldest idle one; so a
    /// browser's connection, whose request is on its way, is never closed by newer idle ones below the hard cap. FX-4: at <see cref="HardCapacity"/> open connections of any kind, the
    /// oldest one that has not completed its request, those with bytes waiting last, so stalled request lines go before a browser's
    /// request that is about to be read.
    /// </summary>
    private Connection? Evicted()
    {
        var now = Environment.TickCount64;
        var idle = _connections.Where(open => !open.LineComplete && !open.Answering && !open.Unread && now - open.Accepted >= (long)Grace.TotalMilliseconds).ToList();
        if (idle.Count >= Capacity)
        {
            return idle.MinBy(open => open.Accepted);
        }

        if (_connections.Count < HardCapacity)
        {
            return null;
        }

        var unfinished = _connections.Where(open => !open.RequestComplete && !open.Answering).ToList();
        return unfinished.Where(open => !open.Unread).MinBy(open => open.Accepted) ?? unfinished.MinBy(open => open.Accepted)
            ?? _connections.Where(open => !open.Answering).MinBy(open => open.Accepted);
    }

    private async Task ServeAsync(Connection connection)
    {
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            deadline.CancelAfter(RequestDeadline);
            var stream = connection.Client.GetStream();
            var request = await ReadRequestAsync(stream, connection, deadline.Token).ConfigureAwait(false);
            if (request is null)
            {
                return;
            }

            var result = Check(request);
            if (result is null)
            {
                Interlocked.Increment(ref _refused);
                LogRefusals();
                await WriteAsync(stream, "400 Bad Request", "text/plain; charset=utf-8", BadRequest, deadline.Token).ConfigureAwait(false);
                return;
            }

            if (Interlocked.CompareExchange(ref _served, 1, 0) != 0)
            {
                return;
            }

            // The single use is consumed and the result kept before the answer is written: a browser that resets the connection does not
            // leave the flow waiting for its expiry (N2 review sec N-3). The answer has its own deadline, not cut by the stop.
            connection.Answering = true;
            _result.TrySetResult(result);
            Stop();
            using var answer = new CancellationTokenSource(RequestDeadline);
            await WriteAsync(stream, "200 OK", "text/html; charset=utf-8", Page, answer.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or SocketException or OperationCanceledException or ObjectDisposedException
            or InvalidOperationException)
        {
            // An idle, slow or reset connection is closed silently; it is not a refused request.
        }
        finally
        {
            connection.Close();
            lock (_lock)
            {
                _connections.Remove(connection);
            }
        }
    }

    /// <summary>Reads the request line and the header block within the limits; a request beyond them is a bad request.</summary>
    private static async Task<Request?> ReadRequestAsync(NetworkStream stream, Connection connection, CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxRequestLine + MaxHeaderBytes + 4];
        var length = 0;
        var lineEnd = -1;
        while (true)
        {
            if (length == buffer.Length)
            {
                return Request.Bad;
            }

            var read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            var start = Math.Max(0, length - 3);
            length += read;
            if (lineEnd < 0)
            {
                lineEnd = IndexOf(buffer.AsSpan(0, length), "\r\n"u8);
                if (lineEnd < 0 && length > MaxRequestLine + 1)
                {
                    return Request.Bad;
                }

                if (lineEnd >= 0)
                {
                    if (lineEnd > MaxRequestLine)
                    {
                        return Request.Bad;
                    }

                    connection.LineComplete = true;
                }
            }

            var end = IndexOf(buffer.AsSpan(start, length - start), "\r\n\r\n"u8);
            if (end >= 0)
            {
                end += start;
                if (lineEnd < 0 || end - lineEnd - 2 > MaxHeaderBytes)
                {
                    return Request.Bad;
                }

                connection.RequestComplete = true;
                return Request.Parse(Encoding.Latin1.GetString(buffer, 0, lineEnd), Encoding.Latin1.GetString(buffer, lineEnd + 2, Math.Max(0, end - lineEnd - 2)),
                    length > end + 4);
            }

            if (lineEnd >= 0 && length - lineEnd - 2 > MaxHeaderBytes + 2)
            {
                return Request.Bad;
            }
        }
    }

    private static int IndexOf(ReadOnlySpan<byte> span, ReadOnlySpan<byte> value) => span.IndexOf(value);

    /// <summary>The valid request's result, or <see langword="null"/> for any other request.</summary>
    private LoopbackResult? Check(Request request)
    {
        if (!request.Valid || request.Method != "GET" || request.Version is not ("HTTP/1.1" or "HTTP/1.0") || request.HasBody
            || request.Hosts.Count != 1 || !string.Equals(request.Hosts[0], Authority, StringComparison.Ordinal))
        {
            return null;
        }

        const string Prefix = "/callback?";
        var target = request.Target;
        if (!target.StartsWith(Prefix, StringComparison.Ordinal) || target.Contains('%', StringComparison.Ordinal) || target.Contains('#', StringComparison.Ordinal))
        {
            return null;
        }

        var keys = target[Prefix.Length..].Split('&');
        if (keys.Length != 2 || !keys[1].StartsWith("state=", StringComparison.Ordinal))
        {
            return null;
        }

        var presented = Encoding.ASCII.GetBytes(keys[1]["state=".Length..]);
        byte[] expected;
        lock (_lock)
        {
            expected = _state;
        }

        if (presented.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(presented, expected))
        {
            return null;
        }

        if (keys[0] == "error=access_denied")
        {
            return new LoopbackResult(LoopbackOutcome.Denied, null);
        }

        return keys[0].StartsWith("code=", StringComparison.Ordinal) && Pkce.IsBase64Url43(keys[0]["code=".Length..])
            ? new LoopbackResult(LoopbackOutcome.Code, keys[0]["code=".Length..])
            : null;
    }

    private void LogRefusals()
    {
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastLog);
        if ((last == 0 || now - last >= 60_000) && Interlocked.CompareExchange(ref _lastLog, now, last) == last)
        {
            _log?.Info("cloud.sign_in.loopback_refused", new LogField("refused", (long)Refused));
        }
    }

    private static async Task WriteAsync(NetworkStream stream, string status, string type, string body, CancellationToken cancellationToken)
    {
        var content = Encoding.UTF8.GetBytes(body);
        var head = "HTTP/1.1 " + status + "\r\nContent-Type: " + type + "\r\nContent-Length: " + content.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + "\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'\r\nX-Content-Type-Options: nosniff"
            + "\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(head), cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private sealed class Connection(TcpClient client)
    {
        private int _closed;

        public TcpClient Client { get; } = client;

        public long Accepted { get; } = Environment.TickCount64;

        public bool LineComplete { get; set; }

        public bool RequestComplete { get; set; }

        public bool Answering { get; set; }

        /// <summary>Bytes arrived that the receiver has not read yet.</summary>
        public bool Unread
        {
            get
            {
                try
                {
                    return Volatile.Read(ref _closed) == 0 && Client.Client is { } socket && socket.Available > 0;
                }
                catch (Exception exception) when (exception is ObjectDisposedException or SocketException)
                {
                    return false;
                }
            }
        }

        public void Close()
        {
            if (Interlocked.Exchange(ref _closed, 1) == 0)
            {
                Client.Dispose();
            }
        }
    }

    private sealed class Request
    {
        public static readonly Request Bad = new() { Valid = false };

        public bool Valid { get; private init; } = true;

        public string Method { get; private init; } = string.Empty;

        public string Target { get; private init; } = string.Empty;

        public string Version { get; private init; } = string.Empty;

        public List<string> Hosts { get; } = [];

        public bool HasBody { get; private set; }

        public static Request Parse(string line, string headers, bool trailingBytes)
        {
            var parts = line.Split(' ');
            if (parts.Length != 3 || parts.Any(part => part.Length == 0))
            {
                return Bad;
            }

            var request = new Request { Method = parts[0], Target = parts[1], Version = parts[2], HasBody = trailingBytes };
            var lines = headers.Length == 0 ? [] : headers.Split("\r\n");
            if (lines.Length > MaxHeaderLines)
            {
                return Bad;
            }

            foreach (var header in lines)
            {
                var colon = header.IndexOf(':', StringComparison.Ordinal);
                if (colon <= 0)
                {
                    return Bad;
                }

                var name = header[..colon];
                var value = header[(colon + 1)..].Trim(' ', '\t');
                if (name.Equals("Host", StringComparison.OrdinalIgnoreCase))
                {
                    request.Hosts.Add(value);
                }
                else if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
                    || (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) && value != "0"))
                {
                    request.HasBody = true;
                }
            }

            return request;
        }
    }
}
