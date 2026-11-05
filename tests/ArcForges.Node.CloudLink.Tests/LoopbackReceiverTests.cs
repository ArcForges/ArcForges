// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N2-1: the loopback receiver over REAL sockets (CTR4-NODE-12 as amended by node-14 and N2 decision R-1; SEC-09, SEC-18), against the
/// center's vendored loopback-redirect vectors (<c>url-vectors.json</c> <c>redirects</c>, Cloud 41c8a72).
/// </summary>
public sealed class LoopbackReceiverTests
{
    private const string State = "node-state-0123456789abcdefghij";
    private const string Code = "xcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcU";

    private static JsonElement Vectors()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "center-vectors", "url-vectors.json")));
        return document.RootElement.Clone();
    }

    [Fact]
    public void TheRedirectUriBuilderMakesOnlyWhatTheCenterAdmits()
    {
        var root = Vectors();
        Assert.Equal(State, root.GetProperty("loopbackState").GetString());
        Assert.Equal(Code, root.GetProperty("loopbackCode").GetString());
        foreach (var vector in root.GetProperty("redirects").EnumerateArray())
        {
            var input = vector.GetProperty("input").GetString()!;
            var accepted = vector.GetProperty("accepted").GetBoolean();
            Assert.Equal(accepted, FakeCenter.AdmittedRedirect(input));
            var uri = Uri.TryCreate(input, UriKind.Absolute, out var parsed) ? parsed : null;
            if (accepted)
            {
                // The builder makes exactly the accepted vectors from their address and port.
                Assert.Equal(input, SignInUrls.RedirectUri(uri!.Host == "[::1]" ? IPAddress.IPv6Loopback : IPAddress.Loopback, uri.Port));
            }
        }

        Assert.Null(SignInUrls.RedirectUri(IPAddress.Loopback, 1023));
        Assert.Null(SignInUrls.RedirectUri(IPAddress.Loopback, 65536));
        Assert.Null(SignInUrls.RedirectUri(IPAddress.Any, 53682));
        Assert.Equal("http://127.0.0.1:1024/callback", SignInUrls.RedirectUri(IPAddress.Loopback, 1024));
        Assert.Equal("http://[::1]:65535/callback", SignInUrls.RedirectUri(IPAddress.IPv6Loopback, 65535));
    }

    [Fact]
    public async Task TheReceiverAcceptsExactlyTheCentersApprovalAndDenialRedirects()
    {
        foreach (var vector in Vectors().GetProperty("redirects").EnumerateArray().Where(vector => vector.GetProperty("accepted").GetBoolean()).Take(1))
        {
            foreach (var (property, outcome) in new[] { ("codeRedirect", LoopbackOutcome.Code), ("denyRedirect", LoopbackOutcome.Denied) })
            {
                await using var receiver = Start();
                var redirect = vector.GetProperty(property).GetString()!.Replace(":53682/", ":" + receiver.Port + "/", StringComparison.Ordinal);
                Assert.StartsWith(receiver.RedirectUri, redirect, StringComparison.Ordinal);
                var reply = await ScriptedBrowser.FullAsync(redirect);
                Assert.StartsWith("HTTP/1.1 200 OK", reply, StringComparison.Ordinal);
                foreach (var header in new[] { "Cache-Control: no-store", "Referrer-Policy: no-referrer", "Content-Security-Policy: default-src 'none'", "X-Content-Type-Options: nosniff" })
                {
                    Assert.Contains(header, reply, StringComparison.Ordinal);
                }

                Assert.DoesNotContain("<script", reply, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("Access-Control", reply, StringComparison.OrdinalIgnoreCase);
                var result = await receiver.Result.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
                Assert.Equal(outcome, result.Outcome);
                Assert.Equal(outcome == LoopbackOutcome.Code ? Code : null, result.Code);
                await receiver.Closed.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            }
        }
    }

    [Theory]
    [InlineData("foreign host")]
    [InlineData("localhost host")]
    [InlineData("two hosts")]
    [InlineData("wrong state")]
    [InlineData("state prefix")]
    [InlineData("extra key")]
    [InlineData("repeated key")]
    [InlineData("reordered keys")]
    [InlineData("percent")]
    [InlineData("other path")]
    [InlineData("trailing slash")]
    [InlineData("short code")]
    [InlineData("other error")]
    [InlineData("post")]
    [InlineData("head")]
    [InlineData("body")]
    [InlineData("chunked")]
    [InlineData("fragment")]
    public async Task EveryOtherRequestIsRefusedAndTheFlowContinues(string variant)
    {
        await using var receiver = Start();
        var base_ = "http://127.0.0.1:" + receiver.Port;
        var good = base_ + "/callback?code=" + Code + "&state=" + State;
        var status = variant switch
        {
            "foreign host" => await ScriptedBrowser.GetAsync(good, host: "evil.example:" + receiver.Port),
            "localhost host" => await ScriptedBrowser.GetAsync(good, host: "localhost:" + receiver.Port),
            "two hosts" => await ScriptedBrowser.GetAsync(good, extraHeaders: "Host: 127.0.0.1:" + receiver.Port + "\r\n"),
            "wrong state" => await ScriptedBrowser.GetAsync(base_ + "/callback?code=" + Code + "&state=" + State[..^1] + "x"),
            "state prefix" => await ScriptedBrowser.GetAsync(base_ + "/callback?code=" + Code + "&state=" + State[..^1]),
            "extra key" => await ScriptedBrowser.GetAsync(good + "&x=1"),
            "repeated key" => await ScriptedBrowser.GetAsync(good + "&state=" + State),
            "reordered keys" => await ScriptedBrowser.GetAsync(base_ + "/callback?state=" + State + "&code=" + Code),
            "percent" => await ScriptedBrowser.GetAsync(base_ + "/callback?code=" + Code + "&state=node%2Dstate-0123456789abcdefghij"),
            "other path" => await ScriptedBrowser.GetAsync(base_ + "/cb?code=" + Code + "&state=" + State),
            "trailing slash" => await ScriptedBrowser.GetAsync(base_ + "/callback/?code=" + Code + "&state=" + State),
            "short code" => await ScriptedBrowser.GetAsync(base_ + "/callback?code=" + Code[1..] + "&state=" + State),
            "other error" => await ScriptedBrowser.GetAsync(base_ + "/callback?error=server_error&state=" + State),
            "post" => await ScriptedBrowser.GetAsync(good, method: "POST"),
            "head" => await ScriptedBrowser.GetAsync(good, method: "HEAD"),
            "body" => await ScriptedBrowser.GetAsync(good, body: "x=1"),
            "chunked" => await ScriptedBrowser.GetAsync(good, extraHeaders: "Transfer-Encoding: chunked\r\n"),
            _ => await ScriptedBrowser.GetAsync(good + "#x"),
        };
        Assert.Equal("HTTP/1.1 400 Bad Request", status);
        Assert.False(receiver.Result.IsCompleted);
        Assert.Equal(1, receiver.Refused);

        // The flow continues: the valid request still completes.
        Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync(good));
        Assert.Equal(LoopbackOutcome.Code, (await receiver.Result.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken)).Outcome);
    }

    [Fact]
    public async Task OversizeRequestsAreRefused()
    {
        await using var receiver = Start();
        var line = "GET /callback?code=" + Code + "&state=" + State + "&pad=" + new string('a', 2100) + " HTTP/1.1\r\nHost: 127.0.0.1:" + receiver.Port + "\r\n\r\n";
        Assert.Equal("HTTP/1.1 400 Bad Request", await ScriptedBrowser.RawAsync("127.0.0.1", receiver.Port, line));
        var headers = new StringBuilder("GET /callback?code=" + Code + "&state=" + State + " HTTP/1.1\r\nHost: 127.0.0.1:" + receiver.Port + "\r\n");
        for (var i = 0; i < 33; i++)
        {
            headers.Append("X-Pad-").Append(i).Append(": 1\r\n");
        }

        Assert.Equal("HTTP/1.1 400 Bad Request", await ScriptedBrowser.RawAsync("127.0.0.1", receiver.Port, headers + "\r\n"));
        var big = "GET /callback?code=" + Code + "&state=" + State + " HTTP/1.1\r\nHost: 127.0.0.1:" + receiver.Port + "\r\nX-Big: " + new string('b', 8300) + "\r\n\r\n";
        Assert.Equal("HTTP/1.1 400 Bad Request", await ScriptedBrowser.RawAsync("127.0.0.1", receiver.Port, big));
        Assert.False(receiver.Result.IsCompleted);
    }

    [Fact]
    public async Task ABurstOfBadRequestsDoesNotEndTheFlow()
    {
        await using var receiver = Start();
        var bad = "http://127.0.0.1:" + receiver.Port + "/favicon.ico";
        for (var round = 0; round < 250; round++)
        {
            await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => ScriptedBrowser.GetAsync(bad)));
        }

        Assert.Equal(1000, receiver.Refused);
        Assert.False(receiver.Result.IsCompleted);
        Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync("http://127.0.0.1:" + receiver.Port + "/callback?code=" + Code + "&state=" + State));
        Assert.Equal(LoopbackOutcome.Code, (await receiver.Result.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken)).Outcome);
    }

    [Fact]
    public async Task IdleConnectionsDoNotDelayAValidRequest()
    {
        await using var receiver = Start();
        var idle = new List<TcpClient>();
        try
        {
            for (var i = 0; i < 20; i++)
            {
                var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, receiver.Port, TestContext.Current.CancellationToken);
                idle.Add(client);
            }

            var watch = Stopwatch.StartNew();
            Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync("http://127.0.0.1:" + receiver.Port + "/callback?code=" + Code + "&state=" + State));
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(1), "the valid request took " + watch.Elapsed);
        }
        finally
        {
            idle.ForEach(client => client.Dispose());
        }
    }

    [Fact]
    public async Task ReopenedIdleConnectionsNeverLockTheBrowserOut()
    {
        await using var receiver = Start();
        using var stop = new CancellationTokenSource();
        var pressure = Task.Run(async () =>
        {
            var open = new Queue<TcpClient>();
            while (!stop.IsCancellationRequested)
            {
                var client = new TcpClient();
                try
                {
                    await client.ConnectAsync(IPAddress.Loopback, receiver.Port, stop.Token);
                    open.Enqueue(client);
                    if (open.Count > 30)
                    {
                        open.Dequeue().Dispose();
                    }
                }
                catch (Exception exception) when (exception is SocketException or OperationCanceledException)
                {
                    client.Dispose();
                }
            }

            while (open.Count > 0)
            {
                open.Dequeue().Dispose();
            }
        }, TestContext.Current.CancellationToken);
        await Task.Delay(200, TestContext.Current.CancellationToken);
        var watch = Stopwatch.StartNew();
        var status = await ScriptedBrowser.GetAsync("http://127.0.0.1:" + receiver.Port + "/callback?code=" + Code + "&state=" + State);
        await stop.CancelAsync();
        await pressure;
        Assert.Equal("HTTP/1.1 200 OK", status);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), "the valid request took " + watch.Elapsed);
    }

    [Fact]
    public async Task ASlowSenderIsClosedAtItsDeadlineAndRefusesNothing()
    {
        await using var receiver = Start();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, receiver.Port, TestContext.Current.CancellationToken);
        var stream = client.GetStream();
        var watch = Stopwatch.StartNew();
        var buffer = new byte[64];
        var read = 0;
        try
        {
            // Slowloris: a byte a second; one total deadline of 5 s closes it.
            for (var i = 0; i < 12 && read == 0; i++)
            {
                await stream.WriteAsync("G"u8.ToArray(), TestContext.Current.CancellationToken);
                using var tick = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                try
                {
                    read = await stream.ReadAsync(buffer, tick.Token);
                    break;
                }
                catch (OperationCanceledException)
                {
                }
            }
        }
        catch (IOException)
        {
        }

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(9), "the slow connection lived " + watch.Elapsed);
        Assert.Equal(0, read);
        Assert.Equal(0, receiver.Refused);
        Assert.False(receiver.Result.IsCompleted);
    }

    [Fact]
    public async Task OneValidRequestClosesTheListener()
    {
        var receiver = Start();
        Assert.Equal(IPAddress.Loopback, receiver.Address);
        Assert.Equal("http://127.0.0.1:" + receiver.Port + "/callback", receiver.RedirectUri);
        Assert.InRange(receiver.Port, 1024, 65535);
        var good = "http://127.0.0.1:" + receiver.Port + "/callback?code=" + Code + "&state=" + State;
        Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync(good));
        await receiver.Closed.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(1, receiver.Served);

        // A later request is not served by this receiver (single use).
        try
        {
            await ScriptedBrowser.GetAsync(good);
        }
        catch (SocketException)
        {
        }

        Assert.Equal(1, receiver.Served);
        await receiver.DisposeAsync();
    }

    [Fact]
    public async Task TheReceiverFallsBackToIPv6AndReportsAFailedBind()
    {
        var ipv6 = Socket.OSSupportsIPv6;
        await using (var receiver = LoopbackReceiver.TryStart(State, null, address => address.Equals(IPAddress.Loopback) ? throw new SocketException(10013) : new TcpListener(address, 0)))
        {
            if (ipv6 && receiver is not null)
            {
                Assert.Equal(IPAddress.IPv6Loopback, receiver.Address);
                Assert.Equal("http://[::1]:" + receiver.Port + "/callback", receiver.RedirectUri);
                Assert.Equal("[::1]:" + receiver.Port, receiver.Authority);
            }
        }

        Assert.Null(LoopbackReceiver.TryStart(State, null, _ => throw new SocketException(10013)));
    }

    [Fact]
    public async Task AnotherStateIsExpectedAfterExpect()
    {
        await using var receiver = Start();
        receiver.Expect("another-state-0123456789");
        Assert.Equal("HTTP/1.1 400 Bad Request", await ScriptedBrowser.GetAsync("http://127.0.0.1:" + receiver.Port + "/callback?code=" + Code + "&state=" + State));
        Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync("http://127.0.0.1:" + receiver.Port + "/callback?code=" + Code + "&state=another-state-0123456789"));
    }

    [Fact]
    public async Task ConnectionsThatSendARequestLineAndStallNeverExceedTheHardCapAndTheBrowserIsServed()
    {
        // N2 review FX-4 (sec B-4): every open connection counts, also one whose request line arrived; at the cap the oldest that has not
        // completed its request is closed, so a stream of stalled request lines cannot pin sockets beyond it or lock the browser out.
        await using var receiver = Start();
        using var stop = new CancellationTokenSource();
        var stalled = new System.Collections.Concurrent.ConcurrentQueue<TcpClient>();
        async Task FloodAsync()
        {
            while (!stop.IsCancellationRequested)
            {
                var client = new TcpClient();
                try
                {
                    await client.ConnectAsync(IPAddress.Loopback, receiver.Port, stop.Token);
                    await client.GetStream().WriteAsync("GET / HTTP/1.1\r\n"u8.ToArray(), stop.Token);
                    stalled.Enqueue(client);
                }
                catch (Exception exception) when (exception is SocketException or IOException or OperationCanceledException)
                {
                    client.Dispose();
                    return;
                }
            }
        }

        var flood = Enumerable.Range(0, 4).Select(_ => Task.Run(FloodAsync, TestContext.Current.CancellationToken)).ToArray();
        try
        {
            var deadline = Stopwatch.StartNew();
            while (stalled.Count < LoopbackReceiver.HardCapacity + 64 && deadline.Elapsed < TimeSpan.FromSeconds(3))
            {
                await Task.Delay(20, TestContext.Current.CancellationToken);
            }

            Assert.True(stalled.Count > LoopbackReceiver.HardCapacity, "only " + stalled.Count + " connections were opened");
            Assert.InRange(receiver.Peak, 1, LoopbackReceiver.HardCapacity);
            Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync("http://127.0.0.1:" + receiver.Port + "/callback?code=" + Code + "&state=" + State));
            Assert.InRange(receiver.Peak, 1, LoopbackReceiver.HardCapacity);
        }
        finally
        {
            await stop.CancelAsync();
            await Task.WhenAll(flood);
            while (stalled.TryDequeue(out var client))
            {
                client.Dispose();
            }
        }
    }

    [Fact]
    public async Task StalledRequestLinesAreClosedAtTheCapWhileAFlowWaits()
    {
        await using var receiver = Start();
        var stalled = new List<TcpClient>();
        try
        {
            const int Count = LoopbackReceiver.HardCapacity + 44;
            for (var i = 0; i < Count; i++)
            {
                var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, receiver.Port, TestContext.Current.CancellationToken);
                await client.GetStream().WriteAsync("GET / HTTP/1.1\r\n"u8.ToArray(), TestContext.Current.CancellationToken);
                stalled.Add(client);
            }

            await Task.Delay(300, TestContext.Current.CancellationToken);
            Assert.InRange(receiver.Peak, 1, LoopbackReceiver.HardCapacity);
            Assert.InRange(receiver.Open, 0, LoopbackReceiver.HardCapacity);
            var closed = 0;
            foreach (var client in stalled)
            {
                if (client.Client.Poll(0, SelectMode.SelectRead) && client.Client.Available == 0)
                {
                    closed++;
                }
            }

            // At least the connections beyond the cap were closed by the receiver (on 1483afb none was: each lived its 5 s).
            Assert.True(closed >= Count - LoopbackReceiver.HardCapacity, "closed " + closed);
            Assert.False(receiver.Result.IsCompleted);
            Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync("http://127.0.0.1:" + receiver.Port + "/callback?code=" + Code + "&state=" + State));
        }
        finally
        {
            stalled.ForEach(client => client.Dispose());
        }
    }

    [Fact]
    public async Task AConnectionWhoseRequestLineArrivedIsNotClosedBelowTheHardCap()
    {
        // R-1's other half (sec S3): below the hard cap only idle connections (no complete request line) are closed, the oldest first.
        await using var receiver = Start();
        using var early = new TcpClient();
        await early.ConnectAsync(IPAddress.Loopback, receiver.Port, TestContext.Current.CancellationToken);
        var stream = early.GetStream();
        await stream.WriteAsync("GET / HTTP/1.1\r\n"u8.ToArray(), TestContext.Current.CancellationToken);
        var idle = new List<TcpClient>();
        try
        {
            // Every connection past the grace, then a stream of new idle ones: the old idle ones are closed, the oldest first; the early
            // connection, the oldest of all, is not idle.
            await Task.Delay(LoopbackReceiver.Grace + TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);
            await OpenAsync(2 * LoopbackReceiver.Capacity);
            await Task.Delay(LoopbackReceiver.Grace + TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);
            await OpenAsync(2 * LoopbackReceiver.Capacity);
            await Task.Delay(200, TestContext.Current.CancellationToken);
            var closed = idle.Take(2 * LoopbackReceiver.Capacity).Count(client => client.Client.Poll(0, SelectMode.SelectRead) && client.Client.Available == 0);
            Assert.True(closed > LoopbackReceiver.Capacity, "only " + closed + " old idle connections were closed");
            await stream.WriteAsync(Encoding.ASCII.GetBytes("Host: 127.0.0.1:" + receiver.Port + "\r\n\r\n"), TestContext.Current.CancellationToken);
            var buffer = new byte[64];
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            wait.CancelAfter(TimeSpan.FromSeconds(5));
            var read = await stream.ReadAsync(buffer, wait.Token);
            Assert.StartsWith("HTTP/1.1 400 Bad Request", Encoding.ASCII.GetString(buffer, 0, read), StringComparison.Ordinal);
        }
        finally
        {
            idle.ForEach(client => client.Dispose());
        }

        async Task OpenAsync(int count)
        {
            for (var i = 0; i < count; i++)
            {
                var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, receiver.Port, TestContext.Current.CancellationToken);
                idle.Add(client);
            }
        }
    }

    [Fact]
    public async Task AFreshConnectionOutlivesAFloodOfIdleOnesBelowTheHardCap()
    {
        // The grace (S2): a connection that has not sent yet (a browser between connect and send) is not closed by newer idle ones.
        await using var receiver = Start();
        using var fresh = new TcpClient();
        await fresh.ConnectAsync(IPAddress.Loopback, receiver.Port, TestContext.Current.CancellationToken);
        var idle = new List<TcpClient>();
        try
        {
            for (var i = 0; i < 4 * LoopbackReceiver.Capacity; i++)
            {
                var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, receiver.Port, TestContext.Current.CancellationToken);
                idle.Add(client);
            }

            await Task.Delay(100, TestContext.Current.CancellationToken);
            var stream = fresh.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes("GET /callback?code=" + Code + "&state=" + State + " HTTP/1.1\r\nHost: 127.0.0.1:" + receiver.Port + "\r\n\r\n"),
                TestContext.Current.CancellationToken);
            var buffer = new byte[64];
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            wait.CancelAfter(TimeSpan.FromSeconds(5));
            var read = await stream.ReadAsync(buffer, wait.Token);
            Assert.StartsWith("HTTP/1.1 200 OK", Encoding.ASCII.GetString(buffer, 0, read), StringComparison.Ordinal);
        }
        finally
        {
            idle.ForEach(client => client.Dispose());
        }
    }

    [Fact]
    public async Task TheReceiverBindsOnlyALoopbackAddress()
    {
        // N2 review FX-8 (tests B-3): the bound endpoint as the socket reports it, not the address the receiver believes it chose.
        await using var receiver = Start();
        Assert.Equal(IPAddress.Loopback, receiver.LocalEndpoint.Address);
        Assert.True(IPAddress.IsLoopback(receiver.LocalEndpoint.Address));
        Assert.Equal(receiver.Port, receiver.LocalEndpoint.Port);
        if (Socket.OSSupportsIPv6)
        {
            await using var ipv6 = LoopbackReceiver.TryStart(State, null, address => address.Equals(IPAddress.Loopback) ? throw new SocketException(10013) : new TcpListener(address, 0));
            if (ipv6 is not null)
            {
                Assert.Equal(IPAddress.IPv6Loopback, ipv6.LocalEndpoint.Address);
                Assert.True(IPAddress.IsLoopback(ipv6.LocalEndpoint.Address));
            }
        }
    }

    [Fact]
    public async Task AValidRequestWhoseConnectionIsResetStillEndsTheWait()
    {
        // N2 review sec N-3: the result is kept before the answer is written.
        await using var receiver = Start();
        var client = new TcpClient { LingerState = new LingerOption(true, 0) };
        await client.ConnectAsync(IPAddress.Loopback, receiver.Port, TestContext.Current.CancellationToken);
        await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes("GET /callback?code=" + Code + "&state=" + State + " HTTP/1.1\r\nHost: 127.0.0.1:" + receiver.Port + "\r\n\r\n"),
            TestContext.Current.CancellationToken);
        client.Dispose();
        var result = await receiver.Result.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(LoopbackOutcome.Code, result.Outcome);
    }

    private static LoopbackReceiver Start() => LoopbackReceiver.TryStart(State, null) ?? throw new InvalidOperationException("no loopback port");
}
