// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using Google.Protobuf;
using Microsoft.AspNetCore.Http;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>A call the test builds and the channel peer signs (every field can be overridden to forge or alter it).</summary>
internal sealed record FakeCallSpec
{
    public RoutedMethod Method { get; init; } = RoutedMethod.GetNodeTask;

    public byte[] Payload { get; init; } = new TaskServiceGetTaskRequest { TaskId = CommandIds.New() }.ToByteArray();

    public TimeSpan IssuedOffset { get; init; } = TimeSpan.Zero;

    public TimeSpan Lifetime { get; init; } = TimeSpan.FromSeconds(60);

    public Id? CallId { get; init; }

    public Id? HeaderCallId { get; init; }

    public byte[]? TargetNodeId { get; init; }

    public byte[]? AccountId { get; init; }

    public string? CenterUrl { get; init; }

    public string? HeaderKid { get; init; }

    public string? FrameKid { get; init; }

    public string Algorithm { get; init; } = "ES256";

    /// <summary>The key that signs the header (null: the peer's command key).</summary>
    public ECDsa? SigningKey { get; init; }

    /// <summary>The domain string of the signature (the routed-call one by default).</summary>
    public string Domain { get; init; } = "ArcForges relay-call v1\n";

    /// <summary>A change of the header bytes after the signature (a flipped byte), or of the payload.</summary>
    public Func<byte[], byte[]>? AlterHeader { get; init; }

    public Func<byte[], byte[]>? AlterPayload { get; init; }

    /// <summary>A change of the signature (high-S, other length).</summary>
    public Func<byte[], byte[]>? AlterSignature { get; init; }

    /// <summary>Raw header bytes instead of an encoded CallHeader (then signed as given).</summary>
    public byte[]? RawHeader { get; init; }
}

/// <summary>
/// FakeCenter's node channel peer (AF-CTR-05 part N1; the Plan's <c>fakes_allowed</c> FakeCenter channel peer, P0): the center side of
/// <c>GET &lt;center&gt;/fleet/v1/node</c> over a real loopback WebSocket, for forged and altered frames the real center never sends. It admits
/// the upgrade on a live access token of FakeCenter's sessions (else 401 with the refusal header), sends ChannelChallenge, verifies the
/// NodeHello proof with its OWN verifier (independent of the node's builder) against the node key registered for the token's installation,
/// replaces an older proved connection (4409), answers relay nonce requests, records TokenRefresh frames and results, and verifies every
/// result's signature independently. Heartbeats and calls are sent only when a test asks. It never stands in for an end-to-end result;
/// its frames are conformance-tested against the Contracts golden vectors and the 14 captures of the real hub (Cloud E1a, c14156bf).
/// </summary>
internal sealed class FakeChannelPeer(FakeCenter center)
{
    public const string Path = "/fleet/v1/node";
    public const string Subprotocol = "arcforges.relay.v1";
    public const string Kid = "cmd-fake-0001";

    private readonly ConcurrentQueue<FakeChannelConnection> _connections = new();
    private readonly ConcurrentDictionary<string, byte[]> _nodeKeys = new(StringComparer.Ordinal);
    private int _upgrades;

    /// <summary>The upgrade requests received (refused or not).</summary>
    public int Upgrades => Volatile.Read(ref _upgrades);

    /// <summary>The center URL whose SHA-256 the hello proof and the calls carry.</summary>
    public string CenterUrl => center.Endpoint.Url;

    /// <summary>The command key the peer signs calls with (P-256).</summary>
    public ECDsa CommandKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>The public half as a center delivers it at sign-in and refresh.</summary>
    public PublicKey CommandPublicKey => new()
    {
        Kid = Kid,
        Algorithm = "ES256",
        Key = ByteString.CopyFrom(CommandKey.ExportSubjectPublicKeyInfo()),
        NotBefore = ProtoTime.ToInstant(center.Clock.GetUtcNow() - TimeSpan.FromDays(1)),
        NotAfter = ProtoTime.ToInstant(center.Clock.GetUtcNow() + TimeSpan.FromDays(30)),
    };

    /// <summary>The kids ChannelAccepted names (default: the peer's command key).</summary>
    public List<string> SigningKids { get; } = [Kid];

    /// <summary>Answers the next upgrade with this HTTP status and refusal code instead of upgrading (Plan PN-3).</summary>
    public (int Status, string? Code)? RefuseUpgrade { get; set; }

    /// <summary>
    /// Serves the next upgrade from a captured exchange of the real center (Cloud E1a captures): its HTTP refusal with its refusal header,
    /// or the captured center frames byte for byte (the first before the node's hello, the rest after it) and the captured close code.
    /// </summary>
    public FakeChannelReplay? Replay { get; set; }

    /// <summary>The frames the node sent during replays.</summary>
    public ConcurrentQueue<byte[]> ReplayReceived { get; } = new();

    /// <summary>When false, the peer never answers a NodeHello (the node's handshake times out).</summary>
    public bool Accepting { get; set; } = true;

    /// <summary>When false, relay nonce requests stay unanswered.</summary>
    public bool AnswerNonces { get; set; } = true;

    /// <summary>The limits ChannelAccepted carries.</summary>
    public ChannelLimits Limits { get; set; } = DefaultLimits;

    /// <summary>The policy defaults of the center's limits (relay.proto ChannelLimits).</summary>
    public static ChannelLimits DefaultLimits => new()
    {
        MaxFrameBytes = 1_048_576,
        MaxInFlightCalls = 8,
        HeartbeatIntervalMs = 25_000,
        HeartbeatDeadlineMs = 60_000,
        MaxRelayNonces = 8,
    };

    /// <summary>The upgrade attempts, in order (proved or not).</summary>
    public IReadOnlyList<FakeChannelConnection> Connections => [.. _connections];

    /// <summary>Registers the node key of the session of <paramref name="accessToken"/> (as a sign-in registers it for the installation).</summary>
    public void RegisterNodeKey(string accessToken, byte[] spki)
    {
        var identity = center.ChannelIdentity(accessToken) ?? throw new InvalidOperationException("No session of that token.");
        _nodeKeys[Convert.ToHexString(identity.Installation)] = spki;
    }

    /// <summary>Registers the key a sign-in delivered for <paramref name="installation"/> (FakeCenter's enrollment).</summary>
    internal void RegisterInstallationKey(byte[] installation, byte[] spki) => _nodeKeys[Convert.ToHexString(installation)] = spki;

    /// <summary>The registered key of an installation.</summary>
    public byte[]? NodeKeyOf(byte[] installation) => _nodeKeys.GetValueOrDefault(Convert.ToHexString(installation));

    /// <summary>Waits (real time) for the <paramref name="count"/>th proved connection.</summary>
    public async Task<FakeChannelConnection> ProvedAsync(int count = 1)
    {
        var until = DateTime.UtcNow + TimeSpan.FromSeconds(15);
        while (DateTime.UtcNow < until)
        {
            var proved = Connections.Where(connection => connection.Proved).ToList();
            if (proved.Count >= count)
            {
                return proved[count - 1];
            }

            await Task.Delay(20);
        }

        throw new TimeoutException("No proved channel connection " + count + " within 15 s.");
    }

    /// <summary>Builds and signs a call to the node of <paramref name="connection"/> from <paramref name="spec"/>.</summary>
    public (ChannelCall Call, CallHeader? Header) BuildCall(FakeChannelConnection connection, FakeCallSpec spec)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(spec);
        var now = center.Clock.GetUtcNow() + spec.IssuedOffset;
        var callId = spec.CallId ?? CommandIds.New();
        var payload = spec.Payload;
        var commanded = spec.Method is RoutedMethod.SubmitNodeTask or RoutedMethod.CancelNodeTask;
        CallHeader? header = null;
        byte[] headerBytes;
        if (spec.RawHeader is { } raw)
        {
            headerBytes = raw;
        }
        else
        {
            header = new CallHeader
            {
                CallId = spec.HeaderCallId ?? callId,
                Kid = spec.HeaderKid ?? Kid,
                CenterUrlSha256 = ByteString.CopyFrom(SHA256.HashData(Encoding.UTF8.GetBytes(spec.CenterUrl ?? center.Endpoint.Url))),
                AccountId = new Id { Value = ByteString.CopyFrom(spec.AccountId ?? connection.AccountId) },
                TargetNodeId = new Id { Value = ByteString.CopyFrom(spec.TargetNodeId ?? connection.NodeId) },
                Caller = new CenterCaller
                {
                    Kind = CenterCallerKind.AccountSession,
                    AccountId = new Id { Value = ByteString.CopyFrom(spec.AccountId ?? connection.AccountId) },
                    UserId = CommandIds.New(),
                    SessionId = CommandIds.New(),
                },
                Method = spec.Method,
                RequestSha256 = ByteString.CopyFrom(SHA256.HashData(payload)),
                RequestSize = (uint)payload.Length,
                IssuedAt = ProtoTime.ToInstant(now),
                ExpiresAt = ProtoTime.ToInstant(now + spec.Lifetime),
                Deadline = ProtoTime.ToInstant(now + TimeSpan.FromTicks(Math.Min(spec.Lifetime.Ticks, TimeSpan.FromSeconds(10).Ticks))),
            };
            if (commanded)
            {
                header.CommandId = CommandIds.New();
            }

            headerBytes = header.ToByteArray();
        }

        var signature = Sign(spec.SigningKey ?? CommandKey, [.. Encoding.ASCII.GetBytes(spec.Domain), .. headerBytes]);
        var call = new ChannelCall
        {
            CallId = callId,
            Header = new SignedHeader
            {
                Header = ByteString.CopyFrom(spec.AlterHeader?.Invoke(headerBytes) ?? headerBytes),
                Signature = ByteString.CopyFrom(spec.AlterSignature?.Invoke(signature) ?? signature),
                Kid = spec.FrameKid ?? Kid,
                Algorithm = spec.Algorithm,
            },
            Payload = ByteString.CopyFrom(spec.AlterPayload?.Invoke(payload) ?? payload),
        };
        return (call, header);
    }

    /// <summary>ES256 P1363 low-S (the center's signer, independent of the node's code).</summary>
    public static byte[] Sign(ECDsa key, byte[] input)
    {
        var signature = key.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var s = new BigInteger(signature.AsSpan(32), isUnsigned: true, isBigEndian: true);
        if (s > HalfOrder)
        {
            var low = (Order - s).ToByteArray(isUnsigned: true, isBigEndian: true);
            Array.Clear(signature, 32, 32);
            low.CopyTo(signature.AsSpan(64 - low.Length));
        }

        return signature;
    }

    /// <summary>The same signature with s replaced by n - s (high-S).</summary>
    public static byte[] HighS(byte[] signature)
    {
        var copy = (byte[])signature.Clone();
        var s = new BigInteger(copy.AsSpan(32), isUnsigned: true, isBigEndian: true);
        var high = (Order - s).ToByteArray(isUnsigned: true, isBigEndian: true);
        Array.Clear(copy, 32, 32);
        high.CopyTo(copy.AsSpan(64 - high.Length));
        return copy;
    }

    /// <summary>Verifies a P-256 P1363 low-S signature (independent of the node's verifier).</summary>
    public static bool Verify(byte[] spki, byte[] input, byte[] signature)
    {
        if (signature.Length != 64 || new BigInteger(signature.AsSpan(32), isUnsigned: true, isBigEndian: true) > HalfOrder)
        {
            return false;
        }

        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(spki, out _);
        return key.VerifyData(input, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>The account's name for the node in ChannelAccepted, or <see langword="null"/> (the captured hub sends none).</summary>
    public string? NodeName { get; set; }

    /// <summary>The challenge frame the peer sends first (its own encoder; the conformance test compares it with the hub's).</summary>
    public static RelayFrame ChallengeFrame(byte[] nonce, Id connectionId, DateTimeOffset helloDeadline) => new()
    {
        Challenge = new ChannelChallenge { Nonce = ByteString.CopyFrom(nonce), ConnectionId = connectionId, HelloDeadline = ProtoTime.ToInstant(helloDeadline) },
    };

    /// <summary>The acceptance the peer sends after a proved hello.</summary>
    public static RelayFrame AcceptedFrame(Id connectionId, ChannelLimits limits, IEnumerable<string> kids, string? nodeName)
    {
        var accepted = new ChannelAccepted { ConnectionId = connectionId, Limits = limits };
        accepted.SigningKids.AddRange(kids);
        if (nodeName is not null)
        {
            accepted.NodeName = nodeName;
        }

        return new RelayFrame { Accepted = accepted };
    }

    /// <summary>
    /// The center's own check of a hello (relay.proto, "channel hello proof"; the hub's reasons): <c>hello_malformed</c>,
    /// <c>hello_signature</c> (the proof by the installation's registered key over this connection's nonce and ID and the credential's
    /// node and installation), <c>hello_mismatch</c> (the hello names another node or installation), or <see langword="null"/> when it proves.
    /// </summary>
    public static string? HelloFailure(NodeHello hello, byte[]? key, byte[] nonce, Id connectionId, string centerUrl, byte[] nodeId, byte[] installation)
    {
        ArgumentNullException.ThrowIfNull(hello);
        if (hello.NodeId?.Value.Length != 16 || hello.InstallationId?.Value.Length != 16 || hello.HelloSignature.Length != 64)
        {
            return "hello_malformed";
        }

        var input = new byte[137];
        Encoding.ASCII.GetBytes("ArcForges relay-hello v1\n", input);
        nonce.CopyTo(input, 25);
        connectionId.Value.Span.CopyTo(input.AsSpan(57));
        SHA256.HashData(Encoding.UTF8.GetBytes(centerUrl)).CopyTo(input, 73);
        nodeId.CopyTo(input, 105);
        installation.CopyTo(input, 121);
        if (key is null || !Verify(key, input, hello.HelloSignature.ToByteArray()))
        {
            return "hello_signature";
        }

        return hello.NodeId.Value.Span.SequenceEqual(nodeId) && hello.InstallationId.Value.Span.SequenceEqual(installation) ? null : "hello_mismatch";
    }

    /// <summary>The close frame of the center (the golden vector's encoding at its frame_seq).</summary>
    public static RelayFrame CloseFrame(uint code, string reason, uint? reconnectAfterMs)
    {
        var close = new RelayClose { Code = code, Reason = reason };
        if (reconnectAfterMs is { } after)
        {
            close.ReconnectAfterMs = after;
        }

        return new RelayFrame { Close = close };
    }

    internal static readonly BigInteger Order = BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

    private static readonly BigInteger HalfOrder = Order >> 1;

    /// <summary>Serves one upgrade request.</summary>
    internal async Task HandleAsync(HttpContext context)
    {
        Interlocked.Increment(ref _upgrades);
        var bearer = context.Request.Headers.Authorization.ToString();
        var token = bearer.StartsWith("Bearer ", StringComparison.Ordinal) ? bearer[7..] : null;
        if (!context.WebSockets.IsWebSocketRequest || !context.WebSockets.WebSocketRequestedProtocols.Contains(Subprotocol))
        {
            context.Response.StatusCode = 400;
            return;
        }

        if (Replay is { } replay)
        {
            Replay = null;
            await ReplayAsync(context, replay);
            return;
        }

        if (RefuseUpgrade is { } refusal)
        {
            RefuseUpgrade = null;
            context.Response.StatusCode = refusal.Status;
            if (refusal.Code is { } code)
            {
                context.Response.Headers[CenterChannelClient.RefusalHeader] = code;
            }
            return;
        }

        if (token is null || center.ChannelIdentity(token) is not { } identity)
        {
            context.Response.StatusCode = 401;
            context.Response.Headers[CenterChannelClient.RefusalHeader] = "AUTHENTICATION/unauthenticated";
            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync(new WebSocketAcceptContext { SubProtocol = Subprotocol, DangerousEnableCompression = false });
        var connection = new FakeChannelConnection(this, socket, identity.NodeId, identity.Installation, identity.Account, token);
        _connections.Enqueue(connection);
        await connection.RunAsync(center.Clock);
    }

    private async Task ReplayAsync(HttpContext context, FakeChannelReplay replay)
    {
        if (replay.Status != 101)
        {
            // The captured refusal: its status, its refusal header and its JSON body (the node reads only the first two).
            context.Response.StatusCode = replay.Status;
            if (replay.Refusal is { } code)
            {
                context.Response.Headers[CenterChannelClient.RefusalHeader] = code;
            }

            context.Response.ContentType = "application/json";
            foreach (var body in replay.Frames)
            {
                await context.Response.Body.WriteAsync(body);
            }

            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync(new WebSocketAcceptContext { SubProtocol = Subprotocol, DangerousEnableCompression = false });
        var buffer = new byte[1_048_576];
        try
        {
            await socket.SendAsync(replay.Frames[0], WebSocketMessageType.Binary, true, CancellationToken.None);
            var length = 0;
            ValueWebSocketReceiveResult received;
            do
            {
                received = await socket.ReceiveAsync(buffer.AsMemory(length), CancellationToken.None);
                length += received.Count;
            }
            while (!received.EndOfMessage && received.MessageType != WebSocketMessageType.Close);
            ReplayReceived.Enqueue(buffer[..length]);
            var index = 0;
            foreach (var frame in replay.Frames.Skip(1))
            {
                // A capture whose later center frames answered the node (the "accepted" capture's close is the hub's echo of the node's
                // own close) holds them until the node's next frame, so they are replayed in the captured order.
                if (++index == replay.HoldAfter + 1)
                {
                    var echo = await socket.ReceiveAsync(buffer.AsMemory(), CancellationToken.None);
                    if (echo.MessageType != WebSocketMessageType.Close)
                    {
                        ReplayReceived.Enqueue(buffer[..echo.Count]);
                    }
                }

                await socket.SendAsync(frame, WebSocketMessageType.Binary, true, CancellationToken.None);
            }

            await socket.CloseOutputAsync((WebSocketCloseStatus)replay.Close, null, CancellationToken.None);
            while (socket.State is WebSocketState.Open or WebSocketState.CloseSent)
            {
                var more = await socket.ReceiveAsync(buffer.AsMemory(), CancellationToken.None);
                if (more.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }

                ReplayReceived.Enqueue(buffer[..more.Count]);
            }
        }
        catch (Exception exception) when (exception is WebSocketException or IOException or ObjectDisposedException or OperationCanceledException)
        {
        }
    }

    /// <summary>Called by a connection whose hello verified: an older proved connection of the node is closed 4409.</summary>
    internal async Task ProvedAsync(FakeChannelConnection proved)
    {
        foreach (var older in Connections.Where(connection => connection != proved && connection.Proved && !connection.Closed
            && connection.NodeId.AsSpan().SequenceEqual(proved.NodeId)))
        {
            await older.CloseAsync(4409, "replaced", null);
        }
    }

    internal (byte[] NodeId, byte[] Installation, byte[] Account)? Identity(string token) => center.ChannelIdentity(token);
}

/// <summary>One channel connection at the peer.</summary>
internal sealed class FakeChannelConnection(FakeChannelPeer peer, WebSocket socket, byte[] nodeId, byte[] installation, byte[] account, string token) : IDisposable
{
    private readonly SemaphoreSlim _send = new(1, 1);
    private readonly ConcurrentQueue<RelayFrame> _received = new();
    private readonly TaskCompletionSource _done = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private long _sequence;

    public byte[] NodeId { get; } = nodeId;

    public byte[] Installation { get; } = installation;

    public byte[] AccountId { get; } = account;

    public string Token { get; private set; } = token;

    public byte[] Nonce { get; } = RandomNumberGenerator.GetBytes(32);

    public Id ConnectionId { get; } = CommandIds.New();

    public NodeHello? Hello { get; private set; }

    public bool Proved { get; private set; }

    public bool Closed { get; private set; }

    /// <summary>Why the peer closed the connection (its close code), or 0.</summary>
    public int ClosedWith { get; private set; }

    public IReadOnlyList<RelayFrame> Received => [.. _received];

    public List<string> TokenRefreshes { get; } = [];

    /// <summary>The results whose signature verified against the installation's registered key under the result domain string.</summary>
    public ConcurrentQueue<(ResultHeader Header, ChannelResult Frame)> VerifiedResults { get; } = new();

    /// <summary>Results whose signature did not verify (a test of the node's signer would fail on any).</summary>
    public ConcurrentQueue<ChannelResult> UnverifiedResults { get; } = new();

    public Task Done => _done.Task;

    /// <inheritdoc />
    public void Dispose() => _send.Dispose();

    public async Task SendAsync(RelayFrame frame)
    {
        await _send.WaitAsync();
        try
        {
            frame.FrameVersion = 1;
            frame.FrameSeq = (ulong)Interlocked.Increment(ref _sequence);
            await socket.SendAsync(frame.ToByteArray(), WebSocketMessageType.Binary, true, CancellationToken.None);
        }
        finally
        {
            _send.Release();
        }
    }

    public Task SendCallAsync(ChannelCall call) => SendAsync(new RelayFrame { Call = call });

    public Task SendHeartbeatAsync(ulong seq, DateTimeOffset at) =>
        SendAsync(new RelayFrame { Heartbeat = new ChannelHeartbeat { Seq = seq, SentAt = ProtoTime.ToInstant(at) } });

    /// <summary>Sends RelayClose with <paramref name="code"/>, then closes the WebSocket with the same code.</summary>
    public async Task CloseAsync(int code, string reason, uint? reconnectAfterMs)
    {
        if (Closed)
        {
            return;
        }

        Closed = true;
        ClosedWith = code;
        try
        {
            await SendAsync(FakeChannelPeer.CloseFrame((uint)code, reason, reconnectAfterMs));
            await socket.CloseOutputAsync((WebSocketCloseStatus)code, reason, CancellationToken.None);
        }
        catch (Exception exception) when (exception is WebSocketException or ObjectDisposedException or IOException)
        {
        }
    }

    /// <summary>Closes the WebSocket with <paramref name="code"/> and no RelayClose frame (what a proxy in front of the center may send).</summary>
    public async Task CloseSocketAsync(int code)
    {
        Closed = true;
        ClosedWith = code;
        try
        {
            await socket.CloseOutputAsync((WebSocketCloseStatus)code, null, CancellationToken.None);
        }
        catch (Exception exception) when (exception is WebSocketException or ObjectDisposedException or IOException)
        {
        }
    }

    /// <summary>Drops the connection without a close (an abnormal close, 1006 at the node).</summary>
    public void Abort()
    {
        Closed = true;
        socket.Abort();
    }

    /// <summary>Waits (real time) for a received frame matching <paramref name="match"/>.</summary>
    public async Task<RelayFrame> WaitForAsync(Func<RelayFrame, bool> match, string what, int after = 0)
    {
        var until = DateTime.UtcNow + TimeSpan.FromSeconds(15);
        while (DateTime.UtcNow < until)
        {
            if (Received.Skip(after).FirstOrDefault(match) is { } frame)
            {
                return frame;
            }

            await Task.Delay(20);
        }

        throw new TimeoutException("No " + what + " within 15 s.");
    }

    /// <summary>Waits for the result of <paramref name="callId"/>.</summary>
    public async Task<ChannelResult> ResultOfAsync(Id callId) =>
        (await WaitForAsync(frame => frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(callId), "result")).CallResult;

    internal async Task RunAsync(TimeProvider clock)
    {
        try
        {
            await SendAsync(FakeChannelPeer.ChallengeFrame(Nonce, ConnectionId, clock.GetUtcNow() + TimeSpan.FromSeconds(10)));
            var buffer = new byte[1_048_576 + 1];
            while (socket.State == WebSocketState.Open)
            {
                var length = 0;
                ValueWebSocketReceiveResult result;
                do
                {
                    result = await socket.ReceiveAsync(buffer.AsMemory(length), CancellationToken.None);
                    length += result.Count;
                    if (length > 1_048_576)
                    {
                        await CloseAsync(4413, "frame_too_large", null);
                        return;
                    }
                }
                while (!result.EndOfMessage && result.MessageType != WebSocketMessageType.Close);

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    Closed = true;
                    return;
                }

                var frame = RelayFrame.Parser.ParseFrom(buffer, 0, length);
                _received.Enqueue(frame);
                await OnFrameAsync(frame, clock);
            }
        }
        catch (Exception exception) when (exception is WebSocketException or IOException or ObjectDisposedException or OperationCanceledException)
        {
        }
        finally
        {
            Closed = true;
            _done.TrySetResult();
        }
    }

    private async Task OnFrameAsync(RelayFrame frame, TimeProvider clock)
    {
        switch (frame.FrameCase)
        {
            case RelayFrame.FrameOneofCase.NodeHello when !Proved:
                Hello = frame.NodeHello;
                if (!peer.Accepting)
                {
                    return;
                }

                // The hub's order and reasons (Cloud E1a hub.go; the hello-* captures): the shape, the proof by the installation's key over
                // this connection's challenge and the credential's IDs, then the hello's IDs.
                if (FakeChannelPeer.HelloFailure(frame.NodeHello, peer.NodeKeyOf(Installation), Nonce, ConnectionId, peer.CenterUrl, NodeId, Installation) is { } failure)
                {
                    await CloseAsync(4403, failure, null);
                    return;
                }

                Proved = true;
                await peer.ProvedAsync(this);
                await SendAsync(FakeChannelPeer.AcceptedFrame(ConnectionId, peer.Limits, peer.SigningKids, peer.NodeName));
                break;
            case RelayFrame.FrameOneofCase.TokenRefresh:
                if (peer.Identity(frame.TokenRefresh.Token) is not { } identity || !identity.NodeId.AsSpan().SequenceEqual(NodeId)
                    || !identity.Installation.AsSpan().SequenceEqual(Installation))
                {
                    await CloseAsync(4401, "token_refused", null);
                    return;
                }

                Token = frame.TokenRefresh.Token;
                lock (TokenRefreshes)
                {
                    TokenRefreshes.Add(frame.TokenRefresh.Token);
                }

                break;
            case RelayFrame.FrameOneofCase.RelayNonceRequest when peer.AnswerNonces:
                await SendAsync(new RelayFrame
                {
                    RelayNonce = new RelayNonce
                    {
                        RequestId = frame.RelayNonceRequest.RequestId,
                        Nonce = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(32)),
                        ExpiresAt = ProtoTime.ToInstant(clock.GetUtcNow() + TimeSpan.FromSeconds(60)),
                    },
                });
                break;
            case RelayFrame.FrameOneofCase.CallResult:
                var result = frame.CallResult;
                var key = peer.NodeKeyOf(Installation);
                var input = Encoding.ASCII.GetBytes("ArcForges relay-result v1\n").Concat(result.Header.Header.ToByteArray()).ToArray();
                if (key is not null && FakeChannelPeer.Verify(key, input, result.Header.Signature.ToByteArray()))
                {
                    VerifiedResults.Enqueue((ResultHeader.Parser.ParseFrom(result.Header.Header), result));
                }
                else
                {
                    UnverifiedResults.Enqueue(result);
                }

                break;
        }
    }

}

/// <summary>A captured exchange the channel peer replays (<see cref="FakeChannelPeer.Replay"/>).</summary>
/// <param name="Status">101, or the HTTP status of a refusal before the upgrade.</param>
/// <param name="Refusal">The captured refusal header, or <see langword="null"/>.</param>
/// <param name="Frames">The captured center frames.</param>
/// <param name="Close">The captured WebSocket close code.</param>
/// <param name="HoldAfter">After this many center frames past the first, the next waits for a frame of the node (0: none waits).</param>
internal sealed record FakeChannelReplay(int Status, string? Refusal, IReadOnlyList<byte[]> Frames, int Close, int HoldAfter = 0);
