// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Net.Http;
using System.Net.WebSockets;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink;

/// <summary>How a channel connection attempt ended before the WebSocket opened (PN-3: the reason is read from the status and headers).</summary>
internal enum ChannelConnectFailure
{
    /// <summary>No answer, a transport error, or an answer that is no refusal of the center (a proxy, an edge, a 404).</summary>
    Network,

    /// <summary>401: the access token expired or was revoked (as close 4401: a refresh first).</summary>
    Unauthenticated,

    /// <summary>403: refused (feature, plan or account state; as close 4403).</summary>
    Refused,

    /// <summary>429: the upgrade bucket is spent (as close 4429).</summary>
    RateLimited,
}

/// <summary>A refused or failed channel connection attempt.</summary>
internal sealed class ChannelConnectException(ChannelConnectFailure failure, string? code, Exception? inner)
    : Exception("The node channel did not open: " + failure + (code is null ? string.Empty : " (" + code + ")") + ".", inner)
{
    /// <summary>What ended the attempt.</summary>
    public ChannelConnectFailure Failure { get; } = failure;

    /// <summary>The center's closed refusal code from its response header, when it sent one (identifier characters only).</summary>
    public string? Code { get; } = code;
}

/// <summary>
/// The node's second network seam (AF-CTR-05 CTR5-NODE-01; the repository rule allows this file and <see cref="CenterHttpClient"/> only): the
/// outbound WebSocket of the node channel. <c>ClientWebSocket.ConnectAsync(uri, invoker, ...)</c> over
/// <c>HttpMessageInvoker(AuthorityGuardHandler(SocketsHttpHandler))</c>: the same authority guard and connect log as the HTTP seam, no
/// redirect, no cookies, no proxy credentials, HTTP/1.1 upgrade only, the platform's certificate validation (nothing here relaxes it), no
/// compression. URL <c>wss://&lt;center origin&gt;&lt;path base&gt;/fleet/v1/node</c> (<c>ws://</c> only for the loopback centers
/// <see cref="CenterEndpoint"/> accepts), the bearer access token, the subprotocol <c>arcforges.relay.v1</c>, one binary RelayFrame per
/// message, every received message bounded by the 1 MiB frame pin (relay.proto ChannelLimits.max_frame_bytes).
/// </summary>
internal sealed class CenterChannelClient : IAsyncDisposable
{
    /// <summary>The channel's subprotocol.</summary>
    public const string Subprotocol = "arcforges.relay.v1";

    /// <summary>The channel's path under the center URL.</summary>
    public const string ChannelPath = "/fleet/v1/node";

    internal const string V2Subprotocol = "arcforges.relay.v2";
    internal const string V2ChannelPath = "/fleet/v2/node";

    /// <summary>The frame bound (relay.proto ChannelLimits.max_frame_bytes: exactly 1,048,576).</summary>
    public const int MaxFrameBytes = 1_048_576;

    /// <summary>The response header that carries the center's closed refusal reason before the upgrade (Plan PN-3; Cloud E1a hub).</summary>
    public const string RefusalHeader = "ArcForges-Refusal";

    private readonly ClientWebSocket _socket;
    private readonly HttpMessageInvoker _invoker;
    private readonly bool _useV2;
    private readonly SemaphoreSlim _send = new(1, 1);
    private readonly byte[] _receive = new byte[64 * 1024];
    private long _sequence;

    private CenterChannelClient(ClientWebSocket socket, HttpMessageInvoker invoker, bool useV2)
    {
        _socket = socket;
        _invoker = invoker;
        _useV2 = useV2;
    }

    /// <summary>The WebSocket URI of <paramref name="center"/>'s channel.</summary>
    public static Uri ChannelUri(CenterEndpoint center, bool useV2 = false)
    {
        ArgumentNullException.ThrowIfNull(center);
        var scheme = center.Scheme == "https" ? "wss" : "ws";
        return new Uri(scheme + "://" + center.Origin[(center.Scheme.Length + 3)..] + center.PathBase + (useV2 ? V2ChannelPath : ChannelPath));
    }

    /// <summary>
    /// Opens the channel to <paramref name="center"/> with <paramref name="accessToken"/>. A refusal before the upgrade throws
    /// <see cref="ChannelConnectException"/> with its reason (status and the center's refusal header; the body is never read).
    /// </summary>
    public static async Task<CenterChannelClient> ConnectAsync(CenterEndpoint center, string accessToken, string? connectLog,
        CancellationToken cancellationToken, bool useV2 = false)
    {
        ArgumentNullException.ThrowIfNull(center);
        ArgumentException.ThrowIfNullOrEmpty(accessToken);
        var transport = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = true,
            PreAuthenticate = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            AutomaticDecompression = DecompressionMethods.None,
            PooledConnectionLifetime = TimeSpan.Zero,
        };
        var guard = new CenterHttpClient.AuthorityGuardHandler(center, connectLog) { InnerHandler = transport };
        var invoker = new HttpMessageInvoker(guard, disposeHandler: true);
        var socket = new ClientWebSocket();
        var protocol = useV2 ? V2Subprotocol : Subprotocol;
        socket.Options.AddSubProtocol(protocol);
        socket.Options.SetRequestHeader("Authorization", "Bearer " + accessToken);
        socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(30);
        socket.Options.HttpVersion = HttpVersion.Version11;
        socket.Options.HttpVersionPolicy = HttpVersionPolicy.RequestVersionExact;
        socket.Options.CollectHttpResponseDetails = true;
        socket.Options.DangerousDeflateOptions = null;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await (useV2
                ? socket.ConnectAsync(ChannelUri(center, useV2: true), invoker, timeout.Token)
                : socket.ConnectAsync(ChannelUri(center), invoker, timeout.Token)).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is WebSocketException or HttpRequestException or IOException
            || (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            // Review A N-4: a 401, 403 or 429 is the center's refusal only with the center's refusal header; an edge's or a proxy's answer
            // without it is a network failure (normal backoff, never REFUSED for an hour).
            var code = socket.HttpResponseHeaders?.TryGetValue(RefusalHeader, out var values) == true ? ClosedCode(values.FirstOrDefault()) : null;
            var failure = code is null ? ChannelConnectFailure.Network : socket.HttpStatusCode switch
            {
                HttpStatusCode.Unauthorized => ChannelConnectFailure.Unauthenticated,
                HttpStatusCode.Forbidden => ChannelConnectFailure.Refused,
                HttpStatusCode.TooManyRequests => ChannelConnectFailure.RateLimited,
                _ => ChannelConnectFailure.Network,
            };
            socket.Dispose();
            invoker.Dispose();
            throw new ChannelConnectException(failure, code, exception);
        }
        catch
        {
            socket.Dispose();
            invoker.Dispose();
            throw;
        }

        if (socket.SubProtocol != protocol)
        {
            socket.Abort();
            socket.Dispose();
            invoker.Dispose();
            throw new ChannelConnectException(ChannelConnectFailure.Network, null, null);
        }

        socket.HttpResponseHeaders = null;
        return new CenterChannelClient(socket, invoker, useV2);
    }

    /// <summary>The close status the center sent, or <see langword="null"/>.</summary>
    public WebSocketCloseStatus? CloseStatus => _socket.CloseStatus;

    /// <summary>Sends one frame (frame_version 1, this direction's next frame_seq); sends are serialized.</summary>
    public Task SendAsync(RelayFrame frame, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(frame);
        return SendFrameAsync(isV2: false, sequence =>
        {
            frame.FrameVersion = 1;
            frame.FrameSeq = sequence;
            return frame.ToByteArray();
        }, cancellationToken);
    }

    internal Task SendV2Async(V2ChannelKind kind, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken) =>
        SendFrameAsync(isV2: true, sequence => V2ChannelProtocol.Encode(kind, sequence, payload.Span), cancellationToken);

    internal Task SendV2DataResultAsync(V2ControlSelector selector, ReadOnlyMemory<byte> payload, uint maxFrameBytes,
        CancellationToken cancellationToken)
    {
        RequireV2BaseFrameLimit(maxFrameBytes);
        if (!V2ControlWire.IsData(selector))
        {
            throw new ArgumentOutOfRangeException(nameof(selector));
        }

        var limit = checked((int)V2ControlWire.ResultFrameLimit(selector, maxFrameBytes));
        return SendFrameAsync(isV2: true, sequence => V2ChannelProtocol.Encode(V2ChannelKind.DataResult, sequence, payload.Span),
            cancellationToken, limit);
    }

    private async Task SendFrameAsync(bool isV2, Func<ulong, byte[]> encode, CancellationToken cancellationToken,
        int maxFrameBytes = MaxFrameBytes)
    {
        if (isV2 != _useV2)
        {
            throw new InvalidOperationException("The frame codec must match the authenticated WebSocket subprotocol.");
        }

        await _send.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var sequence = checked(_sequence + 1);
            _sequence = sequence;
            var bytes = encode((ulong)sequence);
            if (bytes.Length > maxFrameBytes)
            {
                throw new InvalidOperationException("A frame larger than the channel's frame bound is never sent.");
            }

            await _socket.SendAsync(bytes, WebSocketMessageType.Binary, endOfMessage: true, cancellationToken).ConfigureAwait(false);
        }
        catch when (isV2)
        {
            // A partially transmitted frame cannot be safely replayed on a strictly sequenced connection.
            _socket.Abort();
            throw;
        }
        finally
        {
            _send.Release();
        }
    }

    /// <summary>
    /// Receives one whole binary message of at most <see cref="MaxFrameBytes"/>; <see langword="null"/> when the center closed the
    /// channel. A larger or a text message throws <see cref="WebSocketException"/> (the channel then closes).
    /// </summary>
    public Task<byte[]?> ReceiveAsync(CancellationToken cancellationToken) =>
        ReceiveFrameAsync(MaxFrameBytes, 0, cancellationToken);

    internal Task<byte[]?> ReceiveV2Async(uint maxFrameBytes, ulong largeWriteSequence, CancellationToken cancellationToken)
    {
        RequireV2BaseFrameLimit(maxFrameBytes);
        return ReceiveFrameAsync((int)maxFrameBytes, largeWriteSequence, cancellationToken);
    }

    private void RequireV2BaseFrameLimit(uint maxFrameBytes)
    {
        if (!_useV2 || maxFrameBytes is 0 or > MaxFrameBytes)
        {
            throw new InvalidOperationException("The negotiated base frame limit must match an authenticated V2 connection.");
        }
    }

    private async Task<byte[]?> ReceiveFrameAsync(int frameLimit, ulong largeWriteSequence, CancellationToken cancellationToken)
    {
        var buffer = new ArrayBufferWriter();
        while (true)
        {
            var result = await _socket.ReceiveAsync(_receive.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                return null;
            }

            if (result.MessageType != WebSocketMessageType.Binary)
            {
                throw new WebSocketException(WebSocketError.InvalidMessageType, "The channel carries only binary frames.");
            }

            var incoming = _receive.AsSpan(0, result.Count);
            int total = buffer.Length + incoming.Length;
            if (largeWriteSequence != 0 && total >= V2ControlWire.RequestPrefixBytes)
            {
                // Only the fixed prefix can select the extended frame bound, before buffering the remaining message.
                if (buffer.HasLargeWritePrefix(incoming, largeWriteSequence))
                {
                    frameLimit = V2ControlWire.ExtendedFrameLimit;
                }

                largeWriteSequence = 0;
            }

            if (total > frameLimit)
            {
                throw new WebSocketException(WebSocketError.InvalidMessageType, "The frame exceeds its channel limit.");
            }

            buffer.Write(incoming, frameLimit);
            if (result.EndOfMessage)
            {
                return buffer.ToArray();
            }
        }
    }

    /// <summary>Closes the channel with <paramref name="code"/> (bounded wait), then disposes it.</summary>
    public async Task CloseAsync(int code, string reason)
    {
        try
        {
            if (_socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await _socket.CloseOutputAsync((WebSocketCloseStatus)code, reason, timeout.Token).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (exception is WebSocketException or OperationCanceledException or ObjectDisposedException or IOException)
        {
        }

        await DisposeAsync().ConfigureAwait(false);
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        _socket.Abort();
        _socket.Dispose();
        _invoker.Dispose();
        _send.Dispose();
        return ValueTask.CompletedTask;
    }

    /// <summary>The refusal header's code when it is an identifier token (never free text).</summary>
    private static string? ClosedCode(string? value) =>
        value is { Length: > 0 and <= 64 } && value.All(c => char.IsAsciiLetter(c) || char.IsAsciiDigit(c) || c is '_' or '.' or '/')
            ? value
            : null;

    /// <summary>A growing buffer of the received message (bounded by the caller).</summary>
    private sealed class ArrayBufferWriter
    {
        private byte[] _bytes = new byte[4096];

        public int Length { get; private set; }

        public bool HasLargeWritePrefix(ReadOnlySpan<byte> incoming, ulong sequence)
        {
            Span<byte> prefix = stackalloc byte[V2ControlWire.RequestPrefixBytes];
            _bytes.AsSpan(0, Length).CopyTo(prefix);
            incoming[..(prefix.Length - Length)].CopyTo(prefix[Length..]);
            return V2ControlWire.IsLargeWritePrefix(prefix, sequence);
        }

        public void Write(ReadOnlySpan<byte> data, int frameLimit)
        {
            if (Length + data.Length > _bytes.Length)
            {
                Array.Resize(ref _bytes, Math.Min(frameLimit, Math.Max(_bytes.Length * 2, Length + data.Length)));
            }

            data.CopyTo(_bytes.AsSpan(Length));
            Length += data.Length;
        }

        public byte[] ToArray() => _bytes.AsSpan(0, Length).ToArray();
    }
}
