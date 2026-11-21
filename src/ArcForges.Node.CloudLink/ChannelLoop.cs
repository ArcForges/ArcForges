// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.WebSockets;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using Google.Protobuf;
using RelayShapes = ArcForges.Contracts.Relay.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink;

/// <summary>What one channel connection needs from the link: the live credential, bound to its center.</summary>
/// <param name="Center">The credential's center, which is the configured one.</param>
/// <param name="AccessToken">The current access token.</param>
/// <param name="Generation">The link's rotation generation of that token.</param>
/// <param name="NodeId">This node's ID.</param>
/// <param name="InstallationId">The credential's installation ID (16 bytes).</param>
internal sealed record ChannelTicket(CenterEndpoint Center, string AccessToken, long Generation, ReadOnlyMemory<byte> NodeId, ReadOnlyMemory<byte> InstallationId)
{
    internal bool UseV2 { get; init; }

    internal ReadOnlyMemory<byte> AccountId { get; init; }
}

/// <summary>The link as the channel sees it (implemented by <see cref="CloudLinkService"/>).</summary>
internal interface IChannelHost
{
    /// <summary>The credential the channel may use now, or <see langword="null"/> and the DISABLED reason.</summary>
    (ChannelTicket? Ticket, string Reason) Ticket();

    /// <summary>
    /// What calls are verified against now (re-read for every call: the key sets change at each refresh), or <see langword="null"/> while the
    /// link gives the channel no credential: signed out, the cloud link off, or stranded (AF-CTR-05 N1 review A C-N1).
    /// </summary>
    CallBinding? Binding();

    /// <summary>True once the node's stop began (<see cref="CloudLinkService.BeginStop"/>; N1 review B N-12).</summary>
    bool Stopping { get; }

    /// <summary>The node key of the ticket's center, or <see langword="null"/> (the caller disposes it).</summary>
    INodeKey? OpenKey(ChannelTicket ticket);

    /// <summary>A refresh of the node credential unless a rotation happened after <paramref name="seenGeneration"/> (single flight).</summary>
    Task RefreshAsync(long seenGeneration, CancellationToken cancellationToken);

    /// <summary>The relay state changed (the link publishes its status).</summary>
    void RelayChanged();

    /// <summary>A notification of the channel (the center replaced this node's channel with another proved connection).</summary>
    void Notice(CloudNotice notice);

    /// <summary>The exact current local V2 authority and observed capabilities.</summary>
    V2ChannelSnapshot? V2Snapshot() => null;

    /// <summary>The fixed Node API callback for verified private V2 control requests.</summary>
    Func<V2ControlCall, CancellationToken, Task<ReadOnlyMemory<byte>>>? V2ControlDispatch => null;

    /// <summary>The fixed callback for the separately negotiated stream and Sandbox data selectors.</summary>
    Func<V2ControlCall, CancellationToken, Task<ReadOnlyMemory<byte>>>? V2StreamDataDispatch => null;

    /// <summary>Publishes verified enrollment while the corresponding V2 session is live.</summary>
    void V2EnrollmentChanged(V2ChannelEnrollment? enrollment) { }
}

/// <summary>
/// The node channel's SM-RELAY loop (AF-CTR-05 CTR5-NODE-02..07; Design state machine SM-RELAY). While the link holds a usable credential and
/// the cloud link is on, it connects (<see cref="CenterChannelClient"/>), answers the center's challenge with the hello proof signed by the
/// node key over that connection's nonce (PB-4, D0-B2), waits for the acceptance, then answers heartbeats, sends <c>TokenRefresh</c> after
/// each credential refresh and serves typed V2 control and data. The V1 channel carries connection management only. States: DISABLED, CONNECTING, CONNECTED, BACKOFF (1 s doubling to 60 s, full jitter, reset
/// after 60 s connected), REFUSED (retried after 1 h or at a credential refresh). Nothing of a frame, a token or a payload is logged.
/// </summary>
internal sealed partial class ChannelLoop : IAsyncDisposable
{
    private readonly IChannelHost _host;
    private readonly NodeLog _nodeLog;
    private readonly TimeProvider _clock;
    private readonly string? _connectLog;
    private readonly string _version;
    private readonly string _contractVersion;
    private readonly Func<double> _random;
    private readonly Lock _gate = new();
    private readonly CancellationTokenSource _stop = new();
    private TaskCompletionSource _wake = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource _rotated = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private ChannelStatus _status = new(Contracts.Node.V1.RelayState.Disabled, ChannelReasons.SignedOut);
    private Session? _session;
    private Task _loop = Task.CompletedTask;
    private int _failures;
    private long _keysRefreshGeneration = long.MinValue;
    private long? _keysRefreshAt;

    /// <summary>Creates the loop (nothing runs until <see cref="Start"/>).</summary>
    public ChannelLoop(IChannelHost host, NodeLog nodeLog, TimeProvider clock, string? connectLog,
        string version, string contractVersion, Func<double>? random = null)
    {
        _host = host ?? throw new ArgumentNullException(nameof(host));
        _nodeLog = nodeLog ?? throw new ArgumentNullException(nameof(nodeLog));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _connectLog = connectLog;
        _version = version;
        _contractVersion = contractVersion;
        _random = random ?? Random.Shared.NextDouble;
    }

    /// <summary>The SM-RELAY state and reason now.</summary>
    public ChannelStatus Status
    {
        get
        {
            lock (_gate)
            {
                return _status;
            }
        }
    }

    /// <summary>The consecutive failures the backoff counts (tests).</summary>
    internal int Failures => Volatile.Read(ref _failures);

    /// <summary>Starts the loop.</summary>
    public void Start() => _loop = Task.Run(() => RunAsync(_stop.Token), CancellationToken.None);

    /// <summary>
    /// The link changed (signed in or out, the cloud link switched, a center change, a credential ended): a session whose credential is no
    /// longer the link's closes, and a waiting loop re-reads the link at once.
    /// </summary>
    public void LinkChanged()
    {
        Session? session;
        lock (_gate)
        {
            session = _session;
        }

        if (session is not null)
        {
            var (ticket, _) = _host.Ticket();
            if (!SameChannelAuthority(session.Ticket, ticket))
            {
                _ = EndSessionAsync(session);
            }
        }

        Volatile.Read(ref _wake).TrySetResult();
    }

    /// <summary>
    /// The node credential rotated (CTR5-NODE-04): a connected session sends <c>TokenRefresh</c> with the new access token, of the same
    /// session family, node and installation (relay.proto TokenRefresh); a REFUSED loop retries now.
    /// </summary>
    public void CredentialRotated()
    {
        Session? session;
        lock (_gate)
        {
            session = _session;
        }

        if (session is { Accepted: true })
        {
            SendTokenRefresh(session);
        }

        Volatile.Read(ref _rotated).TrySetResult();
    }

    /// <summary>
    /// Sends TokenRefresh when the link's token is newer than the one <paramref name="session"/> holds and of the same center and
    /// installation (relay.proto TokenRefresh; review A N-8: the center is compared too).
    /// </summary>
    private void SendTokenRefresh(Session session)
    {
        if (session.Ticket.UseV2)
        {
            StartV2TokenRefresh(session);
            return;
        }

        if (_host.Ticket().Ticket is { } ticket && ticket.Generation != session.Generation && ticket.Center.Url == session.Ticket.Center.Url
            && ticket.InstallationId.Span.SequenceEqual(session.Ticket.InstallationId.Span))
        {
            session.Generation = ticket.Generation;
            _ = SendQuietlyAsync(session, new RelayFrame { TokenRefresh = new TokenRefresh { Token = ticket.AccessToken } });
        }
    }

    /// <summary>
    /// Plan PN-14's refresh for an unknown signing kid, bounded (review A N-1): at most once per credential generation and once in
    /// <see cref="ChannelPolicy.KeysRefreshWindow"/>, so a center (or a path in front of it) that keeps naming an unknown kid cannot drive a
    /// reconnect-and-refresh loop. True when the caller may refresh now (and the attempt is recorded).
    /// </summary>
    private bool TakeKeysRefresh(long generation)
    {
        lock (_gate)
        {
            var now = _clock.GetTimestamp();
            if (generation == _keysRefreshGeneration || (_keysRefreshAt is { } at && _clock.GetElapsedTime(at, now) < ChannelPolicy.KeysRefreshWindow))
            {
                return false;
            }

            _keysRefreshGeneration = generation;
            _keysRefreshAt = now;
            return true;
        }
    }

    /// <summary>The PN-14 refresh itself, its failure logged (never thrown into the frame's answer).</summary>
    private async Task RefreshKeysAsync(Session session)
    {
        try
        {
            // Not cancelled by the connection's end (the Windows leg at e50b0e9): RefreshNodeSession rotates strictly, so a refresh cut off
            // after the center committed loses the new tokens, and the spent one revokes the family at the next refresh. The call keeps its
            // own 10 s deadline; the node's stop waits for it until the stop's bound and starts none itself (CloudLinkService.BeginStop).
            await _host.RefreshAsync(session.Generation, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
        {
            _nodeLog.Warning("cloud.channel.refresh_failed", new LogField("errorType", exception.GetType().Name));
        }
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync() => StopAsync(CloudLinkService.StopBound);

    /// <summary>
    /// Ends the channel and waits at most <paramref name="wait"/> for its loop: the link passes the time left to its stop's bound
    /// (<see cref="CloudLinkService.BeginStop"/>), by which a refresh the channel asked for has answered or been cancelled.
    /// </summary>
    public async ValueTask StopAsync(TimeSpan wait)
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        Volatile.Read(ref _wake).TrySetResult();
        try
        {
            await _loop.WaitAsync(wait).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException)
        {
        }

        _stop.Dispose();
    }

    private async Task RunAsync(CancellationToken stop)
    {
        while (!stop.IsCancellationRequested)
        {
            try
            {
                var wake = Volatile.Read(ref _wake).Task;
                var (ticket, reason) = _host.Ticket();
                if (ticket is null)
                {
                    Interlocked.Exchange(ref _failures, 0);
                    Set(Contracts.Node.V1.RelayState.Disabled, reason);
                    await WaitAsync(null, wake, null, stop).ConfigureAwait(false);
                    Reset();
                    continue;
                }

                Set(Contracts.Node.V1.RelayState.Connecting, ChannelReasons.Connecting);
                var end = await SessionAsync(ticket, stop).ConfigureAwait(false);
                if (stop.IsCancellationRequested)
                {
                    return;
                }

                if (end.State == Contracts.Node.V1.RelayState.Disabled)
                {
                    Set(end.State, end.Reason, end.V2Reason);
                    await WaitAsync(null, wake, null, stop).ConfigureAwait(false);
                    Reset();
                    continue;
                }

                if (end.RefreshFirst)
                {
                    try
                    {
                        // Not cancelled by the connection's end either; bounded by the node's stop (see RefreshKeysAsync).
                        await _host.RefreshAsync(ticket.Generation, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
                    {
                        _nodeLog.Warning("cloud.channel.refresh_failed", new LogField("errorType", exception.GetType().Name));
                    }
                }

                if (end.State == Contracts.Node.V1.RelayState.Refused)
                {
                    // Only a refresh after the refusal retries early: one during the refused attempt (PN-14's, or a 4401's) does not.
                    if (Volatile.Read(ref _rotated).Task.IsCompleted)
                    {
                        Interlocked.Exchange(ref _rotated, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
                    }

                    Set(end.State, end.Reason, end.V2Reason);
                    await WaitAsync(ChannelPolicy.RefusedRetry, wake, Volatile.Read(ref _rotated).Task, stop).ConfigureAwait(false);
                    Reset();
                    continue;
                }

                var failures = Interlocked.Increment(ref _failures);
                var delay = end.Delay is { } asked ? ChannelPolicy.CenterDelay(asked, _random()) : ChannelPolicy.Backoff(failures, _random());
                Set(Contracts.Node.V1.RelayState.Backoff, end.Reason, end.V2Reason);
                _nodeLog.Info("cloud.channel.backoff", new LogField("reason", end.Reason), new LogField("delayMs", (long)delay.TotalMilliseconds),
                    new LogField("failures", failures));
                await WaitAsync(delay, wake, null, stop).ConfigureAwait(false);
                Reset();
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
            {
                _nodeLog.Error("cloud.channel.loop_failed", exception);
                Set(Contracts.Node.V1.RelayState.Backoff, ChannelReasons.ProtocolError);
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), _clock, stop).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    /// <summary>
    /// Waits for <paramref name="delay"/> (none: only a wake), a link change (<paramref name="wake"/>, which ends the wait only when the link
    /// is no longer usable as it was, or while DISABLED), or a credential rotation (<paramref name="rotated"/>, REFUSED only).
    /// </summary>
    private async Task WaitAsync(TimeSpan? delay, Task wake, Task? rotated, CancellationToken stop)
    {
        var timer = delay is { } span ? Task.Delay(span, _clock, stop) : Task.Delay(Timeout.InfiniteTimeSpan, stop);
        var waits = rotated is null ? new[] { timer, wake } : [timer, wake, rotated];
        while (true)
        {
            var done = await Task.WhenAny(waits).ConfigureAwait(false);
            stop.ThrowIfCancellationRequested();
            if (done != wake || delay is null || _host.Ticket().Ticket is null)
            {
                return;
            }

            // A link change that left the link usable (a refresh, a report) does not cut a backoff short.
            Reset();
            wake = Volatile.Read(ref _wake).Task;
            waits = rotated is null ? [timer, wake] : [timer, wake, rotated];
        }
    }

    private void Reset()
    {
        if (Volatile.Read(ref _wake).Task.IsCompleted)
        {
            Interlocked.Exchange(ref _wake, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
        }

        if (Volatile.Read(ref _rotated).Task.IsCompleted)
        {
            Interlocked.Exchange(ref _rotated, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
        }
    }

    /// <summary>One connection, from the attempt to its end.</summary>
    private async Task<ChannelEnd> SessionAsync(ChannelTicket ticket, CancellationToken stop)
    {
        using var key = _host.OpenKey(ticket);
        if (key is null)
        {
            return new ChannelEnd(Contracts.Node.V1.RelayState.Disabled, ChannelReasons.NodeKeyMissing);
        }

        CenterChannelClient client;
        try
        {
            client = await CenterChannelClient.ConnectAsync(ticket.Center, ticket.AccessToken, _connectLog, stop, ticket.UseV2).ConfigureAwait(false);
        }
        catch (ChannelConnectException refused)
        {
            _nodeLog.Info("cloud.channel.connect_refused", new LogField("failure", refused.Failure), new LogField("code", refused.Code ?? string.Empty),
                new LogField("protocol", ticket.UseV2 ? 2 : 1));
            var end = ChannelPolicy.Refused(refused.Failure);
            return ticket.UseV2 && refused.Failure == ChannelConnectFailure.Refused && refused.Code == V2ChannelProtocol.UpgradeRequired
                ? end with { V2Reason = V2ChannelProtocol.UpgradeRequired }
                : end;
        }
        catch (Exception exception) when (exception is HttpRequestException or WebSocketException or IOException)
        {
            return new ChannelEnd(Contracts.Node.V1.RelayState.Backoff, ChannelReasons.NetworkFailure);
        }

        var session = new Session(ticket, client, key, CancellationTokenSource.CreateLinkedTokenSource(stop));
        lock (_gate)
        {
            _session = session;
        }

        var connectedAt = (long?)null;
        try
        {
            var end = await (ticket.UseV2 ? HandshakeV2Async(session) : HandshakeAsync(session)).ConfigureAwait(false);
            if (end is not null)
            {
                return end;
            }

            connectedAt = _clock.GetTimestamp();
            Set(Contracts.Node.V1.RelayState.Connected, ChannelReasons.Connected);
            _nodeLog.Info("cloud.channel.connected", new LogField("center", ticket.Center.Url), new LogField("protocol", ticket.UseV2 ? 2 : 1));
            return await (ticket.UseV2 ? ServeV2Async(session) : ServeAsync(session)).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!stop.IsCancellationRequested)
        {
            // The link ended or changed under the session (LinkChanged).
            return new ChannelEnd(Contracts.Node.V1.RelayState.Backoff, ChannelReasons.NetworkFailure);
        }
        catch (Exception exception) when (exception is WebSocketException or IOException or InvalidProtocolBufferException or ObjectDisposedException)
        {
            return client.CloseStatus is { } status ? ChannelPolicy.Closed((int)status, null) : new ChannelEnd(Contracts.Node.V1.RelayState.Backoff, ChannelReasons.NetworkFailure);
        }
        finally
        {
            if (ticket.UseV2)
            {
                // Fence waiting effect calls before the enrollment callback can wait on Core's ownership gate.
                session.Ending = true;
                PublishV2Enrollment(session, null);
            }

            lock (_gate)
            {
                if (_session == session)
                {
                    _session = null;
                }
            }

            session.Cancel();
            await session.Calls.WaitAsync().ConfigureAwait(false);
            if (session.Accepted && client.CloseStatus is null && !session.SentClose)
            {
                session.SentClose = true;
                // The node's own end of an accepted connection, as the center's nodetest peer sends it: RelayClose 1000, then the close.
                await SendNodeCloseAsync(session).ConfigureAwait(false);
            }

            await client.CloseAsync(1000, "node_closed").ConfigureAwait(false);
            session.Dispose();
            if (connectedAt is { } at && _clock.GetElapsedTime(at) >= ChannelPolicy.StableAfter)
            {
                Interlocked.Exchange(ref _failures, 0);
            }
        }
    }

    /// <summary>The challenge, the hello proof and the acceptance; <see langword="null"/> once accepted, else how the attempt ended.</summary>
    private async Task<ChannelEnd?> HandshakeAsync(Session session)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(session.Token);
        timeout.CancelAfter(ChannelPolicy.HandshakeTimeout);
        var first = await ReceiveFrameAsync(session, timeout.Token).ConfigureAwait(false);
        if (first.End is { } closed)
        {
            return closed;
        }

        if (first.Frame is not { FrameCase: RelayFrame.FrameOneofCase.Challenge } challengeFrame || !RelayShapes.IsValid(challengeFrame.Challenge))
        {
            return await ProtocolErrorAsync(session, "challenge_expected").ConfigureAwait(false);
        }

        var challenge = challengeFrame.Challenge;
        var input = RelaySignatures.HelloInput(challenge.Nonce.Span, challenge.ConnectionId, session.Ticket.Center, session.Ticket.NodeId.Span,
            session.Ticket.InstallationId.Span);
        if (input is null)
        {
            return await ProtocolErrorAsync(session, "challenge_malformed").ConfigureAwait(false);
        }

        var hello = new NodeHello
        {
            NodeId = new Id { Value = ByteString.CopyFrom(session.Ticket.NodeId.Span) },
            InstallationId = new Id { Value = ByteString.CopyFrom(session.Ticket.InstallationId.Span) },
            Version = _version,
            ContractVersion = _contractVersion,
            HelloSignature = ByteString.CopyFrom(session.Key.Sign(input)),
        };
        await session.Client.SendAsync(new RelayFrame { NodeHello = hello }, timeout.Token).ConfigureAwait(false);

        var second = await ReceiveFrameAsync(session, timeout.Token).ConfigureAwait(false);
        if (second.End is { } refused)
        {
            return refused;
        }

        if (second.Frame is not { FrameCase: RelayFrame.FrameOneofCase.Accepted } acceptedFrame || !RelayShapes.IsValid(acceptedFrame.Accepted)
            || !acceptedFrame.Accepted.ConnectionId.Equals(challenge.ConnectionId))
        {
            return await ProtocolErrorAsync(session, "acceptance_expected").ConfigureAwait(false);
        }

        var accepted = acceptedFrame.Accepted;
        session.Limits = accepted.Limits;

        // Plan PN-14: refresh the credential once if the peer advertises an unknown signing key.
        if (_host.Binding() is { } binding && accepted.SigningKids.Any(kid => binding.Keys?.CommandKeys.All(key => key.Kid != kid) ?? true)
            && TakeKeysRefresh(session.Generation))
        {
            await RefreshKeysAsync(session).ConfigureAwait(false);
        }

        session.Accepted = true;

        // Review A N-2: a refresh during the handshake rotated the token this connection is bound to: TokenRefresh at once.
        SendTokenRefresh(session);
        return null;
    }

    /// <summary>The accepted V1 connection carries heartbeat and credential lifecycle messages.</summary>
    private async Task<ChannelEnd> ServeAsync(Session session)
    {
        var limits = session.Limits!;
        var deadline = TimeSpan.FromMilliseconds(limits.HeartbeatDeadlineMs);
        session.Heard = _clock.GetTimestamp();
        using var watchdog = CancellationTokenSource.CreateLinkedTokenSource(session.Token);
        var silent = WatchAsync(session, deadline, watchdog.Token);
        try
        {
            while (true)
            {
                var receive = ReceiveFrameAsync(session, session.Token);
                var done = await Task.WhenAny(receive, silent).ConfigureAwait(false);
                if (done == silent)
                {
                    _nodeLog.Info("cloud.channel.heartbeat_missed", new LogField("deadlineMs", (long)deadline.TotalMilliseconds));
                    await session.Client.CloseAsync(4408, "heartbeat_deadline").ConfigureAwait(false);
                    return new ChannelEnd(Contracts.Node.V1.RelayState.Backoff, ChannelReasons.HeartbeatTimeout);
                }

                var (frame, end) = await receive.ConfigureAwait(false);
                if (end is not null)
                {
                    if (end.Reason == ChannelReasons.Replaced)
                    {
                        _host.Notice(CloudLinkService.Notices.ChannelReplaced);
                    }

                    return end;
                }

                session.Heard = _clock.GetTimestamp();
                switch (frame!.FrameCase)
                {
                    case RelayFrame.FrameOneofCase.Heartbeat when RelayShapes.IsValid(frame.Heartbeat):
                        await session.Client.SendAsync(new RelayFrame
                        {
                            Heartbeat = new ChannelHeartbeat { SentAt = ProtoTime.ToInstant(_clock.GetUtcNow()), Seq = frame.Heartbeat.Seq },
                        }, session.Token).ConfigureAwait(false);
                        break;
                    case RelayFrame.FrameOneofCase.Call or RelayFrame.FrameOneofCase.RelayNonce or RelayFrame.FrameOneofCase.RelayNonceRequest:
                        return await ProtocolErrorAsync(session, "legacy_routed_operation_retired").ConfigureAwait(false);
                    case RelayFrame.FrameOneofCase.Challenge or RelayFrame.FrameOneofCase.Accepted or RelayFrame.FrameOneofCase.Heartbeat:
                        return await ProtocolErrorAsync(session, "unexpected_frame").ConfigureAwait(false);
                    default:
                        // The members of the retired FleetHub relay (command 15 included) are neither sent nor accepted on this channel.
                        _nodeLog.Debug("cloud.channel.frame_ignored", new LogField("member", (int)frame.FrameCase));
                        break;
                }
            }
        }
        finally
        {
            await watchdog.CancelAsync().ConfigureAwait(false);
            try
            {
                await silent.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    /// <summary>Completes when the center has been silent for <paramref name="deadline"/>.</summary>
    private async Task WatchAsync(Session session, TimeSpan deadline, CancellationToken cancellationToken)
    {
        while (true)
        {
            var since = _clock.GetElapsedTime(Volatile.Read(ref session.Heard));
            if (since >= deadline)
            {
                return;
            }

            await Task.Delay(deadline - since, _clock, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>One frame, or how the channel ended (a close frame, the socket's close, a frame too large or malformed).</summary>
    private async Task<(RelayFrame? Frame, ChannelEnd? End)> ReceiveFrameAsync(Session session, CancellationToken cancellationToken)
    {
        byte[]? bytes;
        try
        {
            bytes = await session.Client.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (WebSocketException) when (session.Client.CloseStatus is null && !cancellationToken.IsCancellationRequested)
        {
            return (null, new ChannelEnd(Contracts.Node.V1.RelayState.Backoff, ChannelReasons.NetworkFailure));
        }

        if (bytes is null)
        {
            return (null, ChannelPolicy.Closed((int?)session.Client.CloseStatus ?? 1006, null));
        }

        RelayFrame frame;
        try
        {
            frame = RelayFrame.Parser.ParseFrom(bytes);
        }
        catch (InvalidProtocolBufferException)
        {
            return (null, await ProtocolErrorAsync(session, "frame_unparsable").ConfigureAwait(false));
        }

        if (frame.FrameVersion != 1)
        {
            return (null, await ProtocolErrorAsync(session, "frame_version").ConfigureAwait(false));
        }

        if (frame.FrameCase == RelayFrame.FrameOneofCase.Close)
        {
            var close = frame.Close;
            return (null, ChannelPolicy.Closed((int)close.Code, close.HasReconnectAfterMs && close.Code == 4500 ? close.ReconnectAfterMs : null));
        }

        return (frame, null);
    }

    private async Task<ChannelEnd> ProtocolErrorAsync(Session session, string what)
    {
        _nodeLog.Warning("cloud.channel.protocol_error", new LogField("what", what));
        await session.Client.CloseAsync(1002, "protocol_error").ConfigureAwait(false);
        return new ChannelEnd(Contracts.Node.V1.RelayState.Backoff, ChannelReasons.ProtocolError);
    }

    /// <summary>
    /// The node ends a connection itself (the link ended or was switched off): RelayClose 1000 first, while the connection is still whole
    /// (cancelling its pending receive aborts a ClientWebSocket), then the session's cancellation.
    /// </summary>
    private async Task EndSessionAsync(Session session)
    {
        // Fence V2 operations before sending the close.
        session.Ending = true;
        if (session.Ticket.UseV2)
        {
            PublishV2Enrollment(session, null);
        }

        if (session.Accepted && session.Client.CloseStatus is null && !session.SentClose)
        {
            session.SentClose = true;
            await SendNodeCloseAsync(session).ConfigureAwait(false);
        }

        session.Cancel();
    }

    private static Task SendQuietlyAsync(Session session, RelayFrame frame) => SendQuietlyAsync(session.Client, frame, session.Token);

    private static async Task SendQuietlyAsync(CenterChannelClient client, RelayFrame frame, CancellationToken cancellationToken = default)
    {
        try
        {
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            bounded.CancelAfter(TimeSpan.FromSeconds(2));
            await client.SendAsync(frame, bounded.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or WebSocketException or ObjectDisposedException or IOException or InvalidOperationException)
        {
        }
    }

    private void Set(Contracts.Node.V1.RelayState state, string reason, string? v2Reason = null)
    {
        lock (_gate)
        {
            if (_status.State == state && _status.Reason == reason && _status.V2Reason == v2Reason)
            {
                return;
            }

            _status = new ChannelStatus(state, reason, v2Reason);
        }

        _nodeLog.Info("cloud.channel.state", new LogField("state", state), new LogField("reason", reason));
        _host.RelayChanged();
    }

    /// <summary>One connection's state.</summary>
    private sealed class Session(ChannelTicket ticket, CenterChannelClient client, INodeKey key, CancellationTokenSource cancel) : IDisposable
    {
        public long Heard;

        public ChannelTicket Ticket { get; } = ticket;

        public CenterChannelClient Client { get; } = client;

        public INodeKey Key { get; } = key;

        public CancellationToken Token { get; } = cancel.Token;

        private readonly CancellationTokenSource _effectsEnding = new();

        public CancellationToken EffectsEnding => _effectsEnding.Token;

        public long Generation { get; set; } = ticket.Generation;

        public bool Accepted
        {
            get => Volatile.Read(ref _accepted);
            set => Volatile.Write(ref _accepted, value);
        }

        private bool _accepted;

        public bool SentClose { get; set; }

        /// <summary>Set before the node's own close is sent: no call of this session is dispatched any more.</summary>
        public bool Ending
        {
            get => Volatile.Read(ref _ending);
            set
            {
                Volatile.Write(ref _ending, value);
                if (value) EndEffects();
            }
        }

        private bool _ending;

        public ChannelLimits? Limits { get; set; }

        public V2ChannelLimits V2Limits { get; set; }

        public ulong V2ReceivedSequence { get; set; }

        public V2ChannelEnrollment? V2Enrollment { get; set; }

        public Func<V2ControlCall, CancellationToken, Task<ReadOnlyMemory<byte>>>? V2ControlDispatch { get; set; }

        public Func<V2ControlCall, CancellationToken, Task<ReadOnlyMemory<byte>>>? V2StreamDataDispatch { get; set; }

        public SemaphoreSlim V2Refresh { get; } = new(1, 1);

        public SemaphoreSlim V2ControlSlots { get; } = new(MaxV2ControlCalls, MaxV2ControlCalls);

        public Lock V2ControlSigning { get; } = new();

        public CallTasks Calls { get; } = new();

        private void EndEffects()
        {
            try { _effectsEnding.Cancel(); }
            catch (ObjectDisposedException) { }
        }

        public void Cancel()
        {
            EndEffects();
            try
            {
                cancel.Cancel();
            }
            catch (ObjectDisposedException)
            {
            }
        }

        public void Dispose()
        {
            V2ControlSlots.Dispose();
            V2Refresh.Dispose();
            _effectsEnding.Dispose();
            cancel.Dispose();
        }
    }

    /// <summary>The call tasks of one connection (awaited before the connection's key is disposed).</summary>
    private sealed class CallTasks
    {
        private readonly List<Task> _tasks = [];
        private bool _closed;

        /// <summary>Adds a task the connection waits for before it disposes its key; false once the connection is ending.</summary>
        public bool Add(Task task)
        {
            lock (_tasks)
            {
                if (_closed)
                {
                    return false;
                }

                _tasks.RemoveAll(running => running.IsCompleted);
                _tasks.Add(task);
                return true;
            }
        }

        public Task WaitAsync()
        {
            lock (_tasks)
            {
                _closed = true;
                return Task.WhenAll(_tasks);
            }
        }
    }
}
