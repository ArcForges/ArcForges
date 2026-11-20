// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.WebSockets;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink;

internal sealed partial class ChannelLoop
{
    private readonly Lock _v2EnrollmentGate = new();
    private Session? _publishedV2Session;

    private static bool SameChannelAuthority(ChannelTicket opened, ChannelTicket? current) =>
        current is not null && opened.UseV2 == current.UseV2 && opened.Center.Url == current.Center.Url &&
        opened.InstallationId.Span.SequenceEqual(current.InstallationId.Span) &&
        (!opened.UseV2 || opened.AccountId.Span.SequenceEqual(current.AccountId.Span) &&
            opened.NodeId.Span.SequenceEqual(current.NodeId.Span));

    private async Task<ChannelEnd?> HandshakeV2Async(Session session)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(session.Token);
        timeout.CancelAfter(ChannelPolicy.HandshakeTimeout);
        var first = await ReceiveV2Async(session, timeout.Token).ConfigureAwait(false);
        if (first.End is { } refused)
        {
            return refused;
        }

        if (!V2ChannelProtocol.TryChallenge(first.Frame, out var challenge) ||
            !challenge.AccountId.SequenceEqual(session.Ticket.AccountId.Span))
        {
            return await ProtocolErrorAsync(session, "v2_challenge_binding").ConfigureAwait(false);
        }

        var now = _clock.GetUtcNow();
        var deadline = DateTimeOffset.FromUnixTimeMilliseconds(challenge.DeadlineMilliseconds);
        if (deadline <= now - CallVerifier.Skew || deadline > now + CallVerifier.Skew + ChannelPolicy.HandshakeTimeout)
        {
            return await ProtocolErrorAsync(session, "v2_challenge_expired").ConfigureAwait(false);
        }

        if (_host.V2Snapshot() is not { } snapshot ||
            V2ChannelProtocol.Hello(session.Ticket, snapshot, challenge, session.Key) is not { } hello)
        {
            return await ProtocolErrorAsync(session, "v2_node_snapshot_unavailable").ConfigureAwait(false);
        }

        await session.Client.SendV2Async(V2ChannelKind.Hello, hello, timeout.Token).ConfigureAwait(false);
        var second = await ReceiveV2Async(session, timeout.Token).ConfigureAwait(false);
        if (second.End is { } closed)
        {
            return closed;
        }

        if (!V2ChannelProtocol.TryAccept(second.Frame, challenge, out var limits))
        {
            return await ProtocolErrorAsync(session, "v2_acceptance_binding").ConfigureAwait(false);
        }

        if (_host.Stopping || !SameChannelAuthority(session.Ticket, _host.Ticket().Ticket) ||
            !PublishV2Enrollment(session, challenge.Enrollment(session.Ticket, _clock.GetUtcNow())))
        {
            return new ChannelEnd(RelayState.Backoff, ChannelReasons.Replaced);
        }

        session.V2Limits = limits;
        session.Accepted = true;
        StartV2TokenRefresh(session);
        return null;
    }

    private async Task<ChannelEnd> ServeV2Async(Session session)
    {
        while (true)
        {
            session.Token.ThrowIfCancellationRequested();
            using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(session.V2Limits.HeartbeatDeadlineMilliseconds), _clock);
            using var inbound = CancellationTokenSource.CreateLinkedTokenSource(session.Token, deadline.Token);
            try
            {
                var received = await ReceiveV2Async(session, inbound.Token).ConfigureAwait(false);
                if (received.End is { } end)
                {
                    return end;
                }

                if (!V2ChannelProtocol.IsHeartbeat(received.Frame))
                {
                    return await ProtocolErrorAsync(session, "v2_unexpected_frame").ConfigureAwait(false);
                }

                await session.Client.SendV2Async(V2ChannelKind.Heartbeat, received.Frame.Payload, inbound.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested && !session.Token.IsCancellationRequested)
            {
                return ChannelPolicy.Closed(4408, null);
            }
        }
    }

    private async Task<(V2ChannelFrame Frame, ChannelEnd? End)> ReceiveV2Async(Session session, CancellationToken cancellationToken)
    {
        var bytes = await session.Client.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        if (bytes is null)
        {
            return (default, ChannelPolicy.Closed((int?)session.Client.CloseStatus ?? 1006, null));
        }

        if (!V2ChannelProtocol.TryDecode(bytes, checked(++session.V2ReceivedSequence), out var frame))
        {
            return (default, await ProtocolErrorAsync(session, "v2_protocol_or_sequence").ConfigureAwait(false));
        }

        if (frame.Kind != V2ChannelKind.Close)
        {
            return (frame, null);
        }

        if (!V2ChannelProtocol.TryClose(frame, out var code, out var reconnectAfter, out var reason))
        {
            return (default, await ProtocolErrorAsync(session, "v2_close_malformed").ConfigureAwait(false));
        }

        // Preserve the closed upgrade reason; never log a token, payload or open-ended peer detail.
        var end = ChannelPolicy.Closed(code, reconnectAfter);
        if (code == 4403 && reason == V2ChannelProtocol.UpgradeRequired)
        {
            _nodeLog.Warning("cloud.channel.upgrade_required", new LogField("protocol", 2), new LogField("closeCode", code));
            end = end with { V2Reason = V2ChannelProtocol.UpgradeRequired };
        }

        return (default, end);
    }

    private bool PublishV2Enrollment(Session session, V2ChannelEnrollment? enrollment)
    {
        lock (_v2EnrollmentGate)
        {
            if (enrollment is null ? _publishedV2Session != session : session.Ending || session.Token.IsCancellationRequested)
            {
                return false;
            }

            _publishedV2Session = enrollment is null ? null : session;
            _host.V2EnrollmentChanged(enrollment);
            return true;
        }
    }

    private void StartV2TokenRefresh(Session session)
    {
        // Register before touching the connection so teardown can join the send.
        var dispatch = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var sending = SendV2TokenRefreshAsync(session, dispatch.Task);
        dispatch.SetResult(session.Calls.Add(sending));
    }

    private async Task SendV2TokenRefreshAsync(Session session, Task<bool> dispatch)
    {
        if (!await dispatch.ConfigureAwait(false))
        {
            return;
        }

        try
        {
            await session.V2Refresh.WaitAsync(session.Token).ConfigureAwait(false);
            try
            {
                var ticket = _host.Ticket().Ticket;
                if (session.Ending || ticket is null || !SameChannelAuthority(session.Ticket, ticket) ||
                    ticket.Generation <= session.Generation)
                {
                    return;
                }

                var payload = V2ChannelProtocol.Refresh(ticket.AccessToken);
                if (payload is null || payload.Length + V2ChannelProtocol.HeaderBytes > session.V2Limits.MaxFrameBytes)
                {
                    _nodeLog.Warning("cloud.channel.v2_refresh_refused", new LogField("reason", "credential_shape_or_bound"));
                    session.Cancel();
                    return;
                }

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(session.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(2));
                await session.Client.SendV2Async(V2ChannelKind.Refresh, payload, timeout.Token).ConfigureAwait(false);
                session.Generation = ticket.Generation;
            }
            finally
            {
                session.V2Refresh.Release();
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or WebSocketException or IOException or InvalidOperationException)
        {
            session.Cancel();
        }
    }

    private static async Task SendNodeCloseAsync(Session session)
    {
        if (!session.Ticket.UseV2)
        {
            await SendQuietlyAsync(session.Client, new RelayFrame { Close = new RelayClose { Code = 1000, Reason = "node_closed" } },
                CancellationToken.None).ConfigureAwait(false);
            return;
        }

        try
        {
            using var bounded = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await session.Client.SendV2Async(V2ChannelKind.Close, V2ChannelProtocol.Close(1000, "node_closed"), bounded.Token)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or WebSocketException or IOException or InvalidOperationException)
        {
        }
    }
}
