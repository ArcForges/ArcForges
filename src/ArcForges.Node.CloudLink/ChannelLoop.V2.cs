// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.WebSockets;
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink;

internal sealed partial class ChannelLoop
{
    private readonly Lock _v2EnrollmentGate = new();
    private Session? _publishedV2Session;
    private const int MaxV2ControlCalls = 8;
    private const long LastUtcMillisecond = 253402300799999L;
    private static readonly TimeSpan V2ControlCallTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan V2DataCallTimeout = TimeSpan.FromSeconds(30);

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

        if (_host.V2Snapshot() is not { } snapshot)
        {
            return await ProtocolErrorAsync(session, "v2_node_snapshot_unavailable").ConfigureAwait(false);
        }

        var dispatch = _host.V2ControlDispatch;
        var streamDataDispatch = _host.V2StreamDataDispatch;
        var capabilities = snapshot.Capabilities.Where(capability =>
            capability is not (V2ControlWire.ControlCapability or V2ControlWire.StreamDataCapability));
        if (dispatch is not null)
        {
            capabilities = capabilities.Append(V2ControlWire.ControlCapability);
        }

        if (streamDataDispatch is not null)
        {
            capabilities = capabilities.Append(V2ControlWire.StreamDataCapability);
        }

        snapshot = snapshot with { Capabilities = capabilities.ToArray() };
        if (V2ChannelProtocol.Hello(session.Ticket, snapshot, challenge, session.Key) is not { } hello)
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

        var enrollment = challenge.Enrollment(session.Ticket, _clock.GetUtcNow());
        if (_host.Stopping || !SameChannelAuthority(session.Ticket, _host.Ticket().Ticket) || !PublishV2Enrollment(session, enrollment))
        {
            return new ChannelEnd(RelayState.Backoff, ChannelReasons.Replaced);
        }

        session.V2Limits = limits;
        session.V2Enrollment = enrollment;
        session.V2ControlDispatch = dispatch;
        session.V2StreamDataDispatch = streamDataDispatch;
        session.Accepted = true;
        StartV2TokenRefresh(session);
        return null;
    }

    private async Task<ChannelEnd> ServeV2Async(Session session)
    {
        var heartbeat = _clock.GetTimestamp();
        var heartbeatDeadline = TimeSpan.FromMilliseconds(session.V2Limits.HeartbeatDeadlineMilliseconds);
        while (true)
        {
            session.Token.ThrowIfCancellationRequested();
            var remaining = heartbeatDeadline - _clock.GetElapsedTime(heartbeat);
            if (remaining <= TimeSpan.Zero)
            {
                return ChannelPolicy.Closed(4408, null);
            }

            using var deadline = new CancellationTokenSource(remaining, _clock);
            using var inbound = CancellationTokenSource.CreateLinkedTokenSource(session.Token, deadline.Token);
            try
            {
                var received = await ReceiveV2Async(session, inbound.Token).ConfigureAwait(false);
                if (received.End is { } end)
                {
                    return end;
                }

                if (V2ChannelProtocol.IsHeartbeat(received.Frame))
                {
                    heartbeat = _clock.GetTimestamp();
                    await session.Client.SendV2Async(V2ChannelKind.Heartbeat, received.Frame.Payload, inbound.Token).ConfigureAwait(false);
                    continue;
                }

                if (received.Frame.Kind is not (V2ChannelKind.ControlRequest or V2ChannelKind.DataRequest))
                {
                    return await ProtocolErrorAsync(session, "v2_unexpected_frame").ConfigureAwait(false);
                }

                if (!StartV2Control(session, received.Bytes, session.V2ReceivedSequence))
                {
                    session.Ending = true;
                    _nodeLog.Warning("cloud.channel.v2_control_refused", new LogField("reason", "control_capacity"));
                    return ChannelPolicy.Closed(4429, null);
                }
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested && !session.Token.IsCancellationRequested)
            {
                return ChannelPolicy.Closed(4408, null);
            }
        }
    }

    private async Task<(V2ChannelFrame Frame, ReadOnlyMemory<byte> Bytes, ChannelEnd? End)> ReceiveV2Async(
        Session session, CancellationToken cancellationToken)
    {
        ulong sequence = checked(session.V2ReceivedSequence + 1);
        bool streamDataEnabled = session.Accepted && session.V2StreamDataDispatch is not null;
        uint maxFrameBytes = session.Accepted ? session.V2Limits.MaxFrameBytes : CenterChannelClient.MaxFrameBytes;
        var bytes = await session.Client.ReceiveV2Async(maxFrameBytes, streamDataEnabled ? sequence : 0, cancellationToken).ConfigureAwait(false);
        if (bytes is null)
        {
            return (default, default, ChannelPolicy.Closed((int?)session.Client.CloseStatus ?? 1006, null));
        }

        if (!V2ChannelProtocol.TryDecode(bytes, sequence, out var frame,
                controlEnabled: session.Accepted && session.V2ControlDispatch is not null, streamDataEnabled: streamDataEnabled))
        {
            return (default, default, await ProtocolErrorAsync(session, "v2_protocol_or_sequence").ConfigureAwait(false));
        }

        session.V2ReceivedSequence = sequence;
        if (frame.Kind != V2ChannelKind.Close)
        {
            return (frame, bytes, null);
        }

        if (!V2ChannelProtocol.TryClose(frame, out var code, out var reconnectAfter, out var reason))
        {
            return (default, default, await ProtocolErrorAsync(session, "v2_close_malformed").ConfigureAwait(false));
        }

        // Preserve the closed upgrade reason; never log a token, payload or open-ended peer detail.
        var end = ChannelPolicy.Closed(code, reconnectAfter);
        if (code == 4403 && reason == V2ChannelProtocol.UpgradeRequired)
        {
            _nodeLog.Warning("cloud.channel.upgrade_required", new LogField("protocol", 2), new LogField("closeCode", code));
            end = end with { V2Reason = V2ChannelProtocol.UpgradeRequired };
        }

        return (default, default, end);
    }

    private bool StartV2Control(Session session, ReadOnlyMemory<byte> frame, ulong sequence)
    {
        if (!session.V2ControlSlots.Wait(0))
        {
            return false;
        }

        var receivedAt = _clock.GetUtcNow();
        var receivedTimestamp = _clock.GetTimestamp();
        var registered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var handling = Task.Run(async () =>
        {
            if (!await registered.Task.ConfigureAwait(false))
            {
                return;
            }

            try
            {
                await AnswerV2ControlAsync(session, frame, sequence, receivedAt, receivedTimestamp).ConfigureAwait(false);
            }
            finally
            {
                session.V2ControlSlots.Release();
            }
        }, CancellationToken.None);

        bool added = session.Calls.Add(handling);
        if (!added)
        {
            session.V2ControlSlots.Release();
        }

        registered.SetResult(added);
        return added;
    }

    private async Task AnswerV2ControlAsync(Session session, ReadOnlyMemory<byte> frame, ulong sequence, DateTimeOffset receivedAt,
        long receivedTimestamp)
    {
        try
        {
            if (!CurrentV2ControlSession(session) || session.V2Enrollment is not { } enrollment)
            {
                return;
            }

            bool extended = session.V2StreamDataDispatch is not null;
            if (!V2ControlWire.TryDecodeRequest(frame, sequence, session.V2Limits.MaxFrameBytes, receivedAt, out var request,
                    streamDataEnabled: extended))
            {
                RefuseV2Control(session, "control_frame_or_deadline");
                return;
            }

            var selector = request.Header.Selector;
            var dispatch = V2ControlWire.IsLegacyControl(selector) ? session.V2ControlDispatch : session.V2StreamDataDispatch;
            bool data = V2ControlWire.IsData(selector);
            var timeout = data && selector != V2ControlSelector.DataInspectTransfer ? V2DataCallTimeout : V2ControlCallTimeout;
            if (dispatch is null || !TryV2ControlDeadline(request.Header.DeadlineUnixMilliseconds, receivedAt, timeout, out var signedDeadline))
            {
                RefuseV2Control(session, "control_frame_or_deadline");
                return;
            }

            if (_host.Binding() is not { } binding)
            {
                RefuseV2Control(session, "control_authority_binding");
                return;
            }

            if (CallVerifier.CurrentCommandKey(binding, request.Header.KeyId, _clock.GetUtcNow()) is not { } key ||
                !RelaySignatures.Verify(key, request.SigningInput.Span, request.Signature.Span))
            {
                RefuseV2Control(session, "control_signature_invalid");
                return;
            }

            if (!MatchesV2ControlBinding(session, enrollment, request.Header, binding))
            {
                RefuseV2Control(session, "control_authority_binding");
                return;
            }

            if (!CurrentV2ControlSession(session))
            {
                return;
            }

            var signedRemaining = signedDeadline - _clock.GetUtcNow();
            var localRemaining = timeout - _clock.GetElapsedTime(receivedTimestamp);
            var remaining = signedRemaining < localRemaining ? signedRemaining : localRemaining;
            if (remaining <= TimeSpan.Zero)
            {
                return;
            }

            using var expired = new CancellationTokenSource(remaining, _clock);
            using var active = CancellationTokenSource.CreateLinkedTokenSource(expired.Token, session.Token, session.EffectsEnding);
            active.Token.ThrowIfCancellationRequested();
            var call = new V2ControlCall(request, enrollment, receivedAt, signedDeadline)
            {
                MaximumResponseBodyBytes = V2ControlWire.MaximumResponseBodyBytes(selector, session.V2Limits.MaxFrameBytes),
            };
            var response = await dispatch(call, active.Token).ConfigureAwait(false);
            active.Token.ThrowIfCancellationRequested();
            if (!CurrentV2ControlSession(session))
            {
                return;
            }

            var result = V2ControlWire.PrepareResultPayload(request.Header.CallId.Span, request.RequestBinding.Span,
                response.Span, session.V2Limits.MaxFrameBytes, selector, streamDataEnabled: extended);
            if (result is null)
            {
                RefuseV2Control(session, "control_result_unavailable");
                return;
            }

            byte[]? signedPayload;
            lock (session.V2ControlSigning)
            {
                active.Token.ThrowIfCancellationRequested();
                signedPayload = result.AttachPayloadSignature(session.Key.Sign(result.SigningInput.Span));
            }

            if (signedPayload is null)
            {
                RefuseV2Control(session, "control_result_signature");
                return;
            }

            if (CurrentV2ControlSession(session))
            {
                var send = data
                    ? session.Client.SendV2DataResultAsync(selector, signedPayload, session.V2Limits.MaxFrameBytes, active.Token)
                    : session.Client.SendV2Async(V2ChannelKind.ControlResult, signedPayload, active.Token);
                await send.ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // The Center must reconcile an unobserved result after timeout or connection loss.
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            RefuseV2Control(session, "control_processing_failed", exception.GetType().Name);
        }
    }

    private bool CurrentV2ControlSession(Session session) =>
        session.Accepted && !session.Ending && !session.Token.IsCancellationRequested && !_host.Stopping &&
        Volatile.Read(ref _publishedV2Session) == session && SameChannelAuthority(session.Ticket, _host.Ticket().Ticket);

    private static bool TryV2ControlDeadline(long deadline, DateTimeOffset receivedAt, TimeSpan timeout, out DateTimeOffset signedDeadline)
    {
        signedDeadline = default;
        long received = receivedAt.ToUnixTimeMilliseconds();
        if (deadline <= received || deadline > LastUtcMillisecond ||
            deadline - received > (long)(timeout + CallVerifier.Skew).TotalMilliseconds)
        {
            return false;
        }

        signedDeadline = DateTimeOffset.FromUnixTimeMilliseconds(deadline);
        return true;
    }

    private static bool MatchesV2ControlBinding(Session session, V2ChannelEnrollment enrollment, in V2ControlRequestHeader header,
        CallBinding binding) =>
        binding.Center.Url == session.Ticket.Center.Url && binding.Center.Url == enrollment.Center.Url &&
        binding.InstallationId == enrollment.LinkedInstallationId &&
        binding.NodeId.Span.SequenceEqual(session.Ticket.NodeId.Span) && header.NodeId.Span.SequenceEqual(binding.NodeId.Span) &&
        binding.AccountId.Span.SequenceEqual(session.Ticket.AccountId.Span) && header.AccountId.Span.SequenceEqual(binding.AccountId.Span) &&
        Convert.ToHexStringLower(header.AccountId.Span) == enrollment.AccountId &&
        Convert.ToHexStringLower(header.EnrollmentId.Span) == enrollment.EnrollmentId &&
        Convert.ToHexStringLower(header.ProtocolEpoch.Span) == enrollment.ProtocolEpoch &&
        Convert.ToHexStringLower(header.ConnectionId.Span) == enrollment.ConnectionId && header.HubFence == enrollment.HubFence &&
        CryptographicOperations.FixedTimeEquals(header.AudienceSha256.Span, RelaySignatures.Audience(enrollment.Center));

    private void RefuseV2Control(Session session, string reason, string? errorType = null)
    {
        _nodeLog.Warning("cloud.channel.v2_control_refused", new LogField("reason", reason), new LogField("errorType", errorType));
        session.Ending = true;
        session.Cancel();
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
            using var active = CancellationTokenSource.CreateLinkedTokenSource(session.Token, session.EffectsEnding);
            await session.V2Refresh.WaitAsync(active.Token).ConfigureAwait(false);
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

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(active.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(2));
                await session.Client.SendV2Async(V2ChannelKind.Refresh, payload, timeout.Token).ConfigureAwait(false);
                session.Generation = ticket.Generation;
            }
            finally
            {
                session.V2Refresh.Release();
            }
        }
        catch (OperationCanceledException) when (session.Ending)
        {
            // Session teardown owns the final close.
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
