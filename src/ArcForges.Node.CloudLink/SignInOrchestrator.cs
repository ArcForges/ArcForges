// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Net.Sockets;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink;

/// <summary>A node-side sign-in state (account.proto <c>SignInFlowState</c>), plus the reservation before the first center answer.</summary>
internal enum FlowPhase
{
    /// <summary>Reserved; the first center call is in flight (it counts as active: N2 decision R-2).</summary>
    Starting,

    /// <summary>Waiting for the person's decision.</summary>
    Pending,

    /// <summary>The code is presented or the credentials are being adopted.</summary>
    Completing,

    /// <summary>Signed in.</summary>
    SignedIn,

    /// <summary>The person denied it.</summary>
    Denied,

    /// <summary>It expired.</summary>
    Expired,

    /// <summary>It failed (the flow's error says why).</summary>
    Failed,

    /// <summary>Cancelled (CancelSignIn, a sign-out or the node's stop).</summary>
    Cancelled,
}

/// <summary>What <see cref="SignInOrchestrator.BeginAsync"/> answers: the flow, or the refusal, and reply warnings.</summary>
/// <param name="Flow">The flow (the active one when one exists).</param>
/// <param name="Error">The refusal.</param>
/// <param name="Warnings">The reply's warnings (<c>browser_not_opened</c>).</param>
internal sealed record SignInReply(SignInFlow? Flow, ArcError? Error, IReadOnlyList<string> Warnings);

/// <summary>
/// The node's sign-in flows (AF-CTR-04 CTR4-NODE-12/13/14/17 as amended; N2 decisions R-2, F-1..F-21). One flow at a time: the slot is
/// reserved under the link's gate in the same step as the link's preconditions, before the first center call (a STARTING flow counts as
/// active, so a concurrent BeginSignIn returns it). The flow captures the configured center at its start and uses it for every URL check,
/// every proof audience and the adoption; it lives in memory only (a restart cancels it). <c>SignInFlow.flow_id</c> is node-local: the
/// center's flow ID appears only inside the derived <c>authorize_url</c> (in SignInFlow replies, the CLI's output, the opener and the
/// test-mode file) and is otherwise sent only in CompleteNodeSignIn; it is never in a log, event, notification, error or the connect log.
/// Credentials are adopted only onto no link or a held <c>center_rejected_credential</c>; any other delivered credentials (a cancelled flow,
/// a refused or failed adoption) are revoked at once with SignOutNode, never stored.
/// </summary>
internal sealed class SignInOrchestrator : IAsyncDisposable
{
    /// <summary>The share of BeginSignIn's 15 s deadline the center calls and the opener may use (one budget from the handler's entry).</summary>
    public static readonly TimeSpan BeginBudget = TimeSpan.FromSeconds(14);

    /// <summary>The longest wait for the system browser's opener.</summary>
    public static readonly TimeSpan OpenerWait = TimeSpan.FromSeconds(5);

    /// <summary>A browser flow's life (fleet.proto <c>expires_at</c>: "10 minutes").</summary>
    public static readonly TimeSpan BrowserLifetime = TimeSpan.FromMinutes(10);

    /// <summary>The device flow's hard stop: the contract's 600 s plus 30 s.</summary>
    public static readonly TimeSpan DeviceHardStop = TimeSpan.FromSeconds(630);

    /// <summary>The shortest poll interval (the contract's 5,000 ms).</summary>
    public static readonly TimeSpan PollFloor = TimeSpan.FromSeconds(5);

    /// <summary>The longest poll interval (the center's cap).</summary>
    public static readonly TimeSpan PollCap = TimeSpan.FromSeconds(60);

    /// <summary>The one-use code's life (<c>nodeCodeLifetime</c> default): the bound of Complete's retries before its body reached the center.</summary>
    public static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(2);

    private readonly CloudLinkService _link;
    private readonly CloudLinkOptions _options;
    private readonly Lock _lock = new();
    private readonly CancellationTokenSource _stop = new();
    private Run? _current;
    private int _disposed;

    /// <summary>Creates the flows of <paramref name="link"/>.</summary>
    public SignInOrchestrator(CloudLinkService link, CloudLinkOptions options)
    {
        _link = link;
        _options = options;
    }

    /// <summary>Replaces the loopback listener's construction (tests: a bind failure).</summary>
    internal Func<IPAddress, TcpListener>? Listen { get; set; }

    /// <summary>The active flow's loopback receiver (tests).</summary>
    internal LoopbackReceiver? Receiver
    {
        get
        {
            lock (_lock)
            {
                return _current?.Receiver;
            }
        }
    }

    /// <summary>True while a flow is reserved, pending or completing.</summary>
    public bool Active
    {
        get
        {
            lock (_lock)
            {
                return _current is { IsActive: true };
            }
        }
    }

    /// <summary>
    /// BeginSignIn: the active flow, or a new one. <paramref name="entered"/> is the monotonic instant of the handler's entry (the budget of
    /// N2 decision F-4/N-5 counts from it).
    /// </summary>
    public async Task<SignInReply> BeginAsync(SignInMethod method, long entered, CancellationToken cancellationToken)
    {
        Run? existing = null;
        Run? run = null;
        using (await _link.EnterAsync(cancellationToken).ConfigureAwait(false))
        {
            lock (_lock)
            {
                if (_current is { IsActive: true } active)
                {
                    existing = active;
                }
            }

            if (existing is null)
            {
                if (_link.ReserveSignIn(out var center) is { } refusal)
                {
                    return new SignInReply(null, refusal, []);
                }

                run = new Run(CommandIds.New(_options.Clock), center!, CancellationTokenSource.CreateLinkedTokenSource(_stop.Token));
                lock (_lock)
                {
                    _current?.Dispose();
                    _current = run;
                }
            }
        }

        if (existing is not null)
        {
            try
            {
                await existing.Started.Task.WaitAsync(Left(entered), cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
            }

            return new SignInReply(Snapshot(existing), null, []);
        }

        var warnings = new List<string>();
        ArcError? error;
        try
        {
            error = await StartAsync(run!, method == SignInMethod.DeviceCode ? SignInMethod.DeviceCode : SignInMethod.Browser, entered, warnings).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            _options.Log.Warning("cloud.sign_in.start_failed", new LogField("errorType", exception.GetType().Name));
            error = NodeErrors.CloudUnreachable("sign_in_start_failed");
        }

        if (error is not null)
        {
            Finish(run!, FlowPhase.Failed, error);
            return new SignInReply(null, error, []);
        }

        return new SignInReply(Snapshot(run!), null, warnings);
    }

    /// <summary>GetSignInFlow: the flow of <paramref name="flowId"/> (the active or the last one), or <see langword="null"/> (not found).</summary>
    public SignInFlow? Get(Id? flowId)
    {
        lock (_lock)
        {
            return _current is { } run && flowId is { } id && id.Value.Span.SequenceEqual(run.Id.Value.Span) ? Snapshot(run) : null;
        }
    }

    /// <summary>
    /// CancelSignIn (account.proto: "state: SM-SIGN-IN: PENDING -&gt; CANCELLED"): a reserved or pending flow is CANCELLED at once; a poll in
    /// flight is not cut, and credentials it brings are revoked. A completing flow is <c>STATE/invalid_state</c> (<c>completing</c>), an ended
    /// one with its state's name, an unknown one <c>STATE/not_found</c>.
    /// </summary>
    public (SignInFlow? Flow, ArcError? Error) Cancel(Id? flowId)
    {
        Run run;
        lock (_lock)
        {
            if (_current is not { } current || flowId is not { } id || !id.Value.Span.SequenceEqual(current.Id.Value.Span))
            {
                return (null, NodeErrors.NotFound("sign_in_flow", flowId is null ? [] : flowId.Value.Span));
            }

            if (current.State == FlowPhase.Completing)
            {
                return (null, NodeErrors.InvalidState("sign_in_flow", "completing"));
            }

            if (!current.IsActive)
            {
                return (null, NodeErrors.InvalidState("sign_in_flow", StateName(current.State)));
            }

            run = current;
        }

        Finish(run, FlowPhase.Cancelled, null);
        return (Snapshot(run), null);
    }

    /// <summary>
    /// Ends the active flow before a sign-out (N2 decision N-2), so the sign-out never deletes the key under a flow: a reserved or pending
    /// flow is cancelled; a completing one is marked, so credentials it still brings are revoked instead of adopted.
    /// </summary>
    public void CancelActive()
    {
        Run? run;
        lock (_lock)
        {
            run = _current is { IsActive: true } active ? active : null;
            if (run is not null)
            {
                run.CancelRequested = true;
            }
        }

        if (run is not null && run.State != FlowPhase.Completing)
        {
            Finish(run, FlowPhase.Cancelled, null);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        CancelActive();
        Run? run;
        lock (_lock)
        {
            run = _current;
        }

        try
        {
            await _stop.CancelAsync().ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
        }

        if (run?.Work is { } work)
        {
            try
            {
                await work.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is TimeoutException or OperationCanceledException)
            {
            }
        }

        if (run is not null)
        {
            await run.CloseReceiverAsync().ConfigureAwait(false);
        }
    }

    private TimeSpan Left(long entered)
    {
        var left = BeginBudget - _options.Clock.GetElapsedTime(entered);
        return left > TimeSpan.Zero ? left : TimeSpan.Zero;
    }

    /// <summary>Starts the flow: the key, the receiver (or the fallback), the center's Begin or Start with the key replace-once, the opener.</summary>
    private async Task<ArcError?> StartAsync(Run run, SignInMethod method, long entered, List<string> warnings)
    {
        run.Key = LoadOrCreateKey(run.Center);
        if (method == SignInMethod.Browser)
        {
            var state = Pkce.NewState();
            run.Receiver = LoopbackReceiver.TryStart(state, _options.Log, Listen);
            if (run.Receiver is null)
            {
                // The only automatic fallback (node-11 corrected item 1; account.proto: "loopback port unavailable").
                method = SignInMethod.DeviceCode;
                run.FellBack = true;
                _options.Log.Warning("cloud.sign_in.fell_back_to_device_code");
            }
            else
            {
                run.State0 = state;
            }
        }

        run.Method = method;
        using var client = Client(run.Center);
        run.Client = client.Client;
        var error = method == SignInMethod.Browser
            ? await BeginBrowserAsync(run, run.Center, run.State0!, () => Left(entered), allowReplace: true).ConfigureAwait(false)
            : await BeginDeviceAsync(run, run.Center, () => Left(entered), allowReplace: true).ConfigureAwait(false);
        if (error is not null)
        {
            return error;
        }

        lock (_lock)
        {
            if (run.State != FlowPhase.Starting)
            {
                // Cancelled while the first call was in flight: nothing was approved, nothing to revoke.
                run.Started.TrySetResult();
                return null;
            }

            run.State = FlowPhase.Pending;
        }

        _options.Log.Info("cloud.sign_in.started", new LogField("method", method.ToString()), new LogField("fellBack", run.FellBack));
        if (method == SignInMethod.Browser)
        {
            var wait = Left(entered) - TimeSpan.FromMilliseconds(500);
            if (!await Open(run, wait < OpenerWait ? wait : OpenerWait).ConfigureAwait(false))
            {
                warnings.Add("browser_not_opened");
            }
        }

        run.Started.TrySetResult();
        run.Work = Task.Run(() => method == SignInMethod.Browser ? RunBrowserAsync(run) : RunDeviceAsync(run));
        return null;
    }

    private async Task<bool> Open(Run run, TimeSpan wait)
    {
        if (_options.Opener is not { } opener || run.Authorize is not { } url)
        {
            return false;
        }

        try
        {
            return await opener.OpenAsync(url, wait > TimeSpan.Zero ? wait : TimeSpan.Zero, run.Stop.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            _options.Log.Warning("cloud.sign_in.browser_not_opened", new LogField("errorType", exception.GetType().Name));
            return false;
        }
    }

    /// <summary>BeginNodeSignIn with fresh PKCE (and the given state), the held-key refusal replaced once.</summary>
    private async Task<ArcError?> BeginBrowserAsync(Run run, CenterEndpoint center, string state, Func<TimeSpan> left, bool allowReplace)
    {
        for (var attempt = 0; ; attempt++)
        {
            var verifier = Pkce.NewVerifier();
            run.Receiver!.Expect(state);
            var request = new NodeEnrollmentServiceBeginNodeSignInRequest
            {
                CodeChallenge = Pkce.Challenge(verifier),
                RedirectUri = run.Receiver.RedirectUri,
                Node = _options.NodeInfo(),
                State = state,
                NodePublicKey = ByteString.CopyFrom(run.Key!.PublicKey),
            };
            var reply = await CallAsync(left, token => run.Client!.BeginNodeSignInAsync(request, token)).ConfigureAwait(false);
            if (reply.Value is { } value)
            {
                if (SignInUrls.Authorize(center, value.FlowId?.Value, value.HasAuthorizeUrl ? value.AuthorizeUrl : null, out var failure) is not { } url)
                {
                    return NodeErrors.InvalidArgument(failure!);
                }

                run.CenterFlowId = value.FlowId!.Value.ToByteArray();
                run.Verifier = verifier;
                run.Authorize = url;
                run.ExpiresAt = value.ExpiresAt;
                run.Received = _options.Clock.GetTimestamp();
                return null;
            }

            if (allowReplace && attempt == 0 && KeyHeld(reply) && left() >= TimeSpan.FromSeconds(3))
            {
                ReplaceKey(run);
                continue;
            }

            return BeginRefusal(reply);
        }
    }

    /// <summary>StartDeviceAuthorization, the held-key refusal replaced once.</summary>
    private async Task<ArcError?> BeginDeviceAsync(Run run, CenterEndpoint center, Func<TimeSpan> left, bool allowReplace)
    {
        for (var attempt = 0; ; attempt++)
        {
            var request = new NodeEnrollmentServiceStartDeviceAuthorizationRequest
            {
                Node = _options.NodeInfo(),
                NodePublicKey = ByteString.CopyFrom(run.Key!.PublicKey),
            };
            var reply = await CallAsync(left, token => run.Client!.StartDeviceAuthorizationAsync(request, token)).ConfigureAwait(false);
            if (reply.Value is { } value)
            {
                if (SignInUrls.Device(center, value.Authorization, out var failure) is not { } device)
                {
                    return NodeErrors.InvalidArgument(failure!);
                }

                run.Device = device;
                run.ExpiresAt = value.Authorization.ExpiresAt;
                run.Interval = Interval(value.Authorization.HasIntervalMs ? value.Authorization.IntervalMs : 0, PollFloor);
                run.Received = _options.Clock.GetTimestamp();
                return null;
            }

            if (allowReplace && attempt == 0 && KeyHeld(reply) && left() >= TimeSpan.FromSeconds(3))
            {
                ReplaceKey(run);
                continue;
            }

            return BeginRefusal(reply);
        }
    }

    private static async Task<CenterReply<T>> CallAsync<T>(Func<TimeSpan> left, Func<CancellationToken, Task<CenterReply<T>>> call)
        where T : class
    {
        var budget = left();
        using var bounded = new CancellationTokenSource(budget > TimeSpan.Zero ? budget : TimeSpan.FromMilliseconds(1));
        return await call(bounded.Token).ConfigureAwait(false);
    }

    /// <summary>A Begin or Start refusal as BeginSignIn answers it (only its annotated codes; N2 decision F-12).</summary>
    private static ArcError BeginRefusal<T>(CenterReply<T> reply)
        where T : class
    {
        if (reply.Outcome == CenterOutcome.Refused && reply.Error is { } error)
        {
            return error.Code switch
            {
                "rate_limited" => error,
                "not_activated" => error,
                "kill_switch_active" => NodeErrors.NotActivated("kill_switch"),
                _ when error.Category == ErrorCategory.Validation => NodeErrors.InvalidState("center_refused", error.Details?.State?.Reason is { Length: > 0 } reason ? reason : error.Code),
                _ when error.Code == "already_exists" => NodeErrors.InvalidState("center_refused", "node_key: already_registered"),
                _ => NodeErrors.CloudUnreachable(error.Category.ToString().ToLowerInvariant() + "/" + error.Code),
            };
        }

        return NodeErrors.CloudUnreachable(reply.Outcome == CenterOutcome.ProtocolMismatch ? "center_protocol_mismatch" : "no_center_answer");
    }

    /// <summary>fleet.proto Begin/Start: "CONFLICT/already_exists (state.state node_key, state.reason already_registered)".</summary>
    private static bool KeyHeld<T>(CenterReply<T> reply)
        where T : class =>
        reply.Outcome == CenterOutcome.Refused && reply.Error is { Code: "already_exists" } error && error.Details?.State?.State == "node_key";

    /// <summary>Complete/Poll: the held key or the retired key (credential_revoked) mean "the node deletes its key and starts again".</summary>
    private static bool KeyRefused<T>(CenterReply<T> reply)
        where T : class =>
        KeyHeld(reply) || (reply.Outcome == CenterOutcome.Refused && reply.Error is { Code: "credential_revoked" });

    private INodeKey LoadOrCreateKey(CenterEndpoint center) =>
        _options.Keys.Load(_options.NodeId.Span, center.Origin) ?? _options.Keys.Create(_options.NodeId.Span, center.Origin, _options.Clock);

    /// <summary>The contract's replace-once: the key is deleted and a new one created (persisted before its public half leaves the node).</summary>
    private void ReplaceKey(Run run)
    {
        run.Key?.Dispose();
        run.Key = _options.Keys.Create(_options.NodeId.Span, run.Center.Origin, _options.Clock);
        run.Replaced = true;
        _options.Log.Info("cloud.sign_in.key_replaced");
    }

    private ClientScope Client(CenterEndpoint center) => new(center, _options);

    private async Task RunBrowserAsync(Run run)
    {
        try
        {
            using var scope = Client(run.Center);
            run.Client = scope.Client;
            while (true)
            {
                var receiver = run.Receiver!;
                var expiry = Task.Delay(BrowserLifetime - _options.Clock.GetElapsedTime(run.Received), _options.Clock, run.Stop.Token);
                var done = await Task.WhenAny(receiver.Result, expiry, run.Cancelled.Task).ConfigureAwait(false);
                if (done != receiver.Result)
                {
                    if (done == expiry && !run.Stop.IsCancellationRequested)
                    {
                        Finish(run, FlowPhase.Expired, null);
                    }

                    return;
                }

                var result = await receiver.Result.ConfigureAwait(false);
                await run.CloseReceiverAsync().ConfigureAwait(false);
                if (result.Outcome == LoopbackOutcome.Denied)
                {
                    Finish(run, FlowPhase.Denied, null);
                    return;
                }

                if (!MarkCompleting(run))
                {
                    return;
                }

                var restart = await CompleteAsync(run, result.Code!).ConfigureAwait(false);
                if (!restart)
                {
                    return;
                }

                // The center retired or holds the key: a new key and a new flow, once (the same node-local flow, PENDING again).
                ReplaceKey(run);
                var state = Pkce.NewState();
                run.Receiver = LoopbackReceiver.TryStart(state, _options.Log, Listen);
                if (run.Receiver is null)
                {
                    Finish(run, FlowPhase.Failed, NodeErrors.InvalidState("sign_in_flow", "loopback_unavailable"));
                    return;
                }

                var error = await BeginBrowserAsync(run, run.Center, state, () => TimeSpan.FromSeconds(10), allowReplace: false).ConfigureAwait(false);
                if (error is not null)
                {
                    Finish(run, FlowPhase.Failed, error);
                    return;
                }

                lock (_lock)
                {
                    if (run.State != FlowPhase.Completing)
                    {
                        return;
                    }

                    run.State = FlowPhase.Pending;
                }

                await Open(run, OpenerWait).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (run.Stop.IsCancellationRequested)
        {
            Finish(run, FlowPhase.Cancelled, null);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            _options.Log.Error("cloud.sign_in.failed", exception);
            Finish(run, FlowPhase.Failed, NodeErrors.Internal(_options.Clock.GetUtcNow()));
        }
    }

    /// <summary>
    /// CompleteNodeSignIn with the code, the verifier and the key proof (purpose 0x01). A Complete whose body may have reached the center is
    /// never sent again (an unknown outcome ends the flow: sign in again); an <c>overloaded</c> refusal is a received answer that leaves the
    /// code unredeemed, so the identical request is sent once more after its <c>retry_at</c>. True when the flow restarts with a new key.
    /// </summary>
    private async Task<bool> CompleteAsync(Run run, string code)
    {
        var started = _options.Clock.GetTimestamp();
        var overloaded = false;
        var backoff = TimeSpan.FromSeconds(1);
        while (true)
        {
            if (CenterChanged(run))
            {
                return false;
            }

            var proof = run.Key!.Sign(CloudIdentity.ProofMessage(CloudIdentity.PurposeComplete, run.Center, _options.NodeId.Span,
                CloudIdentity.CompleteBinding(run.CenterFlowId, code)));
            var request = new NodeEnrollmentServiceCompleteNodeSignInRequest
            {
                FlowId = new Id { Value = ByteString.CopyFrom(run.CenterFlowId) },
                Code = code,
                CodeVerifier = run.Verifier,
                NodeKeyProof = ByteString.CopyFrom(proof),
            };
            var reply = await run.Client!.CompleteNodeSignInAsync(request, run.Stop.Token).ConfigureAwait(false);
            if (reply.Value is { } value)
            {
                await DeliveredAsync(run, value.Credentials).ConfigureAwait(false);
                return false;
            }

            if (KeyRefused(reply))
            {
                if (!run.Replaced)
                {
                    return true;
                }

                Finish(run, FlowPhase.Failed, reply.Error);
                return false;
            }

            if (reply.Outcome == CenterOutcome.Refused && reply.Error is { } error)
            {
                if (error.Code == "overloaded" && !overloaded)
                {
                    overloaded = true;
                    await Task.Delay(RetryWait(error, TimeSpan.FromSeconds(1)), _options.Clock, run.Stop.Token).ConfigureAwait(false);
                    continue;
                }

                Finish(run, error.Code == "expired" ? FlowPhase.Expired : FlowPhase.Failed, error.Code == "expired" ? null : error);
                return false;
            }

            if (reply.Outcome == CenterOutcome.Unreachable && !reply.MaybeApplied && _options.Clock.GetElapsedTime(started) + backoff < CodeLifetime)
            {
                await Task.Delay(backoff, _options.Clock, run.Stop.Token).ConfigureAwait(false);
                backoff = backoff * 2 > TimeSpan.FromSeconds(16) ? TimeSpan.FromSeconds(16) : backoff * 2;
                continue;
            }

            // The body may have reached the center (a lost reply): never resent (SEC-23); sign in again.
            Finish(run, FlowPhase.Failed, NodeErrors.CloudUnreachable(reply.MaybeApplied ? "complete_reply_lost" : "no_center_answer"));
            return false;
        }
    }

    private async Task RunDeviceAsync(Run run)
    {
        try
        {
            using var scope = Client(run.Center);
            run.Client = scope.Client;
            var ambiguous = false;
            while (true)
            {
                var remaining = DeviceHardStop - _options.Clock.GetElapsedTime(run.Received);
                if (remaining <= TimeSpan.Zero)
                {
                    Finish(run, FlowPhase.Expired, null);
                    return;
                }

                var wait = Task.Delay(run.Interval < remaining ? run.Interval : remaining, _options.Clock, run.Stop.Token);
                if (await Task.WhenAny(wait, run.Cancelled.Task).ConfigureAwait(false) != wait)
                {
                    return;
                }

                await wait.ConfigureAwait(false);
                if (_options.Clock.GetElapsedTime(run.Received) >= DeviceHardStop)
                {
                    Finish(run, FlowPhase.Expired, null);
                    return;
                }

                if (CenterChanged(run))
                {
                    return;
                }

                var device = run.Device!;
                var proof = run.Key!.Sign(CloudIdentity.ProofMessage(CloudIdentity.PurposePoll, run.Center, _options.NodeId.Span,
                    CloudIdentity.PollBinding(device.DeviceCode)));
                var request = new NodeEnrollmentServicePollDeviceAuthorizationRequest { DeviceCode = device.DeviceCode, NodeKeyProof = ByteString.CopyFrom(proof) };

                // One poll at a time, never before the previous reply; a CancelSignIn does not cut it (credentials it brings are revoked).
                var reply = await run.Client!.PollDeviceAuthorizationAsync(request, run.Stop.Token).ConfigureAwait(false);
                if (reply.Value is { } value)
                {
                    if (value.HasIntervalMs && value.IntervalMs > 0)
                    {
                        run.Interval = Interval(value.IntervalMs, PollFloor);
                    }

                    switch (value.State)
                    {
                        case DeviceAuthorizationState.Pending:
                            ambiguous = false;
                            continue;
                        case DeviceAuthorizationState.SlowDown:
                            if (!value.HasIntervalMs || value.IntervalMs == 0)
                            {
                                run.Interval = Interval((ulong)(run.Interval + TimeSpan.FromSeconds(5)).TotalMilliseconds, PollFloor);
                            }

                            ambiguous = false;
                            continue;
                        case DeviceAuthorizationState.Approved when value.Credentials is { } credentials:
                            if (MarkCompleting(run) || run.CancelRequested)
                            {
                                await DeliveredAsync(run, credentials).ConfigureAwait(false);
                            }
                            else
                            {
                                await _link.RevokeDeliveredAsync(credentials, run.Center, CancellationToken.None).ConfigureAwait(false);
                            }

                            return;
                        case DeviceAuthorizationState.Denied:
                            Finish(run, FlowPhase.Denied, null);
                            return;
                        case DeviceAuthorizationState.Expired:
                            Finish(run, FlowPhase.Expired, null);
                            return;
                        case DeviceAuthorizationState.Completed:
                            // "credentials already delivered": the reuse revoked the family. A lost poll reply is the usual cause.
                            Finish(run, FlowPhase.Failed, NodeErrors.CloudUnreachable(ambiguous ? "poll_reply_lost" : "credentials_already_delivered"));
                            return;
                        default:
                            Finish(run, FlowPhase.Failed, NodeErrors.InvalidArgument("state: unknown"));
                            return;
                    }
                }

                if (KeyRefused(reply))
                {
                    if (run.Replaced)
                    {
                        Finish(run, FlowPhase.Failed, reply.Error);
                        return;
                    }

                    // A new key and a new user code, once: the person approves the new code (N2 decision F-20).
                    ReplaceKey(run);
                    var error = await BeginDeviceAsync(run, run.Center, () => TimeSpan.FromSeconds(10), allowReplace: false).ConfigureAwait(false);
                    if (error is not null)
                    {
                        Finish(run, FlowPhase.Failed, error);
                        return;
                    }

                    ambiguous = false;
                    continue;
                }

                if (reply.Outcome == CenterOutcome.Refused && reply.Error is { } refusal)
                {
                    if (refusal.Code is "rate_limited" or "overloaded")
                    {
                        run.Interval = Interval((ulong)RetryWait(refusal, run.Interval).TotalMilliseconds, run.Interval);
                        continue;
                    }

                    if (refusal.Code == "internal")
                    {
                        // N2 decision N-15: the next poll either delivers the credentials or revokes a delivered family by the reuse rule.
                        ambiguous = true;
                        continue;
                    }

                    Finish(run, FlowPhase.Failed, refusal);
                    return;
                }

                // No center answer: the next poll after the interval (an applied delivery is then revoked by the reuse rule: poll_reply_lost).
                ambiguous |= reply.MaybeApplied;
            }
        }
        catch (OperationCanceledException) when (run.Stop.IsCancellationRequested)
        {
            Finish(run, FlowPhase.Cancelled, null);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            _options.Log.Error("cloud.sign_in.failed", exception);
            Finish(run, FlowPhase.Failed, NodeErrors.Internal(_options.Clock.GetUtcNow()));
        }
    }

    private TimeSpan RetryWait(ArcError error, TimeSpan fallback)
    {
        if (ProtoTime.ToDateTimeOffset(error.Retry?.RetryAt) is { } at)
        {
            var wait = at - _options.Clock.GetUtcNow();
            return wait < fallback ? fallback : wait > PollCap ? PollCap : wait;
        }

        return fallback;
    }

    private static TimeSpan Interval(ulong milliseconds, TimeSpan floor)
    {
        var interval = TimeSpan.FromMilliseconds(milliseconds);
        if (interval < floor)
        {
            interval = floor;
        }

        if (interval < PollFloor)
        {
            interval = PollFloor;
        }

        return interval > PollCap ? PollCap : interval;
    }

    /// <summary>An out-of-band change of the configured center during a flow ends it without sending anything more.</summary>
    private bool CenterChanged(Run run)
    {
        CenterEndpoint? configured;
        try
        {
            configured = _options.Center();
        }
        catch (Exception exception) when (exception is NodeConfigurationException or IOException or UnauthorizedAccessException)
        {
            configured = null;
        }

        if (configured?.Url == run.Center.Url)
        {
            return false;
        }

        Finish(run, FlowPhase.Failed, NodeErrors.InvalidState("signing_in", "center_url"));
        return true;
    }

    private bool MarkCompleting(Run run)
    {
        lock (_lock)
        {
            if (run.State is not (FlowPhase.Pending or FlowPhase.Completing))
            {
                return false;
            }

            run.State = FlowPhase.Completing;
            return true;
        }
    }

    /// <summary>The delivered credentials: adopted (onto no link or a held rejected credential), else revoked at once.</summary>
    private async Task DeliveredAsync(Run run, NodeCredentials? credentials)
    {
        if (credentials is null || !credentials.HasAccessToken || !credentials.HasRefreshToken || credentials.InstallationId is not { Value.Length: 16 })
        {
            if (credentials is not null)
            {
                await _link.RevokeDeliveredAsync(credentials, run.Center, CancellationToken.None).ConfigureAwait(false);
            }

            Finish(run, FlowPhase.Failed, NodeErrors.InvalidArgument("credentials: shape"));
            return;
        }

        if (run.CancelRequested)
        {
            await _link.RevokeDeliveredAsync(credentials, run.Center, CancellationToken.None).ConfigureAwait(false);
            Finish(run, FlowPhase.Cancelled, null);
            return;
        }

        var refused = await _link.AdoptSignInAsync(credentials, run.Center).ConfigureAwait(false);
        if (refused is null)
        {
            Finish(run, FlowPhase.SignedIn, null);
            return;
        }

        await _link.RevokeDeliveredAsync(credentials, run.Center, CancellationToken.None).ConfigureAwait(false);
        Finish(run, FlowPhase.Failed, NodeErrors.InvalidState("signing_in", refused));
    }

    /// <summary>Ends the flow once: its state, the receiver, the reservation (the phase is the link's own again, a held probe resumes).</summary>
    private void Finish(Run run, FlowPhase state, ArcError? error)
    {
        lock (_lock)
        {
            if (run.Ended)
            {
                return;
            }

            run.Ended = true;
            run.State = state;
            run.Error = state == FlowPhase.Failed ? error : null;
        }

        run.Cancelled.TrySetResult();
        run.Started.TrySetResult();
        run.Receiver?.Stop();
        _link.ReleaseSignIn();
        _options.Log.Info("cloud.sign_in.ended", new LogField("state", StateName(state)),
            new LogField("error", error is null ? null : error.Category.ToString().ToLowerInvariant() + "/" + error.Code));
    }

    private SignInFlow Snapshot(Run run)
    {
        lock (_lock)
        {
            var flow = new SignInFlow
            {
                FlowId = run.Id.Clone(),
                Method = run.Method,
                State = run.State switch
                {
                    FlowPhase.Starting or FlowPhase.Pending => SignInFlowState.Pending,
                    FlowPhase.Completing => SignInFlowState.Completing,
                    FlowPhase.SignedIn => SignInFlowState.SignedIn,
                    FlowPhase.Denied => SignInFlowState.Denied,
                    FlowPhase.Expired => SignInFlowState.Expired,
                    FlowPhase.Failed => SignInFlowState.Failed,
                    _ => SignInFlowState.Cancelled,
                },
                FellBackToDeviceCode = run.FellBack,
            };
            if (run.Key is { } key)
            {
                flow.NodeKeyFingerprint = CloudIdentity.Fingerprint(key.PublicKey);
            }

            if (run.Method == SignInMethod.Browser && run.Authorize is { } url)
            {
                flow.AuthorizeUrl = url.Value;
            }

            if (run.Method == SignInMethod.DeviceCode && run.Device is { } device)
            {
                flow.UserCode = device.UserCode;
                flow.VerificationUri = device.Verification.Value;
                flow.VerificationUriComplete = device.Complete.Value;
                flow.QrPayload = device.Complete.Value;
                flow.PollIntervalMs = (ulong)run.Interval.TotalMilliseconds;
            }

            if (run.ExpiresAt is { } expires)
            {
                flow.ExpiresAt = expires.Clone();
            }

            if (run.Error is { } error)
            {
                flow.Error = error.Clone();
            }

            return flow;
        }
    }

    private static string StateName(FlowPhase state) => state switch
    {
        FlowPhase.Starting or FlowPhase.Pending => "pending",
        FlowPhase.Completing => "completing",
        FlowPhase.SignedIn => "signed_in",
        FlowPhase.Denied => "denied",
        FlowPhase.Expired => "expired",
        FlowPhase.Failed => "failed",
        _ => "cancelled",
    };

    /// <summary>A center client of the flow's center (its own HTTP seam instance).</summary>
    private sealed class ClientScope : IDisposable
    {
        private readonly CenterHttpClient _http;

        public ClientScope(CenterEndpoint center, CloudLinkOptions options)
        {
            _http = new CenterHttpClient(center, options.ConnectLog);
            Client = new CenterClient(_http, options.Clock);
        }

        public CenterClient Client { get; }

        public void Dispose() => _http.Dispose();
    }

    /// <summary>One flow.</summary>
    private sealed class Run(Id id, CenterEndpoint center, CancellationTokenSource stop) : IDisposable
    {
        public Id Id { get; } = id;

        public CenterEndpoint Center { get; } = center;

        public CancellationTokenSource Stop { get; } = stop;

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Cancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public FlowPhase State { get; set; } = FlowPhase.Starting;

        public bool Ended { get; set; }

        public bool CancelRequested { get; set; }

        public bool IsActive => State is FlowPhase.Starting or FlowPhase.Pending or FlowPhase.Completing;

        public SignInMethod Method { get; set; } = SignInMethod.Browser;

        public bool FellBack { get; set; }

        public bool Replaced { get; set; }

        public INodeKey? Key { get; set; }

        public CenterClient? Client { get; set; }

        public LoopbackReceiver? Receiver { get; set; }

        public string? State0 { get; set; }

        public string? Verifier { get; set; }

        public byte[] CenterFlowId { get; set; } = [];

        public DerivedUrl? Authorize { get; set; }

        public DeviceUrls? Device { get; set; }

        public Instant? ExpiresAt { get; set; }

        public TimeSpan Interval { get; set; } = PollFloor;

        public long Received { get; set; }

        public ArcError? Error { get; set; }

        public Task? Work { get; set; }

        public async Task CloseReceiverAsync()
        {
            if (Receiver is { } receiver)
            {
                await receiver.DisposeAsync().ConfigureAwait(false);
            }
        }

        public void Dispose()
        {
            Key?.Dispose();
            Receiver?.Stop();
            Stop.Dispose();
        }
    }
}
