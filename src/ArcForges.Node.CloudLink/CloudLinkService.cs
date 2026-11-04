// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink;

/// <summary>A notification the link raises with a state change.</summary>
/// <param name="Kind">The notification kind.</param>
/// <param name="Title">The title.</param>
/// <param name="Body">The text.</param>
internal sealed record CloudNotice(string Kind, string Title, string Body);

/// <summary>What the link publishes on a state change: the ACCOUNT topic's status, and optionally a notification.</summary>
/// <param name="Status">The account status.</param>
/// <param name="Notice">The notification, or <see langword="null"/>.</param>
internal sealed record CloudLinkPublication(AccountStatus Status, CloudNotice? Notice);

/// <summary>The outcome of <see cref="CloudLinkService.SignOutHeldAsync"/>.</summary>
internal enum SignOutResult
{
    /// <summary>The node held no credential and no stranded link state.</summary>
    NotSignedIn,

    /// <summary>Signed out locally; the center confirmed the credential is not live.</summary>
    RemoteConfirmed,

    /// <summary>Signed out locally only (<c>revoke_remote</c> false).</summary>
    LocalOnly,

    /// <summary>Signed out locally; the center's revocation was not confirmed (the credential may stay live until it expires).</summary>
    RemoteUnconfirmed,
}

/// <summary>The cloud link's inputs (the host builds them at startup step 8; tests give a temporary data root and a test center).</summary>
internal sealed record CloudLinkOptions
{
    /// <summary>The data root.</summary>
    public required string DataRoot { get; init; }

    /// <summary>The store's node ID (16 bytes).</summary>
    public required ReadOnlyMemory<byte> NodeId { get; init; }

    /// <summary>The node's secret store (the injected composition root's).</summary>
    public required NodeSecretStore Secrets { get; init; }

    /// <summary>The node key store (<see cref="NodeKeyStores"/>).</summary>
    public required NodeKeyStore Keys { get; init; }

    /// <summary>
    /// The effective center now (node.json, the official default, or the test hook); <see langword="null"/> when there is none. It may throw
    /// <see cref="NodeConfigurationException"/> (an invalid <c>node.json</c>); the link then sends nothing and keeps answering.
    /// </summary>
    public required Func<CenterEndpoint?> Center { get; init; }

    /// <summary>The node log.</summary>
    public required NodeLog Log { get; init; }

    /// <summary>The node clock (monotonic timestamps schedule; the wall clock only for the skew warning and key pruning).</summary>
    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>The node as it describes itself to the center (<c>ReportNodeInfo</c>).</summary>
    public required Func<EnrollingNodeInfo> NodeInfo { get; init; }

    /// <summary>Publishes a state change (the host journals it on topic ACCOUNT through the command processor).</summary>
    public required Func<CloudLinkPublication, Task> Publish { get; init; }

    /// <summary>The test-mode hook <c>ARCFORGES_TEST_CONNECT_LOG</c> (already checked), or <see langword="null"/>.</summary>
    public string? ConnectLog { get; init; }

    /// <summary>The test-mode hook <c>ARCFORGES_TEST_CLOUDLINK_REFRESH_SECONDS</c> (already checked), or <see langword="null"/>.</summary>
    public TimeSpan? RefreshInterval { get; init; }
}

/// <summary>
/// The node's link to its center (AF-CTR-04 N1: CTR4-NODE-04..09 and -11 as amended): the node credential and its refresh, the center's key
/// sets, ReportNodeInfo and sign-out, behind one async gate (node-3, node-9 item 1) that every center call and every credential write
/// takes. The gate is never the single writer: center and secret-store I/O run outside the command processor, and the host journals each
/// state change afterwards (<see cref="CloudLinkOptions.Publish"/>).
/// <para>Strict rotation (fleet.proto RefreshNodeSession): "Presenting a spent refresh token (also a retry whose reply was lost) revokes the
/// credential family, and the node signs in again." A refresh whose outcome is unknown is retried with backoff with the same token (the
/// only one the node holds) until the center answers; no client measure recovers a lost reply, and <c>refresh_reply_lost</c> is a
/// diagnosis. A rotated credential is written before it is used; a failed write keeps it in memory, is retried at every later rotation and
/// flushed at shutdown; a restart before a successful write presents the spent stored token, which the center treats as a reuse that
/// revokes the family and signs the node out (it fails closed).</para>
/// </summary>
internal sealed class CloudLinkService : ICloudLinkView, IAsyncDisposable
{
    /// <summary>The access lifetime assumed when the center states none (the policy minimum, so the node never refreshes late).</summary>
    public static readonly TimeSpan FallbackAccessLifetime = TimeSpan.FromMinutes(15);

    /// <summary>A rejected credential is kept at most this long after it was written (the 90-day idle limit, CRD-02).</summary>
    public static readonly TimeSpan RejectedKeep = TimeSpan.FromDays(90);

    /// <summary>The delay before the first refresh after a start (jittered up to twice this).</summary>
    public static readonly TimeSpan StartRefreshDelay = TimeSpan.FromSeconds(15);

    /// <summary>The SignOut deadline (account.proto SignOut: 15 s), counted from the handler's entry (N1 decision R-5).</summary>
    public static readonly TimeSpan SignOutDeadline = TimeSpan.FromSeconds(15);

    /// <summary>What a SignOut keeps of its deadline for the local ending and the recorded outcome.</summary>
    public static readonly TimeSpan SignOutLocalReserve = TimeSpan.FromSeconds(3);

    /// <summary>The longest a SignOut's remote part may take: the deadline less the local reserve.</summary>
    public static readonly TimeSpan SignOutRemoteBudget = SignOutDeadline - SignOutLocalReserve;

    /// <summary>A remote part with less time than this left is skipped and answered as not confirmed.</summary>
    public static readonly TimeSpan SignOutRemoteMinimum = TimeSpan.FromSeconds(1);

    /// <summary>The longest wait a refresh's <c>retry_at</c> can ask for: the probe cadence of a held credential (an hour).</summary>
    public static readonly TimeSpan RefreshRetryCap = TimeSpan.FromHours(1);

    /// <summary>The shortest and longest wait a report's <c>retry_at</c> can ask for (<c>node_report_installation</c>: 12 per hour).</summary>
    public static readonly (TimeSpan Floor, TimeSpan Cap) ReportRetryBounds = (TimeSpan.FromMinutes(1), TimeSpan.FromHours(1));

    private static readonly TimeSpan SkewTolerance = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ReportDebounce = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan KeyPruneAge = TimeSpan.FromDays(7);

    private readonly CloudLinkOptions _options;
    private readonly CloudCredentialStore _store;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Lock _stateLock = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly HashSet<string> _warnings = new(StringComparer.Ordinal);
    private readonly string _nodeHex;
    private TaskCompletionSource _wake = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private CenterHttpClient? _http;
    private CloudLinkPhase _phase = CloudLinkPhase.SignedOut;
    private CloudCredentialRecord? _record;
    private CloudLinkFile? _link;
    private string? _lastError;
    private bool _rejected;
    private bool _pendingWrite;
    private bool _reload;
    private int _configurationInvalid;
    private TimeSpan _centerOffset;
    private CancellationTokenSource? _work;
    private string? _ambiguousToken;
    private long _generation;
    private long _receipt;
    private long _nextRefresh = long.MaxValue;
    private long _nextReport = long.MaxValue;
    private int _failures;
    private bool? _reachable;
    private DateTimeOffset? _lastContact;
    private Id? _reportCommand;
    private Task _loop = Task.CompletedTask;
    private int _disposed;
    private int _idle;

    /// <summary>Creates the link (nothing is read until <see cref="StartAsync"/>).</summary>
    public CloudLinkService(CloudLinkOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _store = new CloudCredentialStore(options.DataRoot, options.Secrets);
        _nodeHex = Convert.ToHexStringLower(options.NodeId.Span);
    }

    /// <inheritdoc />
    public CloudLinkPhase Phase
    {
        get
        {
            lock (_stateLock)
            {
                return _phase;
            }
        }
    }

    /// <inheritdoc />
    public bool AccountLinked => Phase == CloudLinkPhase.SignedIn;

    /// <summary>Incremented at every rotation (the single-flight gate's generation, node-9 item 1).</summary>
    public long Generation => Interlocked.Read(ref _generation);

    /// <summary>True while the loop waits for its next due time (tests advance a manual clock only then, so no due time is skipped).</summary>
    internal bool Idle => Volatile.Read(ref _idle) == 1 && _gate.CurrentCount == 1;

    /// <summary>The storage (tests read the files and the record through it).</summary>
    internal CloudCredentialStore Storage => _store;

    /// <summary>Loads the stored link (startup step 8) and starts the refresh loop.</summary>
    public async Task StartAsync()
    {
        using (await EnterAsync(CancellationToken.None).ConfigureAwait(false))
        {
            Load();
        }

        await PublishAsync(null).ConfigureAwait(false);
        _loop = Task.Run(() => LoopAsync(_stop.Token), CancellationToken.None);
    }

    /// <inheritdoc />
    public async Task<IDisposable> EnterAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new Held(_gate);
    }

    /// <summary>
    /// The gate for a sign-out (N1 decision R-5): waits at most <paramref name="wait"/> for the center call in flight (the loop releases the
    /// gate between a refresh and a report, so that is one call of at most its 10 s deadline); a call that outlasts it is cancelled (its
    /// outcome becomes unknown, which the ending makes moot), then the gate is taken.
    /// </summary>
    public async Task<IDisposable> EnterForSignOutAsync(TimeSpan wait, CancellationToken cancellationToken)
    {
        if (wait > TimeSpan.Zero && await _gate.WaitAsync(wait, cancellationToken).ConfigureAwait(false))
        {
            return new Held(_gate);
        }

        CancellationTokenSource? work;
        lock (_stateLock)
        {
            work = _work;
        }

        try
        {
            if (work is not null)
            {
                await work.CancelAsync().ConfigureAwait(false);
            }
        }
        catch (ObjectDisposedException)
        {
            // The call ended meanwhile.
        }

        _options.Log.Info("cloud.sign_out.cancelled_call_in_flight");
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new Held(_gate);
    }

    /// <inheritdoc />
    public void NodeInfoChanged()
    {
        lock (_stateLock)
        {
            _nextReport = _options.Clock.GetTimestamp() + Ticks(ReportDebounce);
        }

        Wake();
    }

    /// <inheritdoc />
    /// <remarks>
    /// N1 decision G-1 in both directions: every credential record of another center than the one now configured ends, two-phase (record,
    /// key sets, node key, link file), a held <c>center_rejected_credential</c> included; nothing of it is sent anywhere. A stored credential
    /// of the center now configured (a <c>credential_for_other_center</c> link whose center is configured again) is signed in as at start.
    /// A record the node cannot reach here (another node ID, another backend, an unavailable store) is left alone and stays reported. Without
    /// a credential, the old center's key sets and node key go.
    /// </remarks>
    public async Task CenterChangedAsync()
    {
        using (await EnterAsync(CancellationToken.None).ConfigureAwait(false))
        {
            var center = Configured();
            CloudCredentialRecord? held;
            lock (_stateLock)
            {
                held = _phase == CloudLinkPhase.SignedIn ? _record : null;
            }

            if (held is null || center?.Url != held.CenterUrl)
            {
                _http?.Dispose();
                _http = null;
                Load();
                if (HasWarning(Warnings.OtherCenter))
                {
                    EndCredential("center_changed", notice: null, _link);
                }
                else if (Phase != CloudLinkPhase.SignedIn)
                {
                    TryDeleteKeySets();
                    if (_link is null)
                    {
                        TryDeleteKey(null);
                    }
                }
            }
        }

        await PublishAsync(null).ConfigureAwait(false);
    }

    /// <summary>The account status (account.proto <c>AccountStatus</c>; AF-CTR-04 N1 d.2).</summary>
    public AccountStatus Status()
    {
        lock (_stateLock)
        {
            var status = new AccountStatus
            {
                SignedIn = _phase == CloudLinkPhase.SignedIn,
                NodeEnrolled = _phase == CloudLinkPhase.SignedIn,
                Relay = RelayState.Disabled,
                RelayReason = "not_delivered",
                CloudLinkEnabled = false,
            };
            var center = Configured();
            if (_phase == CloudLinkPhase.SignedIn && _record is { } record)
            {
                status.CenterUrl = record.CenterUrl;
                if (record.DisplayName is { } name)
                {
                    status.AccountDisplayName = name;
                }

                if (record.EmailMasked is { } email)
                {
                    status.AccountEmailMasked = email;
                }

                if (record.SessionExpiresAtMs > 0)
                {
                    status.CredentialExpiresAt = ProtoTime.ToInstant(DateTimeOffset.FromUnixTimeMilliseconds(record.SessionExpiresAtMs));
                }

                status.CredentialInOsStore = _link is { } link && link.Protection == nameof(SecretStoreProtection.OsSecretStore) && !link.Isolated;
            }
            else if (center is not null)
            {
                status.CenterUrl = center.Url;
            }

            if (_reachable is { } reachable)
            {
                status.CloudReachable = reachable;
            }

            if (_lastContact is { } contact)
            {
                status.LastContactAt = ProtoTime.ToInstant(contact);
            }

            if (_options.Keys.Recorded() is { } key && key.NodeId == _nodeHex)
            {
                status.NodeKeyFingerprint = key.Fingerprint;
            }

            status.Warnings.AddRange(CurrentWarnings(center));
            return status;
        }
    }

    /// <summary>The last error the link met (signed-out reasons), for logs and tests.</summary>
    public string? LastError
    {
        get
        {
            lock (_stateLock)
            {
                return _lastError;
            }
        }
    }

    /// <summary>
    /// Adopts credentials a sign-in delivered (for part N2's flows; tests seed with it in process): two-phase, <c>run/cloud-link.json</c>
    /// <c>committing</c> first, then the record, the key sets, then <c>signed_in</c>. Takes the gate. It never replaces another credential's
    /// link (another center or node, or one being ended): that credential is ended first, or it would be left without a pointer.
    /// </summary>
    /// <exception cref="InvalidOperationException">A link of another credential, or one being ended, exists.</exception>
    public async Task AdoptAsync(NodeCredentials credentials, CenterEndpoint center)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(center);
        using (await EnterAsync(CancellationToken.None).ConfigureAwait(false))
        {
            var now = _options.Clock.GetUtcNow();
            var lifetime = credentials.HasAccessLifetimeMs ? (long)credentials.AccessLifetimeMs : 0;
            var accessExpires = ProtoTime.ToDateTimeOffset(credentials.AccessExpiresAt)?.ToUnixTimeMilliseconds() ?? 0;
            var sessionExpires = ProtoTime.ToDateTimeOffset(credentials.SessionExpiresAt)?.ToUnixTimeMilliseconds() ?? 0;
            var record = new CloudCredentialRecord
            {
                NodeId = _nodeHex,
                CenterUrl = center.Url,
                AccountId = credentials.Account?.AccountId is { } account ? Convert.ToHexStringLower(account.Value.Span) : null,
                DisplayName = credentials.Account is { HasDisplayName: true } a ? a.DisplayName : null,
                EmailMasked = credentials.Account is { HasEmailMasked: true } m ? m.EmailMasked : null,
                InstallationId = credentials.InstallationId is { } installation ? Convert.ToHexStringLower(installation.Value.Span) : string.Empty,
                AccessToken = credentials.AccessToken,
                AccessExpiresAtMs = accessExpires,
                AccessLifetimeMs = lifetime,
                RefreshToken = credentials.RefreshToken,
                SessionExpiresAtMs = sessionExpires,
                FamilyLifetimeMs = sessionExpires > 0 && accessExpires > 0 ? sessionExpires - (accessExpires - lifetime) : 0,
                WrittenAtMs = now.ToUnixTimeMilliseconds(),
            };
            var target = CloudCredentialStore.Target(_options.NodeId.Span, center.Origin);
            if (_store.ReadLink() is { } existing && (existing.Target != target || existing.State == LinkStates.Ending))
            {
                throw new InvalidOperationException("The node holds the link of another credential (" + existing.State + "); it is ended first.");
            }

            var link = new CloudLinkFile
            {
                State = LinkStates.Committing,
                Backend = _options.Secrets.Backend.ToString(),
                Protection = _options.Secrets.Protection.ToString(),
                Isolated = _options.Secrets.Isolated,
                Target = target,
                CenterUrl = center.Url,
                NodeId = _nodeHex,
            };
            _store.WriteLink(link);
            _store.WriteRecord(target, record);
            ReplaceKeySets(record, credentials.CommandKeys, credentials.EntitlementKeys, now);
            link.State = LinkStates.SignedIn;
            _store.WriteLink(link);
            lock (_stateLock)
            {
                _link = link;
                _record = record;
                _phase = CloudLinkPhase.SignedIn;
                _rejected = false;
                _lastError = null;
                _pendingWrite = false;
                _ambiguousToken = null;
                _failures = 0;
                _warnings.Clear();
                _receipt = _options.Clock.GetTimestamp();
                _nextRefresh = _receipt + Ticks(RefreshDelay(record));
                _nextReport = _options.Clock.GetTimestamp();
                _centerOffset = CenterOffset(record, now);
                Interlocked.Increment(ref _generation);
            }

            _options.Log.Info("cloud.signed_in", new LogField("center", center.Url), new LogField("backend", link.Backend), new LogField("isolated", link.Isolated));
        }

        await PublishAsync(null).ConfigureAwait(false);
        Wake();
    }

    /// <summary>
    /// A refresh requested by a caller that saw the access token of <paramref name="seenGeneration"/> fail: it calls the center only when no
    /// rotation happened since (single flight, node-9 item 1). Takes the gate.
    /// </summary>
    public async Task RefreshAsync(long seenGeneration, CancellationToken cancellationToken)
    {
        bool changed;
        using (await EnterAsync(cancellationToken).ConfigureAwait(false))
        {
            if (Generation != seenGeneration || Phase != CloudLinkPhase.SignedIn)
            {
                return;
            }

            using var work = BeginWork(cancellationToken);
            changed = await RefreshCoreAsync(work.Token).ConfigureAwait(false);
        }

        if (changed)
        {
            await PublishAsync(null).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Signs the node out (AF-CTR-04 CTR4-NODE-11 as amended; N1 decision R-5) while the caller holds the gate
    /// (<see cref="EnterForSignOutAsync"/>): the center call in flight has ended by then. With <paramref name="revokeRemote"/>, SignOutNode
    /// with the current access token, to the credential's own center only, within <paramref name="remoteBudget"/> (real time, as the
    /// caller's deadline; default <see cref="SignOutRemoteBudget"/>; less than <see cref="SignOutRemoteMinimum"/> skips it). Whatever the
    /// answer, the credential ends locally, two-phase (R-1). A link this node cannot end here (another node ID or secret-store backend, an
    /// unreadable or inconsistent file) is left alone: <see cref="SignOutResult.NotSignedIn"/>, and the status keeps reporting it.
    /// </summary>
    public async Task<SignOutResult> SignOutHeldAsync(bool revokeRemote, TimeSpan? remoteBudget = null)
    {
        CloudCredentialRecord? record;
        CloudLinkFile? link;
        lock (_stateLock)
        {
            record = _record;
            link = _link;
        }

        if (link is null)
        {
            try
            {
                link = _store.ReadLink();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                return SignOutResult.NotSignedIn;
            }
        }

        if (link is null || Unowned(link) is not null)
        {
            return SignOutResult.NotSignedIn;
        }

        var result = !revokeRemote ? SignOutResult.LocalOnly : SignOutResult.RemoteUnconfirmed;
        var budget = remoteBudget ?? SignOutRemoteBudget;
        if (revokeRemote && record is not null && Phase == CloudLinkPhase.SignedIn)
        {
            if (budget < SignOutRemoteMinimum)
            {
                _options.Log.Warning("cloud.sign_out.remote_skipped", new LogField("budgetMs", (long)budget.TotalMilliseconds));
            }
            else if (BoundClient(record, strand: false, out _) is { } client)
            {
                using var cancel = new CancellationTokenSource(budget);
                try
                {
                    result = await RemoteSignOutAsync(client, record, cancel.Token).ConfigureAwait(false) ? SignOutResult.RemoteConfirmed : SignOutResult.RemoteUnconfirmed;
                }
                catch (OperationCanceledException) when (cancel.IsCancellationRequested)
                {
                    result = SignOutResult.RemoteUnconfirmed;
                }
            }
        }

        EndCredential("signed_out", notice: null, link);
        _options.Log.Info("cloud.signed_out", new LogField("revokeRemote", revokeRemote), new LogField("result", result));
        return result;
    }

    /// <summary>Publishes the current state (after a sign-out the handler calls it, outside the gate).</summary>
    public Task PublishCurrentAsync() => PublishAsync(null);

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _stop.CancelAsync().ConfigureAwait(false);
        Wake();
        try
        {
            await _loop.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException)
        {
        }

        // The shutdown sequence flushes a rotated credential whose write failed (CTR4-NODE-05).
        if (await _gate.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false))
        {
            try
            {
                FlushPendingWrite();
            }
            finally
            {
                _gate.Release();
            }
        }

        _http?.Dispose();
    }

    private async Task<bool> RemoteSignOutAsync(CenterClient client, CloudCredentialRecord record, CancellationToken cancellationToken)
    {
        var command = CommandIds.New(_options.Clock);
        var reply = await client.SignOutNodeAsync(record.AccessToken, command, cancellationToken).ConfigureAwait(false);
        if (NotLive(reply))
        {
            return true;
        }

        if (reply.Outcome != CenterOutcome.Transport || reply.TransportCode is not ("auth.token_expired" or "auth.unauthenticated"))
        {
            return false;
        }

        // The access token expired, or a refresh committed but its reply was lost (the access digest was replaced): present the held
        // refresh token once. A spent one revokes the family by the reuse rule, which is the sign-out asked for; a live one rotates and
        // the sign-out is sent once more with the new access token.
        var refresh = await client.RefreshAsync(record.RefreshToken, cancellationToken).ConfigureAwait(false);
        if (refresh.Outcome == CenterOutcome.Refused && refresh.Error?.Code is "credential_revoked" or "token_expired")
        {
            return true;
        }

        if (refresh.Value is not { } value)
        {
            return false;
        }

        var retry = await client.SignOutNodeAsync(value.AccessToken, CommandIds.New(_options.Clock), cancellationToken).ConfigureAwait(false);
        return NotLive(retry);
    }

    private static bool NotLive<T>(CenterReply<T> reply)
        where T : class =>
        reply.Outcome == CenterOutcome.Value
        || (reply.Outcome == CenterOutcome.Transport && reply.TransportCode == "auth.credential_revoked")
        || (reply.Outcome == CenterOutcome.Refused && reply.Error?.Code is "credential_revoked" or "unauthenticated");

    private async Task LoopAsync(CancellationToken stop)
    {
        while (!stop.IsCancellationRequested)
        {
            try
            {
                var wake = Volatile.Read(ref _wake).Task;
                var delay = NextWake();
                if (delay > TimeSpan.Zero)
                {
                    var due = Task.Delay(delay, _options.Clock, stop);
                    Volatile.Write(ref _idle, 1);
                    await Task.WhenAny(wake, due).ConfigureAwait(false);
                    Volatile.Write(ref _idle, 0);
                }

                if (stop.IsCancellationRequested)
                {
                    return;
                }

                Interlocked.CompareExchange(ref _wake, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously), _wake);
                var changed = false;
                var now = _options.Clock.GetTimestamp();
                using (await EnterAsync(stop).ConfigureAwait(false))
                using (var work = BeginWork(stop))
                {
                    if (_reload || (_link?.State == LinkStates.Ending))
                    {
                        Load();
                        changed = true;
                    }

                    if (_pendingWrite)
                    {
                        changed |= FlushPendingWrite();
                    }

                    if ((Phase == CloudLinkPhase.SignedIn || _rejected) && now >= Interlocked.Read(ref _nextRefresh))
                    {
                        changed |= await RefreshCoreAsync(work.Token).ConfigureAwait(false);
                    }
                }

                // The gate is released between the refresh and the report, so a sign-out waits for one center call at most (R-5).
                if (Phase == CloudLinkPhase.SignedIn && now >= Interlocked.Read(ref _nextReport))
                {
                    using (await EnterAsync(stop).ConfigureAwait(false))
                    using (var work = BeginWork(stop))
                    {
                        if (Phase == CloudLinkPhase.SignedIn && now >= Interlocked.Read(ref _nextReport))
                        {
                            changed |= await ReportCoreAsync(work.Token).ConfigureAwait(false);
                        }
                    }
                }

                if (changed)
                {
                    await PublishAsync(TakeNotice()).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                return;
            }
            catch (OperationCanceledException)
            {
                // A sign-out cancelled the call in flight (EnterForSignOutAsync); its ending decides what follows.
            }
            catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
            {
                _options.Log.Error("cloud.loop.failed", exception);
                var pause = Task.Delay(TimeSpan.FromSeconds(5), _options.Clock, stop);
                Volatile.Write(ref _idle, 1);
                await pause.ConfigureAwait(false);
                Volatile.Write(ref _idle, 0);
            }
        }
    }

    private CloudNotice? _notice;

    private CloudNotice? TakeNotice()
    {
        lock (_stateLock)
        {
            var notice = _notice;
            _notice = null;
            return notice;
        }
    }

    private TimeSpan NextWake()
    {
        var now = _options.Clock.GetTimestamp();
        long next;
        lock (_stateLock)
        {
            next = _phase == CloudLinkPhase.SignedIn || _rejected ? Math.Min(_nextRefresh, _phase == CloudLinkPhase.SignedIn ? _nextReport : long.MaxValue) : long.MaxValue;
            if (_reload || _pendingWrite)
            {
                next = Math.Min(next, now + Ticks(TimeSpan.FromSeconds(60)));
            }
        }

        if (next == long.MaxValue)
        {
            return TimeSpan.FromHours(1);
        }

        var remaining = _options.Clock.GetElapsedTime(now, Math.Max(now, next));
        return remaining > TimeSpan.FromHours(1) ? TimeSpan.FromHours(1) : remaining;
    }

    /// <summary>
    /// Loads the stored link (N1 decision R-1 and node-10): nothing is deleted on an absent record, a store failure, an unreadable link file
    /// or a link this node cannot end here. A link is this node's to use or end only when its node ID, its secret-store backend pair and its
    /// target (recomputed from the node ID and the link's center) match; only then is an interrupted ending finished, in the backend that
    /// holds the record.
    /// </summary>
    private void Load()
    {
        var center = Configured(out var configurationInvalid);
        CloudLinkFile? link;
        try
        {
            link = _store.ReadLink();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            // An unreadable or unparsable link file is never read as "absent": reported, retried, nothing deleted.
            SetStranded(Warnings.StoreUnavailable, "the link file cannot be read: " + exception.GetType().Name);
            lock (_stateLock)
            {
                _reload = true;
            }

            return;
        }

        lock (_stateLock)
        {
            _reload = false;
            _link = link;
            _record = null;
            _rejected = false;
            _rejectedRecord = null;
            _phase = CloudLinkPhase.SignedOut;
            _nextRefresh = long.MaxValue;
            _nextReport = long.MaxValue;
            _centerOffset = TimeSpan.Zero;
            _warnings.Remove(Warnings.StoreUnavailable);
            _warnings.Remove(Warnings.BackendChanged);
            _warnings.Remove(Warnings.OtherCenter);
            _warnings.Remove(Warnings.OtherNode);
            _warnings.Remove(Warnings.Rejected);
        }

        if (link is null)
        {
            // Key sets without a link belong to no credential.
            TryDeleteKeySets();
            return;
        }

        if (Unowned(link) is { } unowned)
        {
            SetStranded(unowned.Warning, unowned.Reason);
            return;
        }

        if (link.State == LinkStates.Ending)
        {
            EndCredential(LastError ?? "signed_out", notice: null, link);
            return;
        }

        CloudCredentialRecord? record;
        try
        {
            record = _store.ReadRecord(link.Target);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
        {
            // A locked keyring or an unavailable Secret Service is never read as "absent" (R-1): reported, retried, nothing deleted.
            SetStranded(Warnings.StoreUnavailable, "the secret store failed: " + exception.GetType().Name);
            lock (_stateLock)
            {
                _reload = true;
            }

            return;
        }

        if (record is null)
        {
            if (link.State == LinkStates.Committing)
            {
                // A sign-in that never wrote its record (the crash points of the amendments' storage table): signed out, files removed.
                EndCredential("sign_in_not_completed", notice: null, link);
                return;
            }

            SetStranded(Warnings.BackendChanged, "the selected secret store holds no credential for the link file");
            return;
        }

        if (record.NodeId != _nodeHex)
        {
            SetStranded(Warnings.OtherNode, "the credential belongs to another node ID");
            return;
        }

        if (record.CenterUrl != link.CenterUrl)
        {
            SetStranded(Warnings.StoreUnavailable, "the record and the link file name different centers");
            return;
        }

        if (configurationInvalid)
        {
            // node.json cannot be read, so the record's center is not confirmed: nothing is sent; retried every minute.
            lock (_stateLock)
            {
                _reload = true;
                _lastError = "center_configuration_invalid";
            }

            return;
        }

        if (center is null || record.CenterUrl != center.Url)
        {
            SetStranded(Warnings.OtherCenter, "the credential belongs to " + record.CenterUrl);
            return;
        }

        if (link.State == LinkStates.Committing)
        {
            link.State = LinkStates.SignedIn;
            _store.WriteLink(link);
        }

        var keys = _store.ReadKeys();
        if (keys is not null && (keys.CenterUrl != record.CenterUrl || keys.InstallationId != record.InstallationId))
        {
            _store.DeleteKeys();
        }

        var now = _options.Clock.GetTimestamp();
        lock (_stateLock)
        {
            _record = record;
            _phase = CloudLinkPhase.SignedIn;
            _receipt = now;
            _nextRefresh = now + Ticks(_options.RefreshInterval ?? StartRefreshDelay + Jitter(StartRefreshDelay));
            var info = _options.NodeInfo();
            _nextReport = info.Name != link.ReportedName || info.Version != link.ReportedVersion ? now : long.MaxValue;
        }

        _options.Log.Info("cloud.loaded", new LogField("center", record.CenterUrl), new LogField("backend", link.Backend), new LogField("isolated", link.Isolated));
    }

    private void SetStranded(string warning, string reason)
    {
        lock (_stateLock)
        {
            _phase = CloudLinkPhase.SignedOut;
            _record = null;
            _warnings.Add(warning);
            _lastError = warning;
        }

        _options.Log.Warning("cloud.credential_unusable", new LogField("warning", warning), new LogField("reason", reason));
    }

    /// <summary>One refresh under the gate; returns whether the published state changed.</summary>
    private async Task<bool> RefreshCoreAsync(CancellationToken cancellationToken)
    {
        CloudCredentialRecord? record;
        lock (_stateLock)
        {
            record = _record ?? (_rejected ? _rejectedRecord : null);
        }

        if (record is null)
        {
            return false;
        }

        if (BoundClient(record, strand: true, out var stranded) is not { } client)
        {
            // Another center is configured (stranded: nothing is sent) or node.json cannot be read (retried in a minute).
            if (!stranded)
            {
                Interlocked.Exchange(ref _nextRefresh, _options.Clock.GetTimestamp() + Ticks(TimeSpan.FromMinutes(1)));
            }

            return stranded;
        }

        var token = record.RefreshToken;
        var reply = await client.RefreshAsync(token, cancellationToken).ConfigureAwait(false);
        var now = _options.Clock.GetTimestamp();
        switch (reply.Outcome)
        {
            case CenterOutcome.Value:
                return Rotated(record, reply.Value!);
            case CenterOutcome.Refused when reply.Error!.Code == "credential_revoked":
                Contact(true);
                var lost = _ambiguousToken == token;
                EndCredential(lost ? "refresh_reply_lost" : "credential_revoked", lost ? Notices.ReplyLost : Notices.Revoked, _link);
                return true;
            case CenterOutcome.Refused when reply.Error!.Code == "token_expired":
                Contact(true);
                EndCredential("token_expired", Notices.Expired, _link);
                return true;
            case CenterOutcome.Refused when reply.Error!.Code is "unauthenticated" or "permission_denied" or "invalid_argument":
                Contact(true);
                return Rejected(record, reply.Code!);
            case CenterOutcome.Refused when reply.Error!.Code is "rate_limited" or "overloaded":
                Contact(true);
                var wait = RetryWait(reply.Error.Retry?.RetryAt, TimeSpan.FromSeconds(30), RefreshFloor(record), RefreshRetryCap);
                Interlocked.Exchange(ref _nextRefresh, now + Ticks(wait + Jitter(TimeSpan.FromSeconds(2))));
                return false;
            case CenterOutcome.Refused when reply.Error!.Code == "not_activated":
                Contact(true);
                AddWarning(Warnings.NotActivated);
                Interlocked.Exchange(ref _nextRefresh, now + Ticks(TimeSpan.FromHours(1) + Jitter(TimeSpan.FromMinutes(5))));
                return true;
            case CenterOutcome.Refused:
                // INTERNAL/internal (effect UNKNOWN) and anything else: the outcome is unknown; the same token is retried with backoff.
                Contact(true);
                _ambiguousToken = token;
                Backoff();
                return false;
            case CenterOutcome.ProtocolMismatch:
                Contact(true);
                AddWarning(Warnings.ProtocolMismatch);
                _options.Log.Warning("cloud.refresh.protocol_mismatch", new LogField("detail", reply.Detail));
                Backoff();
                return true;
            default:
                // An ingress answer (stale generation, dependency unavailable) still reached the center's front (d.2 cloud_reachable).
                Contact(reply.TransportCode is not null);
                if (reply.MaybeApplied)
                {
                    _ambiguousToken = token;
                }

                _options.Log.Info("cloud.refresh.unreachable", new LogField("detail", reply.Detail), new LogField("maybeApplied", reply.MaybeApplied));
                Backoff();
                return false;
        }
    }

    private CloudCredentialRecord? _rejectedRecord;

    private bool Rotated(CloudCredentialRecord previous, NodeEnrollmentServiceRefreshNodeSessionValue value)
    {
        var wall = _options.Clock.GetUtcNow();
        var record = previous.Clone();
        record.AccessToken = value.AccessToken;
        record.RefreshToken = value.RefreshToken;
        record.AccessExpiresAtMs = ProtoTime.ToDateTimeOffset(value.AccessExpiresAt)?.ToUnixTimeMilliseconds() ?? 0;
        record.AccessLifetimeMs = value.HasAccessLifetimeMs ? (long)value.AccessLifetimeMs : 0;
        if (ProtoTime.ToDateTimeOffset(value.SessionExpiresAt) is { } session)
        {
            record.SessionExpiresAtMs = session.ToUnixTimeMilliseconds();
        }

        record.WrittenAtMs = wall.ToUnixTimeMilliseconds();
        var recovered = _rejected;
        try
        {
            // Written before it is used (CTR4-NODE-05).
            _store.WriteRecord(_link!.Target, record);
            RemoveWarning(Warnings.StorageFailed);
            _pendingWrite = false;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
        {
            _pendingWrite = true;
            AddWarning(Warnings.StorageFailed);
            _options.Log.Warning("cloud.credential_storage_failed", new LogField("errorType", exception.GetType().Name));
        }

        ReplaceKeySets(record, value.CommandKeys, value.EntitlementKeys, wall);
        var now = _options.Clock.GetTimestamp();
        lock (_stateLock)
        {
            _record = record;
            _rejectedRecord = null;
            _rejected = false;
            _phase = CloudLinkPhase.SignedIn;
            _warnings.Remove(Warnings.Rejected);
            _warnings.Remove(Warnings.NotActivated);
            _warnings.Remove(Warnings.ProtocolMismatch);
            _ambiguousToken = null;
            _failures = 0;
            _receipt = now;
            _nextRefresh = now + Ticks(RefreshDelay(record));
            _lastError = null;
            _centerOffset = CenterOffset(record, wall);
            Interlocked.Increment(ref _generation);
            var lifetime = Lifetime(record);
            var skew = (DateTimeOffset.FromUnixTimeMilliseconds(record.AccessExpiresAtMs) - wall - lifetime).Duration();
            if (record.AccessExpiresAtMs > 0 && skew > SkewTolerance)
            {
                _warnings.Add(Warnings.ClockSkew);
            }
            else
            {
                _warnings.Remove(Warnings.ClockSkew);
            }
        }

        Contact(true);
        return true;
    }

    private bool Rejected(CloudCredentialRecord record, string code)
    {
        var now = _options.Clock.GetTimestamp();
        var wall = _options.Clock.GetUtcNow();
        if (wall - DateTimeOffset.FromUnixTimeMilliseconds(record.WrittenAtMs) >= RejectedKeep)
        {
            EndCredential("center_rejected_credential", Notices.Revoked, _link);
            return true;
        }

        lock (_stateLock)
        {
            _rejected = true;
            _rejectedRecord = record;
            _record = null;
            _phase = CloudLinkPhase.SignedOut;
            _warnings.Add(Warnings.Rejected);
            _lastError = "center_rejected_credential";
            _nextRefresh = now + Ticks(TimeSpan.FromMinutes(50) + Jitter(TimeSpan.FromMinutes(10)));
        }

        _options.Log.Warning("cloud.credential_rejected", new LogField("code", code));
        return true;
    }

    private async Task<bool> ReportCoreAsync(CancellationToken cancellationToken)
    {
        CloudCredentialRecord? record;
        lock (_stateLock)
        {
            record = _record;
            _nextReport = long.MaxValue;
        }

        if (record is null || _link is not { } link)
        {
            return false;
        }

        if (BoundClient(record, strand: true, out var stranded) is not { } client)
        {
            if (!stranded)
            {
                Interlocked.Exchange(ref _nextReport, _options.Clock.GetTimestamp() + Ticks(TimeSpan.FromMinutes(1)));
            }

            return stranded;
        }

        var info = _options.NodeInfo();
        if (info.Name == link.ReportedName && info.Version == link.ReportedVersion)
        {
            return false;
        }

        _reportCommand ??= CommandIds.New(_options.Clock);
        var reply = await client.ReportNodeInfoAsync(record.AccessToken, info, _reportCommand, cancellationToken).ConfigureAwait(false);
        if (reply.Outcome == CenterOutcome.Transport && reply.TransportCode is "auth.token_expired" or "auth.credential_revoked" or "auth.unauthenticated"
            || reply.Outcome == CenterOutcome.Refused && reply.Error!.Code == "unauthenticated")
        {
            // Only a gated refresh; the refresh's own answer decides (node-9 item 1). Then the report once more with the same command ID.
            var generation = Generation;
            var changed = await RefreshCoreAsync(cancellationToken).ConfigureAwait(false);
            if (Generation == generation || _record is not { } refreshed)
            {
                return changed;
            }

            reply = await client.ReportNodeInfoAsync(refreshed.AccessToken, info, _reportCommand, cancellationToken).ConfigureAwait(false);
        }

        switch (reply.Outcome)
        {
            case CenterOutcome.Value:
                _reportCommand = null;
                link.ReportedName = info.Name;
                link.ReportedVersion = info.Version;
                _store.WriteLink(link);
                var changed = RemoveWarning(Warnings.InfoRejected) | RemoveWarning(Warnings.Restricted);
                Contact(true);
                return changed;
            case CenterOutcome.Refused when reply.Error!.Code == "command_id_reused":
                _reportCommand = CommandIds.New(_options.Clock);
                _options.Log.Error("cloud.report.command_id_reused");
                NodeInfoChanged();
                return false;
            case CenterOutcome.Refused when reply.Error!.Code == "invalid_argument":
                _reportCommand = null;
                _options.Log.Warning("cloud.report.rejected", new LogField("reason", reply.Error.Details?.State?.Reason ?? string.Empty));
                return AddWarning(Warnings.InfoRejected);
            case CenterOutcome.Refused when reply.Error!.Code == "permission_denied":
                _reportCommand = null;
                Interlocked.Exchange(ref _nextReport, _options.Clock.GetTimestamp() + Ticks(TimeSpan.FromHours(24)));
                return AddWarning(Warnings.Restricted);
            case CenterOutcome.Refused when reply.Error!.Code is "rate_limited" or "overloaded":
                var retry = RetryWait(reply.Error.Retry?.RetryAt, TimeSpan.FromMinutes(5), ReportRetryBounds.Floor, ReportRetryBounds.Cap);
                Interlocked.Exchange(ref _nextReport, _options.Clock.GetTimestamp() + Ticks(retry));
                return false;
            default:
                // Unreachable or unknown: the same command ID later (a committed report replays its receipt).
                Interlocked.Exchange(ref _nextReport, _options.Clock.GetTimestamp() + Ticks(TimeSpan.FromMinutes(1) + Jitter(TimeSpan.FromMinutes(1))));
                Contact(reply.Outcome != CenterOutcome.Unreachable || reply.TransportCode is not null);
                return false;
        }
    }

    /// <summary>
    /// Ends the credential, two-phase (N1 decision R-1): <c>ending</c> first, then the record (in the backend that holds it), the key sets,
    /// the node key, and last the link file, the only pointer to the record. A step that fails keeps the ending recorded and reported
    /// (<c>credential_store_unavailable</c>); the loop retries it every minute and every start resumes it. A link this node cannot end
    /// here (<see cref="Unowned"/>) is not touched at all.
    /// </summary>
    private void EndCredential(string reason, CloudNotice? notice, CloudLinkFile? link)
    {
        var finished = true;
        string? blocked = null;
        if (link is not null)
        {
            if (Unowned(link) is { } unowned)
            {
                finished = false;
                blocked = unowned.Warning;
                _options.Log.Warning("cloud.ending.not_here", new LogField("warning", unowned.Warning), new LogField("reason", unowned.Reason));
            }
            else
            {
                try
                {
                    if (link.State != LinkStates.Ending)
                    {
                        link.State = LinkStates.Ending;
                        _store.WriteLink(link);
                    }

                    _store.DeleteRecord(link.Target);
                }
                catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
                {
                    finished = false;
                    _options.Log.Warning("cloud.ending.record_delete_failed", new LogField("errorType", exception.GetType().Name));
                }
            }
        }

        finished = finished && TryDeleteKeySets() && TryDeleteKey(link);
        if (finished)
        {
            try
            {
                _store.DeleteLink();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                finished = false;
                _options.Log.Warning("cloud.ending.link_delete_failed", new LogField("errorType", exception.GetType().Name));
            }
        }

        blocked ??= finished ? null : Warnings.StoreUnavailable;
        lock (_stateLock)
        {
            _phase = CloudLinkPhase.SignedOut;
            _record = null;
            _rejectedRecord = null;
            _rejected = false;
            _pendingWrite = false;
            _ambiguousToken = null;
            _link = finished ? null : link;
            _reload = blocked == Warnings.StoreUnavailable;
            _lastError = reason;
            _warnings.Clear();
            if (blocked is not null)
            {
                _warnings.Add(blocked);
            }

            _notice = notice;
            _nextRefresh = long.MaxValue;
            _nextReport = long.MaxValue;
        }

        _options.Log.Info("cloud.credential_ended", new LogField("reason", reason), new LogField("finished", finished));
    }

    /// <summary>
    /// Why <paramref name="link"/> is not this node's to use or end here, or <see langword="null"/>: another node ID, another secret-store
    /// backend pair (the record lives there: deleting here would delete nothing and lose the pointer), or a target that is not the one the
    /// node derives from its node ID and the link's center (a damaged or edited file never names another entry to delete).
    /// </summary>
    private (string Warning, string Reason)? Unowned(CloudLinkFile link)
    {
        if (link.NodeId != _nodeHex)
        {
            return (Warnings.OtherNode, "the link file belongs to another node ID");
        }

        if (link.Backend != _options.Secrets.Backend.ToString() || link.Isolated != _options.Secrets.Isolated)
        {
            return (Warnings.BackendChanged, "the credential is in another secret-store backend (" + link.Backend + ")");
        }

        if (!CenterEndpoint.TryParse(link.CenterUrl, out var center, out _) || link.Target != CloudCredentialStore.Target(_options.NodeId.Span, center.Origin))
        {
            return (Warnings.StoreUnavailable, "the link file names a credential this node does not derive");
        }

        return null;
    }

    /// <summary>A credential of another center than the configured one: nothing is sent; the record is kept (node-10), as at start.</summary>
    private void StrandOtherCenter(CloudCredentialRecord record)
    {
        lock (_stateLock)
        {
            _phase = CloudLinkPhase.SignedOut;
            _record = null;
            _rejected = false;
            _rejectedRecord = null;
            _warnings.Remove(Warnings.Rejected);
            _warnings.Add(Warnings.OtherCenter);
            _lastError = Warnings.OtherCenter;
            _nextRefresh = long.MaxValue;
            _nextReport = long.MaxValue;
        }

        _options.Log.Warning("cloud.credential_unusable", new LogField("warning", Warnings.OtherCenter),
            new LogField("reason", "the credential belongs to " + record.CenterUrl));
    }

    private bool TryDeleteKeySets()
    {
        try
        {
            _store.DeleteKeys();
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _options.Log.Warning("cloud.key_sets.delete_failed", new LogField("errorType", exception.GetType().Name));
            return false;
        }
    }

    /// <summary>
    /// Deletes the node key (N1 decision G-1): the recorded one, and by its derived name for the link's center and the configured one, so a
    /// missing or damaged <c>run/node-key.json</c> leaves no key behind. False when a deletion failed (the ending then stays recorded).
    /// </summary>
    private bool TryDeleteKey(CloudLinkFile? link)
    {
        var origins = new HashSet<string>(StringComparer.Ordinal);
        if (link is not null && CenterEndpoint.TryParse(link.CenterUrl, out var linked, out _))
        {
            origins.Add(linked.Origin);
        }

        if (Configured() is { } center)
        {
            origins.Add(center.Origin);
        }

        try
        {
            if (_options.Keys.Delete(_options.NodeId.Span, origins) == NodeKeyDeletion.OtherBackend)
            {
                // Recorded in a key store this run does not use (a --test-mode run over a production data root): reported, kept recorded.
                _options.Log.Warning("cloud.node_key.orphaned", new LogField("backend", _options.Keys.Recorded()?.Backend ?? "unknown"));
            }

            return true;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
        {
            _options.Log.Warning("cloud.node_key.delete_failed", new LogField("errorType", exception.GetType().Name));
            return false;
        }
    }

    private bool FlushPendingWrite()
    {
        if (!_pendingWrite || _record is not { } record || _link is not { } link)
        {
            return false;
        }

        try
        {
            _store.WriteRecord(link.Target, record);
            _pendingWrite = false;
            return RemoveWarning(Warnings.StorageFailed);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
        {
            _options.Log.Warning("cloud.credential_storage_failed", new LogField("errorType", exception.GetType().Name));
            return false;
        }
    }

    private void ReplaceKeySets(CloudCredentialRecord record, IEnumerable<PublicKey> command, IEnumerable<PublicKey> entitlement, DateTimeOffset now)
    {
        _store.WriteKeys(new CloudKeySetFile
        {
            CenterUrl = record.CenterUrl,
            InstallationId = record.InstallationId,
            CommandKeys = Prune(command, now),
            EntitlementKeys = Prune(entitlement, now),
        });
    }

    /// <summary>The set as received, without keys whose <c>not_after</c> lies more than 7 days in the past by the wall clock.</summary>
    internal static List<CloudKeyEntry> Prune(IEnumerable<PublicKey> keys, DateTimeOffset now) =>
    [
        .. keys.Select(key => new CloudKeyEntry
        {
            Kid = key.HasKid ? key.Kid : null,
            Algorithm = key.HasAlgorithm ? key.Algorithm : null,
            Key = key.HasKey ? Convert.ToBase64String(key.Key.Span) : null,
            NotBeforeMs = ProtoTime.ToDateTimeOffset(key.NotBefore)?.ToUnixTimeMilliseconds() ?? 0,
            NotAfterMs = ProtoTime.ToDateTimeOffset(key.NotAfter)?.ToUnixTimeMilliseconds() ?? 0,
        }).Where(key => key.NotAfterMs == 0 || DateTimeOffset.FromUnixTimeMilliseconds(key.NotAfterMs) + KeyPruneAge >= now),
    ];

    /// <summary>
    /// The client of <paramref name="record"/>'s own center (CTR4-SEC-19): built from the URL the record is bound to, and only while that is
    /// the configured center. Otherwise nothing is sent: with <paramref name="strand"/> the credential is held as
    /// <c>credential_for_other_center</c> (<paramref name="stranded"/>), as at start; an unreadable node.json strands nothing.
    /// </summary>
    private CenterClient? BoundClient(CloudCredentialRecord record, bool strand, out bool stranded)
    {
        stranded = false;
        var configured = Configured(out var invalid);
        if (invalid)
        {
            return null;
        }

        if (configured is null || configured.Url != record.CenterUrl || !CenterEndpoint.TryParse(record.CenterUrl, out var bound, out _))
        {
            if (strand)
            {
                StrandOtherCenter(record);
                stranded = true;
            }

            return null;
        }

        if (_http is null || !_http.Center.Equals(bound))
        {
            _http?.Dispose();
            _http = new CenterHttpClient(bound, _options.ConnectLog);
        }

        return new CenterClient(_http, _options.Clock);
    }

    /// <summary>The configured center, or <see langword="null"/> (none, or an invalid node.json, which is logged once per occurrence).</summary>
    private CenterEndpoint? Configured() => Configured(out _);

    private CenterEndpoint? Configured(out bool invalid)
    {
        try
        {
            var center = _options.Center();
            invalid = false;
            Interlocked.Exchange(ref _configurationInvalid, 0);
            return center;
        }
        catch (Exception exception) when (exception is NodeConfigurationException or IOException or UnauthorizedAccessException)
        {
            invalid = true;
            if (Interlocked.Exchange(ref _configurationInvalid, 1) == 0)
            {
                _options.Log.Warning("cloud.center_configuration_invalid", new LogField("errorType", exception.GetType().Name));
            }

            return null;
        }
    }

    private bool HasWarning(string warning)
    {
        lock (_stateLock)
        {
            return _warnings.Contains(warning);
        }
    }

    private WorkScope BeginWork(CancellationToken outer)
    {
        var work = CancellationTokenSource.CreateLinkedTokenSource(outer);
        lock (_stateLock)
        {
            _work = work;
        }

        return new WorkScope(this, work);
    }

    /// <summary>
    /// The center's clock less the node's wall clock, from the last receipt: <c>access_expires_at</c> less the stated lifetime is the center's
    /// time of issue (zero when the lifetime is not stated).
    /// </summary>
    private static TimeSpan CenterOffset(CloudCredentialRecord record, DateTimeOffset wall) =>
        record.AccessExpiresAtMs > 0 && record.AccessLifetimeMs > 0
            ? DateTimeOffset.FromUnixTimeMilliseconds(record.AccessExpiresAtMs - record.AccessLifetimeMs) - wall
            : TimeSpan.Zero;

    /// <summary>The delay to the next refresh: two thirds of the issued lifetime, less up to a tenth of jitter, at least min(60 s, L/2).</summary>
    internal TimeSpan RefreshDelay(CloudCredentialRecord record)
    {
        if (_options.RefreshInterval is { } hook)
        {
            return hook;
        }

        var lifetime = Lifetime(record);
        var floor = RefreshFloor(record);
        var delay = lifetime * 2 / 3 - Jitter(lifetime / 10);
        return delay < floor ? floor : delay > lifetime ? lifetime : delay;
    }

    /// <summary>The shortest wait between two refreshes: min(60 s, L/2).</summary>
    internal static TimeSpan RefreshFloor(CloudCredentialRecord record) =>
        TimeSpan.FromTicks(Math.Min(TimeSpan.FromSeconds(60).Ticks, Lifetime(record).Ticks / 2));

    private static TimeSpan Lifetime(CloudCredentialRecord record) =>
        record.AccessLifetimeMs > 0 ? TimeSpan.FromMilliseconds(record.AccessLifetimeMs) : FallbackAccessLifetime;

    private void Backoff()
    {
        var failures = Math.Min(Interlocked.Increment(ref _failures), 6);
        var ceiling = TimeSpan.FromSeconds(Math.Min(60, 1 << failures));
        var delay = TimeSpan.FromSeconds(1) + Jitter(ceiling - TimeSpan.FromSeconds(1));
        Interlocked.Exchange(ref _nextRefresh, _options.Clock.GetTimestamp() + Ticks(delay));
    }

    /// <summary>
    /// The wait for a center's <c>retry_at</c> (CTR4-SEC-15): converted to the node's clock with the center-time offset measured at the last
    /// receipt, then held within [<paramref name="floor"/>, <paramref name="cap"/>], so a node clock ahead never retries in a loop and one
    /// behind never waits past the limit's window.
    /// </summary>
    private TimeSpan RetryWait(Instant? retryAt, TimeSpan fallback, TimeSpan floor, TimeSpan cap)
    {
        TimeSpan offset;
        lock (_stateLock)
        {
            offset = _centerOffset;
        }

        var wait = ProtoTime.ToDateTimeOffset(retryAt) is { } at ? at - (_options.Clock.GetUtcNow() + offset) : fallback;
        return wait < floor ? floor : wait > cap ? cap : wait;
    }

    private void Contact(bool reached)
    {
        lock (_stateLock)
        {
            _reachable = reached;
            if (reached)
            {
                _lastContact = _options.Clock.GetUtcNow();
            }
        }
    }

    private bool AddWarning(string warning)
    {
        lock (_stateLock)
        {
            return _warnings.Add(warning);
        }
    }

    private bool RemoveWarning(string warning)
    {
        lock (_stateLock)
        {
            return _warnings.Remove(warning);
        }
    }

    private List<string> CurrentWarnings(CenterEndpoint? center)
    {
        var warnings = new List<string>();
        if (_phase == CloudLinkPhase.SignedIn && _link is { } link && link.Protection == nameof(SecretStoreProtection.FileOwnerOnly))
        {
            warnings.Add(Warnings.FilePermissionsOnly);
        }

        if (_options.Secrets.Isolated)
        {
            warnings.Add(Warnings.IsolatedBackend);
        }

        if (center is { ExceedsFleetBase: true })
        {
            warnings.Add(Warnings.CenterUrlTooLong);
        }

        if (_phase == CloudLinkPhase.SignedIn && _record is { FamilyLifetimeMs: > 0, SessionExpiresAtMs: > 0 } record)
        {
            // From the center's values plus the monotonic time since the last receipt, never the wall clock (protocol-15 item 2).
            var lifetime = Lifetime(record);
            var remaining = TimeSpan.FromMilliseconds(record.SessionExpiresAtMs - record.AccessExpiresAtMs) + lifetime
                - _options.Clock.GetElapsedTime(_receipt);
            var threshold = TimeSpan.FromMilliseconds(Math.Min(TimeSpan.FromDays(30).TotalMilliseconds, record.FamilyLifetimeMs / 4.0));
            if (remaining < threshold)
            {
                warnings.Add(Warnings.ExpiresSoon);
            }
        }

        warnings.AddRange(_warnings.Order(StringComparer.Ordinal));
        return warnings;
    }

    private async Task PublishAsync(CloudNotice? notice)
    {
        try
        {
            await _options.Publish(new CloudLinkPublication(Status(), notice)).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
        {
            _options.Log.Warning("cloud.publish.failed", new LogField("errorType", exception.GetType().Name));
        }
    }

    private void Wake() => Volatile.Read(ref _wake).TrySetResult();

    private long Ticks(TimeSpan span) => (long)(span.TotalSeconds * _options.Clock.TimestampFrequency);

    private static TimeSpan Jitter(TimeSpan range) => range <= TimeSpan.Zero ? TimeSpan.Zero : TimeSpan.FromTicks(Random.Shared.NextInt64(range.Ticks + 1));

    /// <summary>A center call in flight under the gate, which a sign-out can cancel (<see cref="EnterForSignOutAsync"/>).</summary>
    private readonly struct WorkScope(CloudLinkService owner, CancellationTokenSource work) : IDisposable
    {
        public CancellationToken Token => work.Token;

        public void Dispose()
        {
            lock (owner._stateLock)
            {
                if (owner._work == work)
                {
                    owner._work = null;
                }
            }

            work.Dispose();
        }
    }

    private sealed class Held(SemaphoreSlim gate) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                gate.Release();
            }
        }
    }

    /// <summary>The closed list of <c>AccountStatus.warnings</c> (AF-CTR-04 N1 d.2).</summary>
    internal static class Warnings
    {
        public const string FilePermissionsOnly = "FILE_PERMISSIONS_ONLY";
        public const string IsolatedBackend = "isolated_test_backend";
        public const string BackendChanged = "credential_backend_changed";
        public const string OtherCenter = "credential_for_other_center";
        public const string OtherNode = "credential_for_other_node";
        public const string StoreUnavailable = "credential_store_unavailable";
        public const string StorageFailed = "credential_storage_failed";
        public const string ClockSkew = "clock_skew";
        public const string ExpiresSoon = "credential_expires_soon";
        public const string Rejected = "center_rejected_credential";
        public const string NotActivated = "center_not_activated";
        public const string ProtocolMismatch = "center_protocol_mismatch";
        public const string InfoRejected = "node_info_rejected";
        public const string Restricted = "account_restricted";
        public const string CenterUrlTooLong = "center_url_too_long";
    }

    /// <summary>The notifications of a credential's end (texts per N1 decision R-4).</summary>
    internal static class Notices
    {
        public static readonly CloudNotice Revoked = new("account_signed_out", "Signed out of the center",
            "The center no longer accepts this node's credential (signed out on the web, replaced by a newer sign-in of this node, or revoked); sign in again.");

        public static readonly CloudNotice Expired = new("account_signed_out", "Signed out of the center",
            "The node credential expired (unused for 90 days or at its absolute end); sign in again.");

        public static readonly CloudNotice ReplyLost = new("account_signed_out", "Signed out of the center",
            "The reply to a credential refresh was lost and the center then refused the credential (refresh_reply_lost: strict rotation); sign in again.");
    }
}
