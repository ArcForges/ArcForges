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

/// <summary>The cloud link's inputs (the host builds them at startup step 8; tests give a temporary data root and a FakeCenter URL).</summary>
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

    /// <summary>The effective center now (node.json, the official default, or the test hook); <see langword="null"/> when there is none.</summary>
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

    /// <summary>The longest a SignOut's remote part may take (account.proto SignOut: 15 s; the rest is the local ending).</summary>
    public static readonly TimeSpan SignOutRemoteBudget = TimeSpan.FromSeconds(12);

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
    private bool _storeUnavailable;
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
    public async Task CenterChangedAsync()
    {
        using (await EnterAsync(CancellationToken.None).ConfigureAwait(false))
        {
            if (Phase != CloudLinkPhase.SignedIn)
            {
                _store.DeleteKeys();
                TryDeleteKey();
                _http?.Dispose();
                _http = null;
                lock (_stateLock)
                {
                    _warnings.Remove(Warnings.OtherCenter);
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
            var center = _options.Center();
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
    /// Adopts credentials a sign-in delivered (part N2's flows; tests seed with it in process): two-phase, <c>run/cloud-link.json</c>
    /// <c>committing</c> first, then the record, the key sets, then <c>signed_in</c>. Takes the gate.
    /// </summary>
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

            changed = await RefreshCoreAsync(cancellationToken).ConfigureAwait(false);
        }

        if (changed)
        {
            await PublishAsync(null).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Signs the node out (AF-CTR-04 CTR4-NODE-11 as amended; N1 decision R-5) while the caller holds the gate (<see cref="EnterAsync"/>):
    /// an in-flight refresh has ended by then (it runs under the same gate). With <paramref name="revokeRemote"/>, SignOutNode with the
    /// current access token, within <see cref="SignOutRemoteBudget"/>; whatever the answer, the local credential, key sets, link file and
    /// node key are deleted (the ending is two-phase, R-1).
    /// </summary>
    public async Task<SignOutResult> SignOutHeldAsync(bool revokeRemote)
    {
        CloudCredentialRecord? record;
        CloudLinkFile? link;
        lock (_stateLock)
        {
            record = _record;
            link = _link;
        }

        if (record is null && link is null && _store.ReadLink() is null)
        {
            return SignOutResult.NotSignedIn;
        }

        var result = !revokeRemote ? SignOutResult.LocalOnly : SignOutResult.RemoteUnconfirmed;
        if (revokeRemote && record is not null && Phase == CloudLinkPhase.SignedIn && Client() is { } client)
        {
            using var budget = new CancellationTokenSource(SignOutRemoteBudget, _options.Clock);
            try
            {
                result = await RemoteSignOutAsync(client, record, budget.Token).ConfigureAwait(false) ? SignOutResult.RemoteConfirmed : SignOutResult.RemoteUnconfirmed;
            }
            catch (OperationCanceledException) when (budget.IsCancellationRequested)
            {
                result = SignOutResult.RemoteUnconfirmed;
            }
        }

        EndCredential("signed_out", notice: null, link ?? _store.ReadLink());
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
                using (await EnterAsync(stop).ConfigureAwait(false))
                {
                    var now = _options.Clock.GetTimestamp();
                    if (_storeUnavailable || (_link?.State == LinkStates.Ending))
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
                        changed |= await RefreshCoreAsync(stop).ConfigureAwait(false);
                    }

                    if (Phase == CloudLinkPhase.SignedIn && now >= Interlocked.Read(ref _nextReport))
                    {
                        changed |= await ReportCoreAsync(stop).ConfigureAwait(false);
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
            if (_storeUnavailable || _pendingWrite)
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

    /// <summary>Loads the stored link (N1 decision R-1 and node-10): nothing is deleted on an absent record or a store failure.</summary>
    private void Load()
    {
        var center = _options.Center();
        CloudLinkFile? link;
        try
        {
            link = _store.ReadLink();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            SetStranded(Warnings.StoreUnavailable, "the link file cannot be read: " + exception.GetType().Name);
            lock (_stateLock)
            {
                _storeUnavailable = true;
            }

            return;
        }

        lock (_stateLock)
        {
            _storeUnavailable = false;
            _link = link;
            _record = null;
            _phase = CloudLinkPhase.SignedOut;
            _warnings.Remove(Warnings.StoreUnavailable);
            _warnings.Remove(Warnings.BackendChanged);
            _warnings.Remove(Warnings.OtherCenter);
            _warnings.Remove(Warnings.OtherNode);
        }

        if (link is null)
        {
            // Key sets without a link belong to no credential.
            _store.DeleteKeys();
            return;
        }

        if (link.State == LinkStates.Ending)
        {
            EndCredential(LastError ?? "signed_out", notice: null, link);
            return;
        }

        if (link.NodeId != _nodeHex)
        {
            SetStranded(Warnings.OtherNode, "the link file belongs to another node ID");
            return;
        }

        if (link.Backend != _options.Secrets.Backend.ToString() || link.Isolated != _options.Secrets.Isolated)
        {
            SetStranded(Warnings.BackendChanged, "the credential is in another secret-store backend (" + link.Backend + ")");
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
                _storeUnavailable = true;
            }

            return;
        }

        if (record is null)
        {
            SetStranded(Warnings.BackendChanged, "the selected secret store holds no credential for the link file");
            return;
        }

        if (record.NodeId != _nodeHex)
        {
            SetStranded(Warnings.OtherNode, "the credential belongs to another node ID");
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

        if (record is null || Client() is not { } client)
        {
            return false;
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
                ScheduleAt(reply.Error.Retry?.RetryAt, TimeSpan.FromSeconds(30));
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
                Contact(false);
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

        if (record is null || _link is not { } link || Client() is not { } client)
        {
            return false;
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
                var retry = ProtoTime.ToDateTimeOffset(reply.Error.Retry?.RetryAt) is { } at ? at - _options.Clock.GetUtcNow() : TimeSpan.FromMinutes(5);
                Interlocked.Exchange(ref _nextReport, _options.Clock.GetTimestamp() + Ticks(retry < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : retry));
                return false;
            default:
                // Unreachable or unknown: the same command ID later (a committed report replays its receipt).
                Interlocked.Exchange(ref _nextReport, _options.Clock.GetTimestamp() + Ticks(TimeSpan.FromMinutes(1) + Jitter(TimeSpan.FromMinutes(1))));
                Contact(reply.Outcome != CenterOutcome.Unreachable);
                return false;
        }
    }

    /// <summary>Ends the credential, two-phase (N1 decision R-1): <c>ending</c> first, then record, key sets, node key, link file.</summary>
    private void EndCredential(string reason, CloudNotice? notice, CloudLinkFile? link)
    {
        if (link is not null && link.State != LinkStates.Ending)
        {
            link.State = LinkStates.Ending;
            _store.WriteLink(link);
        }

        var finished = true;
        if (link is not null)
        {
            try
            {
                _store.DeleteRecord(link.Target);
            }
            catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
            {
                // The ending stays recorded; the loop and the next start finish it.
                finished = false;
                _options.Log.Warning("cloud.ending.record_delete_failed", new LogField("errorType", exception.GetType().Name));
            }
        }

        if (finished)
        {
            _store.DeleteKeys();
            TryDeleteKey();
            _store.DeleteLink();
        }

        lock (_stateLock)
        {
            _phase = CloudLinkPhase.SignedOut;
            _record = null;
            _rejectedRecord = null;
            _rejected = false;
            _pendingWrite = false;
            _ambiguousToken = null;
            _link = finished ? null : link;
            _storeUnavailable = !finished;
            _lastError = reason;
            _warnings.Clear();
            _notice = notice;
            _nextRefresh = long.MaxValue;
            _nextReport = long.MaxValue;
        }

        _options.Log.Info("cloud.credential_ended", new LogField("reason", reason), new LogField("finished", finished));
    }

    private void TryDeleteKey()
    {
        try
        {
            _options.Keys.Delete();
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not OperationCanceledException)
        {
            _options.Log.Warning("cloud.node_key.delete_failed", new LogField("errorType", exception.GetType().Name));
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

    private CenterClient? Client()
    {
        var center = _options.Center();
        if (center is null)
        {
            return null;
        }

        if (_http is null || !_http.Center.Equals(center))
        {
            _http?.Dispose();
            _http = new CenterHttpClient(center, _options.ConnectLog);
        }

        return new CenterClient(_http, _options.Clock);
    }

    /// <summary>The delay to the next refresh: two thirds of the issued lifetime, less up to a tenth of jitter, at least min(60 s, L/2).</summary>
    internal TimeSpan RefreshDelay(CloudCredentialRecord record)
    {
        if (_options.RefreshInterval is { } hook)
        {
            return hook;
        }

        var lifetime = Lifetime(record);
        var floor = TimeSpan.FromTicks(Math.Min(TimeSpan.FromSeconds(60).Ticks, lifetime.Ticks / 2));
        var delay = lifetime * 2 / 3 - Jitter(lifetime / 10);
        return delay < floor ? floor : delay > lifetime ? lifetime : delay;
    }

    private static TimeSpan Lifetime(CloudCredentialRecord record) =>
        record.AccessLifetimeMs > 0 ? TimeSpan.FromMilliseconds(record.AccessLifetimeMs) : FallbackAccessLifetime;

    private void Backoff()
    {
        var failures = Math.Min(Interlocked.Increment(ref _failures), 6);
        var ceiling = TimeSpan.FromSeconds(Math.Min(60, 1 << failures));
        var delay = TimeSpan.FromSeconds(1) + Jitter(ceiling - TimeSpan.FromSeconds(1));
        Interlocked.Exchange(ref _nextRefresh, _options.Clock.GetTimestamp() + Ticks(delay));
    }

    private void ScheduleAt(Instant? retryAt, TimeSpan fallback)
    {
        var wait = ProtoTime.ToDateTimeOffset(retryAt) is { } at ? at - _options.Clock.GetUtcNow() : fallback;
        if (wait < TimeSpan.FromSeconds(1))
        {
            wait = TimeSpan.FromSeconds(1);
        }

        Interlocked.Exchange(ref _nextRefresh, _options.Clock.GetTimestamp() + Ticks(wait + Jitter(TimeSpan.FromSeconds(2))));
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
