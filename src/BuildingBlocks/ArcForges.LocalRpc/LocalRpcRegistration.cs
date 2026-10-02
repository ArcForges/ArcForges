// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.LocalRpc;

/// <summary>
/// Why a registration step or a call was refused. These values are for the parent's own diagnostics: the peer is never told
/// which one applied (it sees one UNAUTHENTICATED answer), so a refusal reveals nothing about the launch secret, nonce or state.
/// </summary>
public enum LocalRpcRegistrationRefusal
{
    /// <summary>Accepted.</summary>
    None = 0,

    /// <summary>The registration is over (proof rejected, lease expired, connection lost, launch superseded or revoked, disposed). It is never revived.</summary>
    Ended,

    /// <summary>A bootstrap step arrived when the registration no longer awaits one (a confirmation is running, or the child registered).</summary>
    NotAwaitingBootstrap,

    /// <summary>The launch does not authorize any more (revoked, superseded, expired, parent or child process gone).</summary>
    LaunchRefused,

    /// <summary>The child kind, build or protocol it claims differs from the launch.</summary>
    IdentityMismatch,

    /// <summary>The request is malformed: a challenge or command id of the wrong size, an empty instance id.</summary>
    InvalidRequest,

    /// <summary>No live challenge was issued to this connection under this id (never issued, issued to another connection, or already used).</summary>
    NoChallenge,

    /// <summary>The challenge was older than its five-second lifetime.</summary>
    ChallengeExpired,

    /// <summary>The proof did not match. The launch is revoked.</summary>
    ProofRejected,

    /// <summary>The child has not registered.</summary>
    NotRegistered,

    /// <summary>The call arrived on another connection than the one that registered.</summary>
    WrongConnection,

    /// <summary>The presented peer nonce, caller instance or contract-set digest is not the registered one.</summary>
    BadCredentials,

    /// <summary>The 30-second lease passed without a renewal.</summary>
    LeaseExpired,
}

/// <summary>Where a registration is in its life. <see cref="Ended"/> is final.</summary>
public enum LocalRpcRegistrationState
{
    /// <summary>The launch exists and the child has not registered; only the two bootstrap steps are served.</summary>
    AwaitingBootstrap = 0,

    /// <summary>The child proved the launch secret; calls are served while the lease holds.</summary>
    Registered = 1,

    /// <summary>The registration is over; see <see cref="LocalRpcRegistration.EndReason"/>.</summary>
    Ended = 2,
}

/// <summary>Why a registration ended.</summary>
public enum LocalRpcRegistrationEnd
{
    /// <summary>It has not ended.</summary>
    None = 0,

    /// <summary>The child's confirmation proof did not match; the launch was revoked.</summary>
    ProofRejected,

    /// <summary>The lease passed without a renewal; the launch was revoked.</summary>
    LeaseExpired,

    /// <summary>The registered connection closed; the launch was revoked. A broken stream relaunches under a new epoch.</summary>
    ConnectionLost,

    /// <summary>The launch was superseded by a newer epoch, revoked or disposed, its bootstrap window passed, or its parent or child process ended.</summary>
    LaunchEnded,

    /// <summary>The registration was disposed.</summary>
    Disposed,
}

/// <summary>What the parent sends back for a challenge: ids, 32 random bytes, a lifetime of at most five seconds and its own instance id.</summary>
public sealed record LocalRpcBootstrapChallenge(Guid ChallengeId, ReadOnlyMemory<byte> ServerChallenge, Guid ServerInstanceId, DateTimeOffset ExpiresAtUtc);

/// <summary>What the parent grants after a proven confirmation: a random 32-byte peer nonce valid for the lease.</summary>
public sealed record LocalRpcRegistrationGrant(ReadOnlyMemory<byte> PeerNonce, DateTimeOffset ExpiresAtUtc);

/// <summary>Replaceable timings of a registration; only offline fixtures replace anything.</summary>
internal sealed record RegistrationTimings
{
    internal TimeSpan Lease { get; init; } = LocalRpcRegistration.LeaseDuration;

    internal TimeSpan Challenge { get; init; } = LocalRpcRegistration.ChallengeLifetime;
}

/// <summary>
/// The parent's side of one child's LocalBootstrap registration (WP-08.02). It lives on one launch and one connection:
/// <list type="bullet">
/// <item>The child asks for a challenge (at most five seconds of life), then proves possession of the launch's one-use secret with an
/// HMAC over the transcript. The secret is consumed by the first confirmation attempt that holds a live challenge on its
/// connection. A proof that does not match revokes the launch (the child must be relaunched under a new epoch).</item>
/// <item>A proven confirmation grants a random 32-byte peer nonce and a 30-second lease. Every later call must present the nonce,
/// the registered caller instance and the contract-set digest on the registered connection while the lease holds and the launch
/// authorizes. A renewal (every 10 seconds) extends the lease to 30 seconds from the renewal; nothing else extends it.</item>
/// <item>The registration ends, for good, when the lease passes, the connection closes, the launch is superseded or revoked,
/// the proof is rejected or it is disposed. It revokes the launch when it ends, so an ended child can never be revived or regranted.</item>
/// </list>
/// A relaunch (<see cref="LocalRpcLaunchAuthority.Launch"/>) is a new epoch with a new secret and a new registration: nothing is inherited.
/// The type contains no contract: the generated LocalBootstrap service implementation is the owner's, and the call gate
/// (<see cref="LocalRpcServerBuilder.RequireRegistration"/>) hands it a <see cref="LocalRpcBootstrapCall"/> for every bootstrap call.
/// </summary>
public sealed class LocalRpcRegistration : IAsyncDisposable
{
    /// <summary>Length of the client and server challenge bytes, and of the confirmation proof.</summary>
    public const int ChallengeLength = 32;

    /// <summary>Length of the peer nonce the parent grants.</summary>
    public const int NonceLength = 32;

    /// <summary>Longest renewal command id.</summary>
    public const int MaximumCommandIdLength = 32;

    /// <summary>The generated Platform service the bootstrap steps belong to.</summary>
    public const string BootstrapService = "arcforges.local.platform.v1.LocalBootstrapService";

    /// <summary>gRPC path of the Challenge step: served before registration without credentials.</summary>
    public const string ChallengePath = "/" + BootstrapService + "/Challenge";

    /// <summary>gRPC path of the Confirm step: served before registration without credentials.</summary>
    public const string ConfirmPath = "/" + BootstrapService + "/Confirm";

    /// <summary>gRPC path of the Renew step: served like an ordinary call, with credentials, while the lease holds.</summary>
    public const string RenewPath = "/" + BootstrapService + "/Renew";

    /// <summary>The lease a registration and each renewal grant: 30 seconds.</summary>
    public static readonly TimeSpan LeaseDuration = TimeSpan.FromSeconds(30);

    /// <summary>How often a child renews: 10 seconds.</summary>
    public static readonly TimeSpan RenewInterval = TimeSpan.FromSeconds(10);

    /// <summary>How long a challenge lives: five seconds.</summary>
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromSeconds(5);

    /// <summary>Renewal command ids remembered so that a duplicate returns its recorded expiry instead of extending again.</summary>
    internal const int RememberedRenewals = 16;

    /// <summary>Most challenges pending at once: one per connection, and a server serves at most 64 connections.</summary>
    internal const int MaximumPendingChallenges = 64;

    private readonly LocalRpcLaunch _launch;
    private readonly TimeProvider _clock;
    private readonly RegistrationTimings _timings;
    private readonly object _gate = new();
    private readonly CancellationTokenSource _ended = new();
    private readonly CancellationToken _endedToken;
    private readonly Dictionary<string, PendingChallenge> _pending = new(StringComparer.Ordinal);
    private readonly Queue<(byte[] CommandId, DateTimeOffset Expiry)> _renewals = new();
    private readonly CancellationTokenRegistration _launchRevocation;
    private LocalRpcRegistrationState _state;
    private LocalRpcRegistrationEnd _endReason;
    private bool _confirming;
    private Registered? _registered;
    private ITimer? _watchdog;
    private CancellationTokenRegistration _connectionHook;
    private int _bound;
    private int _disposed;

    private LocalRpcRegistration(LocalRpcLaunch launch, RegistrationTimings timings)
    {
        _launch = launch;
        _clock = launch.Clock;
        _timings = timings;
        _endedToken = _ended.Token;
        ParentInstanceId = Guid.NewGuid();
        _launchRevocation = launch.Revoked.Register(static state => ((LocalRpcRegistration)state!).End(LocalRpcRegistrationEnd.LaunchEnded), this);
    }

    /// <summary>The launch this registration serves.</summary>
    public LocalRpcLaunch Launch => _launch;

    /// <summary>The parent's instance id for this registration, sent in the challenge response and bound into the proof.</summary>
    public Guid ParentInstanceId { get; }

    /// <summary>Cancelled when the registration ends; the owner stops the server and the child process then.</summary>
    public CancellationToken Ended => _endedToken;

    /// <summary>Where the registration is.</summary>
    public LocalRpcRegistrationState State
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    /// <summary>Why the registration ended, or <see cref="LocalRpcRegistrationEnd.None"/>.</summary>
    public LocalRpcRegistrationEnd EndReason
    {
        get
        {
            lock (_gate)
            {
                return _endReason;
            }
        }
    }

    /// <summary>Creates the registration of one launch. The launch is revoked when the registration ends.</summary>
    public static LocalRpcRegistration Create(LocalRpcLaunch launch)
    {
        ArgumentNullException.ThrowIfNull(launch);
        return new LocalRpcRegistration(launch, new RegistrationTimings());
    }

    internal static LocalRpcRegistration Create(LocalRpcLaunch launch, RegistrationTimings timings) => new(launch, timings);

    /// <summary>
    /// The connection decision for a server serving this registration: a connection is admitted only while the child has not
    /// registered, the launch authorizes and the connection arrived on the launch's own endpoint. A registered child has its one
    /// connection; a second connection is never admitted.
    /// </summary>
    public ValueTask<bool> AuthorizeConnectionAsync(LocalRpcConnectionInfo connection, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        lock (_gate)
        {
            if (_state != LocalRpcRegistrationState.AwaitingBootstrap)
            {
                return ValueTask.FromResult(false);
            }
        }

        return _launch.AuthorizeConnectionAsync(connection, cancellationToken);
    }

    /// <summary>Marks the registration as served by one server; a registration serves one server because connection ids are per server.</summary>
    internal void BindToServer()
    {
        if (Interlocked.Exchange(ref _bound, 1) != 0)
        {
            throw new InvalidOperationException("A registration serves one server.");
        }
    }

    internal bool AdmitsBootstrapCalls
    {
        get
        {
            lock (_gate)
            {
                return _state == LocalRpcRegistrationState.AwaitingBootstrap && !_confirming;
            }
        }
    }

    /// <summary>True when a grant was made and its nonce is all zero (after the registration ended).</summary>
    internal bool GrantedNonceIsZeroed()
    {
        lock (_gate)
        {
            return _registered is { } registered && registered.Nonce.All(value => value == 0);
        }
    }

    /// <summary>How many challenges and remembered renewal commands the registration still holds.</summary>
    internal (int Challenges, int Renewals) HeldState()
    {
        lock (_gate)
        {
            return (_pending.Count, _renewals.Count);
        }
    }

    /// <summary>The registered connection's lease expiry as reported to the child, or null when there is no live lease.</summary>
    internal DateTimeOffset? LeaseExpiresAtUtc
    {
        get
        {
            lock (_gate)
            {
                return _registered?.Lease.WallDeadline;
            }
        }
    }

    /// <summary>Issues a challenge to a connection, replacing any it still holds.</summary>
    internal LocalRpcRegistrationRefusal TryChallenge(
        string connectionId,
        Guid callerInstance,
        ReadOnlySpan<byte> clientChallenge,
        LocalRpcLaunchIdentity claimed,
        out LocalRpcBootstrapChallenge? challenge)
    {
        ArgumentException.ThrowIfNullOrEmpty(connectionId);
        ArgumentNullException.ThrowIfNull(claimed);
        challenge = null;
        LocalRpcRegistrationRefusal refusal;
        var endWith = LocalRpcRegistrationEnd.None;
        lock (_gate)
        {
            refusal = AdmitBootstrapLocked();
            if (refusal != LocalRpcRegistrationRefusal.None)
            {
                return refusal;
            }

            if (clientChallenge.Length != ChallengeLength || callerInstance == Guid.Empty)
            {
                return LocalRpcRegistrationRefusal.InvalidRequest;
            }

            var descriptor = _launch.Descriptor;
            var verdict = _launch.Verify(new LocalRpcLaunchClaim(descriptor.LaunchId, descriptor.Slot, descriptor.Epoch, descriptor.Nonce.Span, claimed));
            if (verdict is LocalRpcLaunchRefusal.BuildMismatch or LocalRpcLaunchRefusal.ProtocolMismatch)
            {
                return LocalRpcRegistrationRefusal.IdentityMismatch;
            }

            if (verdict != LocalRpcLaunchRefusal.None)
            {
                // The launch itself is over (revoked, expired, parent or child gone): so is its registration.
                endWith = LocalRpcRegistrationEnd.LaunchEnded;
                refusal = LocalRpcRegistrationRefusal.LaunchRefused;
            }
            else
            {
                PruneExpiredChallengesLocked();
                if (_pending.Count >= MaximumPendingChallenges && !_pending.ContainsKey(connectionId))
                {
                    return LocalRpcRegistrationRefusal.InvalidRequest;
                }

                var issued = new PendingChallenge(
                    Guid.NewGuid(),
                    clientChallenge.ToArray(),
                    RandomNumberGenerator.GetBytes(ChallengeLength),
                    callerInstance,
                    Deadline.Begin(_clock, _timings.Challenge));
                _pending[connectionId] = issued;
                challenge = new LocalRpcBootstrapChallenge(issued.Id, issued.ServerBytes.ToArray(), ParentInstanceId, issued.Lifetime.WallDeadline);
            }
        }

        if (endWith != LocalRpcRegistrationEnd.None)
        {
            End(endWith);
        }

        return refusal;
    }

    /// <summary>
    /// Confirms a challenge with a proof. The first confirmation that holds a live challenge on its connection consumes the launch
    /// secret whatever the proof; a proof that does not match revokes the launch.
    /// </summary>
    internal LocalRpcRegistrationRefusal TryConfirm(
        string connectionId,
        Guid challengeId,
        ReadOnlySpan<byte> proof,
        CancellationToken connectionClosed,
        out LocalRpcRegistrationGrant? grant)
    {
        ArgumentException.ThrowIfNullOrEmpty(connectionId);
        grant = null;
        PendingChallenge pending;
        lock (_gate)
        {
            var admit = AdmitBootstrapLocked();
            if (admit != LocalRpcRegistrationRefusal.None)
            {
                return admit;
            }

            if (!_pending.TryGetValue(connectionId, out var found) || found.Id != challengeId)
            {
                return LocalRpcRegistrationRefusal.NoChallenge;
            }

            // A challenge is used once: whatever happens next, it cannot be confirmed again.
            _ = _pending.Remove(connectionId);
            if (found.Lifetime.Passed(_clock))
            {
                return LocalRpcRegistrationRefusal.ChallengeExpired;
            }

            pending = found;
            _confirming = true;
        }

        // Only a copy of a proof of any size is needed: a longer one cannot match and is bounded here.
        var presented = proof.Length <= LocalBootstrapProof.Length + 1 ? proof.ToArray() : new byte[LocalBootstrapProof.Length + 1];
        var accepted = false;
        var consumed = true;
        try
        {
            accepted = _launch.ConsumeSecret(
                (Pending: pending, Presented: presented, Parent: ParentInstanceId),
                static (state, secret) => LocalBootstrapProof.Matches(
                    secret, state.Pending.Id, state.Pending.ClientBytes, state.Pending.ServerBytes, state.Pending.CallerInstance, state.Parent, state.Presented));
        }
        catch (InvalidOperationException)
        {
            // The launch no longer authorizes (or its secret is gone): nothing can register on it.
            consumed = false;
        }

        var endWith = LocalRpcRegistrationEnd.None;
        LocalRpcRegistrationRefusal refusal;
        lock (_gate)
        {
            _confirming = false;
            if (_state == LocalRpcRegistrationState.Ended)
            {
                return LocalRpcRegistrationRefusal.Ended;
            }

            if (!consumed)
            {
                endWith = LocalRpcRegistrationEnd.LaunchEnded;
                refusal = LocalRpcRegistrationRefusal.LaunchRefused;
            }
            else if (!accepted)
            {
                endWith = LocalRpcRegistrationEnd.ProofRejected;
                refusal = LocalRpcRegistrationRefusal.ProofRejected;
            }
            else
            {
                var registered = new Registered(
                    connectionId,
                    pending.CallerInstance,
                    RandomNumberGenerator.GetBytes(NonceLength),
                    Deadline.Begin(_clock, _timings.Lease));
                _registered = registered;
                _state = LocalRpcRegistrationState.Registered;
                // Challenges other connections still hold can never be confirmed now.
                _pending.Clear();
                _watchdog = _clock.CreateTimer(static state => ((LocalRpcRegistration)state!).OnWatchdog(), this, registered.Lease.Remaining(_clock), Timeout.InfiniteTimeSpan);
                grant = new LocalRpcRegistrationGrant(registered.Nonce.ToArray(), registered.Lease.WallDeadline);
                refusal = LocalRpcRegistrationRefusal.None;
            }
        }

        if (endWith != LocalRpcRegistrationEnd.None)
        {
            End(endWith);
            return refusal;
        }

        WatchConnection(connectionId, connectionClosed);
        return refusal;
    }

    /// <summary>
    /// Verifies the credentials of one call: the registration must be live, on the registered connection, within its lease, and the
    /// call must carry the granted nonce, the registered caller instance and the launch's contract-set digest.
    /// </summary>
    internal LocalRpcRegistrationRefusal Authorize(string connectionId, ReadOnlySpan<byte> peerNonce, Guid callerInstance, ReadOnlySpan<byte> contractSet)
    {
        LocalRpcRegistrationRefusal refusal;
        var endWith = LocalRpcRegistrationEnd.None;
        lock (_gate)
        {
            refusal = LiveLocked(connectionId, out endWith);
            if (refusal == LocalRpcRegistrationRefusal.None)
            {
                var registered = _registered!;
                var nonceMatches = CryptographicOperations.FixedTimeEquals(peerNonce, registered.Nonce);
                var instanceMatches = callerInstance == registered.CallerInstance;
                var contractMatches = CryptographicOperations.FixedTimeEquals(contractSet, _launch.Descriptor.Identity.ContractSetDigest.Span);
                if (!(nonceMatches & instanceMatches & contractMatches))
                {
                    refusal = LocalRpcRegistrationRefusal.BadCredentials;
                }
            }
        }

        if (endWith != LocalRpcRegistrationEnd.None)
        {
            End(endWith);
        }

        return refusal;
    }

    /// <summary>
    /// Renews the lease to 30 seconds from now. The caller is the gate, which has already verified the credentials of this call. A command
    /// id seen before returns its recorded expiry without extending again; an ended or expired registration is never renewed.
    /// </summary>
    internal LocalRpcRegistrationRefusal TryRenew(string connectionId, ReadOnlySpan<byte> commandId, out DateTimeOffset expiresAtUtc)
    {
        expiresAtUtc = default;
        LocalRpcRegistrationRefusal refusal;
        var endWith = LocalRpcRegistrationEnd.None;
        lock (_gate)
        {
            refusal = LiveLocked(connectionId, out endWith);
            if (refusal == LocalRpcRegistrationRefusal.None)
            {
                if (commandId.Length is 0 or > MaximumCommandIdLength)
                {
                    return LocalRpcRegistrationRefusal.InvalidRequest;
                }

                foreach (var (known, expiry) in _renewals)
                {
                    if (commandId.SequenceEqual(known))
                    {
                        expiresAtUtc = expiry;
                        return LocalRpcRegistrationRefusal.None;
                    }
                }

                var registered = _registered!;
                var extended = Deadline.Begin(_clock, _timings.Lease);
                registered.Lease = extended.NotBefore(registered.Lease);
                _watchdog?.Change(registered.Lease.Remaining(_clock), Timeout.InfiniteTimeSpan);
                while (_renewals.Count >= RememberedRenewals)
                {
                    _ = _renewals.Dequeue();
                }

                _renewals.Enqueue((commandId.ToArray(), registered.Lease.WallDeadline));
                expiresAtUtc = registered.Lease.WallDeadline;
            }
        }

        if (endWith != LocalRpcRegistrationEnd.None)
        {
            End(endWith);
        }

        return refusal;
    }

    /// <summary>Tells the registration that a connection closed: a challenge pending on it is dropped and the registered connection ends the registration.</summary>
    internal void NotifyConnectionClosed(string connectionId)
    {
        var endNow = false;
        lock (_gate)
        {
            _ = _pending.Remove(connectionId);
            endNow = _state == LocalRpcRegistrationState.Registered
                && string.Equals(_registered!.ConnectionId, connectionId, StringComparison.Ordinal);
        }

        if (endNow)
        {
            End(LocalRpcRegistrationEnd.ConnectionLost);
        }
    }

    /// <summary>Ends the registration and revokes its launch. Idempotent; nothing is revived afterwards.</summary>
    public async ValueTask DisposeAsync()
    {
        End(LocalRpcRegistrationEnd.Disposed);
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            CancellationTokenRegistration hook;
            lock (_gate)
            {
                hook = _connectionHook;
                _connectionHook = default;
            }

            await hook.DisposeAsync().ConfigureAwait(false);
            await _launchRevocation.DisposeAsync().ConfigureAwait(false);
            _ended.Dispose();
        }
    }

    private LocalRpcRegistrationRefusal AdmitBootstrapLocked()
    {
        if (_state == LocalRpcRegistrationState.Ended)
        {
            return LocalRpcRegistrationRefusal.Ended;
        }

        return _state != LocalRpcRegistrationState.AwaitingBootstrap || _confirming
            ? LocalRpcRegistrationRefusal.NotAwaitingBootstrap
            : LocalRpcRegistrationRefusal.None;
    }

    /// <summary>The registration is registered, its launch authorizes, the connection is the registered one and the lease holds.</summary>
    private LocalRpcRegistrationRefusal LiveLocked(string connectionId, out LocalRpcRegistrationEnd endWith)
    {
        endWith = LocalRpcRegistrationEnd.None;
        if (_state == LocalRpcRegistrationState.Ended)
        {
            return LocalRpcRegistrationRefusal.Ended;
        }

        if (_state != LocalRpcRegistrationState.Registered)
        {
            return LocalRpcRegistrationRefusal.NotRegistered;
        }

        if (_launch.Status() != LocalRpcLaunchRefusal.None)
        {
            endWith = LocalRpcRegistrationEnd.LaunchEnded;
            return LocalRpcRegistrationRefusal.LaunchRefused;
        }

        var registered = _registered!;
        if (registered.Lease.Passed(_clock))
        {
            endWith = LocalRpcRegistrationEnd.LeaseExpired;
            return LocalRpcRegistrationRefusal.LeaseExpired;
        }

        return string.Equals(registered.ConnectionId, connectionId, StringComparison.Ordinal)
            ? LocalRpcRegistrationRefusal.None
            : LocalRpcRegistrationRefusal.WrongConnection;
    }

    private void PruneExpiredChallengesLocked()
    {
        List<string>? expired = null;
        foreach (var (connection, challenge) in _pending)
        {
            if (challenge.Lifetime.Passed(_clock))
            {
                (expired ??= []).Add(connection);
            }
        }

        if (expired is not null)
        {
            foreach (var connection in expired)
            {
                _ = _pending.Remove(connection);
            }
        }
    }

    /// <summary>Hooks the registered connection's closing to the registration; an already closed connection ends it at once.</summary>
    private void WatchConnection(string connectionId, CancellationToken connectionClosed)
    {
        if (!connectionClosed.CanBeCanceled)
        {
            return;
        }

        var hook = connectionClosed.Register(
            static state =>
            {
                var (registration, id) = ((LocalRpcRegistration, string))state!;
                registration.NotifyConnectionClosed(id);
            },
            (this, connectionId));
        var keep = false;
        lock (_gate)
        {
            if (_state == LocalRpcRegistrationState.Registered && Volatile.Read(ref _disposed) == 0)
            {
                _connectionHook = hook;
                keep = true;
            }
        }

        if (!keep)
        {
            hook.Dispose();
        }
    }

    /// <summary>Re-evaluates the lease when the watchdog timer fires; a timer that fires early re-arms for the remainder.</summary>
    private void OnWatchdog()
    {
        var endNow = false;
        lock (_gate)
        {
            if (_state != LocalRpcRegistrationState.Registered)
            {
                return;
            }

            var registered = _registered!;
            if (registered.Lease.Passed(_clock))
            {
                endNow = true;
            }
            else
            {
                _watchdog?.Change(registered.Lease.Remaining(_clock), Timeout.InfiniteTimeSpan);
            }
        }

        if (endNow)
        {
            End(LocalRpcRegistrationEnd.LeaseExpired);
        }
    }

    /// <summary>Latches the end, destroys the grant and revokes the launch. The owner's callbacks run outside the lock.</summary>
    private void End(LocalRpcRegistrationEnd reason)
    {
        ITimer? watchdog;
        lock (_gate)
        {
            if (_state == LocalRpcRegistrationState.Ended)
            {
                return;
            }

            _state = LocalRpcRegistrationState.Ended;
            _endReason = reason;
            _pending.Clear();
            _renewals.Clear();
            if (_registered is { } registered)
            {
                CryptographicOperations.ZeroMemory(registered.Nonce);
            }

            watchdog = _watchdog;
            _watchdog = null;
        }

        watchdog?.Dispose();
        _launch.Revoke();
        try
        {
            _ended.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Disposed concurrently: already ended.
        }
        catch (AggregateException)
        {
            // An Ended callback threw. The registration is over either way and the failure must not reach the code that ended it.
        }
    }

    /// <summary>A lifetime measured on the monotonic clock and on the wall clock: it passes on whichever gets there first.</summary>
    private readonly record struct Deadline(long StartTimestamp, TimeSpan Span, DateTimeOffset WallDeadline)
    {
        internal static Deadline Begin(TimeProvider clock, TimeSpan span) => new(clock.GetTimestamp(), span, clock.GetUtcNow() + span);

        internal bool Passed(TimeProvider clock) => clock.GetElapsedTime(StartTimestamp) >= Span || clock.GetUtcNow() >= WallDeadline;

        internal TimeSpan Remaining(TimeProvider clock)
        {
            var remaining = Span - clock.GetElapsedTime(StartTimestamp);
            var wall = WallDeadline - clock.GetUtcNow();
            var least = remaining < wall ? remaining : wall;
            return least < TimeSpan.Zero ? TimeSpan.Zero : least;
        }

        /// <summary>This deadline, except that the wall-clock deadline never moves earlier than <paramref name="previous"/>'s (a wall clock stepped back must not shorten a renewal).</summary>
        internal Deadline NotBefore(Deadline previous) =>
            WallDeadline >= previous.WallDeadline ? this : this with { WallDeadline = previous.WallDeadline };
    }

    private sealed record PendingChallenge(Guid Id, byte[] ClientBytes, byte[] ServerBytes, Guid CallerInstance, Deadline Lifetime);

    private sealed class Registered(string connectionId, Guid callerInstance, byte[] nonce, Deadline lease)
    {
        internal string ConnectionId { get; } = connectionId;

        internal Guid CallerInstance { get; } = callerInstance;

        internal byte[] Nonce { get; } = nonce;

        internal Deadline Lease { get; set; } = lease;
    }
}
