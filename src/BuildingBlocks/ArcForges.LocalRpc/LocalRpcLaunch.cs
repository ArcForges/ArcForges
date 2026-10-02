// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.LocalRpc;

/// <summary>Whether a launch listens on a private endpoint or the launcher supplies already-connected streams.</summary>
public enum LocalRpcLaunchTransport
{
    /// <summary>The launcher hands already-connected OS streams to the server; no endpoint and no file exists.</summary>
    SuppliedStreams = 0,

    /// <summary>A private per-launch endpoint: a Named Pipe with an unguessable name on Windows, or a socket inside an owner-only launch directory elsewhere.</summary>
    PrivateEndpoint = 1,
}

/// <summary>Runs over the one-use launch secret. The span is valid only during the call.</summary>
public delegate TResult LocalRpcSecretUse<in TState, out TResult>(TState state, ReadOnlySpan<byte> secret);

/// <summary>Replaceable environment of an authority; only offline fixtures replace anything.</summary>
internal sealed record LaunchEnvironment
{
    internal TimeProvider Clock { get; init; } = TimeProvider.System;

    internal Func<LocalRpcProcessIdentity, ProcessLiveness> Probe { get; init; } = ProcessProbe.Probe;

    internal LocalRpcProcessIdentity Parent { get; init; } = LocalRpcProcessIdentity.Current;

    /// <summary>Uses a Unix socket launch directory even on Windows (the same verification route as the transport tests).</summary>
    internal bool ForceUnixSocket { get; init; }

    /// <summary>How long a launch directory without a readable record is left alone before it counts as abandoned.</summary>
    internal TimeSpan AbandonedGrace { get; init; } = TimeSpan.FromSeconds(60);
}

/// <summary>
/// The parent's registry of launches. Each slot (one logical child) has strictly increasing epochs; launching a slot
/// again revokes the launch before it, so an older descriptor can never authorize a child. The authority creates
/// the per-launch endpoint, fixes its descriptor and verifies every claim against its own copy.
/// </summary>
public sealed class LocalRpcLaunchAuthority : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<string, SlotState> _slots = new(StringComparer.Ordinal);
    private readonly HashSet<LocalRpcLaunch> _issued = [];
    private readonly LaunchEnvironment _environment;
    private readonly string _root;
    private readonly TimeSpan _bootstrapWindow;
    private bool _disposed;

    private LocalRpcLaunchAuthority(string root, TimeSpan bootstrapWindow, LaunchEnvironment environment)
    {
        _root = root;
        _bootstrapWindow = bootstrapWindow;
        _environment = environment;
    }

    /// <summary>
    /// Creates an authority whose launch directories live under <paramref name="runtimeRoot"/>, a canonical absolute path
    /// whose parent exists. The root is created owner-only or verified to be, and launches abandoned by dead parents are swept.
    /// </summary>
    public static LocalRpcLaunchAuthority Create(string runtimeRoot, TimeSpan? bootstrapWindow = null) =>
        Create(runtimeRoot, bootstrapWindow, new LaunchEnvironment());

    internal static LocalRpcLaunchAuthority Create(string runtimeRoot, TimeSpan? bootstrapWindow, LaunchEnvironment environment)
    {
        var window = bootstrapWindow ?? TimeSpan.FromSeconds(30);
        if (window < TimeSpan.FromSeconds(1) || window > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(bootstrapWindow), window, "The bootstrap window is one second through five minutes.");
        }

        var authority = new LocalRpcLaunchAuthority(LaunchDirectory.EnsureRoot(runtimeRoot), window, environment);
        _ = authority.SweepStale();
        return authority;
    }

    /// <summary>
    /// Issues the next launch of a slot. The previous launch of the slot, if any, is revoked. The returned launch owns its
    /// endpoint files; dispose it when the child is gone.
    /// </summary>
    public LocalRpcLaunch Launch(string slot, LocalRpcLaunchIdentity identity, LocalRpcLaunchTransport transport = LocalRpcLaunchTransport.PrivateEndpoint)
    {
        LaunchTokens.Validate(slot, nameof(slot));
        ArgumentNullException.ThrowIfNull(identity);
        if (!Enum.IsDefined(transport))
        {
            throw new ArgumentOutOfRangeException(nameof(transport));
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _ = _slots.TryGetValue(slot, out var state);
            var previous = state?.Current;
            var epoch = (state?.Epoch ?? 0) + 1;
            var launchId = Guid.NewGuid();
            var (endpoint, directory) = CreateEndpoint(launchId, epoch, transport);
            LocalRpcLaunch launch;
            try
            {
                var now = _environment.Clock.GetUtcNow();
                var descriptor = new LocalRpcLaunchDescriptor(
                    launchId, slot, epoch, endpoint, _environment.Parent, identity,
                    RandomNumberGenerator.GetBytes(LocalRpcLaunchDescriptor.NonceLength), now, now + _bootstrapWindow);
                launch = new LocalRpcLaunch(descriptor, directory, _environment, Forget);
            }
            catch
            {
                if (directory is not null)
                {
                    LaunchDirectory.Remove(directory);
                }

                throw;
            }

            _slots[slot] = new SlotState(epoch, launch);
            _ = _issued.Add(launch);
            previous?.Revoke();
            return launch;
        }
    }

    /// <summary>
    /// Verifies what a child presents. A claim from an older epoch of the slot is stale and refused whatever else it
    /// carries; every other check is the launch's own.
    /// </summary>
    public LocalRpcLaunchRefusal Verify(LocalRpcLaunchClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        LocalRpcLaunch? current;
        lock (_gate)
        {
            if (!_slots.TryGetValue(claim.Slot, out var state))
            {
                return LocalRpcLaunchRefusal.UnknownSlot;
            }

            if (claim.Epoch < state.Epoch)
            {
                return LocalRpcLaunchRefusal.StaleEpoch;
            }

            if (claim.Epoch > state.Epoch)
            {
                return LocalRpcLaunchRefusal.UnknownLaunch;
            }

            current = state.Current;
        }

        return current.Verify(claim);
    }

    /// <summary>
    /// Removes launch directories under the root whose issuing parent no longer runs (and leftovers of interrupted creates
    /// and removals). Returns how many were removed. A directory of a running or unverifiable parent is never removed.
    /// </summary>
    public int SweepStale()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed), this);
        return LaunchDirectory.SweepStale(_root, _environment.Probe, _environment.Clock, _environment.AbandonedGrace);
    }

    /// <summary>Revokes and disposes every launch this authority issued and has not seen disposed, superseded ones included.</summary>
    public async ValueTask DisposeAsync()
    {
        LocalRpcLaunch[] launches;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            launches = [.. _issued];
        }

        foreach (var launch in launches)
        {
            await launch.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>How many launches this authority still tracks for disposal.</summary>
    internal int IssuedCount
    {
        get
        {
            lock (_gate)
            {
                return _issued.Count;
            }
        }
    }

    private void Forget(LocalRpcLaunch launch)
    {
        lock (_gate)
        {
            _ = _issued.Remove(launch);
        }
    }

    private (LocalRpcEndpoint? Endpoint, string? Directory) CreateEndpoint(Guid launchId, ulong epoch, LocalRpcLaunchTransport transport)
    {
        if (transport == LocalRpcLaunchTransport.SuppliedStreams)
        {
            return (null, null);
        }

        if (OperatingSystem.IsWindows() && !_environment.ForceUnixSocket)
        {
            // The pipe vanishes with its process; its name is unguessable and each launch has its own.
            return (LocalRpcEndpoint.NamedPipe("afl-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16))), null);
        }

        var directory = LaunchDirectory.Publish(_root, launchId, _environment.Parent, epoch, null);
        try
        {
            return (LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.UnixDomainSocket, Path.Combine(directory, "s")), directory);
        }
        catch
        {
            LaunchDirectory.Remove(directory);
            throw;
        }
    }

    private sealed record SlotState(ulong Epoch, LocalRpcLaunch Current);
}

/// <summary>
/// One launch of one child: the descriptor, the endpoint files it owns, and the one-use launch secret. It authorizes
/// connections and claims only while it is current, unrevoked, within its bootstrap window (until the secret is consumed),
/// issued by this running process and, once a child process is bound, while that process runs.
/// </summary>
public sealed class LocalRpcLaunch : IAsyncDisposable
{
    private readonly LaunchEnvironment _environment;
    private readonly string? _directory;
    private readonly object _gate = new();
    private readonly CancellationTokenSource _revoked = new();
    private readonly CancellationToken _revokedToken;
    private readonly Action<LocalRpcLaunch>? _disposedCallback;
    private readonly byte[] _secret = RandomNumberGenerator.GetBytes(LocalRpcLaunchDescriptor.SecretLength);
    private LocalRpcProcessIdentity? _child;
    private bool _handedOff;
    private bool _consumed;
    private int _revocation;
    private int _disposed;

    internal LocalRpcLaunch(LocalRpcLaunchDescriptor descriptor, string? directory, LaunchEnvironment environment, Action<LocalRpcLaunch>? disposed = null)
    {
        _disposedCallback = disposed;
        Descriptor = descriptor;
        _directory = directory;
        _environment = environment;
        _revokedToken = _revoked.Token;
    }

    /// <summary>The immutable descriptor of this launch.</summary>
    public LocalRpcLaunchDescriptor Descriptor { get; }

    /// <summary>The private endpoint of this launch, or null when the launcher supplies streams.</summary>
    public LocalRpcEndpoint? Endpoint => Descriptor.Endpoint;

    /// <summary>Cancelled when the launch is revoked, superseded or disposed; the owner closes its server connections then.</summary>
    public CancellationToken Revoked => _revokedToken;

    internal string? DirectoryPath => _directory;

    /// <summary>True when every byte of the launch secret is zero (after consumption, revocation or disposal).</summary>
    internal bool SecretIsZeroed()
    {
        lock (_gate)
        {
            return _secret.All(value => value == 0);
        }
    }

    /// <summary>
    /// Records the verified child process of this launch (its handle's id and start time, from the launcher). It must be
    /// running and cannot be the parent. Once bound, the launch authorizes only while that process runs. Binds once.
    /// </summary>
    public void BindChild(LocalRpcProcessIdentity child)
    {
        if (child.ProcessId <= 0 || child.Names(Descriptor.Parent))
        {
            throw new ArgumentException("A child process is a process other than the parent.", nameof(child));
        }

        if (_environment.Probe(child) != ProcessLiveness.Live)
        {
            throw new InvalidOperationException("The child process is not running.");
        }

        lock (_gate)
        {
            if (_revocation != 0)
            {
                throw new InvalidOperationException("The launch is revoked.");
            }

            if (_child is not null)
            {
                throw new InvalidOperationException("A launch binds one child process.");
            }

            _child = child;
        }
    }

    /// <summary>
    /// The private bootstrap resource for the child: the encoded descriptor followed by the one-use launch secret. It is
    /// handed over once, through an inherited private resource (never argv, environment or a file); the caller clears it after writing it.
    /// </summary>
    public byte[] HandoffBootstrapResource()
    {
        lock (_gate)
        {
            if (_revocation != 0 || _consumed)
            {
                throw new InvalidOperationException("The launch secret is no longer available.");
            }

            if (_handedOff)
            {
                throw new InvalidOperationException("The bootstrap resource was already handed off.");
            }

            _handedOff = true;
            return [.. Descriptor.Encode(), .. _secret];
        }
    }

    /// <summary>
    /// Runs <paramref name="use"/> over the launch secret exactly once for the life of the launch, then destroys the secret
    /// whatever the outcome. Consuming it ends the bootstrap window: the lease and renewal of the registration task govern from then on.
    /// </summary>
    public TResult ConsumeSecret<TState, TResult>(TState state, LocalRpcSecretUse<TState, TResult> use)
    {
        ArgumentNullException.ThrowIfNull(use);
        lock (_gate)
        {
            if (_revocation != 0 || _consumed)
            {
                throw new InvalidOperationException("The launch secret is no longer available.");
            }

            _consumed = true;
            try
            {
                return use(state, _secret);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(_secret);
            }
        }
    }

    /// <summary>Why this launch would refuse right now, ignoring any claim. <see cref="LocalRpcLaunchRefusal.None"/> means it authorizes.</summary>
    public LocalRpcLaunchRefusal Status()
    {
        LocalRpcProcessIdentity? child;
        bool bootstrapped;
        lock (_gate)
        {
            if (_revocation != 0)
            {
                return LocalRpcLaunchRefusal.Revoked;
            }

            child = _child;
            bootstrapped = _consumed;
        }

        if (!Descriptor.Parent.Names(_environment.Parent) || _environment.Probe(Descriptor.Parent) != ProcessLiveness.Live)
        {
            return LocalRpcLaunchRefusal.ParentMismatch;
        }

        if (child is { } bound && _environment.Probe(bound) != ProcessLiveness.Live)
        {
            return LocalRpcLaunchRefusal.ChildGone;
        }

        return !bootstrapped && _environment.Clock.GetUtcNow() >= Descriptor.BootstrapDeadlineUtc
            ? LocalRpcLaunchRefusal.Expired
            : LocalRpcLaunchRefusal.None;
    }

    /// <summary>Verifies a claim against this launch: its status first, then the launch id, epoch, nonce, build and protocol.</summary>
    public LocalRpcLaunchRefusal Verify(LocalRpcLaunchClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        var status = Status();
        if (status != LocalRpcLaunchRefusal.None)
        {
            return status;
        }

        if (claim.LaunchId != Descriptor.LaunchId || claim.Epoch != Descriptor.Epoch
            || !string.Equals(claim.Slot, Descriptor.Slot, StringComparison.Ordinal))
        {
            return LocalRpcLaunchRefusal.UnknownLaunch;
        }

        if (!CryptographicOperations.FixedTimeEquals(claim.Nonce.Span, Descriptor.Nonce.Span))
        {
            return LocalRpcLaunchRefusal.NonceMismatch;
        }

        if (!claim.Identity.SameBuild(Descriptor.Identity))
        {
            return LocalRpcLaunchRefusal.BuildMismatch;
        }

        return claim.Identity.SameProtocol(Descriptor.Identity) ? LocalRpcLaunchRefusal.None : LocalRpcLaunchRefusal.ProtocolMismatch;
    }

    /// <summary>
    /// The connection decision for a server over this launch's endpoint or streams
    /// (<see cref="LocalRpcServerBuilder.AuthorizeConnectionsAsync"/>): a connection is admitted only while the launch authorizes
    /// and only when it arrived on this launch's own endpoint.
    /// </summary>
    public ValueTask<bool> AuthorizeConnectionAsync(LocalRpcConnectionInfo connection, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        cancellationToken.ThrowIfCancellationRequested();
        var sameEndpoint = Descriptor.Endpoint is null
            ? connection.Endpoint is null
            : connection.Endpoint is { } presented && presented.Transport == Descriptor.Endpoint.Transport
                && string.Equals(presented.Address, Descriptor.Endpoint.Address, StringComparison.Ordinal);
        return ValueTask.FromResult(sameEndpoint && Status() == LocalRpcLaunchRefusal.None);
    }

    /// <summary>Denies every later claim and connection, destroys the secret and cancels <see cref="Revoked"/>. It removes no file; dispose does. Idempotent.</summary>
    public void Revoke()
    {
        lock (_gate)
        {
            if (Interlocked.Exchange(ref _revocation, 1) != 0)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(_secret);
        }

        try
        {
            _revoked.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Disposed concurrently: already revoked.
        }
    }

    /// <summary>Revokes the launch and removes its endpoint files with one rename followed by a delete. Idempotent.</summary>
    public ValueTask DisposeAsync()
    {
        Revoke();
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            if (_directory is not null)
            {
                LaunchDirectory.Remove(_directory);
            }

            _revoked.Dispose();
            _disposedCallback?.Invoke(this);
        }

        return ValueTask.CompletedTask;
    }
}
