// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace ArcForges.LocalRpc;

/// <summary>
/// The child's side of its registration: it takes the parent's private bootstrap resource (descriptor and one-use secret), proves
/// possession of the secret over the LocalBootstrap transcript exactly once, and then presents the granted credentials on every call.
/// The type contains no contract: the child's generated LocalBootstrap client maps its messages onto these steps.
/// </summary>
public sealed class LocalRpcChildBootstrap : IDisposable
{
    private readonly object _gate = new();
    private readonly byte[] _secret;
    private bool _proved;
    private int _disposed;

    private LocalRpcChildBootstrap(LocalRpcLaunchDescriptor descriptor, byte[] secret, Guid instanceId, byte[] clientChallenge)
    {
        Descriptor = descriptor;
        _secret = secret;
        InstanceId = instanceId;
        ClientChallenge = clientChallenge;
    }

    /// <summary>The launch descriptor the parent handed over.</summary>
    public LocalRpcLaunchDescriptor Descriptor { get; }

    /// <summary>The child kind, build and protocol the parent expects, which the child states in its challenge.</summary>
    public LocalRpcLaunchIdentity Identity => Descriptor.Identity;

    /// <summary>This child's instance id, sent in the challenge and bound into the proof.</summary>
    public Guid InstanceId { get; }

    /// <summary>The 32 random bytes the child sends in its challenge.</summary>
    public ReadOnlyMemory<byte> ClientChallenge { get; }

    /// <summary>
    /// Takes ownership of a bootstrap resource (<see cref="LocalRpcLaunch.HandoffBootstrapResource"/>: the encoded descriptor followed by
    /// the 32-byte secret). The caller's array is cleared whatever the outcome, and nothing but the descriptor and a private copy of the
    /// secret survives. A resource that is not exactly a descriptor and a secret is refused as <see cref="FormatException"/>.
    /// </summary>
    public static LocalRpcChildBootstrap FromResource(byte[] resource)
    {
        ArgumentNullException.ThrowIfNull(resource);
        try
        {
            if (resource.Length <= LocalRpcLaunchDescriptor.SecretLength)
            {
                throw new FormatException("A bootstrap resource is a launch descriptor followed by a 32-byte secret.");
            }

            var descriptorLength = resource.Length - LocalRpcLaunchDescriptor.SecretLength;
            var descriptor = LocalRpcLaunchDescriptor.Decode(resource.AsSpan(0, descriptorLength));
            var secret = resource.AsSpan(descriptorLength).ToArray();
            return new LocalRpcChildBootstrap(descriptor, secret, Guid.NewGuid(), RandomNumberGenerator.GetBytes(LocalRpcRegistration.ChallengeLength));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(resource);
        }
    }

    /// <summary>
    /// The confirmation proof for the parent's challenge. The secret is used for this one proof and destroyed: a second call, or a call
    /// after <see cref="Dispose"/>, fails. A malformed argument is refused before the secret is touched.
    /// </summary>
    public byte[] ComputeProof(Guid challengeId, ReadOnlySpan<byte> serverChallenge, Guid serverInstanceId)
    {
        if (serverChallenge.Length != LocalRpcRegistration.ChallengeLength || challengeId == Guid.Empty || serverInstanceId == Guid.Empty)
        {
            throw new ArgumentException("A confirmation names a challenge id, a parent instance id and 32 server bytes.");
        }

        lock (_gate)
        {
            if (_proved || Volatile.Read(ref _disposed) != 0)
            {
                throw new InvalidOperationException("The launch secret is single-use and is already spent.");
            }

            _proved = true;
            try
            {
                return LocalBootstrapProof.Compute(_secret, challengeId, ClientChallenge.Span, serverChallenge, InstanceId, serverInstanceId);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(_secret);
            }
        }
    }

    /// <summary>Turns the parent's grant into the credentials every later call presents.</summary>
    public LocalRpcCallCredentials AcceptGrant(ReadOnlySpan<byte> peerNonce)
    {
        if (peerNonce.Length != LocalRpcRegistration.NonceLength)
        {
            throw new ArgumentException("A peer nonce is 32 bytes.", nameof(peerNonce));
        }

        lock (_gate)
        {
            if (!_proved)
            {
                throw new InvalidOperationException("Credentials are accepted only after the proof was sent.");
            }
        }

        return new LocalRpcCallCredentials(peerNonce, InstanceId, Descriptor.Identity.ContractSetDigest.Span);
    }

    /// <summary>True when every byte of the launch secret is zero.</summary>
    internal bool SecretIsZeroed()
    {
        lock (_gate)
        {
            return _secret.All(value => value == 0);
        }
    }

    /// <summary>Destroys the secret if it was never used.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            lock (_gate)
            {
                CryptographicOperations.ZeroMemory(_secret);
            }
        }
    }
}

/// <summary>
/// A client interceptor that presents the registration credentials on every call: the granted peer nonce, the registered caller
/// instance and the contract-set digest. A caller cannot override them: headers of those names that a caller set are replaced.
/// </summary>
public sealed class LocalRpcCallCredentials : Interceptor, IDisposable
{
    private readonly byte[] _nonce;
    private readonly byte[] _instance;
    private readonly string _contractSet;

    internal LocalRpcCallCredentials(ReadOnlySpan<byte> nonce, Guid instance, ReadOnlySpan<byte> contractSetDigest)
    {
        _nonce = nonce.ToArray();
        _instance = instance.ToByteArray(bigEndian: true);
        _contractSet = Convert.ToHexStringLower(contractSetDigest);
    }

    /// <summary>The headers that carry the credentials.</summary>
    internal Metadata Headers()
    {
        return
        [
            new Metadata.Entry(LocalRpcRegistrationGate.PeerHeader, (byte[])_nonce.Clone()),
            new Metadata.Entry(LocalRpcRegistrationGate.InstanceHeader, (byte[])_instance.Clone()),
            new Metadata.Entry(LocalRpcRegistrationGate.ContractSetHeader, _contractSet),
        ];
    }

    /// <summary>Clears the nonce.</summary>
    public void Dispose() => CryptographicOperations.ZeroMemory(_nonce);

    /// <inheritdoc />
    public override TResponse BlockingUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        BlockingUnaryCallContinuation<TRequest, TResponse> continuation) =>
        base.BlockingUnaryCall(request, With(context), continuation);

    /// <inheritdoc />
    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation) =>
        base.AsyncUnaryCall(request, With(context), continuation);

    /// <inheritdoc />
    public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncServerStreamingCallContinuation<TRequest, TResponse> continuation) =>
        base.AsyncServerStreamingCall(request, With(context), continuation);

    /// <inheritdoc />
    public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncClientStreamingCallContinuation<TRequest, TResponse> continuation) =>
        base.AsyncClientStreamingCall(With(context), continuation);

    /// <inheritdoc />
    public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncDuplexStreamingCallContinuation<TRequest, TResponse> continuation) =>
        base.AsyncDuplexStreamingCall(With(context), continuation);

    private ClientInterceptorContext<TRequest, TResponse> With<TRequest, TResponse>(ClientInterceptorContext<TRequest, TResponse> context)
        where TRequest : class
        where TResponse : class
    {
        var headers = new Metadata();
        if (context.Options.Headers is { } existing)
        {
            foreach (var entry in existing)
            {
                if (!IsReserved(entry.Key))
                {
                    headers.Add(entry);
                }
            }
        }

        foreach (var entry in Headers())
        {
            headers.Add(entry);
        }

        return new ClientInterceptorContext<TRequest, TResponse>(context.Method, context.Host, context.Options.WithHeaders(headers));
    }

    private static bool IsReserved(string key) =>
        string.Equals(key, LocalRpcRegistrationGate.PeerHeader, StringComparison.OrdinalIgnoreCase)
        || string.Equals(key, LocalRpcRegistrationGate.InstanceHeader, StringComparison.OrdinalIgnoreCase)
        || string.Equals(key, LocalRpcRegistrationGate.ContractSetHeader, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Thrown by a renewal delegate to say the parent refused the child: the registration is over and the lease keeper stops at once.</summary>
public sealed class LocalRpcRegistrationLostException : Exception
{
    /// <summary>Creates the exception.</summary>
    public LocalRpcRegistrationLostException()
        : base("The parent ended the registration.")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public LocalRpcRegistrationLostException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and a cause.</summary>
    public LocalRpcRegistrationLostException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Sends one Renew call. The command id is stable across retries of one renewal, so a duplicate never extends the lease twice.</summary>
public delegate ValueTask<DateTimeOffset> LocalRpcRenewal(ReadOnlyMemory<byte> commandId, CancellationToken cancellationToken);

/// <summary>
/// Renews a child's lease every 10 seconds. A failed attempt is retried at the next interval with the same command id; the keeper
/// declares the registration lost, and cancels <see cref="Lost"/>, when the parent refuses (<see cref="LocalRpcRegistrationLostException"/>)
/// or when the 30-second lease passes without a successful renewal. A lost registration is never revived: the owner relaunches.
/// </summary>
public sealed class LocalRpcLeaseKeeper : IAsyncDisposable
{
    private readonly LocalRpcRenewal _renew;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _interval;
    private readonly TimeSpan _lease;
    private readonly CancellationTokenSource _stop = new();
    private readonly CancellationTokenSource _lost = new();
    private readonly CancellationToken _lostToken;
    private readonly Task _loop;
    private long _leaseStart;
    private long _expiresAtUtcTicks;

    private LocalRpcLeaseKeeper(LocalRpcRenewal renew, TimeProvider clock, TimeSpan interval, TimeSpan lease)
    {
        _renew = renew;
        _clock = clock;
        _interval = interval;
        _lease = lease;
        _lostToken = _lost.Token;
        _leaseStart = clock.GetTimestamp();
        _expiresAtUtcTicks = (clock.GetUtcNow() + lease).UtcTicks;
        _loop = Task.Run(RunAsync);
    }

    /// <summary>Cancelled when the registration is lost.</summary>
    public CancellationToken Lost => _lostToken;

    /// <summary>The lease expiry the parent last reported, in UTC.</summary>
    public DateTimeOffset ExpiresAtUtc => new(Interlocked.Read(ref _expiresAtUtcTicks), TimeSpan.Zero);

    /// <summary>Starts renewing a lease that began now, every 10 seconds.</summary>
    public static LocalRpcLeaseKeeper Start(LocalRpcRenewal renew)
    {
        ArgumentNullException.ThrowIfNull(renew);
        return new LocalRpcLeaseKeeper(renew, TimeProvider.System, LocalRpcRegistration.RenewInterval, LocalRpcRegistration.LeaseDuration);
    }

    internal static LocalRpcLeaseKeeper Start(LocalRpcRenewal renew, TimeProvider clock, TimeSpan interval, TimeSpan lease) =>
        new(renew, clock, interval, lease);

    /// <summary>Stops renewing and waits for an attempt in flight.</summary>
    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        try
        {
            await _loop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Stopped.
        }

        _stop.Dispose();
        _lost.Dispose();
    }

    private async Task RunAsync()
    {
        byte[]? commandId = null;
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                await Task.Delay(_interval, _clock, _stop.Token).ConfigureAwait(false);
                commandId ??= RandomNumberGenerator.GetBytes(16);
                var sent = _clock.GetTimestamp();
                try
                {
                    var remaining = _lease - _clock.GetElapsedTime(_leaseStart);
                    using var attempt = new CancellationTokenSource(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero, _clock);
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token, attempt.Token);
                    var expiry = await _renew(commandId, linked.Token).ConfigureAwait(false);
                    _leaseStart = sent;
                    Interlocked.Exchange(ref _expiresAtUtcTicks, expiry.UtcTicks);
                    commandId = null;
                }
                catch (LocalRpcRegistrationLostException)
                {
                    Lose();
                    return;
                }
                catch (OperationCanceledException) when (_stop.IsCancellationRequested)
                {
                    return;
                }
#pragma warning disable CA1031 // Any other failure is a failed attempt: the lease decides whether the registration survives it.
                catch (Exception)
#pragma warning restore CA1031
                {
                    // Retried at the next interval with the same command id.
                }

                if (_clock.GetElapsedTime(_leaseStart) >= _lease)
                {
                    Lose();
                    return;
                }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
            // Stopped while waiting for the next interval.
        }
    }

    private void Lose()
    {
        try
        {
            _lost.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Disposed concurrently.
        }
        catch (AggregateException)
        {
            // A Lost callback threw; the registration is lost either way.
        }
    }
}
