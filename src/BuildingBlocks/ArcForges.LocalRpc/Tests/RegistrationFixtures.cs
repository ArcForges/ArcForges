// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// A clock and a timer factory a test drives by hand: the wall and the monotonic clock move together (or apart), and timers fire
/// only when time is advanced past them, or when a test fires one early on purpose (a real timer can fire before the clock agrees).
/// </summary>
internal sealed class TimerClock(DateTimeOffset start) : TimeProvider
{
    private readonly object _gate = new();
    private readonly List<FakeTimer> _timers = [];
    private long _wall = start.UtcTicks;
    private long _monotonic = 1_000_000;
    private volatile bool _suspended;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    /// <summary>While set, time still passes but no timer fires: a test then observes what a call alone detects.</summary>
    internal bool SuspendTimers
    {
        get => _suspended;
        set => _suspended = value;
    }

    internal int PendingTimers
    {
        get
        {
            lock (_gate)
            {
                return _timers.Count(timer => timer.IsPending);
            }
        }
    }

    public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _wall), TimeSpan.Zero);

    public override long GetTimestamp() => Interlocked.Read(ref _monotonic);

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new FakeTimer(this, callback, state);
        timer.Change(dueTime, period);
        lock (_gate)
        {
            _timers.Add(timer);
        }

        return timer;
    }

    /// <summary>Time passes on both clocks; every timer that became due fires, in due order, on this thread.</summary>
    internal void Advance(TimeSpan by)
    {
        _ = Interlocked.Add(ref _wall, by.Ticks);
        _ = Interlocked.Add(ref _monotonic, by.Ticks);
        FireDue();
    }

    /// <summary>Only the monotonic clock moves.</summary>
    internal void AdvanceMonotonic(TimeSpan by)
    {
        _ = Interlocked.Add(ref _monotonic, by.Ticks);
        FireDue();
    }

    /// <summary>The wall clock is stepped (negative: back); the monotonic clock does not move.</summary>
    internal void StepWallClock(TimeSpan by) => Interlocked.Add(ref _wall, by.Ticks);

    /// <summary>Fires the earliest pending timer without moving any clock, as a real timer that fires a little early does.</summary>
    internal void FireNextEarly()
    {
        FakeTimer? next;
        lock (_gate)
        {
            next = _timers.Where(timer => timer.IsPending).OrderBy(timer => timer.Due).FirstOrDefault();
        }

        next?.Fire();
    }

    /// <summary>How long until the earliest pending timer is due on the monotonic clock.</summary>
    internal TimeSpan? NextDueIn()
    {
        lock (_gate)
        {
            var next = _timers.Where(timer => timer.IsPending).OrderBy(timer => timer.Due).FirstOrDefault();
            return next is null ? null : TimeSpan.FromTicks(next.Due - GetTimestamp());
        }
    }

    private void FireDue()
    {
        while (!_suspended)
        {
            FakeTimer? due;
            lock (_gate)
            {
                due = _timers.Where(timer => timer.IsPending && timer.Due <= GetTimestamp()).OrderBy(timer => timer.Due).FirstOrDefault();
            }

            if (due is null)
            {
                return;
            }

            due.Fire();
        }
    }

    private sealed class FakeTimer(TimerClock clock, TimerCallback callback, object? state) : ITimer
    {
        private long _due = long.MaxValue;
        private bool _pending;
        private bool _disposed;

        internal long Due => Volatile.Read(ref _due);

        internal bool IsPending
        {
            get
            {
                lock (clock._gate)
                {
                    return _pending && !_disposed;
                }
            }
        }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (clock._gate)
            {
                if (_disposed)
                {
                    return false;
                }

                _pending = dueTime != Timeout.InfiniteTimeSpan;
                _due = _pending ? clock.GetTimestamp() + dueTime.Ticks : long.MaxValue;
                return true;
            }
        }

        internal void Fire()
        {
            lock (clock._gate)
            {
                if (!_pending || _disposed)
                {
                    return;
                }

                _pending = false;
            }

            callback(state);
        }

        public void Dispose()
        {
            lock (clock._gate)
            {
                _disposed = true;
                _pending = false;
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>Wire helpers shared by the fixtures: ids are 16 big-endian UUID bytes.</summary>
internal static class Wire
{
    internal static Id ToId(Guid value) => new() { Value = ByteString.CopyFrom(value.ToByteArray(bigEndian: true)) };

    internal static Guid FromId(Id? id) =>
        id?.Value is { Length: 16 } bytes ? new Guid(bytes.Span, bigEndian: true) : Guid.Empty;

    internal static Instant ToInstant(DateTimeOffset value) => new()
    {
        UnixSeconds = value.ToUnixTimeSeconds(),
        Nanos = (uint)(value.UtcTicks % TimeSpan.TicksPerSecond * 100),
    };

    internal static RpcException Refused() => new(new Status(StatusCode.Unauthenticated, "Registration refused."));

    internal static EndpointManifest Manifest(LocalRpcLaunchIdentity identity, string? buildId = null, byte[]? buildDigest = null, byte[]? contractDigest = null, uint? protocol = null)
    {
        var manifest = new EndpointManifest
        {
            AppId = buildId ?? identity.BuildId,
            BuildHash = Convert.ToHexStringLower(buildDigest ?? identity.BuildDigest.Span),
            ContractSetHash = Convert.ToHexStringLower(contractDigest ?? identity.ContractSetDigest.Span),
        };
        manifest.ContractMajors.Add(protocol ?? identity.ProtocolVersion);
        return manifest;
    }
}

/// <summary>
/// The owner's generated LocalBootstrap service: it maps the generated messages onto the three steps of the bootstrap call the
/// registration gate attached, and answers every refusal with one UNAUTHENTICATED status. Test fixture; the library holds no contract.
/// </summary>
internal sealed class BootstrapAdapter : LocalBootstrapService.LocalBootstrapServiceBase
{
    private int _challenges;
    private int _confirms;
    private int _renews;

    internal int Challenges => Volatile.Read(ref _challenges);

    internal int Confirms => Volatile.Read(ref _confirms);

    internal int Renews => Volatile.Read(ref _renews);

    public override Task<LocalBootstrapServiceChallengeResponse> Challenge(LocalBootstrapServiceChallengeRequest request, ServerCallContext context)
    {
        _ = Interlocked.Increment(ref _challenges);
        var call = context.GetBootstrapCall() ?? throw Wire.Refused();
        var expected = call.Registration.Launch.Descriptor.Identity;
        LocalRpcLaunchIdentity claimed;
        try
        {
            var manifest = request.Caller ?? throw Wire.Refused();
            claimed = new LocalRpcLaunchIdentity(
                expected.ChildKind,
                manifest.AppId,
                Convert.FromHexString(manifest.BuildHash),
                manifest.ContractMajors.Count == 1 ? manifest.ContractMajors[0] : 0,
                Convert.FromHexString(manifest.ContractSetHash));
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw Wire.Refused();
        }

        var refusal = call.TryChallenge(Wire.FromId(request.InstanceId), request.Challenge.Span, claimed, out var challenge);
        if (refusal != LocalRpcRegistrationRefusal.None || challenge is null)
        {
            throw Wire.Refused();
        }

        return Task.FromResult(new LocalBootstrapServiceChallengeResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta?.CorrelationId },
            Value = new LocalBootstrapServiceChallengeValue
            {
                ChallengeId = Wire.ToId(challenge.ChallengeId),
                ServerChallenge = ByteString.CopyFrom(challenge.ServerChallenge.Span),
                ExpiresAt = Wire.ToInstant(challenge.ExpiresAtUtc),
                Server = new EndpointManifest { InstanceId = Wire.ToId(challenge.ServerInstanceId) },
            },
        });
    }

    public override Task<LocalBootstrapServiceConfirmResponse> Confirm(LocalBootstrapServiceConfirmRequest request, ServerCallContext context)
    {
        _ = Interlocked.Increment(ref _confirms);
        var call = context.GetBootstrapCall() ?? throw Wire.Refused();
        var refusal = call.TryConfirm(Wire.FromId(request.ChallengeId), request.Proof.Span, out var grant);
        if (refusal != LocalRpcRegistrationRefusal.None || grant is null)
        {
            throw Wire.Refused();
        }

        return Task.FromResult(new LocalBootstrapServiceConfirmResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta?.CorrelationId },
            Value = new LocalBootstrapServiceConfirmValue
            {
                PeerNonce = ByteString.CopyFrom(grant.PeerNonce.Span),
                ExpiresAt = Wire.ToInstant(grant.ExpiresAtUtc),
            },
        });
    }

    public override Task<LocalBootstrapServiceRenewResponse> Renew(LocalBootstrapServiceRenewRequest request, ServerCallContext context)
    {
        _ = Interlocked.Increment(ref _renews);
        var call = context.GetBootstrapCall() ?? throw Wire.Refused();
        var command = request.Meta?.CommandId?.Value ?? ByteString.Empty;
        var refusal = call.TryRenew(command.Span, out var expiry);
        if (refusal != LocalRpcRegistrationRefusal.None)
        {
            throw Wire.Refused();
        }

        return Task.FromResult(new LocalBootstrapServiceRenewResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta?.CorrelationId },
            Value = new LocalBootstrapServiceRenewValue { ExpiresAt = Wire.ToInstant(expiry) },
        });
    }
}

/// <summary>An ordinary generated service (the connector broker's list call) that counts what reached it and can hold its calls.</summary>
internal sealed class ProbeBrokerService : ConnectorBrokerService.ConnectorBrokerServiceBase
{
    private int _dispatched;

    internal int Dispatched => Volatile.Read(ref _dispatched);

    /// <summary>While set, every call waits here (and is released by completing it) after it was counted.</summary>
    internal TaskCompletionSource? Hold { get; set; }

    public override async Task<ConnectorBrokerServiceListDefinitionsResponse> ListDefinitions(
        ConnectorBrokerServiceListDefinitionsRequest request,
        ServerCallContext context)
    {
        _ = Interlocked.Increment(ref _dispatched);
        if (Hold is { } hold)
        {
            await hold.Task.WaitAsync(context.CancellationToken).ConfigureAwait(false);
        }

        return new ConnectorBrokerServiceListDefinitionsResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta?.CorrelationId },
            Value = new ConnectorBrokerServiceListDefinitionsValue(),
        };
    }
}

/// <summary>What a child holds after it registered.</summary>
internal sealed class RegisteredChild(LocalRpcChildBootstrap bootstrap, LocalRpcCallCredentials credentials, byte[] nonce, DateTimeOffset expiresAt, CallInvoker bare)
{
    internal LocalRpcChildBootstrap Bootstrap { get; } = bootstrap;

    internal LocalRpcCallCredentials Credentials { get; } = credentials;

    internal byte[] Nonce { get; } = nonce;

    internal DateTimeOffset ExpiresAt { get; } = expiresAt;

    internal CallInvoker Bare { get; } = bare;

    /// <summary>An invoker whose every call presents the registration credentials.</summary>
    internal CallInvoker Authenticated => Bare.Intercept(Credentials);
}

/// <summary>The child's generated client side of the bootstrap: challenge, proof, confirm, renew.</summary>
internal static class ChildClient
{
    internal static async Task<RegisteredChild> RegisterAsync(CallInvoker invoker, LocalRpcChildBootstrap bootstrap, CancellationToken cancellationToken)
    {
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(invoker);
        var challenge = await client.ChallengeAsync(
            new LocalBootstrapServiceChallengeRequest
            {
                Meta = Meta(),
                InstanceId = Wire.ToId(bootstrap.InstanceId),
                Challenge = ByteString.CopyFrom(bootstrap.ClientChallenge.Span),
                Caller = Wire.Manifest(bootstrap.Identity),
            },
            cancellationToken: cancellationToken);
        var value = challenge.Value;
        var proof = bootstrap.ComputeProof(Wire.FromId(value.ChallengeId), value.ServerChallenge.Span, Wire.FromId(value.Server.InstanceId));
        var confirm = await client.ConfirmAsync(
            new LocalBootstrapServiceConfirmRequest { Meta = Meta(), ChallengeId = value.ChallengeId, Proof = ByteString.CopyFrom(proof) },
            cancellationToken: cancellationToken);
        var nonce = confirm.Value.PeerNonce.ToByteArray();
        var credentials = bootstrap.AcceptGrant(nonce);
        var expires = DateTimeOffset.FromUnixTimeSeconds(confirm.Value.ExpiresAt.UnixSeconds);
        return new RegisteredChild(bootstrap, credentials, nonce, expires, invoker);
    }

    internal static async ValueTask<DateTimeOffset> RenewAsync(CallInvoker authenticated, ReadOnlyMemory<byte> commandId, CancellationToken cancellationToken)
    {
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(authenticated);
        try
        {
            var response = await client.RenewAsync(
                new LocalBootstrapServiceRenewRequest
                {
                    Meta = new RequestMeta { CommandId = new Id { Value = ByteString.CopyFrom(commandId.Span) }, CorrelationId = Wire.ToId(Guid.NewGuid()) },
                },
                cancellationToken: cancellationToken);
            return DateTimeOffset.FromUnixTimeSeconds(response.Value.ExpiresAt.UnixSeconds);
        }
        catch (RpcException exception) when (exception.StatusCode == StatusCode.Unauthenticated)
        {
            throw new LocalRpcRegistrationLostException("The parent ended the registration.", exception);
        }
    }

    /// <summary>The status of an ordinary generated call (the connector broker's list call): <see cref="Status.DefaultSuccess"/> when it was served.</summary>
    internal static async Task<Status> ListStatusAsync(CallInvoker invoker, CancellationToken cancellationToken)
    {
        var client = new ConnectorBrokerService.ConnectorBrokerServiceClient(invoker);
        try
        {
            _ = await client.ListDefinitionsAsync(
                new ConnectorBrokerServiceListDefinitionsRequest { Meta = Meta() },
                deadline: DateTime.UtcNow + TimeSpan.FromSeconds(20),
                cancellationToken: cancellationToken);
            return Status.DefaultSuccess;
        }
        catch (RpcException exception)
        {
            return exception.Status;
        }
    }

    private static RequestMeta Meta() => new() { CorrelationId = Wire.ToId(Guid.NewGuid()), CommandId = Wire.ToId(Guid.NewGuid()) };
}
