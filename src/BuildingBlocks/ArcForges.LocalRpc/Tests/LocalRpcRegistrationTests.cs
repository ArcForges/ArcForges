// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>A launch authority over a fake clock, timers and process table, plus the sessions started on it.</summary>
internal sealed class RegWorld : IDisposable
{
    internal RegWorld(TimeSpan? bootstrapWindow = null, LocalRpcProcessIdentity? parent = null, bool realClock = false)
    {
        World = new LaunchWorld();
        Clock = new TimerClock(DateTimeOffset.UtcNow);
        if (parent is { } restarted)
        {
            World.Processes.Set(restarted, ProcessLiveness.Live);
        }

        var environment = World.Environment(parent, unixSocket: false) with
        {
            Clock = realClock ? TimeProvider.System : Clock,
            Probe = identity =>
            {
                ProbeHook?.Invoke(identity);
                return World.Processes.Probe(identity);
            },
        };
        Authority = LocalRpcLaunchAuthority.Create(World.Root, bootstrapWindow, environment);
    }

    /// <summary>Called with every process the launch probes, before the fake process table answers; a test may block in it.</summary>
    internal Action<LocalRpcProcessIdentity>? ProbeHook { get; set; }

    internal LaunchWorld World { get; }

    internal TimerClock Clock { get; }

    internal LocalRpcLaunchAuthority Authority { get; }

    internal LocalRpcLaunchIdentity Identity { get; } = Launches.Identity();

    internal RegSession Start(string slot = "slot-a", LocalRpcLaunchIdentity? identity = null, RegistrationTimings? timings = null)
    {
        var launch = Authority.Launch(slot, identity ?? Identity, LocalRpcLaunchTransport.SuppliedStreams);
        var registration = timings is null ? LocalRpcRegistration.Create(launch) : LocalRpcRegistration.Create(launch, timings);
        return new RegSession(this, launch, registration);
    }

    public void Dispose()
    {
        Authority.DisposeAsync().AsTask().GetAwaiter().GetResult();
        World.Dispose();
    }
}

/// <summary>One launch and its registration, with the child's side played by hand over the parent's internal API.</summary>
internal sealed class RegSession
{
    internal RegSession(RegWorld world, LocalRpcLaunch launch, LocalRpcRegistration registration, byte[]? secret = null)
    {
        World = world;
        Launch = launch;
        Registration = registration;
        if (secret is not null)
        {
            Secret = secret;
            return;
        }

        var resource = launch.HandoffBootstrapResource();
        Secret = resource[^LocalRpcLaunchDescriptor.SecretLength..];
        Array.Clear(resource);
    }

    internal RegWorld World { get; }

    internal TimerClock Clock => World.Clock;

    internal LocalRpcLaunch Launch { get; }

    internal LocalRpcRegistration Registration { get; }

    internal byte[] Secret { get; }

    internal byte[] ClientBytes { get; } = Launches.Bytes(0x21);

    internal Guid Instance { get; } = Guid.NewGuid();

    internal LocalRpcLaunchIdentity Identity => Launch.Descriptor.Identity;

    internal LocalRpcRegistrationRefusal TryChallenge(string connection = "c1", Guid? instance = null, byte[]? client = null, LocalRpcLaunchIdentity? claimed = null) =>
        Registration.TryChallenge(connection, instance ?? Instance, client ?? ClientBytes, claimed ?? Identity, out _);

    internal LocalRpcBootstrapChallenge Challenge(string connection = "c1")
    {
        var refusal = Registration.TryChallenge(connection, Instance, ClientBytes, Identity, out var challenge);
        Assert.Equal(LocalRpcRegistrationRefusal.None, refusal);
        return challenge!;
    }

    internal byte[] Proof(LocalRpcBootstrapChallenge challenge) =>
        LocalBootstrapProof.Compute(Secret, challenge.ChallengeId, ClientBytes, challenge.ServerChallenge.Span, Instance, challenge.ServerInstanceId);

    internal LocalRpcRegistrationRefusal Confirm(LocalRpcBootstrapChallenge challenge, byte[]? proof = null, string connection = "c1", CancellationTokenSource? closed = null) =>
        Registration.TryConfirm(connection, challenge.ChallengeId, proof ?? Proof(challenge), closed?.Token ?? default, out _);

    internal LocalRpcRegistrationGrant Register(string connection = "c1", CancellationTokenSource? closed = null)
    {
        var challenge = Challenge(connection);
        var refusal = Registration.TryConfirm(connection, challenge.ChallengeId, Proof(challenge), closed?.Token ?? default, out var grant);
        Assert.Equal(LocalRpcRegistrationRefusal.None, refusal);
        return grant!;
    }

    internal LocalRpcRegistrationRefusal Authorize(LocalRpcRegistrationGrant grant, string connection = "c1", byte[]? nonce = null, Guid? instance = null, byte[]? contractSet = null) =>
        Registration.Authorize(
            connection,
            nonce ?? grant.PeerNonce.ToArray(),
            instance ?? Instance,
            contractSet ?? Identity.ContractSetDigest.ToArray());

    internal LocalRpcRegistrationRefusal Renew(byte[] commandId, out DateTimeOffset expiry, string connection = "c1") =>
        Registration.TryRenew(connection, commandId, out expiry);

    internal static byte[] Id(byte value, int length = 16) => Launches.Bytes(value, length);
}

/// <summary>
/// WP-08.02 on the parent's side, without any transport: the bootstrap proof, the five-second challenge, the 30-second lease and
/// its renewal, epoch fencing, fresh grants after a relaunch or a parent restart, and the end of a registration. A fake clock,
/// fake timers and a fake process table make every boundary exact; these are state-machine fixtures, never OS-process evidence.
/// </summary>
public sealed class LocalRpcRegistrationTests
{
    private static readonly TimeSpan Second = TimeSpan.FromSeconds(1);

    // ---- the challenge

    [Fact]
    public void AChallengeCarriesFreshRandomBytesTheParentInstanceAndAFiveSecondLifetime()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var now = world.Clock.GetUtcNow();

        var first = session.Challenge();
        var second = session.Challenge();

        Assert.Equal(now + TimeSpan.FromSeconds(5), first.ExpiresAtUtc);
        Assert.Equal(session.Registration.ParentInstanceId, first.ServerInstanceId);
        Assert.NotEqual(Guid.Empty, session.Registration.ParentInstanceId);
        Assert.Equal(32, first.ServerChallenge.Length);
        Assert.NotEqual(first.ChallengeId, second.ChallengeId);
        Assert.False(first.ServerChallenge.Span.SequenceEqual(second.ServerChallenge.Span));
        Assert.Contains(first.ServerChallenge.ToArray(), value => value != 0);
        // A new challenge replaces the earlier one on the same connection: the earlier one can no longer be confirmed.
        Assert.Equal(LocalRpcRegistrationRefusal.NoChallenge, session.Confirm(first));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Confirm(second));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void AChallengeWithTheWrongNumberOfClientBytesIsRefused(int length)
    {
        using var world = new RegWorld();
        var session = world.Start();

        Assert.Equal(LocalRpcRegistrationRefusal.InvalidRequest, session.TryChallenge(client: new byte[length]));

        _ = session.Register();
    }

    [Fact]
    public void AChallengeWithoutACallerInstanceIsRefused()
    {
        using var world = new RegWorld();
        var session = world.Start();

        Assert.Equal(LocalRpcRegistrationRefusal.InvalidRequest, session.TryChallenge(instance: Guid.Empty));

        _ = session.Register();
    }

    [Fact]
    public void AChallengeNeedsAConnectionAndAClaimedIdentity()
    {
        using var world = new RegWorld();
        var session = world.Start();

        _ = Assert.Throws<ArgumentException>(() => session.Registration.TryChallenge(string.Empty, session.Instance, session.ClientBytes, session.Identity, out _));
        _ = Assert.Throws<ArgumentNullException>(() => session.Registration.TryChallenge("c1", session.Instance, session.ClientBytes, null!, out _));
        _ = Assert.Throws<ArgumentNullException>(() => session.Registration.TryConfirm(null!, Guid.NewGuid(), new byte[32], TestContext.Current.CancellationToken, out _));
        _ = Assert.Throws<ArgumentException>(() => session.Registration.TryConfirm(string.Empty, Guid.NewGuid(), new byte[32], TestContext.Current.CancellationToken, out _));
    }

    public static TheoryData<string> OtherIdentities() => new() { "kind", "build", "digest", "protocol", "contract" };

    [Theory]
    [MemberData(nameof(OtherIdentities))]
    public void AChallengeClaimingAnotherKindBuildDigestProtocolOrContractSetIsRefusedAndTheLaunchStaysUsable(string difference)
    {
        using var world = new RegWorld();
        var session = world.Start();
        var expected = session.Identity;
        var claimed = difference switch
        {
            "kind" => new LocalRpcLaunchIdentity(LocalRpcChildKind.Connector, expected.BuildId, expected.BuildDigest.Span, expected.ProtocolVersion, expected.ContractSetDigest.Span),
            "build" => new LocalRpcLaunchIdentity(expected.ChildKind, "other-build", expected.BuildDigest.Span, expected.ProtocolVersion, expected.ContractSetDigest.Span),
            "digest" => new LocalRpcLaunchIdentity(expected.ChildKind, expected.BuildId, Launches.Flip(expected.BuildDigest), expected.ProtocolVersion, expected.ContractSetDigest.Span),
            "protocol" => new LocalRpcLaunchIdentity(expected.ChildKind, expected.BuildId, expected.BuildDigest.Span, expected.ProtocolVersion + 1, expected.ContractSetDigest.Span),
            _ => new LocalRpcLaunchIdentity(expected.ChildKind, expected.BuildId, expected.BuildDigest.Span, expected.ProtocolVersion, Launches.Flip(expected.ContractSetDigest)),
        };

        Assert.Equal(LocalRpcRegistrationRefusal.IdentityMismatch, session.TryChallenge(claimed: claimed));

        Assert.Equal(LocalRpcLaunchRefusal.None, session.Launch.Status());
        Assert.Equal(LocalRpcRegistrationState.AwaitingBootstrap, session.Registration.State);
        _ = session.Register();
    }

    [Fact]
    public void AChallengeOnARevokedLaunchFindsTheRegistrationEnded()
    {
        using var world = new RegWorld();
        var session = world.Start();

        session.Launch.Revoke();

        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, session.Registration.EndReason);
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.TryChallenge());
    }

    [Fact]
    public void AChallengeAfterTheBootstrapWindowRefusesAndEndsTheRegistration()
    {
        using var world = new RegWorld(TimeSpan.FromSeconds(10));
        var session = world.Start();

        world.Clock.Advance(TimeSpan.FromSeconds(10));

        Assert.Equal(LocalRpcRegistrationRefusal.LaunchRefused, session.TryChallenge());
        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, session.Registration.EndReason);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, session.Launch.Status());
    }

    [Fact]
    public void AChallengeJustBeforeTheBootstrapWindowEndsIsStillIssued()
    {
        using var world = new RegWorld(TimeSpan.FromSeconds(10));
        var session = world.Start();

        world.Clock.Advance(TimeSpan.FromSeconds(10) - TimeSpan.FromMilliseconds(1));

        Assert.Equal(LocalRpcRegistrationRefusal.None, session.TryChallenge());
    }

    [Fact]
    public void AChallengeAfterTheParentOrTheBoundChildProcessEndedRefusesAndEndsTheRegistration()
    {
        using var gone = new RegWorld();
        var parentSession = gone.Start();
        gone.World.Processes.Set(gone.World.Parent, ProcessLiveness.Dead);
        Assert.Equal(LocalRpcRegistrationRefusal.LaunchRefused, parentSession.TryChallenge());
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, parentSession.Registration.EndReason);

        using var child = new RegWorld();
        var childSession = child.Start();
        var process = child.World.SpawnFake(7001);
        childSession.Launch.BindChild(process);
        child.World.Processes.Set(process, ProcessLiveness.Dead);
        Assert.Equal(LocalRpcRegistrationRefusal.LaunchRefused, childSession.TryChallenge());
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, childSession.Registration.EndReason);
    }

    [Fact]
    public void ChallengesPendingAreBoundedOnePerConnection()
    {
        using var world = new RegWorld();
        var session = world.Start();
        for (var index = 0; index < LocalRpcRegistration.MaximumPendingChallenges; index++)
        {
            Assert.Equal(LocalRpcRegistrationRefusal.None, session.TryChallenge("c" + index));
        }

        Assert.Equal(LocalRpcRegistrationRefusal.InvalidRequest, session.TryChallenge("overflow"));
        // A connection that already holds a challenge may replace it even when the table is full.
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.TryChallenge("c0"));
        // Challenges that outlived their five seconds make room.
        world.Clock.Advance(TimeSpan.FromSeconds(5));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.TryChallenge("overflow"));
    }

    [Fact]
    public void ChallengeAndConfirmAreRefusedOnceTheChildRegistered()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var pending = session.Challenge("c2");
        var grant = session.Register();

        Assert.Equal(LocalRpcRegistrationRefusal.NotAwaitingBootstrap, session.TryChallenge("c3"));
        Assert.Equal(LocalRpcRegistrationRefusal.NotAwaitingBootstrap, session.Confirm(pending, connection: "c2"));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Authorize(grant));
    }

    // ---- the confirmation

    [Fact]
    public void AMatchingProofRegistersTheChildWithAThirtySecondLeaseAndSpendsTheSecret()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var now = world.Clock.GetUtcNow();

        var grant = session.Register();

        Assert.Equal(LocalRpcRegistrationState.Registered, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.None, session.Registration.EndReason);
        Assert.Equal(32, grant.PeerNonce.Length);
        Assert.Contains(grant.PeerNonce.ToArray(), value => value != 0);
        Assert.Equal(now + TimeSpan.FromSeconds(30), grant.ExpiresAtUtc);
        Assert.Equal(grant.ExpiresAtUtc, session.Registration.LeaseExpiresAtUtc);
        Assert.True(session.Launch.SecretIsZeroed());
        Assert.Equal(LocalRpcLaunchRefusal.None, session.Launch.Status());
        Assert.False(session.Registration.Ended.IsCancellationRequested);
        Assert.Equal(1, world.Clock.PendingTimers);
    }

    [Fact]
    public void TheGrantedNonceIsFreshForEveryRegistration()
    {
        using var world = new RegWorld();
        var first = world.Start("slot-a").Register();
        var second = world.Start("slot-b").Register();

        Assert.False(first.PeerNonce.Span.SequenceEqual(second.PeerNonce.Span));
    }

    [Fact]
    public void AProofThatDoesNotMatchRevokesTheLaunchAndTheChildMustBeRelaunched()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var claim = session.Launch.Descriptor.ToClaim();
        var challenge = session.Challenge();
        var proof = session.Proof(challenge);
        proof[0] ^= 0x01;

        var refusal = session.Confirm(challenge, proof);

        Assert.Equal(LocalRpcRegistrationRefusal.ProofRejected, refusal);
        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.ProofRejected, session.Registration.EndReason);
        Assert.True(session.Registration.Ended.IsCancellationRequested);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, session.Launch.Status());
        Assert.True(session.Launch.Revoked.IsCancellationRequested);
        Assert.True(session.Launch.SecretIsZeroed());
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, world.Authority.Verify(claim));
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.TryChallenge());
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.Confirm(challenge));
        Assert.Equal(0, world.Clock.PendingTimers);
    }

    public static TheoryData<string> WrongTranscripts() =>
        new() { "challenge-id", "client-bytes", "server-bytes", "client-instance", "server-instance", "secret", "empty", "short", "long", "all-zero" };

    [Theory]
    [MemberData(nameof(WrongTranscripts))]
    public void AProofOverAnyOtherTranscriptOrSecretIsRejected(string wrong)
    {
        using var world = new RegWorld();
        var session = world.Start();
        var challenge = session.Challenge();
        var secret = session.Secret;
        var proof = wrong switch
        {
            "challenge-id" => LocalBootstrapProof.Compute(secret, Guid.NewGuid(), session.ClientBytes, challenge.ServerChallenge.Span, session.Instance, challenge.ServerInstanceId),
            "client-bytes" => LocalBootstrapProof.Compute(secret, challenge.ChallengeId, Launches.Flip(session.ClientBytes), challenge.ServerChallenge.Span, session.Instance, challenge.ServerInstanceId),
            "server-bytes" => LocalBootstrapProof.Compute(secret, challenge.ChallengeId, session.ClientBytes, Launches.Flip(challenge.ServerChallenge), session.Instance, challenge.ServerInstanceId),
            "client-instance" => LocalBootstrapProof.Compute(secret, challenge.ChallengeId, session.ClientBytes, challenge.ServerChallenge.Span, Guid.NewGuid(), challenge.ServerInstanceId),
            "server-instance" => LocalBootstrapProof.Compute(secret, challenge.ChallengeId, session.ClientBytes, challenge.ServerChallenge.Span, session.Instance, Guid.NewGuid()),
            "secret" => LocalBootstrapProof.Compute(Launches.Flip(secret), challenge.ChallengeId, session.ClientBytes, challenge.ServerChallenge.Span, session.Instance, challenge.ServerInstanceId),
            "empty" => [],
            "short" => session.Proof(challenge)[..31],
            "long" => [.. session.Proof(challenge), 0],
            _ => new byte[32],
        };

        Assert.Equal(LocalRpcRegistrationRefusal.ProofRejected, session.Confirm(challenge, proof));
        Assert.Equal(LocalRpcRegistrationEnd.ProofRejected, session.Registration.EndReason);
    }

    [Fact]
    public void AnOversizedProofIsRejectedWithoutBeingCopiedWholeAndRevokesTheLaunch()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var challenge = session.Challenge();

        Assert.Equal(LocalRpcRegistrationRefusal.ProofRejected, session.Confirm(challenge, new byte[1_000_000]));
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, session.Launch.Status());
    }

    [Fact]
    public void AConfirmOnAnotherConnectionIsRefusedWithoutSpendingTheSecret()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var challenge = session.Challenge("c1");

        Assert.Equal(LocalRpcRegistrationRefusal.NoChallenge, session.Confirm(challenge, connection: "c2"));

        Assert.False(session.Launch.SecretIsZeroed());
        Assert.Equal(LocalRpcRegistrationState.AwaitingBootstrap, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Confirm(challenge, connection: "c1"));
    }

    [Fact]
    public void AConfirmNamingAnotherChallengeIdIsRefusedWithoutSpendingTheSecretOrTheChallenge()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var challenge = session.Challenge();

        var refusal = session.Registration.TryConfirm("c1", Guid.NewGuid(), session.Proof(challenge), TestContext.Current.CancellationToken, out _);

        Assert.Equal(LocalRpcRegistrationRefusal.NoChallenge, refusal);
        Assert.False(session.Launch.SecretIsZeroed());
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Confirm(challenge));
    }

    [Fact]
    public void AConfirmWithoutAnyChallengeIsRefusedWithoutSpendingTheSecret()
    {
        using var world = new RegWorld();
        var session = world.Start();

        var refusal = session.Registration.TryConfirm("c1", Guid.NewGuid(), new byte[32], TestContext.Current.CancellationToken, out _);

        Assert.Equal(LocalRpcRegistrationRefusal.NoChallenge, refusal);
        Assert.False(session.Launch.SecretIsZeroed());
        _ = session.Register();
    }

    [Fact]
    public void AChallengeIsUsedOnceAndAConfirmationCannotBeReplayed()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var challenge = session.Challenge();
        var proof = session.Proof(challenge);

        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Confirm(challenge, proof));

        Assert.Equal(LocalRpcRegistrationRefusal.NotAwaitingBootstrap, session.Confirm(challenge, proof));
        Assert.Equal(LocalRpcRegistrationState.Registered, session.Registration.State);
    }

    [Fact]
    public void AChallengeConfirmedJustBeforeItsFiveSecondsAreUpStillRegisters()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var challenge = session.Challenge();

        world.Clock.Advance(TimeSpan.FromSeconds(5) - TimeSpan.FromTicks(1));

        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Confirm(challenge));
    }

    [Fact]
    public void AChallengeIsDeadAtItsFifthSecondAndAnExpiredOneNeverSpendsTheSecret()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var challenge = session.Challenge();
        world.Clock.Advance(TimeSpan.FromSeconds(5));

        Assert.Equal(LocalRpcRegistrationRefusal.ChallengeExpired, session.Confirm(challenge));

        Assert.False(session.Launch.SecretIsZeroed());
        Assert.Equal(LocalRpcRegistrationState.AwaitingBootstrap, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationRefusal.NoChallenge, session.Confirm(challenge));
        _ = session.Register();
    }

    [Fact]
    public void AChallengeExpiresOnTheWallClockAloneAndOnTheMonotonicClockAlone()
    {
        using var wall = new RegWorld();
        var onWall = wall.Start();
        var challenge = onWall.Challenge();
        wall.Clock.StepWallClock(TimeSpan.FromSeconds(5));
        Assert.Equal(LocalRpcRegistrationRefusal.ChallengeExpired, onWall.Confirm(challenge));

        using var monotonic = new RegWorld();
        monotonic.Clock.SuspendTimers = true;
        var onMonotonic = monotonic.Start();
        var other = onMonotonic.Challenge();
        monotonic.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(5));
        Assert.Equal(LocalRpcRegistrationRefusal.ChallengeExpired, onMonotonic.Confirm(other));
    }

    [Fact]
    public void AConfirmAfterTheBootstrapWindowRefusesEndsTheRegistrationAndNeverRegisters()
    {
        using var world = new RegWorld(TimeSpan.FromSeconds(1));
        var session = world.Start();
        var challenge = session.Challenge();
        var proof = session.Proof(challenge);

        world.Clock.Advance(TimeSpan.FromSeconds(1));

        Assert.Equal(LocalRpcRegistrationRefusal.LaunchRefused, session.Confirm(challenge, proof));
        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, session.Registration.EndReason);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, session.Launch.Status());
    }

    [Fact]
    public void ALaunchRevokedWhileTheConfirmationRunsNeverRegisters()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var challenge = session.Challenge();
        var proof = session.Proof(challenge);
        session.Launch.Revoke();

        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.Confirm(challenge, proof));
        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
    }

    [Fact]
    public async Task AConcurrentConfirmationIsRefusedWithoutRevokingTheLaunchAndTheFirstOneRegisters()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var first = session.Challenge("c1");
        var second = session.Challenge("c2");
        var firstProof = session.Proof(first);
        var secondProof = session.Proof(second);
        using var pause = new ManualResetEventSlim();
        using var entered = new ManualResetEventSlim();
        var armed = 1;
        // The first confirmation blocks inside the launch (its status probe) while it holds the confirmation.
        world.ProbeHook = identity =>
        {
            if (Interlocked.Exchange(ref armed, 0) == 1)
            {
                entered.Set();
                _ = pause.Wait(TimeSpan.FromSeconds(30));
            }

            _ = identity;
        };

        var running = Task.Run(() => session.Confirm(first, firstProof, "c1"), TestContext.Current.CancellationToken);
        Assert.True(entered.Wait(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken));
        var concurrent = session.Confirm(second, secondProof, "c2");
        pause.Set();

        Assert.Equal(LocalRpcRegistrationRefusal.NotAwaitingBootstrap, concurrent);
        Assert.Equal(LocalRpcRegistrationRefusal.None, await running);
        Assert.Equal(LocalRpcRegistrationState.Registered, session.Registration.State);
        Assert.Equal(LocalRpcLaunchRefusal.None, session.Launch.Status());
    }

    [Fact]
    public async Task TwoChildrenConfirmingAtOnceNeverBothRegisterAndNeverRevokeTheWinner()
    {
        for (var round = 0; round < 60; round++)
        {
            using var world = new RegWorld();
            var session = world.Start();
            var first = session.Challenge("c1");
            var second = session.Challenge("c2");
            var firstProof = session.Proof(first);
            var secondProof = session.Proof(second);
            using var barrier = new Barrier(2);

            var results = await Task.WhenAll(
                Task.Run(() => { barrier.SignalAndWait(); return session.Confirm(first, firstProof, "c1"); }, TestContext.Current.CancellationToken),
                Task.Run(() => { barrier.SignalAndWait(); return session.Confirm(second, secondProof, "c2"); }, TestContext.Current.CancellationToken));

            Assert.Single(results, LocalRpcRegistrationRefusal.None);
            Assert.Equal(LocalRpcRegistrationState.Registered, session.Registration.State);
            Assert.Equal(LocalRpcLaunchRefusal.None, session.Launch.Status());
        }
    }

    // ---- the lease

    [Fact]
    public void TheLeaseHoldsUntilTheThirtiethSecondAndNotBeyond()
    {
        using var world = new RegWorld();
        world.Clock.SuspendTimers = true;
        var session = world.Start();
        var grant = session.Register();

        world.Clock.Advance(TimeSpan.FromSeconds(30) - TimeSpan.FromTicks(1));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Authorize(grant));

        world.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.Equal(LocalRpcRegistrationRefusal.LeaseExpired, session.Authorize(grant));
        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, session.Registration.EndReason);
        Assert.True(session.Registration.Ended.IsCancellationRequested);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, session.Launch.Status());
    }

    [Fact]
    public void TheLeaseExpiresOnTheMonotonicClockAloneAndOnTheWallClockAlone()
    {
        using var monotonic = new RegWorld();
        monotonic.Clock.SuspendTimers = true;
        var onMonotonic = monotonic.Start();
        var grant = onMonotonic.Register();
        monotonic.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(30));
        Assert.Equal(LocalRpcRegistrationRefusal.LeaseExpired, onMonotonic.Authorize(grant));

        using var wall = new RegWorld();
        wall.Clock.SuspendTimers = true;
        var onWall = wall.Start();
        var other = onWall.Register();
        wall.Clock.StepWallClock(TimeSpan.FromSeconds(30));
        Assert.Equal(LocalRpcRegistrationRefusal.LeaseExpired, onWall.Authorize(other));
    }

    [Fact]
    public void AnExpiredRegistrationIsNeverRevivedByTheClockGoingBackOrByARenewal()
    {
        using var world = new RegWorld();
        world.Clock.SuspendTimers = true;
        var session = world.Start();
        var grant = session.Register();
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(1), out _));
        world.Clock.Advance(TimeSpan.FromSeconds(40));
        Assert.Equal(LocalRpcRegistrationRefusal.LeaseExpired, session.Authorize(grant));

        world.Clock.StepWallClock(-TimeSpan.FromHours(1));

        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.Authorize(grant));
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.Renew(Command(1), out _));
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.Renew(Command(2), out _));
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.TryChallenge());
    }

    [Fact]
    public void TheWatchdogEndsAnUnrenewedRegistrationAtItsExpiryWithoutAnyCall()
    {
        using var world = new RegWorld();
        var session = world.Start();
        _ = session.Register();

        world.Clock.Advance(TimeSpan.FromSeconds(30));

        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, session.Registration.EndReason);
        Assert.True(session.Registration.Ended.IsCancellationRequested);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, session.Launch.Status());
        Assert.Equal(0, world.Clock.PendingTimers);
    }

    [Fact]
    public void AWatchdogThatFiresEarlyReArmsForTheRemainderAndStillEndsTheRegistration()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var grant = session.Register();
        world.Clock.Advance(TimeSpan.FromSeconds(20));
        Assert.Equal(1, world.Clock.PendingTimers);

        world.Clock.FireNextEarly();

        Assert.Equal(LocalRpcRegistrationState.Registered, session.Registration.State);
        Assert.Equal(1, world.Clock.PendingTimers);
        Assert.Equal(TimeSpan.FromSeconds(10), world.Clock.NextDueIn());
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Authorize(grant));
        world.Clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, session.Registration.EndReason);
    }

    [Fact]
    public void AnEarlyWatchdogReArmsForTheNearerOfTheTwoClocksRemainders()
    {
        // The wall clock is 20 s ahead, the monotonic clock has not moved: the wall deadline is the nearer one.
        using var wall = new RegWorld();
        var onWall = wall.Start();
        _ = onWall.Register();
        wall.Clock.StepWallClock(TimeSpan.FromSeconds(20));
        wall.Clock.FireNextEarly();
        Assert.Equal(LocalRpcRegistrationState.Registered, onWall.Registration.State);
        Assert.Equal(TimeSpan.FromSeconds(10), wall.Clock.NextDueIn());

        // The monotonic clock is 20 s ahead, the wall clock has not moved: the monotonic deadline is the nearer one.
        using var monotonic = new RegWorld();
        var onMonotonic = monotonic.Start();
        _ = onMonotonic.Register();
        monotonic.Clock.SuspendTimers = true;
        monotonic.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(20));
        monotonic.Clock.FireNextEarly();
        Assert.Equal(LocalRpcRegistrationState.Registered, onMonotonic.Registration.State);
        Assert.Equal(TimeSpan.FromSeconds(10), monotonic.Clock.NextDueIn());
    }

    [Fact]
    public void ARenewalMovesTheWatchdogToThirtySecondsFromTheRenewal()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var grant = session.Register();
        world.Clock.Advance(TimeSpan.FromSeconds(10));

        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(1), out _));

        Assert.Equal(TimeSpan.FromSeconds(30), world.Clock.NextDueIn());
        world.Clock.Advance(TimeSpan.FromSeconds(30) - TimeSpan.FromTicks(1));
        Assert.Equal(LocalRpcRegistrationState.Registered, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Authorize(grant));
        world.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, session.Registration.EndReason);
    }

    [Fact]
    public async Task ADisposedRegistrationStopsItsWatchdogRevokesTheLaunchAndDisposesTwice()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var grant = session.Register();

        await session.Registration.DisposeAsync();
        await session.Registration.DisposeAsync();

        Assert.Equal(0, world.Clock.PendingTimers);
        Assert.Equal(LocalRpcRegistrationEnd.Disposed, session.Registration.EndReason);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, session.Launch.Status());
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.Authorize(grant));
    }

    // ---- the renewal

    internal static byte[] Command(byte value) => Launches.Bytes(value, 16);

    [Fact]
    public void ARenewalExtendsTheLeaseToThirtySecondsFromTheRenewalAndNeverShortensIt()
    {
        using var world = new RegWorld();
        world.Clock.SuspendTimers = true;
        var session = world.Start();
        var grant = session.Register();
        var start = world.Clock.GetUtcNow();

        world.Clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(1), out var first));
        Assert.Equal(start + TimeSpan.FromSeconds(40), first);

        world.Clock.Advance(TimeSpan.FromSeconds(19));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(2), out var second));
        Assert.Equal(start + TimeSpan.FromSeconds(59), second);
        Assert.Equal(second, session.Registration.LeaseExpiresAtUtc);

        // An immediate second renewal can only move the expiry forward (or keep it), never back.
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(3), out var third));
        Assert.True(third >= second);

        world.Clock.Advance(TimeSpan.FromSeconds(30) - TimeSpan.FromTicks(1));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Authorize(grant));
        world.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.Equal(LocalRpcRegistrationRefusal.LeaseExpired, session.Authorize(grant));
    }

    [Fact]
    public void ARenewalAfterTheWallClockWasSteppedBackKeepsTheLaterWallDeadline()
    {
        using var world = new RegWorld();
        var session = world.Start();
        _ = session.Register();
        var start = world.Clock.GetUtcNow();
        world.Clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(1), out _));

        world.Clock.StepWallClock(-TimeSpan.FromSeconds(5));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(2), out var expiry));

        // The wall clock now reads 5 s earlier, so thirty seconds from now would be earlier than the deadline already granted.
        Assert.Equal(start + TimeSpan.FromSeconds(40), expiry);
    }

    [Fact]
    public void ADuplicateRenewalCommandReturnsTheRecordedExpiryWithoutExtendingAgain()
    {
        using var world = new RegWorld();
        world.Clock.SuspendTimers = true;
        var session = world.Start();
        var grant = session.Register();
        world.Clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(1), out var recorded));

        world.Clock.Advance(TimeSpan.FromSeconds(5));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(1), out var duplicate));

        Assert.Equal(recorded, duplicate);
        Assert.Equal(recorded, session.Registration.LeaseExpiresAtUtc);
        world.Clock.Advance(TimeSpan.FromSeconds(25) - TimeSpan.FromTicks(1));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Authorize(grant));
        world.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.Equal(LocalRpcRegistrationRefusal.LeaseExpired, session.Authorize(grant));
    }

    [Fact]
    public void AFreshRenewalCommandExtendsAgain()
    {
        using var world = new RegWorld();
        var session = world.Start();
        _ = session.Register();
        world.Clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(1), out var first));

        world.Clock.Advance(TimeSpan.FromSeconds(5));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(2), out var second));

        Assert.Equal(first + TimeSpan.FromSeconds(5), second);
    }

    [Fact]
    public void OnlyTheLastSixteenRenewalCommandsAreRemembered()
    {
        using var world = new RegWorld();
        var session = world.Start();
        _ = session.Register();
        DateTimeOffset last = default;
        for (byte id = 1; id <= 17; id++)
        {
            world.Clock.Advance(Second);
            Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(id), out last));
        }

        world.Clock.Advance(Second);
        // The newest command is remembered: it returns its recorded expiry and does not extend.
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(17), out var replayNewest));
        Assert.Equal(last, replayNewest);
        // The oldest was forgotten (the first of seventeen): it is a new command and extends from now.
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(1), out var replayOldest));
        Assert.Equal(last + Second, replayOldest);
        // Inserting it pushed out the next oldest (command 2): that one is new again and extends from now.
        world.Clock.Advance(Second);
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(2), out var replayNext));
        Assert.Equal(replayOldest + Second, replayNext);
        // Command 4 is still remembered: it returns the expiry recorded when it was first seen and extends nothing.
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(4), out var stillRemembered));
        Assert.True(stillRemembered < replayNext);
        Assert.Equal(replayNext, session.Registration.LeaseExpiresAtUtc);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(32, true)]
    [InlineData(33, false)]
    public void ARenewalNeedsACommandIdOfOneToThirtyTwoBytes(int length, bool accepted)
    {
        using var world = new RegWorld();
        var session = world.Start();
        _ = session.Register();

        var refusal = session.Renew(new byte[length], out _);

        Assert.Equal(accepted ? LocalRpcRegistrationRefusal.None : LocalRpcRegistrationRefusal.InvalidRequest, refusal);
    }

    [Fact]
    public void ARenewalBeforeRegistrationOrOnAnotherConnectionIsRefusedAndExtendsNothing()
    {
        using var world = new RegWorld();
        var session = world.Start();
        Assert.Equal(LocalRpcRegistrationRefusal.NotRegistered, session.Renew(Command(1), out _));
        var grant = session.Register();
        world.Clock.Advance(TimeSpan.FromSeconds(10));

        Assert.Equal(LocalRpcRegistrationRefusal.WrongConnection, session.Renew(Command(1), out _, connection: "c2"));

        Assert.Equal(grant.ExpiresAtUtc, session.Registration.LeaseExpiresAtUtc);
    }

    [Fact]
    public void OrdinaryCallsNeverExtendTheLease()
    {
        using var world = new RegWorld();
        world.Clock.SuspendTimers = true;
        var session = world.Start();
        var grant = session.Register();
        foreach (var seconds in new[] { 10, 10, 9 })
        {
            world.Clock.Advance(TimeSpan.FromSeconds(seconds));
            Assert.Equal(LocalRpcRegistrationRefusal.None, session.Authorize(grant));
        }

        world.Clock.Advance(Second);

        Assert.Equal(LocalRpcRegistrationRefusal.LeaseExpired, session.Authorize(grant));
    }

    // ---- the credentials of a call

    public static TheoryData<string> WrongCredentials() =>
        new() { "nonce", "nonce-short", "nonce-long", "nonce-empty", "nonce-zero", "instance", "instance-empty", "contract", "contract-short", "contract-empty", "connection" };

    [Theory]
    [MemberData(nameof(WrongCredentials))]
    public void EveryCredentialIsRequiredOnTheRegisteredConnection(string wrong)
    {
        using var world = new RegWorld();
        var session = world.Start();
        var grant = session.Register();
        var nonce = grant.PeerNonce.ToArray();
        var contract = session.Identity.ContractSetDigest.ToArray();

        var refusal = wrong switch
        {
            "nonce" => session.Authorize(grant, nonce: Launches.Flip(nonce)),
            "nonce-short" => session.Authorize(grant, nonce: nonce[..31]),
            "nonce-long" => session.Authorize(grant, nonce: [.. nonce, 0]),
            "nonce-empty" => session.Authorize(grant, nonce: []),
            "nonce-zero" => session.Authorize(grant, nonce: new byte[32]),
            "instance" => session.Authorize(grant, instance: Guid.NewGuid()),
            "instance-empty" => session.Authorize(grant, instance: Guid.Empty),
            "contract" => session.Authorize(grant, contractSet: Launches.Flip(contract)),
            "contract-short" => session.Authorize(grant, contractSet: contract[..31]),
            "contract-empty" => session.Authorize(grant, contractSet: []),
            _ => session.Authorize(grant, connection: "c2"),
        };

        Assert.Equal(wrong == "connection" ? LocalRpcRegistrationRefusal.WrongConnection : LocalRpcRegistrationRefusal.BadCredentials, refusal);
        // A refused call never ends the registration or the lease: the right credentials still work.
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Authorize(grant));
        Assert.Equal(LocalRpcRegistrationState.Registered, session.Registration.State);
    }

    [Fact]
    public void ACallBeforeRegistrationIsRefusedEvenWithAPendingChallenge()
    {
        using var world = new RegWorld();
        var session = world.Start();
        _ = session.Challenge();

        var refusal = session.Registration.Authorize("c1", new byte[32], session.Instance, session.Identity.ContractSetDigest.Span);

        Assert.Equal(LocalRpcRegistrationRefusal.NotRegistered, refusal);
    }

    [Fact]
    public void AnEndedRegistrationRefusesEvenTheRightCredentials()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var grant = session.Register();

        session.Launch.Revoke();

        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.Authorize(grant));
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, session.Registration.EndReason);
    }

    [Fact]
    public void ACallAfterTheParentOrTheBoundChildProcessEndedRefusesAndEndsTheRegistration()
    {
        using var gone = new RegWorld();
        var parentSession = gone.Start();
        var parentGrant = parentSession.Register();
        gone.World.Processes.Set(gone.World.Parent, ProcessLiveness.Dead);
        Assert.Equal(LocalRpcRegistrationRefusal.LaunchRefused, parentSession.Authorize(parentGrant));
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, parentSession.Registration.EndReason);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, parentSession.Launch.Status());

        using var child = new RegWorld();
        var childSession = child.Start();
        var process = child.World.SpawnFake(7002);
        childSession.Launch.BindChild(process);
        var childGrant = childSession.Register();
        Assert.Equal(LocalRpcRegistrationRefusal.None, childSession.Authorize(childGrant));
        child.World.Processes.Set(process, ProcessLiveness.Dead);
        Assert.Equal(LocalRpcRegistrationRefusal.LaunchRefused, childSession.Authorize(childGrant));
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, childSession.Registration.EndReason);
    }

    // ---- epoch fencing, relaunch and parent restart

    [Fact]
    public void ARelaunchEndsTheOldRegistrationAtOnceAndTheOldChildNeverCallsAgain()
    {
        using var world = new RegWorld();
        var old = world.Start();
        var oldGrant = old.Register();
        Assert.Equal(LocalRpcRegistrationRefusal.None, old.Authorize(oldGrant));

        var next = world.Start();

        Assert.Equal(old.Launch.Descriptor.Epoch + 1, next.Launch.Descriptor.Epoch);
        Assert.Equal(LocalRpcRegistrationState.Ended, old.Registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, old.Registration.EndReason);
        Assert.True(old.Registration.Ended.IsCancellationRequested);
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, old.Authorize(oldGrant));
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, old.Renew(Command(1), out _));
        Assert.Equal(LocalRpcLaunchRefusal.StaleEpoch, world.Authority.Verify(old.Launch.Descriptor.ToClaim()));
        // Nothing of the old grant is inherited: the new epoch registers from scratch with its own secret and nonce.
        var nextGrant = next.Register();
        Assert.False(oldGrant.PeerNonce.Span.SequenceEqual(nextGrant.PeerNonce.Span));
        Assert.Equal(LocalRpcRegistrationRefusal.BadCredentials, next.Authorize(oldGrant, nonce: oldGrant.PeerNonce.ToArray()));
        Assert.Equal(LocalRpcRegistrationRefusal.None, next.Authorize(nextGrant));
    }

    [Fact]
    public void TheOldEpochsSecretCannotRegisterTheNewEpoch()
    {
        using var world = new RegWorld();
        var old = world.Start();
        var next = world.Start();
        var challenge = next.Challenge();
        var proofWithTheOldSecret = LocalBootstrapProof.Compute(old.Secret, challenge.ChallengeId, next.ClientBytes, challenge.ServerChallenge.Span, next.Instance, challenge.ServerInstanceId);

        Assert.Equal(LocalRpcRegistrationRefusal.ProofRejected, next.Confirm(challenge, proofWithTheOldSecret));
    }

    [Fact]
    public void ARestartedParentRequiresFreshGrantsAndNothingOfTheOldRunAuthorizesAnything()
    {
        using var world = new RegWorld();
        var before = world.Start();
        var oldGrant = before.Register();
        var oldClaim = before.Launch.Descriptor.ToClaim();

        // The parent process dies. A restarted parent is a new process: new identity, a new authority with its own epochs.
        world.World.Processes.Set(world.World.Parent, ProcessLiveness.Dead);
        Assert.Equal(LocalRpcRegistrationRefusal.LaunchRefused, before.Authorize(oldGrant));
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, before.Registration.EndReason);

        var restarted = world.World.SpawnFake(4343);
        using var after = new RegWorld(parent: restarted);
        var fresh = after.Start();

        // The restarted authority starts at epoch 1 again, so the epoch number alone fences nothing; every other part differs.
        Assert.Equal(before.Launch.Descriptor.Epoch, fresh.Launch.Descriptor.Epoch);
        Assert.NotEqual(before.Launch.Descriptor.LaunchId, fresh.Launch.Descriptor.LaunchId);
        Assert.False(before.Launch.Descriptor.Nonce.Span.SequenceEqual(fresh.Launch.Descriptor.Nonce.Span));
        Assert.NotEqual(before.Registration.ParentInstanceId, fresh.Registration.ParentInstanceId);
        Assert.NotEqual(LocalRpcLaunchRefusal.None, after.Authority.Verify(oldClaim));
        // Without a fresh confirmation nothing is granted: the old nonce and the old secret's proof do not register or call.
        Assert.Equal(LocalRpcRegistrationRefusal.NotRegistered, fresh.Authorize(oldGrant));
        var challenge = fresh.Challenge();
        var oldProof = LocalBootstrapProof.Compute(before.Secret, challenge.ChallengeId, fresh.ClientBytes, challenge.ServerChallenge.Span, fresh.Instance, challenge.ServerInstanceId);
        Assert.Equal(LocalRpcRegistrationRefusal.ProofRejected, fresh.Confirm(challenge, oldProof));
    }

    [Fact]
    public async Task ARegistrationOfAnAlreadyRevokedLaunchIsBornEnded()
    {
        using var world = new RegWorld();
        var launch = world.Authority.Launch("slot-a", world.Identity, LocalRpcLaunchTransport.SuppliedStreams);
        launch.Revoke();

        await using var registration = LocalRpcRegistration.Create(launch);

        Assert.Equal(LocalRpcRegistrationState.Ended, registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, registration.EndReason);
        Assert.True(registration.Ended.IsCancellationRequested);
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, registration.TryChallenge("c1", Guid.NewGuid(), new byte[32], world.Identity, out _));
    }

    // ---- the connection

    [Fact]
    public void ALostRegisteredConnectionEndsTheRegistrationAndRevokesTheLaunch()
    {
        using var world = new RegWorld();
        var session = world.Start();
        using var closed = new CancellationTokenSource();
        var grant = session.Register(closed: closed);

        closed.Cancel();

        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.ConnectionLost, session.Registration.EndReason);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, session.Launch.Status());
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.Authorize(grant));
    }

    [Fact]
    public void AConnectionThatClosedBeforeTheConfirmationFinishedEndsTheRegistrationAtOnce()
    {
        using var world = new RegWorld();
        var session = world.Start();
        using var closed = new CancellationTokenSource();
        closed.Cancel();

        var challenge = session.Challenge();
        var refusal = session.Registration.TryConfirm("c1", challenge.ChallengeId, session.Proof(challenge), closed.Token, out var grant);

        Assert.Equal(LocalRpcRegistrationRefusal.None, refusal);
        Assert.NotNull(grant);
        Assert.Equal(LocalRpcRegistrationEnd.ConnectionLost, session.Registration.EndReason);
    }

    [Fact]
    public void ClosingAnotherConnectionDoesNotEndTheRegistrationButDropsItsPendingChallenge()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var other = session.Challenge("c2");
        var grant = session.Register("c1");

        session.Registration.NotifyConnectionClosed("c2");
        session.Registration.NotifyConnectionClosed("c3");

        Assert.Equal(LocalRpcRegistrationState.Registered, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Authorize(grant));
        _ = other;

        using var second = new RegWorld();
        var pending = second.Start();
        var challenge = pending.Challenge("c2");
        pending.Registration.NotifyConnectionClosed("c2");
        Assert.Equal(LocalRpcRegistrationRefusal.NoChallenge, pending.Confirm(challenge, connection: "c2"));
    }

    [Fact]
    public async Task ARegistrationAdmitsConnectionsOnlyUntilTheChildRegistered()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var info = new LocalRpcConnectionInfo(LocalRpcTransport.UnixDomainSocket, 1);
        var foreign = new LocalRpcConnectionInfo(LocalRpcTransport.UnixDomainSocket, 2, LocalRpcEndpoint.CreateForVerification(LocalRpcTransport.UnixDomainSocket, Path.Combine(world.World.Root, "x")));

        Assert.True(await session.Registration.AuthorizeConnectionAsync(info, TestContext.Current.CancellationToken));
        Assert.False(await session.Registration.AuthorizeConnectionAsync(foreign, TestContext.Current.CancellationToken));

        var grant = session.Register();
        Assert.False(await session.Registration.AuthorizeConnectionAsync(info, TestContext.Current.CancellationToken));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Authorize(grant));

        using var ended = new RegWorld();
        var gone = ended.Start();
        gone.Launch.Revoke();
        Assert.False(await gone.Registration.AuthorizeConnectionAsync(info, TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<ArgumentNullException>(async () => await session.Registration.AuthorizeConnectionAsync(null!, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void ARegistrationServesOneServer()
    {
        using var world = new RegWorld();
        var session = world.Start();

        session.Registration.BindToServer();

        _ = Assert.Throws<InvalidOperationException>(session.Registration.BindToServer);
    }

    [Fact]
    public void EndingARegistrationDestroysItsNonceAndItsRenewalMemoryAndRegisteringDropsOtherChallenges()
    {
        using var world = new RegWorld();
        var session = world.Start();
        _ = session.Challenge("c2");
        Assert.Equal(1, session.Registration.HeldState().Challenges);
        var grant = session.Register();
        Assert.Equal(0, session.Registration.HeldState().Challenges);
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Renew(Command(1), out _));
        Assert.Equal((0, 1), session.Registration.HeldState());
        Assert.False(session.Registration.GrantedNonceIsZeroed());

        session.Launch.Revoke();

        Assert.True(session.Registration.GrantedNonceIsZeroed());
        Assert.Equal((0, 0), session.Registration.HeldState());
        Assert.Contains(grant.PeerNonce.ToArray(), value => value != 0);
    }

    [Fact]
    public void WhatTheRegistrationHandsOutIsACopyThatCannotChangeItsOwnState()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var challenge = session.Challenge();
        var serverBytes = challenge.ServerChallenge.ToArray();
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(challenge.ServerChallenge, out var challengeArray));
        Array.Clear(challengeArray.Array!);

        // The proof still has to be over the parent's real bytes, whatever the caller did to the array it received.
        var proof = LocalBootstrapProof.Compute(session.Secret, challenge.ChallengeId, session.ClientBytes, serverBytes, session.Instance, challenge.ServerInstanceId);
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Confirm(challenge, proof));
        var grant = session.Registration.LeaseExpiresAtUtc;
        Assert.NotNull(grant);

        using var other = new RegWorld();
        var second = other.Start();
        var granted = second.Register();
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(granted.PeerNonce, out var nonceArray));
        var nonce = granted.PeerNonce.ToArray();
        Array.Clear(nonceArray.Array!);
        Assert.Equal(LocalRpcRegistrationRefusal.None, second.Registration.Authorize("c1", nonce, second.Instance, second.Identity.ContractSetDigest.Span));
    }

    [Fact]
    public void ARenewalOnACallThatCarriedNoVerifiedCredentialsIsRefused()
    {
        using var world = new RegWorld();
        var session = world.Start();
        _ = session.Register();
        var unverified = new LocalRpcBootstrapCall(session.Registration, "c1", credentialsVerified: false, TestContext.Current.CancellationToken);
        var verified = new LocalRpcBootstrapCall(session.Registration, "c1", credentialsVerified: true, TestContext.Current.CancellationToken);

        Assert.Equal(LocalRpcRegistrationRefusal.NotRegistered, unverified.TryRenew(Command(1), out var refusedExpiry));
        Assert.Equal(default, refusedExpiry);
        Assert.Equal(LocalRpcRegistrationRefusal.None, verified.TryRenew(Command(1), out var expiry));
        Assert.NotEqual(default, expiry);
        Assert.Same(session.Registration, verified.Registration);
    }

    // ---- ending is safe

    [Fact]
    [SuppressMessage("Design", "CA1031", Justification = "The callback deliberately throws.")]
    public void AnEndedCallbackThatThrowsNeverReachesTheCodeThatEndedTheRegistration()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var grant = session.Register();
        _ = session.Registration.Ended.Register(() => throw new InvalidOperationException("owner callback failure"));

        world.Clock.Advance(TimeSpan.FromSeconds(30));

        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, session.Registration.EndReason);
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, session.Authorize(grant));
    }

    [Fact]
    public void AnEndedCallbackThatNeedsAnotherThreadToUseTheRegistrationDoesNotDeadlock()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var grant = session.Register();
        var observed = new ManualResetEventSlim();
        _ = session.Registration.Ended.Register(() =>
        {
            // Another thread asks the registration while this callback runs: nothing may hold the registration's lock across the callback.
            var state = Task.Run(() => session.Registration.State).Wait(TimeSpan.FromSeconds(20));
            var refusal = Task.Run(() => session.Authorize(grant)).Wait(TimeSpan.FromSeconds(20));
            if (state && refusal)
            {
                observed.Set();
            }
        });

        world.Clock.Advance(TimeSpan.FromSeconds(30));

        Assert.True(observed.IsSet);
        observed.Dispose();
    }

    [Fact]
    public void ALaunchRevokedCallbackThatNeedsTheRegistrationDoesNotDeadlock()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var grant = session.Register();
        var observed = new ManualResetEventSlim();
        _ = session.Launch.Revoked.Register(() =>
        {
            if (Task.Run(() => session.Authorize(grant)).Wait(TimeSpan.FromSeconds(20)))
            {
                observed.Set();
            }
        });

        world.Authority.Launch("slot-a", world.Identity, LocalRpcLaunchTransport.SuppliedStreams);

        Assert.True(observed.IsSet);
        observed.Dispose();
    }
}
