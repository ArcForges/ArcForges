// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// The LocalBootstrap proof of annex 09 against an independent oracle, and the child's side of registration: the bootstrap resource, the
/// single-use proof, the credentials every call presents and the lease keeper. Offline fixtures with a fake clock; no transport.
/// </summary>
public sealed class LocalRpcChildRegistrationTests
{
    // The transcript and proof computed independently (a Python HMAC) for the contract fixture of the same scenario: the secret is the
    // bytes 0..31, the client bytes 32..63, the server bytes 64..95. Written in short pieces: nothing here is a credential.
    private static readonly string[] ExpectedProofPieces = ["6011473a98e397c8", "cfb77018cd6f20e7", "c281d6d81448821f", "1e4b636ca96c73e0"];

    private static byte[] Range(int from, int count) => [.. Enumerable.Range(from, count).Select(value => (byte)value)];

    private static Guid Uuid(string hex) => new(Convert.FromHexString(hex), bigEndian: true);

    [Fact]
    public void TheProofMatchesTheIndependentlyComputedKnownAnswer()
    {
        var challenge = Uuid("102132435465768798a9bacbdcedfe0f");
        var client = Uuid("112233445566778899aabbccddeeff00");
        var server = Uuid("2233445566778899aabbccddeeff0011");

        var proof = LocalBootstrapProof.Compute(Range(0, 32), challenge, Range(32, 32), Range(64, 32), client, server);

        Assert.Equal(string.Concat(ExpectedProofPieces), Convert.ToHexStringLower(proof));
        Assert.True(LocalBootstrapProof.Matches(Range(0, 32), challenge, Range(32, 32), Range(64, 32), client, server, proof));
    }

    [Fact]
    public void TheTranscriptIsTheLabelThenTheFiveFieldsInTheDocumentedOrderWithBigEndianUuids()
    {
        var challenge = Uuid("102132435465768798a9bacbdcedfe0f");
        var client = Uuid("112233445566778899aabbccddeeff00");
        var server = Uuid("2233445566778899aabbccddeeff0011");

        var transcript = LocalBootstrapProof.Transcript(challenge, Range(32, 32), Range(64, 32), client, server);

        var expected = "arcforges.local.bootstrap.v1"u8.ToArray()
            .Concat(Convert.FromHexString("102132435465768798a9bacbdcedfe0f"))
            .Concat(Range(32, 32))
            .Concat(Range(64, 32))
            .Concat(Convert.FromHexString("112233445566778899aabbccddeeff00"))
            .Concat(Convert.FromHexString("2233445566778899aabbccddeeff0011"))
            .ToArray();
        Assert.Equal(expected, transcript);
    }

    [Fact]
    public void ABareHashOfTheTranscriptIsNotTheProof()
    {
        var challenge = Guid.NewGuid();
        var transcript = LocalBootstrapProof.Transcript(challenge, Range(32, 32), Range(64, 32), Guid.NewGuid(), Guid.NewGuid());

        var proof = LocalBootstrapProof.Compute(Range(0, 32), challenge, Range(32, 32), Range(64, 32), Guid.NewGuid(), Guid.NewGuid());

        Assert.NotEqual(SHA256.HashData(transcript), proof);
        Assert.Equal(32, proof.Length);
    }

    [Theory]
    [InlineData(31, 32, 32)]
    [InlineData(32, 31, 32)]
    [InlineData(32, 32, 31)]
    [InlineData(32, 33, 32)]
    public void TheSecretAndBothChallengesAreExactly32Bytes(int secret, int client, int server)
    {
        _ = Assert.Throws<ArgumentException>(() => LocalBootstrapProof.Compute(new byte[secret], Guid.NewGuid(), new byte[client], new byte[server], Guid.NewGuid(), Guid.NewGuid()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void APresentedProofOfAnotherLengthNeverMatches(int length)
    {
        var challenge = Guid.NewGuid();
        var client = Guid.NewGuid();
        var server = Guid.NewGuid();
        var proof = LocalBootstrapProof.Compute(Range(0, 32), challenge, Range(32, 32), Range(64, 32), client, server);
        var presented = length <= 32 ? proof[..length] : [.. proof, 0];

        Assert.False(LocalBootstrapProof.Matches(Range(0, 32), challenge, Range(32, 32), Range(64, 32), client, server, presented));
    }

    // ---- the child's bootstrap resource

    private static (RegSession Session, byte[] Resource, RegWorld World) Handoff()
    {
        var world = new RegWorld();
        var launch = world.Authority.Launch("slot-a", world.Identity, LocalRpcLaunchTransport.SuppliedStreams);
        var registration = LocalRpcRegistration.Create(launch);
        var resource = launch.HandoffBootstrapResource();
        return (new RegSession(world, launch, registration, resource[^32..]), resource, world);
    }

    [Fact]
    public void TheChildTakesTheDescriptorAndTheSecretFromTheResourceAndClearsTheCallersCopy()
    {
        var (session, resource, world) = Handoff();
        using var disposeWorld = world;

        using var child = LocalRpcChildBootstrap.FromResource(resource);

        Assert.All(resource, value => Assert.Equal(0, value));
        Assert.Equal(session.Launch.Descriptor.Encode(), child.Descriptor.Encode());
        Assert.Equal(session.Launch.Descriptor.Identity.ChildKind, child.Identity.ChildKind);
        Assert.False(child.SecretIsZeroed());
        Assert.NotEqual(Guid.Empty, child.InstanceId);
        Assert.Equal(32, child.ClientChallenge.Length);
        Assert.Contains(child.ClientChallenge.ToArray(), value => value != 0);
    }

    [Fact]
    public void EveryChildHasItsOwnInstanceAndItsOwnClientBytes()
    {
        var (_, first, firstWorld) = Handoff();
        var (_, second, secondWorld) = Handoff();
        using var worlds = firstWorld;
        using var others = secondWorld;
        using var one = LocalRpcChildBootstrap.FromResource(first);
        using var two = LocalRpcChildBootstrap.FromResource(second);

        Assert.NotEqual(one.InstanceId, two.InstanceId);
        Assert.False(one.ClientChallenge.Span.SequenceEqual(two.ClientChallenge.Span));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32)]
    [InlineData(100)]
    public void AResourceThatIsNotADescriptorAndASecretIsRefusedAndStillCleared(int length)
    {
        var resource = Enumerable.Repeat((byte)0x5a, length).ToArray();

        _ = Assert.Throws<FormatException>(() => LocalRpcChildBootstrap.FromResource(resource));

        Assert.All(resource, value => Assert.Equal(0, value));
    }

    [Fact]
    public void AResourceWithTrailingBytesOrATruncatedSecretIsRefused()
    {
        var (_, resource, world) = Handoff();
        using var disposeWorld = world;
        var trailing = new byte[resource.Length + 1];
        resource.CopyTo(trailing, 0);
        var truncated = resource[..^1];

        _ = Assert.Throws<FormatException>(() => LocalRpcChildBootstrap.FromResource(trailing));
        _ = Assert.Throws<FormatException>(() => LocalRpcChildBootstrap.FromResource(truncated));
        _ = Assert.Throws<ArgumentNullException>(() => LocalRpcChildBootstrap.FromResource(null!));
    }

    [Fact]
    public void TheProofIsComputedOnceAndTheSecretIsDestroyedByIt()
    {
        var (session, resource, world) = Handoff();
        using var disposeWorld = world;
        using var child = LocalRpcChildBootstrap.FromResource(resource);
        var challengeId = Guid.NewGuid();
        var server = Guid.NewGuid();
        var serverBytes = Range(64, 32);

        var proof = child.ComputeProof(challengeId, serverBytes, server);

        var expected = LocalBootstrapProof.Compute(session.Secret, challengeId, child.ClientChallenge.Span, serverBytes, child.InstanceId, server);
        Assert.Equal(expected, proof);
        Assert.True(child.SecretIsZeroed());
        _ = Assert.Throws<InvalidOperationException>(() => child.ComputeProof(challengeId, serverBytes, server));
    }

    [Theory]
    [InlineData("empty-challenge")]
    [InlineData("empty-server")]
    [InlineData("short-bytes")]
    [InlineData("long-bytes")]
    public void AMalformedChallengeIsRefusedBeforeTheSecretIsTouched(string malformed)
    {
        var (_, resource, world) = Handoff();
        using var disposeWorld = world;
        using var child = LocalRpcChildBootstrap.FromResource(resource);
        var challengeId = malformed == "empty-challenge" ? Guid.Empty : Guid.NewGuid();
        var server = malformed == "empty-server" ? Guid.Empty : Guid.NewGuid();
        var bytes = malformed switch { "short-bytes" => Range(0, 31), "long-bytes" => Range(0, 33), _ => Range(0, 32) };

        _ = Assert.Throws<ArgumentException>(() => child.ComputeProof(challengeId, bytes, server));

        Assert.False(child.SecretIsZeroed());
        _ = child.ComputeProof(Guid.NewGuid(), Range(0, 32), Guid.NewGuid());
    }

    [Fact]
    public void ADisposedChildCannotProveAndItsUnusedSecretIsDestroyed()
    {
        var (_, resource, world) = Handoff();
        using var disposeWorld = world;
        var child = LocalRpcChildBootstrap.FromResource(resource);

        child.Dispose();
        child.Dispose();

        Assert.True(child.SecretIsZeroed());
        _ = Assert.Throws<InvalidOperationException>(() => child.ComputeProof(Guid.NewGuid(), Range(0, 32), Guid.NewGuid()));
    }

    [Fact]
    public void CredentialsAreAcceptedOnlyAfterTheProofAndOnlyForA32ByteNonce()
    {
        var (_, resource, world) = Handoff();
        using var disposeWorld = world;
        using var child = LocalRpcChildBootstrap.FromResource(resource);
        _ = Assert.Throws<InvalidOperationException>(() => child.AcceptGrant(new byte[32]));
        _ = child.ComputeProof(Guid.NewGuid(), Range(0, 32), Guid.NewGuid());

        _ = Assert.Throws<ArgumentException>(() => child.AcceptGrant(new byte[31]));
        _ = Assert.Throws<ArgumentException>(() => child.AcceptGrant(new byte[33]));
        using var credentials = child.AcceptGrant(Range(1, 32));

        Assert.NotNull(credentials);
    }

    [Fact]
    public void TheCredentialHeadersCarryTheNonceTheInstanceAndTheContractSetInTheDesignedForms()
    {
        var (session, resource, world) = Handoff();
        using var disposeWorld = world;
        using var child = LocalRpcChildBootstrap.FromResource(resource);
        _ = child.ComputeProof(Guid.NewGuid(), Range(0, 32), Guid.NewGuid());
        var nonce = Range(1, 32);
        using var credentials = child.AcceptGrant(nonce);

        var headers = credentials.Headers();

        Assert.Equal(3, headers.Count);
        Assert.Equal(nonce, headers.Get("x-af-peer-bin")!.ValueBytes);
        Assert.Equal(child.InstanceId.ToByteArray(bigEndian: true), headers.Get("x-af-instance-bin")!.ValueBytes);
        Assert.Equal(Convert.ToHexStringLower(session.Identity.ContractSetDigest.Span), headers.Get("x-af-contract-set")!.Value);
        // The headers are copies: changing what a call received never changes what later calls present.
        headers.Get("x-af-peer-bin")!.ValueBytes[0] ^= 0xFF;
        Assert.Equal(nonce, credentials.Headers().Get("x-af-peer-bin")!.ValueBytes);
    }

    [Fact]
    public void DisposingTheCredentialsClearsTheNonce()
    {
        var (_, resource, world) = Handoff();
        using var disposeWorld = world;
        using var child = LocalRpcChildBootstrap.FromResource(resource);
        _ = child.ComputeProof(Guid.NewGuid(), Range(0, 32), Guid.NewGuid());
        var credentials = child.AcceptGrant(Range(1, 32));

        credentials.Dispose();

        Assert.All(credentials.Headers().Get("x-af-peer-bin")!.ValueBytes, value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task TheCredentialsInterceptorPresentsTheHeadersOnEveryKindOfCallAndReplacesWhatACallerSet()
    {
        var (session, resource, world) = Handoff();
        using var disposeWorld = world;
        using var child = LocalRpcChildBootstrap.FromResource(resource);
        _ = child.ComputeProof(Guid.NewGuid(), Range(0, 32), Guid.NewGuid());
        var nonce = Range(1, 32);
        using var credentials = child.AcceptGrant(nonce);
        var method = new Method<ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewRequest, ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewResponse>(
            MethodType.Unary,
            "svc",
            "m",
            Marshallers.Create(_ => [], _ => new ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewRequest()),
            Marshallers.Create(_ => [], _ => new ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewResponse()));
        var seen = new List<Metadata?>();
        var callerHeaders = new Metadata { { "x-af-peer-bin", new byte[32] }, { "x-af-contract-set", "spoofed" }, { "x-keep", "kept" } };
        ClientInterceptorContext<ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewRequest, ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewResponse> Context() =>
            new(method, null, new CallOptions(headers: callerHeaders));
        var request = new ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewRequest();
        var response = new ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewResponse();
        var headersTask = Task.FromResult(new Metadata());

        _ = credentials.BlockingUnaryCall(request, Context(), (_, context) => { seen.Add(context.Options.Headers); return response; });
        using var unary = credentials.AsyncUnaryCall(request, Context(), (_, context) =>
        {
            seen.Add(context.Options.Headers);
            return new AsyncUnaryCall<ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewResponse>(Task.FromResult(response), headersTask, () => Status.DefaultSuccess, () => [], () => { });
        });
        using var serverStreaming = credentials.AsyncServerStreamingCall(request, Context(), (_, context) =>
        {
            seen.Add(context.Options.Headers);
            return new AsyncServerStreamingCall<ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewResponse>(null!, headersTask, () => Status.DefaultSuccess, () => [], () => { });
        });
        using var clientStreaming = credentials.AsyncClientStreamingCall(Context(), context =>
        {
            seen.Add(context.Options.Headers);
            return new AsyncClientStreamingCall<ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewRequest, ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewResponse>(null!, Task.FromResult(response), headersTask, () => Status.DefaultSuccess, () => [], () => { });
        });
        using var duplex = credentials.AsyncDuplexStreamingCall(Context(), context =>
        {
            seen.Add(context.Options.Headers);
            return new AsyncDuplexStreamingCall<ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewRequest, ArcForges.Contracts.LocalRpc.Platform.V1.LocalBootstrapServiceRenewResponse>(null!, null!, headersTask, () => Status.DefaultSuccess, () => [], () => { });
        });
        _ = await unary.ResponseAsync;

        Assert.Equal(5, seen.Count);
        Assert.All(seen, headers =>
        {
            Assert.NotNull(headers);
            Assert.Single(headers, entry => entry.Key == "x-af-peer-bin");
            Assert.Equal(nonce, headers.Get("x-af-peer-bin")!.ValueBytes);
            Assert.Equal(child.InstanceId.ToByteArray(bigEndian: true), headers.Get("x-af-instance-bin")!.ValueBytes);
            Assert.Equal(Convert.ToHexStringLower(session.Identity.ContractSetDigest.Span), headers.Get("x-af-contract-set")!.Value);
            Assert.Equal("kept", headers.Get("x-keep")!.Value);
            Assert.Equal(4, headers.Count);
        });
        // The caller's own metadata object was not changed.
        Assert.Equal(3, callerHeaders.Count);
    }

    [Fact]
    public async Task TheDefaultLeaseKeeperRenewsEveryTenSecondsOnTheRealClockAndKeepsAThirtySecondLease()
    {
        using var renewals = new Renewals();
        var started = DateTimeOffset.UtcNow;
        await using var keeper = LocalRpcLeaseKeeper.Start(renewals.RenewAsync);
        Assert.InRange(keeper.ExpiresAtUtc - started, TimeSpan.FromSeconds(29), TimeSpan.FromSeconds(31));
        _ = Assert.Throws<ArgumentNullException>(() => LocalRpcLeaseKeeper.Start(null!));

        // Nothing is sent before the first interval has passed, and the first renewal follows it.
        await Task.Delay(TimeSpan.FromSeconds(9), TestContext.Current.CancellationToken);
        Assert.Empty(renewals.Commands);
        Assert.True(await renewals.NextCallAsync());
        Assert.InRange(DateTimeOffset.UtcNow - started, TimeSpan.FromSeconds(9.5), TimeSpan.FromSeconds(15));
    }

    // ---- the lease keeper

    private sealed class Renewals : IDisposable
    {
        private readonly object _gate = new();
        private readonly List<byte[]> _commands = [];
        private readonly SemaphoreSlim _calls = new(0);

        internal Func<int, ValueTask<DateTimeOffset>> Behavior { get; set; } = _ => ValueTask.FromResult(DateTimeOffset.UtcNow);

        internal IReadOnlyList<byte[]> Commands
        {
            get
            {
                lock (_gate)
                {
                    return [.. _commands];
                }
            }
        }

        internal async ValueTask<DateTimeOffset> RenewAsync(ReadOnlyMemory<byte> command, CancellationToken cancellationToken)
        {
            int count;
            lock (_gate)
            {
                _commands.Add(command.ToArray());
                count = _commands.Count;
            }

            _ = _calls.Release();
            _ = cancellationToken;
            return await Behavior(count).ConfigureAwait(false);
        }

        internal Task<bool> NextCallAsync() => _calls.WaitAsync(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken);

        public void Dispose() => _calls.Dispose();
    }

    private static async Task SettledAsync(TimerClock clock)
    {
        // The keeper arms its next delay on a pool thread after an attempt: wait until a timer is pending again.
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
        while (clock.PendingTimers == 0)
        {
            Assert.True(DateTime.UtcNow < deadline, "The keeper did not wait for its next interval.");
            await Task.Delay(5, TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task TheKeeperRenewsEveryTenSecondsNotBeforeAndUsesAFreshCommandAfterEachSuccess()
    {
        var clock = new TimerClock(DateTimeOffset.UtcNow);
        using var renewals = new Renewals();
        await using var keeper = LocalRpcLeaseKeeper.Start(renewals.RenewAsync, clock, LocalRpcRegistration.RenewInterval, LocalRpcRegistration.LeaseDuration);
        await SettledAsync(clock);

        clock.Advance(TimeSpan.FromSeconds(10) - TimeSpan.FromTicks(1));
        await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.Empty(renewals.Commands);

        clock.Advance(TimeSpan.FromTicks(1));
        Assert.True(await renewals.NextCallAsync());
        await SettledAsync(clock);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True(await renewals.NextCallAsync());

        var commands = renewals.Commands;
        Assert.Equal(2, commands.Count);
        Assert.All(commands, command => Assert.Equal(16, command.Length));
        Assert.False(commands[0].AsSpan().SequenceEqual(commands[1]));
        Assert.False(keeper.Lost.IsCancellationRequested);
    }

    [Fact]
    public async Task AFailedRenewalIsRetriedAtTheNextIntervalWithTheSameCommandAndANewOneAfterSuccess()
    {
        var clock = new TimerClock(DateTimeOffset.UtcNow);
        using var renewals = new Renewals { Behavior = count => count <= 2 ? throw new IOException("transport") : ValueTask.FromResult(clock.GetUtcNow()) };
        await using var keeper = LocalRpcLeaseKeeper.Start(renewals.RenewAsync, clock, LocalRpcRegistration.RenewInterval, LocalRpcRegistration.LeaseDuration);
        for (var round = 0; round < 4; round++)
        {
            await SettledAsync(clock);
            clock.Advance(TimeSpan.FromSeconds(10));
            Assert.True(await renewals.NextCallAsync());
            await Task.Delay(50, TestContext.Current.CancellationToken);
        }

        var commands = renewals.Commands;
        Assert.Equal(4, commands.Count);
        Assert.Equal(commands[0], commands[1]);
        Assert.Equal(commands[0], commands[2]);
        Assert.NotEqual(commands[2], commands[3]);
    }

    [Fact]
    public async Task TheKeeperDeclaresTheRegistrationLostWhenTheLeasePassesWithoutASuccessfulRenewal()
    {
        var clock = new TimerClock(DateTimeOffset.UtcNow);
        using var renewals = new Renewals { Behavior = _ => throw new IOException("transport") };
        await using var keeper = LocalRpcLeaseKeeper.Start(renewals.RenewAsync, clock, LocalRpcRegistration.RenewInterval, LocalRpcRegistration.LeaseDuration);

        for (var round = 0; round < 3; round++)
        {
            await SettledAsync(clock);
            Assert.False(keeper.Lost.IsCancellationRequested);
            clock.Advance(TimeSpan.FromSeconds(10));
            Assert.True(await renewals.NextCallAsync());
            await Task.Delay(50, TestContext.Current.CancellationToken);
        }

        Assert.True(keeper.Lost.IsCancellationRequested);
    }

    [Fact]
    public async Task ASuccessfulRenewalRestartsTheChildsLeaseClock()
    {
        var clock = new TimerClock(DateTimeOffset.UtcNow);
        using var renewals = new Renewals { Behavior = count => count == 1 ? ValueTask.FromResult(clock.GetUtcNow()) : throw new IOException("transport") };
        await using var keeper = LocalRpcLeaseKeeper.Start(renewals.RenewAsync, clock, LocalRpcRegistration.RenewInterval, LocalRpcRegistration.LeaseDuration);

        // Success at ten seconds, then failures at twenty and thirty: the lease runs thirty seconds from the success, so it holds at thirty.
        for (var round = 0; round < 3; round++)
        {
            await SettledAsync(clock);
            clock.Advance(TimeSpan.FromSeconds(10));
            Assert.True(await renewals.NextCallAsync());
            await Task.Delay(50, TestContext.Current.CancellationToken);
        }

        Assert.False(keeper.Lost.IsCancellationRequested);
        await SettledAsync(clock);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True(await renewals.NextCallAsync());
        await Eventually(() => keeper.Lost.IsCancellationRequested);
    }

    [Fact]
    public async Task AParentsRefusalEndsTheKeepersRegistrationAtOnce()
    {
        var clock = new TimerClock(DateTimeOffset.UtcNow);
        using var renewals = new Renewals { Behavior = _ => throw new LocalRpcRegistrationLostException() };
        await using var keeper = LocalRpcLeaseKeeper.Start(renewals.RenewAsync, clock, LocalRpcRegistration.RenewInterval, LocalRpcRegistration.LeaseDuration);
        await SettledAsync(clock);

        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True(await renewals.NextCallAsync());

        await Eventually(() => keeper.Lost.IsCancellationRequested);
        Assert.Single(renewals.Commands);
    }

    [Fact]
    public async Task TheKeeperReportsTheExpiryTheParentGaveAndStopsWhenDisposed()
    {
        var clock = new TimerClock(DateTimeOffset.UtcNow);
        var reported = clock.GetUtcNow() + TimeSpan.FromSeconds(77);
        using var renewals = new Renewals { Behavior = _ => ValueTask.FromResult(reported) };
        var keeper = LocalRpcLeaseKeeper.Start(renewals.RenewAsync, clock, LocalRpcRegistration.RenewInterval, LocalRpcRegistration.LeaseDuration);
        Assert.Equal(clock.GetUtcNow() + TimeSpan.FromSeconds(30), keeper.ExpiresAtUtc);
        await SettledAsync(clock);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True(await renewals.NextCallAsync());
        await Eventually(() => keeper.ExpiresAtUtc == reported);

        await keeper.DisposeAsync();
        clock.Advance(TimeSpan.FromSeconds(60));
        await Task.Delay(100, TestContext.Current.CancellationToken);

        Assert.Single(renewals.Commands);
        Assert.False(keeper.Lost.IsCancellationRequested);
        Assert.Equal(0, clock.PendingTimers);
    }

    [Fact]
    public async Task AnAttemptThatOutlivesTheLeaseIsCancelledAndTheRegistrationIsLost()
    {
        var clock = new TimerClock(DateTimeOffset.UtcNow);
        var seen = new TaskCompletionSource<CancellationToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var keeper = LocalRpcLeaseKeeper.Start(
            async (_, token) =>
            {
                seen.TrySetResult(token);
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return default;
            },
            clock,
            LocalRpcRegistration.RenewInterval,
            LocalRpcRegistration.LeaseDuration);
        await SettledAsync(clock);
        clock.Advance(TimeSpan.FromSeconds(10));
        var token = await seen.Task.WaitAsync(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken);
        Assert.False(token.IsCancellationRequested);

        clock.Advance(TimeSpan.FromSeconds(20));

        await Eventually(() => token.IsCancellationRequested);
        await Eventually(() => keeper.Lost.IsCancellationRequested);
    }

    [Fact]
    public async Task TheKeeperRenewsOnTheRealClockAndLosesAnUnrenewableLeaseOnTime()
    {
        var failing = 0;
        using var renewals = new Renewals
        {
            Behavior = _ => Volatile.Read(ref failing) == 1 ? throw new IOException("transport") : ValueTask.FromResult(DateTimeOffset.UtcNow),
        };
        await using var keeper = LocalRpcLeaseKeeper.Start(renewals.RenewAsync, TimeProvider.System, TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(1200));

        await Eventually(() => renewals.Commands.Count >= 6);
        Assert.False(keeper.Lost.IsCancellationRequested);
        var failedFrom = DateTime.UtcNow;
        Volatile.Write(ref failing, 1);
        await Eventually(() => keeper.Lost.IsCancellationRequested);

        var lostAfter = DateTime.UtcNow - failedFrom;
        Assert.InRange(lostAfter, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(10));
    }

    private static async Task Eventually(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "The condition did not hold in time.");
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }
    }
}
