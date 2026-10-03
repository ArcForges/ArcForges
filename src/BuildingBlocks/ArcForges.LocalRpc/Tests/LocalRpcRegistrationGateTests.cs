// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>A client interceptor that rewrites the headers of every call, to present broken or partial credentials.</summary>
internal sealed class EditHeaders(Func<Metadata, Metadata> edit) : Interceptor
{
    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        var headers = edit(context.Options.Headers ?? []);
        return continuation(request, new ClientInterceptorContext<TRequest, TResponse>(context.Method, context.Host, context.Options.WithHeaders(headers)));
    }
}

/// <summary>
/// A parent and a child over in-memory streams: a launch with its registration on a fake clock, a real Kestrel HTTP/2 server serving
/// it through the registration gate with the owner's generated services, and the child's bootstrap resource.
/// </summary>
internal sealed class GateHarness : IAsyncDisposable
{
    private GateHarness(RegWorld world, RegSession session, LocalRpcChildBootstrap child, LocalRpcStreamSupplier supplier, BootstrapAdapter adapter, ProbeBrokerService probe, LocalRpcServer server)
    {
        World = world;
        Session = session;
        Child = child;
        Supplier = supplier;
        Adapter = adapter;
        Probe = probe;
        Server = server;
    }

    internal RegWorld World { get; }

    internal RegSession Session { get; }

    internal LocalRpcRegistration Registration => Session.Registration;

    internal LocalRpcLaunch Launch => Session.Launch;

    internal LocalRpcChildBootstrap Child { get; }

    internal LocalRpcStreamSupplier Supplier { get; }

    internal BootstrapAdapter Adapter { get; }

    internal ProbeBrokerService Probe { get; }

    internal LocalRpcServer Server { get; }

    internal static async Task<GateHarness> StartAsync(
        RegWorld world,
        CancellationToken cancellationToken,
        string slot = "slot-a",
        RegistrationTimings? timings = null,
        Action<LocalRpcServerBuilder>? configure = null,
        bool tamperSecret = false)
    {
        var launch = world.Authority.Launch(slot, world.Identity, LocalRpcLaunchTransport.SuppliedStreams);
        var registration = timings is null ? LocalRpcRegistration.Create(launch) : LocalRpcRegistration.Create(launch, timings);
        // The child takes the bootstrap resource the parent hands over; the session keeps its own copy of the secret for hand-made proofs.
        var resource = launch.HandoffBootstrapResource();
        var secret = resource[^LocalRpcLaunchDescriptor.SecretLength..];
        if (tamperSecret)
        {
            resource[^1] ^= 0x01;
        }

        var child = LocalRpcChildBootstrap.FromResource(resource);
        var session = new RegSession(world, launch, registration, secret);
        var supplier = new LocalRpcStreamSupplier();
        var adapter = new BootstrapAdapter();
        var probe = new ProbeBrokerService();
        var builder = LocalRpcServer.CreateBuilder(supplier).RequireRegistration(registration).AddService(adapter).AddService(probe);
        configure?.Invoke(builder);
        var server = builder.Build();
        await server.StartAsync(cancellationToken);
        return new GateHarness(world, session, child, supplier, adapter, probe, server);
    }

    /// <summary>Supplies a fresh connected pair to the server and returns the client end.</summary>
    internal Stream NewClientStream()
    {
        var (client, server) = InMemoryDuplexStream.CreatePair();
        if (!Supplier.TrySupply(server))
        {
            server.Dispose();
            client.Dispose();
            throw new InvalidOperationException("The supplier refused a stream.");
        }

        return client;
    }

    internal LocalRpcClientChannel NewChannel() => LocalRpcClientChannel.CreateFromStreams(_ => ValueTask.FromResult(NewClientStream()));

    internal async Task<RegisteredChild> RegisterAsync(LocalRpcClientChannel channel, CancellationToken cancellationToken) =>
        await ChildClient.RegisterAsync(channel.CallInvoker, Child, cancellationToken);

    public async ValueTask DisposeAsync()
    {
        await Server.DisposeAsync();
        await Registration.DisposeAsync();
        Child.Dispose();
    }
}

/// <summary>
/// The registration gate over real Kestrel HTTP/2 and the generated LocalBootstrap and connector services on in-memory streams: what
/// an unregistered, registered, expired, stale or forged child can and cannot call. The registration's clock is fake and its timers
/// manual; the gRPC stack runs in real time. Framing and authorization fixtures only, never OS-stream evidence.
/// </summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcRegistrationGateTests
{
    private static readonly Status Refused = new(StatusCode.Unauthenticated, "Registration is required.");
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void TheBootstrapPathsAndHeaderNamesAreTheGeneratedAndTheDesignedOnes()
    {
        var service = LocalBootstrapService.Descriptor.FullName;
        Assert.Equal(LocalRpcRegistration.BootstrapService, service);
        Assert.Equal(LocalRpcRegistration.ChallengePath, "/" + service + "/Challenge");
        Assert.Equal(LocalRpcRegistration.ConfirmPath, "/" + service + "/Confirm");
        Assert.Equal(LocalRpcRegistration.RenewPath, "/" + service + "/Renew");
        Assert.Equal(
            ["Challenge", "Confirm", "Renew"],
            LocalBootstrapService.Descriptor.Methods.Select(method => method.Name).Order(StringComparer.Ordinal).ToArray());
        Assert.Equal("x-af-peer-bin", LocalRpcRegistrationGate.PeerHeader);
        Assert.Equal("x-af-instance-bin", LocalRpcRegistrationGate.InstanceHeader);
        Assert.Equal("x-af-contract-set", LocalRpcRegistrationGate.ContractSetHeader);
        Assert.Equal(TimeSpan.FromSeconds(30), LocalRpcRegistration.LeaseDuration);
        Assert.Equal(TimeSpan.FromSeconds(10), LocalRpcRegistration.RenewInterval);
        Assert.Equal(TimeSpan.FromSeconds(5), LocalRpcRegistration.ChallengeLifetime);
    }

    [Fact]
    public async Task ACallBeforeRegistrationNeverReachesAnyService()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();

        var ordinary = await ChildClient.ListStatusAsync(channel.CallInvoker, Ct);
        var renew = await Assert.ThrowsAsync<RpcException>(async () =>
            await new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker).RenewAsync(new LocalBootstrapServiceRenewRequest(), cancellationToken: Ct));

        Assert.Equal(Refused, ordinary);
        Assert.Equal(Refused, renew.Status);
        Assert.Equal(0, harness.Probe.Dispatched);
        Assert.Equal(0, harness.Adapter.Renews);
    }

    [Fact]
    public async Task AChildRegistersOverGeneratedCallsAndThenCallsOrdinaryServicesWithItsCredentials()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();

        var child = await harness.RegisterAsync(channel, Ct);

        Assert.Equal(LocalRpcRegistrationState.Registered, harness.Registration.State);
        Assert.Equal(1, harness.Adapter.Challenges);
        Assert.Equal(1, harness.Adapter.Confirms);
        Assert.Equal(32, child.Nonce.Length);
        // The same connection without credentials is still refused; with them it is served.
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(channel.CallInvoker, Ct));
        Assert.Equal(0, harness.Probe.Dispatched);
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
        Assert.Equal(1, harness.Probe.Dispatched);
        var renewed = await ChildClient.RenewAsync(child.Authenticated, Session.Command(1), Ct);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(world.Clock.GetUtcNow().AddSeconds(30).ToUnixTimeSeconds()), renewed);
    }

    private static class Session
    {
        internal static byte[] Command(byte value) => Launches.Bytes(value, 16);
    }

    public static TheoryData<string> BrokenCredentials() => new()
    {
        "no-nonce", "no-instance", "no-contract-set", "nonce-short", "nonce-long", "instance-short", "instance-long",
        "contract-set-short", "contract-set-not-hex", "contract-set-upper-wrong", "duplicate-nonce", "duplicate-instance", "duplicate-contract-set",
        "wrong-nonce", "wrong-instance", "wrong-contract-set", "empty-nonce",
    };

    [Theory]
    [MemberData(nameof(BrokenCredentials))]
    public async Task ACallWithBrokenOrPartialCredentialsIsRefusedBeforeDispatchWithOneAnswer(string broken)
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        var good = child.Credentials.Headers();
        var nonce = (byte[])good.Get(LocalRpcRegistrationGate.PeerHeader)!.ValueBytes.Clone();
        var instance = (byte[])good.Get(LocalRpcRegistrationGate.InstanceHeader)!.ValueBytes.Clone();
        var contract = good.Get(LocalRpcRegistrationGate.ContractSetHeader)!.Value;
        var edit = new EditHeaders(_ =>
        {
            var headers = new Metadata();
            void Add(string key, byte[] value) => headers.Add(key, value);
            void AddText(string key, string value) => headers.Add(key, value);
            switch (broken)
            {
                case "no-nonce":
                    Add(LocalRpcRegistrationGate.InstanceHeader, instance);
                    AddText(LocalRpcRegistrationGate.ContractSetHeader, contract);
                    return headers;
                case "no-instance":
                    Add(LocalRpcRegistrationGate.PeerHeader, nonce);
                    AddText(LocalRpcRegistrationGate.ContractSetHeader, contract);
                    return headers;
                case "no-contract-set":
                    Add(LocalRpcRegistrationGate.PeerHeader, nonce);
                    Add(LocalRpcRegistrationGate.InstanceHeader, instance);
                    return headers;
            }

            Add(LocalRpcRegistrationGate.PeerHeader, broken switch
            {
                "nonce-short" => nonce[..31],
                "nonce-long" => [.. nonce, 0],
                "wrong-nonce" => Launches.Flip(nonce),
                "empty-nonce" => [],
                _ => nonce,
            });
            if (broken == "duplicate-nonce")
            {
                Add(LocalRpcRegistrationGate.PeerHeader, nonce);
            }

            Add(LocalRpcRegistrationGate.InstanceHeader, broken switch
            {
                "instance-short" => instance[..15],
                "instance-long" => [.. instance, 0],
                "wrong-instance" => Launches.Flip(instance),
                _ => instance,
            });
            if (broken == "duplicate-instance")
            {
                Add(LocalRpcRegistrationGate.InstanceHeader, instance);
            }

            AddText(LocalRpcRegistrationGate.ContractSetHeader, broken switch
            {
                "contract-set-short" => contract[..62],
                "contract-set-not-hex" => contract[..63] + "g",
                "contract-set-upper-wrong" => contract.ToUpperInvariant()[..63] + (contract[63] == 'a' ? "B" : "A"),
                "wrong-contract-set" => (contract[0] == 'a' ? "b" : "a") + contract[1..],
                _ => contract,
            });
            if (broken == "duplicate-contract-set")
            {
                AddText(LocalRpcRegistrationGate.ContractSetHeader, contract);
            }

            return headers;
        });
        var before = harness.Probe.Dispatched;

        var status = await ChildClient.ListStatusAsync(child.Bare.Intercept(edit), Ct);

        Assert.Equal(Refused, status);
        Assert.Equal(before, harness.Probe.Dispatched);
        // A refused call never ends the registration: the right credentials still work.
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
        Assert.Equal(LocalRpcRegistrationState.Registered, harness.Registration.State);
    }

    [Theory]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAA==", true)]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAA", true)]
    [InlineData("AAAAAAAAAAAAAAAAAAAAA", false)]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAA=", false)]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAA==AAAAAAAAAAAA", false)]
    [InlineData("AAAAAAAAAAAAAAAAAAAA!A==", false)]
    [InlineData("AAAA AAAAAAAAAAAAAAAAA==", false)]
    [InlineData("", false)]
    public void ABinaryCredentialHeaderIsBase64OfExactlyTheRightLengthWithOrWithoutPadding(string value, bool accepted)
    {
        Span<byte> decoded = stackalloc byte[16];

        Assert.Equal(accepted, LocalRpcRegistrationGate.TryDecodeBinary(value, decoded));
        if (accepted)
        {
            Assert.True(decoded.ToArray().All(item => item == 0));
        }
    }

    [Fact]
    public void ABinaryCredentialHeaderWithSeveralValuesOrNoneIsRefused()
    {
        Span<byte> decoded = stackalloc byte[16];

        Assert.False(LocalRpcRegistrationGate.TryDecodeBinary(new Microsoft.Extensions.Primitives.StringValues(["AAAAAAAAAAAAAAAAAAAAAA==", "AAAAAAAAAAAAAAAAAAAAAA=="]), decoded));
        Assert.False(LocalRpcRegistrationGate.TryDecodeBinary(default, decoded));
    }

    [Theory]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true)]
    [InlineData("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789ABCDEF", true)]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", false)]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg", false)]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", false)]
    public void TheContractSetDigestHeaderIsSixtyFourHexDigitsInEitherCase(string value, bool accepted)
    {
        var headers = new Microsoft.AspNetCore.Http.HeaderDictionary
        {
            [LocalRpcRegistrationGate.PeerHeader] = Convert.ToBase64String(new byte[32]),
            [LocalRpcRegistrationGate.InstanceHeader] = Convert.ToBase64String(Launches.Bytes(0x07, 16)),
            [LocalRpcRegistrationGate.ContractSetHeader] = value,
        };
        Span<byte> nonce = stackalloc byte[32];
        Span<byte> contract = stackalloc byte[32];

        var read = LocalRpcRegistrationGate.TryReadCredentials(headers, nonce, out var instance, contract);

        Assert.Equal(accepted, read);
        if (accepted)
        {
            Assert.Equal(new Guid(Launches.Bytes(0x07, 16), bigEndian: true), instance);
            Assert.Equal(0x01, contract[0]);
            Assert.Equal(0xef, contract[7]);
        }
    }

    [Fact]
    public async Task ARegisteredChildMayPresentTheContractSetDigestInUpperCaseHex()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        var good = child.Credentials.Headers();
        var edit = new EditHeaders(_ =>
        {
            var headers = new Metadata();
            headers.Add(LocalRpcRegistrationGate.PeerHeader, good.Get(LocalRpcRegistrationGate.PeerHeader)!.ValueBytes);
            headers.Add(LocalRpcRegistrationGate.InstanceHeader, good.Get(LocalRpcRegistrationGate.InstanceHeader)!.ValueBytes);
            headers.Add(LocalRpcRegistrationGate.ContractSetHeader, good.Get(LocalRpcRegistrationGate.ContractSetHeader)!.Value.ToUpperInvariant());
            return headers;
        });

        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(child.Bare.Intercept(edit), Ct));
    }

    [Fact]
    public async Task ACallCannotOverrideTheCredentialsTheInterceptorPresents()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        var spoof = new EditHeaders(headers =>
        {
            headers.Add(LocalRpcRegistrationGate.PeerHeader, new byte[32]);
            headers.Add(LocalRpcRegistrationGate.InstanceHeader, new byte[16]);
            headers.Add(LocalRpcRegistrationGate.ContractSetHeader, new string('0', 64));
            headers.Add("x-unrelated", "kept");
            return headers;
        });

        // The spoofing interceptor is the outer one; the credentials interceptor runs after it and replaces every name it set.
        var invoker = child.Bare.Intercept(child.Credentials).Intercept(spoof);

        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(invoker, Ct));
    }

    [Fact]
    public async Task EveryCauseOfRefusalLooksTheSameToThePeer()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        await using var other = harness.NewChannel();
        // The second connection is admitted (and made) before the child registers; afterwards none is.
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(other.CallInvoker, Ct));
        var child = await harness.RegisterAsync(channel, Ct);
        var good = child.Credentials.Headers();
        var wrongNonce = new EditHeaders(_ =>
        {
            var headers = new Metadata();
            headers.Add(LocalRpcRegistrationGate.PeerHeader, Launches.Flip(good.Get(LocalRpcRegistrationGate.PeerHeader)!.ValueBytes));
            headers.Add(LocalRpcRegistrationGate.InstanceHeader, good.Get(LocalRpcRegistrationGate.InstanceHeader)!.ValueBytes);
            headers.Add(LocalRpcRegistrationGate.ContractSetHeader, good.Get(LocalRpcRegistrationGate.ContractSetHeader)!.Value);
            return headers;
        });

        var statuses = new List<Status>
        {
            await ChildClient.ListStatusAsync(channel.CallInvoker, Ct),
            await ChildClient.ListStatusAsync(child.Bare.Intercept(wrongNonce), Ct),
        };
        world.Clock.Advance(TimeSpan.FromSeconds(30));
        statuses.Add(await ChildClient.ListStatusAsync(child.Authenticated, Ct));
        statuses.Add(await ChildClient.ListStatusAsync(other.CallInvoker, Ct));

        Assert.All(statuses, status => Assert.Equal(Refused, status));
    }

    [Fact]
    public async Task OnlyTheTwoBootstrapStepsPassWithoutCredentialsAndOnlyBeforeRegistration()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        var bootstrap = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);

        // Reaches the service (which refuses a request without a caller manifest): the gate lets the step through.
        _ = await Assert.ThrowsAsync<RpcException>(async () => await bootstrap.ChallengeAsync(new LocalBootstrapServiceChallengeRequest(), cancellationToken: Ct));
        Assert.Equal(1, harness.Adapter.Challenges);
        _ = await Assert.ThrowsAsync<RpcException>(async () => await bootstrap.ConfirmAsync(new LocalBootstrapServiceConfirmRequest(), cancellationToken: Ct));
        Assert.Equal(1, harness.Adapter.Confirms);

        var child = await harness.RegisterAsync(channel, Ct);

        // Once registered, neither step reaches the service again, with credentials or without.
        var before = (harness.Adapter.Challenges, harness.Adapter.Confirms);
        foreach (var invoker in new[] { channel.CallInvoker, child.Authenticated })
        {
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(invoker);
            var challenge = await Assert.ThrowsAsync<RpcException>(async () => await client.ChallengeAsync(new LocalBootstrapServiceChallengeRequest(), cancellationToken: Ct));
            var confirm = await Assert.ThrowsAsync<RpcException>(async () => await client.ConfirmAsync(new LocalBootstrapServiceConfirmRequest(), cancellationToken: Ct));
            Assert.Equal(StatusCode.Unauthenticated, challenge.StatusCode);
            Assert.Equal(StatusCode.Unauthenticated, confirm.StatusCode);
        }

        Assert.Equal(before, (harness.Adapter.Challenges, harness.Adapter.Confirms));
    }

    [Theory]
    [InlineData("/arcforges.local.platform.v1.localbootstrapservice/challenge")]
    [InlineData("/arcforges.local.platform.v1.LocalBootstrapService/Challenge/")]
    [InlineData("/arcforges.local.platform.v1.LocalBootstrapService/Challenge/x")]
    [InlineData("/ARCFORGES.LOCAL.PLATFORM.V1.LOCALBOOTSTRAPSERVICE/CONFIRM")]
    [InlineData("/arcforges.local.platform.v1.LocalBootstrapService/Renew")]
    [InlineData("/arcforges.local.platform.v1.NoSuchService/Challenge")]
    public async Task ADifferentSpellingOfABootstrapPathNeedsCredentialsAndNeverProbesTheServer(string path)
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);

        var status = await RawGrpc.PostAsync(_ => ValueTask.FromResult(harness.NewClientStream()), path, Requests.Frame(8, gzip: false), null, Ct);

        Assert.Equal(StatusCode.Unauthenticated, status);
        Assert.Equal(0, harness.Adapter.Challenges + harness.Adapter.Confirms + harness.Adapter.Renews);
    }

    [Fact]
    public async Task ARegisteredChildThatPresentsValidCredentialsToAnUnknownServiceGetsRoutingsAnswerAndAnyoneElseGetsTheGates()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        var unknown = new Method<LocalBootstrapServiceRenewRequest, LocalBootstrapServiceRenewResponse>(
            MethodType.Unary,
            "arcforges.local.platform.v1.NoSuchService",
            "Anything",
            Marshallers.Create(request => request.ToByteArray(), bytes => LocalBootstrapServiceRenewRequest.Parser.ParseFrom(bytes)),
            Marshallers.Create(response => response.ToByteArray(), bytes => LocalBootstrapServiceRenewResponse.Parser.ParseFrom(bytes)));

        var served = await Assert.ThrowsAsync<RpcException>(async () =>
            await child.Authenticated.AsyncUnaryCall(unknown, null, new CallOptions(cancellationToken: Ct), new LocalBootstrapServiceRenewRequest()));
        var refused = await Assert.ThrowsAsync<RpcException>(async () =>
            await channel.CallInvoker.AsyncUnaryCall(unknown, null, new CallOptions(cancellationToken: Ct), new LocalBootstrapServiceRenewRequest()));

        Assert.Equal(StatusCode.Unimplemented, served.StatusCode);
        Assert.Equal(Refused, refused.Status);
    }

    [Fact]
    public async Task AServerWithoutTheGateGivesTheServiceNoBootstrapCallSoItRefuses()
    {
        var supplier = new LocalRpcStreamSupplier();
        var adapter = new BootstrapAdapter();
        await using var server = LocalRpcServer.CreateBuilder(supplier).AddService(adapter).Build();
        await server.StartAsync(Ct);
        await using var channel = LocalRpcClientChannel.CreateFromStreams(_ =>
        {
            var (client, serverEnd) = InMemoryDuplexStream.CreatePair();
            Assert.True(supplier.TrySupply(serverEnd));
            return ValueTask.FromResult<Stream>(client);
        });
        var bootstrap = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);

        var failure = await Assert.ThrowsAsync<RpcException>(async () =>
            await bootstrap.RenewAsync(new LocalBootstrapServiceRenewRequest(), cancellationToken: Ct));

        Assert.Equal(StatusCode.Unauthenticated, failure.StatusCode);
        Assert.Equal(1, adapter.Renews);
    }

    // ---- connections

    [Fact]
    public async Task AChallengeOnOneConnectionCannotBeConfirmedOnAnotherAndTheRightConnectionStillRegisters()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var first = harness.NewChannel();
        await using var second = harness.NewChannel();
        var bootstrapOnFirst = new LocalBootstrapService.LocalBootstrapServiceClient(first.CallInvoker);
        var bootstrapOnSecond = new LocalBootstrapService.LocalBootstrapServiceClient(second.CallInvoker);
        var challenge = await bootstrapOnFirst.ChallengeAsync(
            new LocalBootstrapServiceChallengeRequest
            {
                Meta = new ArcForges.Contracts.Foundation.V1.RequestMeta(),
                InstanceId = Wire.ToId(harness.Child.InstanceId),
                Challenge = ByteString.CopyFrom(harness.Child.ClientChallenge.Span),
                Caller = Wire.Manifest(harness.Child.Identity),
            },
            cancellationToken: Ct);
        var proof = harness.Child.ComputeProof(Wire.FromId(challenge.Value.ChallengeId), challenge.Value.ServerChallenge.Span, Wire.FromId(challenge.Value.Server.InstanceId));

        var crossed = await Assert.ThrowsAsync<RpcException>(async () =>
            await bootstrapOnSecond.ConfirmAsync(new LocalBootstrapServiceConfirmRequest { ChallengeId = challenge.Value.ChallengeId, Proof = ByteString.CopyFrom(proof) }, cancellationToken: Ct));
        Assert.Equal(StatusCode.Unauthenticated, crossed.StatusCode);
        Assert.Equal(LocalRpcRegistrationState.AwaitingBootstrap, harness.Registration.State);
        Assert.False(harness.Launch.SecretIsZeroed());

        var confirmed = await bootstrapOnFirst.ConfirmAsync(
            new LocalBootstrapServiceConfirmRequest { ChallengeId = challenge.Value.ChallengeId, Proof = ByteString.CopyFrom(proof) },
            cancellationToken: Ct);
        Assert.Equal(32, confirmed.Value.PeerNonce.Length);
        Assert.Equal(LocalRpcRegistrationState.Registered, harness.Registration.State);
    }

    [Fact]
    public async Task TheCredentialsOfTheRegisteredConnectionDoNotWorkOnAnotherConnection()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var registered = harness.NewChannel();
        await using var other = harness.NewChannel();
        // Both connections are admitted before the child registers.
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(other.CallInvoker, Ct));
        var child = await harness.RegisterAsync(registered, Ct);

        var onOther = other.CallInvoker.Intercept(child.Credentials);

        Assert.Equal(Refused, await ChildClient.ListStatusAsync(onOther, Ct));
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
        Assert.Equal(1, harness.Probe.Dispatched);
    }

    [Fact]
    public async Task ASecondConnectionIsDroppedUnreadOnceTheChildRegistered()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        _ = await harness.RegisterAsync(channel, Ct);

        await using var late = harness.NewClientStream();
        var frames = await RawFrames.ReadUntilClosedAsync(late, Patience, Ct);

        Assert.Empty(frames);
    }

    [Fact]
    public async Task AnOwnersConnectionDecisionStillAppliesAlongsideTheRegistrationsOwn()
    {
        using var world = new RegWorld();
        await using var denying = await GateHarness.StartAsync(world, Ct, configure: builder => builder.AuthorizeConnectionsAsync((_, _) => ValueTask.FromResult(false)));

        await using var late = denying.NewClientStream();
        var frames = await RawFrames.ReadUntilClosedAsync(late, Patience, Ct);

        Assert.Empty(frames);
        Assert.Equal(LocalRpcRegistrationState.AwaitingBootstrap, denying.Registration.State);
    }

    [Fact]
    public async Task AClosedRegisteredConnectionEndsTheRegistrationAndTheLaunch()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(child.Authenticated, Ct));

        await channel.DisposeAsync();

        await WaitForEndAsync(harness.Registration);
        Assert.Equal(LocalRpcRegistrationEnd.ConnectionLost, harness.Registration.EndReason);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, harness.Launch.Status());
    }

    // ---- forged, stale, expired

    [Fact]
    public async Task AChildHoldingTheWrongSecretIsRefusedAndRevokesTheLaunchSoTheRealChildMustBeRelaunched()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct, tamperSecret: true);
        await using var channel = harness.NewChannel();

        var failure = await Assert.ThrowsAsync<RpcException>(async () => await harness.RegisterAsync(channel, Ct));

        Assert.Equal(StatusCode.Unauthenticated, failure.StatusCode);
        Assert.Equal(LocalRpcRegistrationEnd.ProofRejected, harness.Registration.EndReason);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, harness.Launch.Status());
        Assert.True(harness.Launch.SecretIsZeroed());
        Assert.Equal(0, harness.Probe.Dispatched);
    }

    [Fact]
    public async Task ARelaunchOfTheSlotStopsTheRegisteredChildAtOnceAndTheNextEpochRegistersFresh()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(child.Authenticated, Ct));

        await using var next = await GateHarness.StartAsync(world, Ct);

        // The old child is stopped at once, long before its lease would have run out.
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, harness.Registration.EndReason);
        Assert.True(harness.Registration.Ended.IsCancellationRequested);
        Assert.Equal(next.Launch.Descriptor.Epoch, harness.Launch.Descriptor.Epoch + 1);
        // The new epoch needs its own proof, and its nonce is its own.
        await using var nextChannel = next.NewChannel();
        var fresh = await next.RegisterAsync(nextChannel, Ct);
        Assert.False(child.Nonce.AsSpan().SequenceEqual(fresh.Nonce));
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(fresh.Authenticated, Ct));
        // Presenting the old credentials to the new epoch's server is refused too.
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(nextChannel.CallInvoker.Intercept(child.Credentials), Ct));
    }

    [Fact]
    public async Task AnUnrenewedChildIsStoppedWhenItsLeaseEndsAndRenewalsKeepAChildAliveThroughManyLeases()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        byte command = 0;
        for (var round = 0; round < 9; round++)
        {
            world.Clock.Advance(TimeSpan.FromSeconds(10));
            _ = await ChildClient.RenewAsync(child.Authenticated, Session.Command(++command), Ct);
        }

        // Ninety seconds in, three leases have passed and the child still calls.
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
        Assert.Equal(LocalRpcRegistrationState.Registered, harness.Registration.State);

        world.Clock.Advance(TimeSpan.FromSeconds(30));

        Assert.Equal(Refused, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
        var renew = await Assert.ThrowsAsync<LocalRpcRegistrationLostException>(async () =>
            await ChildClient.RenewAsync(child.Authenticated, Session.Command(99), Ct).AsTask());
        Assert.NotNull(renew);
        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, harness.Registration.EndReason);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, harness.Launch.Status());
    }

    [Fact]
    public async Task ARestartedParentRequiresFreshGrantsAndTheOldChildsCredentialsMeanNothingToIt()
    {
        using var world = new RegWorld();
        await using var before = await GateHarness.StartAsync(world, Ct);
        await using var oldChannel = before.NewChannel();
        var oldChild = await before.RegisterAsync(oldChannel, Ct);
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(oldChild.Authenticated, Ct));

        // The parent dies; a restarted parent is a new process with a new authority and its own launch and server.
        world.World.Processes.Set(world.World.Parent, ProcessLiveness.Dead);
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(oldChild.Authenticated, Ct));
        Assert.Equal(LocalRpcRegistrationEnd.LaunchEnded, before.Registration.EndReason);

        var restarted = world.World.SpawnFake(4343);
        using var again = new RegWorld(parent: restarted);
        await using var after = await GateHarness.StartAsync(again, Ct);
        await using var newChannel = after.NewChannel();

        // The old credentials do nothing on the restarted parent's server; the child must prove the new launch's secret.
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(newChannel.CallInvoker.Intercept(oldChild.Credentials), Ct));
        var fresh = await after.RegisterAsync(newChannel, Ct);
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(fresh.Authenticated, Ct));
    }

    // ---- the builder

    [Fact]
    public async Task ARegistrationServesOneServerAndABuilderTakesOneRegistration()
    {
        using var world = new RegWorld();
        var session = world.Start();
        var supplier = new LocalRpcStreamSupplier();
        var builder = LocalRpcServer.CreateBuilder(supplier).AddService(new BootstrapAdapter());

        _ = Assert.Throws<ArgumentNullException>(() => builder.RequireRegistration(null!));
        _ = builder.RequireRegistration(session.Registration);
        _ = Assert.Throws<InvalidOperationException>(() => builder.RequireRegistration(session.Registration));
        await using var first = builder.Build();
        _ = Assert.Throws<InvalidOperationException>(() => builder.RequireRegistration(session.Registration));

        var second = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new BootstrapAdapter()).RequireRegistration(session.Registration);
        _ = Assert.Throws<InvalidOperationException>(second.Build);
    }

    // ---- real clocks

    [Fact]
    public async Task OnTheRealClockRenewalsKeepAChildAliveAndAnUnrenewedLeaseEndsWithoutAnyCall()
    {
        using var world = new RegWorld(realClock: true);
        var timings = new RegistrationTimings { Lease = TimeSpan.FromSeconds(2) };
        await using var harness = await GateHarness.StartAsync(world, Ct, timings: timings);
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        var keeper = LocalRpcLeaseKeeper.Start(
            (command, token) => ChildClient.RenewAsync(child.Authenticated, command, token),
            TimeProvider.System,
            TimeSpan.FromMilliseconds(200),
            TimeSpan.FromSeconds(2));

        // Five seconds is more than two leases: only the renewals keep the registration alive.
        await Task.Delay(TimeSpan.FromSeconds(5), Ct);
        Assert.Equal(LocalRpcRegistrationState.Registered, harness.Registration.State);
        Assert.Equal(Status.DefaultSuccess, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
        Assert.False(keeper.Lost.IsCancellationRequested);

        await keeper.DisposeAsync();
        var stoppedAt = DateTime.UtcNow;
        await WaitForEndAsync(harness.Registration);
        var endedAfter = DateTime.UtcNow - stoppedAt;

        // No call arrived to notice the expiry: the watchdog ended it, about one lease after the last renewal.
        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, harness.Registration.EndReason);
        Assert.InRange(endedAfter, TimeSpan.FromMilliseconds(250), TimeSpan.FromSeconds(10));
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
        _ = await Assert.ThrowsAsync<LocalRpcRegistrationLostException>(async () => await ChildClient.RenewAsync(child.Authenticated, Session.Command(1), Ct).AsTask());
    }

    [Fact]
    public async Task OnTheRealClockAChildThatNeverRenewsLosesItsRegistrationAboutOneLeaseAfterConfirming()
    {
        using var world = new RegWorld(realClock: true);
        var timings = new RegistrationTimings { Lease = TimeSpan.FromSeconds(1) };
        await using var harness = await GateHarness.StartAsync(world, Ct, timings: timings);
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        var registered = DateTime.UtcNow;

        await WaitForEndAsync(harness.Registration);

        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, harness.Registration.EndReason);
        Assert.InRange(DateTime.UtcNow - registered, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(10));
        Assert.Equal(Refused, await ChildClient.ListStatusAsync(child.Authenticated, Ct));
    }

    // ---- the call bounds of PLT.13 under saturation

    [Fact]
    public async Task BootstrapAndRenewalRunInTheControlSlotsWhileTheDataLaneIsSaturatedAndUnregisteredCallsTakeNoSlot()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        harness.Probe.Hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var child = await harness.RegisterAsync(channel, Ct);
        var control = harness.Server.GetBoundsSnapshot().ControlAdmitted;
        Assert.Equal(2, control[LocalRpcControlOperation.Bootstrap]);

        // Fill the ordinary lane: 16 active calls and 64 queued ones, every one with valid credentials.
        var flood = Enumerable.Range(0, 80).Select(_ => Task.Run(() => ChildClient.ListStatusAsync(child.Authenticated, Ct), Ct)).ToArray();
        await Eventually(() =>
        {
            var snapshot = harness.Server.GetBoundsSnapshot();
            return snapshot is { DataActive: 16, DataQueued: 64 };
        });
        var before = harness.Server.GetBoundsSnapshot();

        // Renewal still gets through (the lease cannot starve) and refused calls never reach admission at all.
        var renewed = await ChildClient.RenewAsync(child.Authenticated, Session.Command(1), Ct);
        var unauthenticated = await Task.WhenAll(Enumerable.Range(0, 30).Select(_ => ChildClient.ListStatusAsync(channel.CallInvoker, Ct)));

        Assert.True(renewed > world.Clock.GetUtcNow());
        Assert.All(unauthenticated, status => Assert.Equal(Refused, status));
        var after = harness.Server.GetBoundsSnapshot();
        Assert.Equal(1, after.ControlAdmitted[LocalRpcControlOperation.LeaseRenewal]);
        Assert.Equal(before.DataAdmitted, after.DataAdmitted);
        Assert.Equal(before.Refused.Values.Sum(), after.Refused.Values.Sum());
        Assert.Equal(16, after.DataActive);
        Assert.Equal(64, after.DataQueued);

        harness.Probe.Hold.SetResult();
        Assert.All(await Task.WhenAll(flood), status => Assert.Equal(Status.DefaultSuccess, status));
    }

    [Fact]
    public async Task ARegistrationServerMustServeTheBootstrapServiceAndMayDeclareItsStepsOnlyAsTheirOwnControlOperations()
    {
        using var world = new RegWorld();
        var first = world.Start("slot-a");
        await using var withoutBootstrap = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier())
            .AddService(new ProbeBrokerService()).RequireRegistration(first.Registration).Build();
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () => await withoutBootstrap.StartAsync(Ct));
        Assert.Contains("control method", failure.Message, StringComparison.Ordinal);

        var second = world.Start("slot-b");
        var conflicting = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new BootstrapAdapter())
            .RegisterControl(LocalRpcControlOperation.Cancellation, LocalBootstrapService.Descriptor.FullName, "Renew")
            .RequireRegistration(second.Registration);
        _ = Assert.Throws<InvalidOperationException>(conflicting.Build);

        var third = world.Start("slot-c");
        await using var agreeing = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new BootstrapAdapter())
            .RegisterControl(LocalRpcControlOperation.LeaseRenewal, LocalBootstrapService.Descriptor.FullName, "Renew")
            .RequireRegistration(third.Registration).Build();
        await agreeing.StartAsync(Ct);
    }

    private static async Task Eventually(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + Patience;
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "The condition did not hold in time.");
            await Task.Delay(10, Ct);
        }
    }

    private static async Task WaitForEndAsync(LocalRpcRegistration registration)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        bounded.CancelAfter(Patience);
        using var either = CancellationTokenSource.CreateLinkedTokenSource(registration.Ended, bounded.Token);
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, either.Token);
        }
        catch (OperationCanceledException)
        {
            // Either the registration ended or the wait timed out; the caller asserts which.
        }

        Assert.True(registration.Ended.IsCancellationRequested, "The registration did not end in time.");
    }
}
