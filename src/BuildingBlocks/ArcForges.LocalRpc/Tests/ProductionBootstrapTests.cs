// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Platform.Shapes;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace ArcForges.LocalRpc.Tests;

/// <summary>Real generated service, HTTP/2, registration and parent lifecycle. Only streams, process liveness and clock are fixtures; no OS isolation is inferred.</summary>
[Collection(LocalRpcCollection.Name)]
public sealed class ProductionBootstrapTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ActualSharedServiceAuthenticatesRenewsAndReturnsTheFrozenParentManifest()
    {
        using var world = new RegWorld();
        await using var fixture = await Parent.StartAsync(world, Ct);
        await using var channel = fixture.Channel();
        var original = fixture.ServerManifest.Clone();
        fixture.ServerManifest.AppId = "mutated-owner-configuration";
        var child = await fixture.RegisterAsync(channel.CallInvoker, Ct);
        Assert.Equal(original, child.Challenge.Value.Server);
        Assert.Equal(fixture.ParentInstance, fixture.Host.Registration.ParentInstanceId);
        Assert.Equal(StatusCode.OK, (await ChildClient.ListStatusAsync(child.Registered.Authenticated, Ct)).StatusCode);
        world.Clock.Advance(TimeSpan.FromSeconds(10));
        var renewal = await new LocalBootstrapService.LocalBootstrapServiceClient(child.Registered.Authenticated).RenewAsync(
            new() { Meta = Parent.Meta() }, cancellationToken: Ct);
        Assert.True(ContractShapeValidation.IsValid(renewal));
        Assert.Equal(world.Clock.GetUtcNow() + LocalRpcRegistration.LeaseDuration, BootstrapWire.FromInstant(renewal.Value.ExpiresAt));
        await Task.WhenAll(fixture.Host.DisposeAsync().AsTask(), fixture.Host.DisposeAsync().AsTask()).WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.Equal(LocalRpcRegistrationState.Ended, fixture.Host.Registration.State);
        Assert.True(fixture.Host.Completion.IsCompletedSuccessfully);
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    public async Task MalformedOrForgedChallengesAreUniformlyRefusedBeforeGrant(int mutation)
    {
        using var world = new RegWorld();
        await using var fixture = await Parent.StartAsync(world, Ct);
        await using var channel = fixture.Channel();
        var request = fixture.Request();
        switch (mutation)
        {
            case 0: request.Caller.SchemaVersion = ""; break;
            case 1: request.Caller.BuildHash = new string('a', 100_000); break;
            case 2: request.Caller.ContractSetHash = new string('b', 64); break;
            case 3: request.Challenge = ByteString.Empty; break;
            case 4: request.Caller.InstanceId = Wire.ToId(Guid.NewGuid()); break;
            case 5: request.Caller.Endpoint.InstanceId = Wire.ToId(Guid.NewGuid()); break;
            case 6: request.Caller.AppId = "another-child"; break;
            case 7: request.Meta = null; break;
        }
        var error = await Assert.ThrowsAsync<RpcException>(() => new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker)
            .ChallengeAsync(request, cancellationToken: Ct).ResponseAsync);
        Assert.Equal(StatusCode.Unauthenticated, error.StatusCode);
        Assert.Equal(LocalRpcRegistrationState.AwaitingBootstrap, fixture.Host.Registration.State);
        Assert.Equal(0, fixture.Probe.Dispatched);
    }

    [Fact]
    public async Task RejectedProofRevokesTheLaunchAndStopsTheActualParentServer()
    {
        using var world = new RegWorld();
        await using var fixture = await Parent.StartAsync(world, Ct);
        await using var channel = fixture.Channel();
        var client = new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker);
        var challenge = await client.ChallengeAsync(fixture.Request(), cancellationToken: Ct);
        await Assert.ThrowsAsync<RpcException>(() => client.ConfirmAsync(new()
        {
            Meta = Parent.Meta(), ChallengeId = challenge.Value.ChallengeId,
            Proof = ByteString.CopyFrom(new byte[32]),
        }, cancellationToken: Ct).ResponseAsync);
        await fixture.Host.Completion.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.True(fixture.Launch.Revoked.IsCancellationRequested);
        Assert.Equal(LocalRpcRegistrationEnd.ProofRejected, fixture.Host.Registration.EndReason);
        Assert.Equal(0, fixture.Probe.Dispatched);
    }

    [Fact]
    public async Task ExpiryAndLostConnectionStopTheHostAndOldGrantsNeverTransferToRelaunch()
    {
        using var world = new RegWorld();
        await using var old = await Parent.StartAsync(world, Ct);
        await using var oldChannel = old.Channel();
        var oldChild = await old.RegisterAsync(oldChannel.CallInvoker, Ct);
        world.Clock.Advance(LocalRpcRegistration.LeaseDuration + TimeSpan.FromMilliseconds(1));
        await old.Host.Completion.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, old.Host.Registration.EndReason);
        await using var fresh = await Parent.StartAsync(world, Ct);
        await using var freshChannel = fresh.Channel();
        Assert.NotEqual(old.Launch.Descriptor.LaunchId, fresh.Launch.Descriptor.LaunchId);
        Assert.True(fresh.Launch.Descriptor.Epoch > old.Launch.Descriptor.Epoch);
        Assert.Equal(StatusCode.Unauthenticated, (await ChildClient.ListStatusAsync(freshChannel.CallInvoker.Intercept(oldChild.Registered.Credentials), Ct)).StatusCode);
        var freshChild = await fresh.RegisterAsync(freshChannel.CallInvoker, Ct);
        Assert.Equal(StatusCode.OK, (await ChildClient.ListStatusAsync(freshChild.Registered.Authenticated, Ct)).StatusCode);
        await freshChannel.DisposeAsync();
        await fresh.Host.Completion.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.Equal(LocalRpcRegistrationEnd.ConnectionLost, fresh.Host.Registration.EndReason);
    }

    [Fact]
    public async Task SupersededLaunchClosesParentAndCancelledStartupCannotLeaveAnAdmittedRegistration()
    {
        using var world = new RegWorld();
        await using var old = await Parent.StartAsync(world, Ct);
        await using var replacement = await Parent.StartAsync(world, Ct);
        await old.Host.Completion.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.True(old.Launch.Revoked.IsCancellationRequested);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var launch = world.Authority.Launch("cancelled", world.Identity, LocalRpcLaunchTransport.SuppliedStreams);
        var supplier = new LocalRpcStreamSupplier();
        var manifest = Parent.Manifest(world.Identity, Guid.NewGuid(), launch.Descriptor.Parent);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => LocalRpcParentBootstrapHost.StartAsync(
            launch, manifest, LocalRpcServer.CreateBuilder(supplier), cancellation.Token));
        Assert.True(launch.Revoked.IsCancellationRequested);
    }

    [Fact]
    public async Task ExplicitParentInstanceIsRequiredAndMisboundActualProcessManifestFailsClosed()
    {
        using var world = new RegWorld();
        var launch = world.Authority.Launch("invalid-config", world.Identity, LocalRpcLaunchTransport.SuppliedStreams);
        Assert.Throws<ArgumentException>(() => LocalRpcRegistration.Create(launch, Guid.Empty));
        var instance = Guid.NewGuid();
        await using var registration = LocalRpcRegistration.Create(launch, instance);
        var manifest = Parent.Manifest(world.Identity, instance, launch.Descriptor.Parent);
        manifest.ProcessId++;
        Assert.Throws<ArgumentException>(() => new LocalRpcBootstrapService(registration, manifest));
        manifest.ProcessId--;
        manifest.InstanceId = Wire.ToId(Guid.NewGuid());
        Assert.Throws<ArgumentException>(() => new LocalRpcBootstrapService(registration, manifest));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidManifestOrFailedRealServerStartupRevokesTheLaunch(bool invalidManifest)
    {
        using var world = new RegWorld();
        var launch = world.Authority.Launch("failed-start", world.Identity, LocalRpcLaunchTransport.SuppliedStreams);
        var manifest = Parent.Manifest(world.Identity, Guid.NewGuid(), launch.Descriptor.Parent);
        var supplier = new LocalRpcStreamSupplier();
        var builder = LocalRpcServer.CreateBuilder(supplier);
        if (invalidManifest) manifest.SchemaVersion = "";
        else builder.RegisterControl(LocalRpcControlOperation.Health, "not.served.Service", "Health");
        if (invalidManifest)
            await Assert.ThrowsAsync<ArgumentException>(() => LocalRpcParentBootstrapHost.StartAsync(launch, manifest, builder, Ct));
        else
            await Assert.ThrowsAsync<InvalidOperationException>(() => LocalRpcParentBootstrapHost.StartAsync(launch, manifest, builder, Ct));
        Assert.True(launch.Revoked.IsCancellationRequested);
        Assert.True(launch.SecretIsZeroed());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualServiceRefusesAnUngatedOrForeignRegistration(bool foreign)
    {
        using var world = new RegWorld();
        var ownLaunch = world.Authority.Launch("service-owner", world.Identity, LocalRpcLaunchTransport.SuppliedStreams);
        var instance = Guid.NewGuid();
        await using var own = LocalRpcRegistration.Create(ownLaunch, instance);
        var service = new LocalRpcBootstrapService(own, Parent.Manifest(world.Identity, instance, ownLaunch.Descriptor.Parent));
        var otherLaunch = world.Authority.Launch("service-foreign", world.Identity, LocalRpcLaunchTransport.SuppliedStreams);
        await using var other = LocalRpcRegistration.Create(otherLaunch, Guid.NewGuid());
        var supplier = new LocalRpcStreamSupplier();
        var builder = LocalRpcServer.CreateBuilder(supplier).AddService(service);
        if (foreign) builder.RequireRegistration(other);
        await using var server = builder.Build();
        await server.StartAsync(Ct);
        await using var channel = LocalRpcClientChannel.CreateFromStreams(_ =>
        {
            var (client, accepted) = InMemoryDuplexStream.CreatePair();
            Assert.True(supplier.TrySupply(accepted));
            return ValueTask.FromResult(client);
        });
        using var child = LocalRpcChildBootstrap.FromResource((foreign ? otherLaunch : ownLaunch).HandoffBootstrapResource());
        var request = new LocalBootstrapServiceChallengeRequest
        {
            Meta = Parent.Meta(), InstanceId = Wire.ToId(child.InstanceId), Challenge = ByteString.CopyFrom(child.ClientChallenge.Span),
            Caller = Parent.Manifest(world.Identity, child.InstanceId, ownLaunch.Descriptor.Parent),
        };
        var error = await Assert.ThrowsAsync<RpcException>(() => new LocalBootstrapService.LocalBootstrapServiceClient(channel.CallInvoker)
            .ChallengeAsync(request, cancellationToken: Ct).ResponseAsync);
        Assert.Equal(StatusCode.Unauthenticated, error.StatusCode);
        Assert.Equal(LocalRpcRegistrationState.AwaitingBootstrap, own.State);
        Assert.Equal(LocalRpcRegistrationState.AwaitingBootstrap, other.State);
    }

    private sealed class Parent : IAsyncDisposable
    {
        private readonly LocalRpcStreamSupplier _supplier;
        private readonly LocalRpcChildBootstrap _child;
        private readonly RegWorld _world;
        private Parent(RegWorld world, LocalRpcLaunch launch, LocalRpcStreamSupplier supplier, LocalRpcChildBootstrap child,
            LocalRpcParentBootstrapHost host, EndpointManifest manifest, ProbeBrokerService probe)
        {
            _world = world; Launch = launch; _supplier = supplier; _child = child; Host = host;
            ServerManifest = manifest; ParentInstance = Wire.FromId(manifest.InstanceId); Probe = probe;
        }
        internal LocalRpcLaunch Launch { get; }
        internal LocalRpcParentBootstrapHost Host { get; }
        internal EndpointManifest ServerManifest { get; }
        internal Guid ParentInstance { get; }
        internal ProbeBrokerService Probe { get; }

        internal static async Task<Parent> StartAsync(RegWorld world, CancellationToken cancellation)
        {
            var launch = world.Authority.Launch("production-adapter", world.Identity, LocalRpcLaunchTransport.SuppliedStreams);
            var child = LocalRpcChildBootstrap.FromResource(launch.HandoffBootstrapResource());
            var supplier = new LocalRpcStreamSupplier();
            var manifest = Manifest(world.Identity, Guid.NewGuid(), launch.Descriptor.Parent);
            var probe = new ProbeBrokerService();
            var host = await LocalRpcParentBootstrapHost.StartAsync(launch, manifest,
                LocalRpcServer.CreateBuilder(supplier).AddService(probe), cancellation);
            return new(world, launch, supplier, child, host, manifest, probe);
        }
        internal LocalRpcClientChannel Channel() => LocalRpcClientChannel.CreateFromStreams(_ =>
        {
            var (client, server) = InMemoryDuplexStream.CreatePair();
            if (!_supplier.TrySupply(server)) { server.Dispose(); client.Dispose(); throw new InvalidOperationException("The closed parent refused the stream."); }
            return ValueTask.FromResult(client);
        });
        internal LocalBootstrapServiceChallengeRequest Request() => new()
        {
            Meta = Meta(), InstanceId = Wire.ToId(_child.InstanceId), Challenge = ByteString.CopyFrom(_child.ClientChallenge.Span),
            Caller = Manifest(_world.Identity, _child.InstanceId, Launch.Descriptor.Parent),
        };
        internal async Task<(RegisteredChild Registered, LocalBootstrapServiceChallengeResponse Challenge)> RegisterAsync(CallInvoker invoker, CancellationToken cancellation)
        {
            var client = new LocalBootstrapService.LocalBootstrapServiceClient(invoker);
            var challenge = await client.ChallengeAsync(Request(), cancellationToken: cancellation);
            Assert.True(ContractShapeValidation.IsValid(challenge));
            var value = challenge.Value;
            var proof = _child.ComputeProof(Wire.FromId(value.ChallengeId), value.ServerChallenge.Span, Wire.FromId(value.Server.InstanceId));
            var confirmed = await client.ConfirmAsync(new()
            {
                Meta = Meta(), ChallengeId = value.ChallengeId, Proof = ByteString.CopyFrom(proof),
            }, cancellationToken: cancellation);
            Assert.True(ContractShapeValidation.IsValid(confirmed));
            var nonce = confirmed.Value.PeerNonce.ToByteArray();
            return (new(_child, _child.AcceptGrant(nonce), nonce, BootstrapWire.FromInstant(confirmed.Value.ExpiresAt), invoker), challenge);
        }
        internal static RequestMeta Meta() => new() { CorrelationId = Wire.ToId(Guid.NewGuid()), CommandId = Wire.ToId(Guid.NewGuid()) };
        internal static EndpointManifest Manifest(LocalRpcLaunchIdentity identity, Guid instance, LocalRpcProcessIdentity process)
        {
            var value = new EndpointManifest
            {
                SchemaVersion = "1", AppId = identity.BuildId, InstallationId = Wire.ToId(Guid.NewGuid()), InstanceId = Wire.ToId(instance),
                ProcessId = (ulong)process.ProcessId, ProcessStartedAt = Wire.ToInstant(new DateTimeOffset(process.StartTimeUtcTicks, TimeSpan.Zero)),
                Endpoint = new LocalEndpoint { Transport = "supplied-stream", Address = "memory-test", InstanceId = Wire.ToId(instance) },
                BuildHash = Convert.ToHexStringLower(identity.BuildDigest.Span), ContractSetHash = Convert.ToHexStringLower(identity.ContractSetDigest.Span),
            };
            value.ContractMajors.Add(identity.ProtocolVersion);
            Assert.True(ContractShapeValidation.IsValid(value));
            return value;
        }
        public async ValueTask DisposeAsync() { await Host.DisposeAsync(); _child.Dispose(); }
    }
}
