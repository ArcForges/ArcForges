// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>Declarations and requests the routing tests share. The sandbox service name is data only: no Sandbox contract is admitted here.</summary>
internal static class RouteFixtures
{
    internal const string SandboxService = "arcforges.local.sandbox.v1.ContentSandboxService";

    internal const string OtherService = "arcforges.local.sandbox.v1.OtherService";

    internal static readonly string BootstrapService = LocalBootstrapService.Descriptor.FullName;

    internal static readonly string BrokerService = ConnectorBrokerService.Descriptor.FullName;

    /// <summary>A sandbox child: its service at majors 1 and 2 with two capabilities, and the bootstrap service.</summary>
    internal static LocalRpcChildDeclaration Sandbox(LocalRpcChildKind kind = LocalRpcChildKind.ContentSandbox) =>
        new(
            kind,
            [
                new LocalRpcServiceDeclaration(SandboxService, [1u, 2u], ["image.read", "pdf.render"]),
                new LocalRpcServiceDeclaration(BootstrapService, [1u]),
            ]);

    internal static LocalRpcRouteRequest Request(string slot = "slot-a", string service = SandboxService, uint major = 1, params string[] capabilities) =>
        new(slot, service, major, capabilities);

    internal static LocalRpcResolvedRoute Resolve(LocalRpcRouter router, LocalRpcRouteRequest request)
    {
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(request, out var route));
        return route!;
    }

    /// <summary>A registered child on the world's authority, added to the router with the sandbox declaration.</summary>
    internal static RegSession AddRegistered(RegWorld world, LocalRpcRouter router, string slot = "slot-a", LocalRpcChildDeclaration? declaration = null)
    {
        var session = world.Start(slot);
        _ = session.Register();
        router.Add(session.Registration, declaration ?? Sandbox());
        return session;
    }
}

/// <summary>
/// WP-08.03 without any transport: what a declaration may say, and what the router resolves, refuses and never does. The registrations
/// run on the fake clock, fake timers and fake process table of the registration fixtures; these are state fixtures, never OS evidence.
/// </summary>
public sealed class LocalRpcRoutingTests
{
    private static readonly TimeSpan Second = TimeSpan.FromSeconds(1);

    // ---- declarations

    [Fact]
    public void AServiceDeclarationIsValidatedCopiedAndNormalized()
    {
        var majors = new uint[] { 3, 1, 3, 2 };
        var capabilities = new[] { "pdf.render", "image.read", "pdf.render" };

        var declaration = new LocalRpcServiceDeclaration(RouteFixtures.SandboxService, majors, capabilities);

        Assert.Equal(RouteFixtures.SandboxService, declaration.ServiceName);
        Assert.Equal([1u, 2u, 3u], declaration.ContractMajors);
        Assert.Equal(["image.read", "pdf.render"], declaration.Capabilities);
        majors[0] = 9;
        capabilities[0] = "mutated";
        Assert.Equal([1u, 2u, 3u], declaration.ContractMajors);
        Assert.Equal(["image.read", "pdf.render"], declaration.Capabilities);
        Assert.Empty(new LocalRpcServiceDeclaration("a.B", [1u]).Capabilities);
        Assert.True(declaration.Serves(2));
        Assert.False(declaration.Serves(4));
        Assert.True(declaration.Offers("pdf.render"));
        Assert.False(declaration.Offers("PDF.render"));
    }

    [Fact]
    public void AServiceDeclarationRefusesWhatIsNotAServiceAMajorOrACapability()
    {
        _ = Assert.Throws<ArgumentNullException>(() => new LocalRpcServiceDeclaration(null!, [1u]));
        _ = Assert.Throws<ArgumentNullException>(() => new LocalRpcServiceDeclaration("a.B", null!));
        foreach (var name in new[] { string.Empty, "1a.B", "a..B", ".a.B", "a.B.", "a.B c", "a/B", new string('a', LocalRpcServiceDeclaration.MaximumNameLength + 1) })
        {
            _ = Assert.Throws<ArgumentException>(() => new LocalRpcServiceDeclaration(name, [1u]));
        }

        _ = new LocalRpcServiceDeclaration(new string('a', LocalRpcServiceDeclaration.MaximumNameLength), [1u]);
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcServiceDeclaration("a.B", []));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcServiceDeclaration("a.B", [1u, 0u]));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcServiceDeclaration("a.B", Enumerable.Range(1, LocalRpcServiceDeclaration.MaximumMajors + 1).Select(value => (uint)value)));
        _ = new LocalRpcServiceDeclaration("a.B", Enumerable.Range(1, LocalRpcServiceDeclaration.MaximumMajors).Select(value => (uint)value));
        foreach (var capability in new[] { string.Empty, "1x", ".x", "has space", "x/y", "xé", new string('x', LocalRpcServiceDeclaration.MaximumNameLength + 1) })
        {
            _ = Assert.Throws<ArgumentException>(() => new LocalRpcServiceDeclaration("a.B", [1u], [capability]));
        }

        _ = Assert.Throws<ArgumentException>(() => new LocalRpcServiceDeclaration("a.B", [1u], [null!]));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcServiceDeclaration("a.B", [1u], Enumerable.Range(0, LocalRpcServiceDeclaration.MaximumCapabilities + 1).Select(value => "c" + value)));
        _ = new LocalRpcServiceDeclaration("a.B", [1u], Enumerable.Range(0, LocalRpcServiceDeclaration.MaximumCapabilities).Select(value => "c" + value));
        _ = new LocalRpcServiceDeclaration("a.B", [1u], ["a", "a.b-c_d:e9", new string('x', LocalRpcServiceDeclaration.MaximumNameLength)]);
    }

    [Fact]
    public void AChildDeclarationNeedsAKindAndUniqueServicesAndOrdersThem()
    {
        var late = new LocalRpcServiceDeclaration("z.Last", [1u]);
        var early = new LocalRpcServiceDeclaration("a.First", [1u]);

        var declaration = new LocalRpcChildDeclaration(LocalRpcChildKind.Connector, [late, early]);

        Assert.Equal(LocalRpcChildKind.Connector, declaration.ChildKind);
        Assert.Equal([early, late], declaration.Services);
        Assert.Same(early, declaration.Find("a.First"));
        Assert.Null(declaration.Find("a.first"));
        Assert.Null(declaration.Find("a.Fir"));
        _ = Assert.Throws<ArgumentNullException>(() => new LocalRpcChildDeclaration(LocalRpcChildKind.Connector, null!));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcChildDeclaration(LocalRpcChildKind.None, [early]));
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new LocalRpcChildDeclaration((LocalRpcChildKind)99, [early]));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcChildDeclaration(LocalRpcChildKind.Connector, []));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcChildDeclaration(LocalRpcChildKind.Connector, [early, null!]));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcChildDeclaration(LocalRpcChildKind.Connector, [early, new LocalRpcServiceDeclaration("a.First", [2u])]));
        _ = Assert.Throws<ArgumentException>(() => new LocalRpcChildDeclaration(
            LocalRpcChildKind.Connector,
            Enumerable.Range(0, LocalRpcChildDeclaration.MaximumServices + 1).Select(value => new LocalRpcServiceDeclaration("s.S" + value, [1u]))));
        _ = new LocalRpcChildDeclaration(
            LocalRpcChildKind.Connector,
            Enumerable.Range(0, LocalRpcChildDeclaration.MaximumServices).Select(value => new LocalRpcServiceDeclaration("s.S" + value, [1u])));
    }

    // ---- resolution

    [Fact]
    public void ARegisteredChildResolvesItsDeclaredServiceAtAServedMajorWithItsCapabilities()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        var session = RouteFixtures.AddRegistered(world, router);

        var route = RouteFixtures.Resolve(router, RouteFixtures.Request(major: 2, capabilities: ["pdf.render", "image.read"]));

        Assert.Equal("slot-a", route.Slot);
        Assert.Equal(session.Launch.Descriptor.Epoch, route.Epoch);
        Assert.Equal(session.Launch.Descriptor.LaunchId, route.LaunchId);
        Assert.Equal(LocalRpcChildKind.ContentSandbox, route.ChildKind);
        Assert.Equal(RouteFixtures.SandboxService, route.ServiceName);
        Assert.Equal(2u, route.ContractMajor);
        Assert.Equal(["pdf.render", "image.read"], route.Capabilities);
        Assert.Equal(1u, RouteFixtures.Resolve(router, RouteFixtures.Request(major: 1)).ContractMajor);
        Assert.Empty(RouteFixtures.Resolve(router, new LocalRpcRouteRequest("slot-a", RouteFixtures.BootstrapService, 1)).Capabilities);
    }

    [Fact]
    public void AChildThatWasNeverAddedResolvesToNothingEvenWhenItIsLaunchedAndRegistered()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        var launched = world.Start("slot-a");
        _ = launched.Register();
        _ = RouteFixtures.AddRegistered(world, router, "slot-b");

        Assert.Equal(LocalRpcRouteRefusal.UnknownChild, router.TryResolve(RouteFixtures.Request("slot-a"), out var route));
        Assert.Null(route);
        Assert.Equal(LocalRpcRouteRefusal.UnknownChild, router.TryResolve(RouteFixtures.Request("SLOT-B"), out _));
        Assert.Equal(LocalRpcRouteRefusal.UnknownChild, router.TryResolve(RouteFixtures.Request("slot-"), out _));
        Assert.Equal(LocalRpcRouteRefusal.UnknownChild, router.TryResolve(RouteFixtures.Request("sandbox"), out _));
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request("slot-b"), out _));
    }

    [Fact]
    public void AServiceTheChildDidNotDeclareIsRefusedAndNoOtherChildIsConsulted()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        _ = RouteFixtures.AddRegistered(world, router, "slot-a", new LocalRpcChildDeclaration(LocalRpcChildKind.ContentSandbox, [new LocalRpcServiceDeclaration(RouteFixtures.SandboxService, [1u])]));
        _ = RouteFixtures.AddRegistered(world, router, "slot-b", new LocalRpcChildDeclaration(LocalRpcChildKind.ContentSandbox, [new LocalRpcServiceDeclaration(RouteFixtures.OtherService, [1u])]));

        Assert.Equal(LocalRpcRouteRefusal.ServiceNotDeclared, router.TryResolve(RouteFixtures.Request("slot-a", RouteFixtures.OtherService), out var route));
        Assert.Null(route);
        Assert.Equal(LocalRpcRouteRefusal.ServiceNotDeclared, router.TryResolve(RouteFixtures.Request("slot-b", RouteFixtures.SandboxService), out _));
        Assert.Equal(LocalRpcRouteRefusal.ServiceNotDeclared, router.TryResolve(RouteFixtures.Request("slot-a", RouteFixtures.SandboxService.ToUpperInvariant()), out _));
        Assert.Equal(LocalRpcRouteRefusal.ServiceNotDeclared, router.TryResolve(RouteFixtures.Request("slot-a", RouteFixtures.SandboxService[..^1]), out _));
        Assert.Equal(LocalRpcRouteRefusal.ServiceNotDeclared, router.TryResolve(RouteFixtures.Request("slot-a", RouteFixtures.BootstrapService), out _));
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request("slot-a", RouteFixtures.SandboxService), out _));
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request("slot-b", RouteFixtures.OtherService), out _));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(3u)]
    [InlineData(uint.MaxValue)]
    public void AContractMajorTheChildDoesNotServeIsRefused(uint major)
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        _ = RouteFixtures.AddRegistered(world, router);

        Assert.Equal(LocalRpcRouteRefusal.VersionUnsupported, router.TryResolve(RouteFixtures.Request(major: major), out var route));
        Assert.Null(route);
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request(major: 1), out _));
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request(major: 2), out _));
    }

    [Fact]
    public void ACapabilityTheChildDoesNotOfferIsRefusedWhateverElseItOffers()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        _ = RouteFixtures.AddRegistered(world, router);

        Assert.Equal(LocalRpcRouteRefusal.CapabilityUnsupported, router.TryResolve(RouteFixtures.Request(capabilities: ["ocr"]), out var route));
        Assert.Null(route);
        Assert.Equal(LocalRpcRouteRefusal.CapabilityUnsupported, router.TryResolve(RouteFixtures.Request(capabilities: ["image.read", "ocr"]), out _));
        Assert.Equal(LocalRpcRouteRefusal.CapabilityUnsupported, router.TryResolve(RouteFixtures.Request(capabilities: ["ocr", "image.read"]), out _));
        Assert.Equal(LocalRpcRouteRefusal.CapabilityUnsupported, router.TryResolve(RouteFixtures.Request(capabilities: ["Image.read"]), out _));
        Assert.Equal(LocalRpcRouteRefusal.CapabilityUnsupported, router.TryResolve(RouteFixtures.Request("slot-a", RouteFixtures.BootstrapService, 1, "image.read"), out _));
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request(capabilities: ["image.read"]), out _));
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request(capabilities: ["image.read", "image.read", "pdf.render"]), out _));
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(new LocalRpcRouteRequest("slot-a", RouteFixtures.SandboxService, 1, null), out _));
    }

    [Fact]
    public void AMalformedRequestIsRefusedBeforeAnythingIsLookedUp()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        _ = RouteFixtures.AddRegistered(world, router);
        var tooMany = Enumerable.Range(0, LocalRpcServiceDeclaration.MaximumCapabilities + 1).Select(value => "c" + value).ToArray();

        _ = Assert.Throws<ArgumentNullException>(() => router.TryResolve(null!, out _));
        foreach (var request in new LocalRpcRouteRequest[]
        {
            new(null!, RouteFixtures.SandboxService, 1),
            new(string.Empty, RouteFixtures.SandboxService, 1),
            new(new string('s', LocalRpcLaunchIdentity.MaximumTokenLength + 1), RouteFixtures.SandboxService, 1),
            new("slot-a", null!, 1),
            new("slot-a", string.Empty, 1),
            new("slot-a", "not a service", 1),
            new("slot-a", RouteFixtures.SandboxService + "/Method", 1),
            new("slot-a", new string('a', LocalRpcServiceDeclaration.MaximumNameLength + 1), 1),
            new("slot-a", RouteFixtures.SandboxService, 1, ["image.read", null!]),
            new("slot-a", RouteFixtures.SandboxService, 1, ["bad name"]),
            new("slot-a", RouteFixtures.SandboxService, 1, tooMany),
        })
        {
            Assert.Equal(LocalRpcRouteRefusal.InvalidRequest, router.TryResolve(request, out var route));
            Assert.Null(route);
        }

        Assert.Equal(LocalRpcRouteRefusal.InvalidRequest, router.TryResolve(new LocalRpcRouteRequest("unknown-slot", "not a service", 1), out _));
        // The limits are inclusive: a 64-character slot is a valid (unknown) slot, and 32 capabilities are a valid (unoffered) list.
        Assert.Equal(LocalRpcRouteRefusal.UnknownChild, router.TryResolve(new LocalRpcRouteRequest(new string('s', LocalRpcLaunchIdentity.MaximumTokenLength), RouteFixtures.SandboxService, 1), out _));
        Assert.Equal(LocalRpcRouteRefusal.CapabilityUnsupported, router.TryResolve(RouteFixtures.Request(capabilities: tooMany[..LocalRpcServiceDeclaration.MaximumCapabilities]), out _));
    }

    [Fact]
    public void TheRefusalsComeInAFixedOrderAndTheFirstFailureIsTheAnswer()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        var waiting = world.Start("slot-w");
        router.Add(waiting.Registration, RouteFixtures.Sandbox());
        var ended = RouteFixtures.AddRegistered(world, router, "slot-e");
        ended.Launch.Revoke();
        _ = RouteFixtures.AddRegistered(world, router, "slot-a");

        // Not registered and ended outrank every question about the service.
        Assert.Equal(LocalRpcRouteRefusal.ChildNotRegistered, router.TryResolve(RouteFixtures.Request("slot-w", RouteFixtures.OtherService, 9, "ocr"), out _));
        Assert.Equal(LocalRpcRouteRefusal.ChildEnded, router.TryResolve(RouteFixtures.Request("slot-e", RouteFixtures.OtherService, 9, "ocr"), out _));
        // An undeclared service outranks the major, and an unsupported major outranks a missing capability.
        Assert.Equal(LocalRpcRouteRefusal.ServiceNotDeclared, router.TryResolve(RouteFixtures.Request("slot-a", RouteFixtures.OtherService, 9, "ocr"), out _));
        Assert.Equal(LocalRpcRouteRefusal.VersionUnsupported, router.TryResolve(RouteFixtures.Request("slot-a", RouteFixtures.SandboxService, 9, "ocr"), out _));
        Assert.Equal(LocalRpcRouteRefusal.CapabilityUnsupported, router.TryResolve(RouteFixtures.Request("slot-a", RouteFixtures.SandboxService, 1, "ocr"), out _));
        // A malformed request outranks everything, including an unknown slot.
        Assert.Equal(LocalRpcRouteRefusal.InvalidRequest, router.TryResolve(RouteFixtures.Request(string.Empty), out _));
        Assert.Equal(LocalRpcRouteRefusal.UnknownChild, router.TryResolve(RouteFixtures.Request("slot-x", RouteFixtures.OtherService, 9, "ocr"), out _));
    }

    [Fact]
    public void AChildAddedBeforeItRegisteredIsNotRoutedToUntilItDoes()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        var session = world.Start("slot-a");
        router.Add(session.Registration, RouteFixtures.Sandbox());

        Assert.Equal(LocalRpcRouteRefusal.ChildNotRegistered, router.TryResolve(RouteFixtures.Request(), out _));
        var challenge = session.Challenge();
        Assert.Equal(LocalRpcRouteRefusal.ChildNotRegistered, router.TryResolve(RouteFixtures.Request(), out _));
        Assert.Equal(LocalRpcRegistrationRefusal.None, session.Confirm(challenge));

        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request(), out _));
    }

    [Fact]
    public void AChildWhoseLeasePassedIsEndedEvenBeforeAnyTimerFires()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        var session = RouteFixtures.AddRegistered(world, router);
        var route = RouteFixtures.Resolve(router, RouteFixtures.Request());
        world.Clock.SuspendTimers = true;

        world.Clock.Advance(LocalRpcRegistration.LeaseDuration - Second);
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request(), out _));
        Assert.Equal(LocalRpcRegistrationRefusal.None, route.CheckLive());
        world.Clock.Advance(Second);

        Assert.Equal(LocalRpcRegistrationState.Registered, session.Registration.State);
        Assert.Equal(LocalRpcRouteRefusal.ChildEnded, router.TryResolve(RouteFixtures.Request(), out var after));
        Assert.Null(after);
        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
        Assert.Equal(LocalRpcRegistrationEnd.LeaseExpired, session.Registration.EndReason);
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, route.CheckLive());
        Assert.Equal(LocalRpcRouteRefusal.ChildEnded, router.TryResolve(RouteFixtures.Request(), out _));
    }

    [Fact]
    public async Task ARevokedLaunchAndADisposedRegistrationEndTheRoute()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        var revoked = RouteFixtures.AddRegistered(world, router, "slot-r");
        var disposed = RouteFixtures.AddRegistered(world, router, "slot-d");

        revoked.Launch.Revoke();
        await disposed.Registration.DisposeAsync();

        Assert.Equal(LocalRpcRouteRefusal.ChildEnded, router.TryResolve(RouteFixtures.Request("slot-r"), out _));
        Assert.Equal(LocalRpcRouteRefusal.ChildEnded, router.TryResolve(RouteFixtures.Request("slot-d"), out _));
    }

    [Fact]
    public void ARelaunchedSlotNeedsItsNewRegistrationAddedAndTheOldRouteStopsAtOnce()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        var first = RouteFixtures.AddRegistered(world, router);
        var oldRoute = RouteFixtures.Resolve(router, RouteFixtures.Request());

        var second = world.Start("slot-a");

        Assert.Equal(LocalRpcRegistrationState.Ended, first.Registration.State);
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, oldRoute.CheckLive());
        Assert.Equal(LocalRpcRouteRefusal.ChildEnded, router.TryResolve(RouteFixtures.Request(), out _));
        router.Add(second.Registration, RouteFixtures.Sandbox());
        Assert.Equal(LocalRpcRouteRefusal.ChildNotRegistered, router.TryResolve(RouteFixtures.Request(), out _));
        _ = second.Register();
        var newRoute = RouteFixtures.Resolve(router, RouteFixtures.Request());
        Assert.Equal(first.Launch.Descriptor.Epoch + 1, newRoute.Epoch);
        Assert.NotEqual(oldRoute.LaunchId, newRoute.LaunchId);
        Assert.Equal(LocalRpcRegistrationRefusal.None, newRoute.CheckLive());
        Assert.Equal(LocalRpcRegistrationRefusal.Ended, oldRoute.CheckLive());
    }

    [Fact]
    public void AddRefusesWhatItCannotRouteTo()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        var session = world.Start("slot-a");

        _ = Assert.Throws<ArgumentNullException>(() => router.Add(null!, RouteFixtures.Sandbox()));
        _ = Assert.Throws<ArgumentNullException>(() => router.Add(session.Registration, null!));
        _ = Assert.Throws<ArgumentException>(() => router.Add(session.Registration, RouteFixtures.Sandbox(LocalRpcChildKind.Connector)));
        _ = Assert.Throws<ArgumentException>(() => router.Add(session.Registration, RouteFixtures.Sandbox(LocalRpcChildKind.ExecutableExtension)));
        Assert.Equal(LocalRpcRouteRefusal.UnknownChild, router.TryResolve(RouteFixtures.Request(), out _));

        router.Add(session.Registration, RouteFixtures.Sandbox());
        // A slot holds one child while its registration lives, whether it awaits its bootstrap or is registered.
        _ = Assert.Throws<InvalidOperationException>(() => router.Add(session.Registration, RouteFixtures.Sandbox()));
        _ = session.Register();
        _ = Assert.Throws<InvalidOperationException>(() => router.Add(session.Registration, RouteFixtures.Sandbox()));
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request(), out _));

        var ended = world.Start("slot-b");
        ended.Launch.Revoke();
        _ = Assert.Throws<InvalidOperationException>(() => router.Add(ended.Registration, RouteFixtures.Sandbox()));
        Assert.Equal(LocalRpcRouteRefusal.UnknownChild, router.TryResolve(RouteFixtures.Request("slot-b"), out _));
    }

    [Fact]
    public void ResolvingNeverExtendsALeaseOrTouchesTheRegistration()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        var session = RouteFixtures.AddRegistered(world, router);
        var expiry = session.Registration.LeaseExpiresAtUtc;
        var held = session.Registration.HeldState();
        world.Clock.Advance(Second * 10);

        for (var attempt = 0; attempt < 3; attempt++)
        {
            _ = RouteFixtures.Resolve(router, RouteFixtures.Request(capabilities: ["image.read"]));
            Assert.Equal(LocalRpcRouteRefusal.VersionUnsupported, router.TryResolve(RouteFixtures.Request(major: 7), out _));
            Assert.Equal(LocalRpcRouteRefusal.ServiceNotDeclared, router.TryResolve(RouteFixtures.Request(service: RouteFixtures.OtherService), out _));
        }

        Assert.Equal(expiry, session.Registration.LeaseExpiresAtUtc);
        Assert.Equal(held, session.Registration.HeldState());
        Assert.Equal(LocalRpcRegistrationState.Registered, session.Registration.State);
        world.Clock.Advance(LocalRpcRegistration.LeaseDuration - (Second * 10));
        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
        Assert.Equal(LocalRpcRouteRefusal.ChildEnded, router.TryResolve(RouteFixtures.Request(), out _));
    }

    [Fact]
    public void TheRouterDecidesFromWhatWasAddedAndNothingElse()
    {
        using var world = new RegWorld();
        var empty = new LocalRpcRouter();
        var router = new LocalRpcRouter();
        _ = RouteFixtures.AddRegistered(world, router, "slot-a");

        // A second router knows nothing of the first one's children, and a launch the authority issued is not a route.
        Assert.Equal(LocalRpcRouteRefusal.UnknownChild, empty.TryResolve(RouteFixtures.Request(), out _));
        Assert.Equal(LocalRpcRouteRefusal.UnknownChild, empty.TryResolve(RouteFixtures.Request("slot-a", RouteFixtures.BootstrapService), out _));
        Assert.Equal(1, world.Authority.IssuedCount);
        Assert.Equal(LocalRpcRouteRefusal.None, router.TryResolve(RouteFixtures.Request(), out _));
    }
}

/// <summary>A call invoker that only counts the calls that reach it, and throws a marker so a test can tell a call that passed an interceptor.</summary>
internal sealed class ReachedInvoker : CallInvoker
{
    private int _reached;

    internal int Reached => Volatile.Read(ref _reached);

    public override TResponse BlockingUnaryCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request) => Reach<TResponse>();

    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request) => Reach<AsyncUnaryCall<TResponse>>();

    public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request) => Reach<AsyncServerStreamingCall<TResponse>>();

    public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options) => Reach<AsyncClientStreamingCall<TRequest, TResponse>>();

    public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options) => Reach<AsyncDuplexStreamingCall<TRequest, TResponse>>();

    private T Reach<T>()
    {
        _ = Interlocked.Increment(ref _reached);
        throw new ReachedException();
    }
}

internal sealed class ReachedException : Exception
{
    public ReachedException()
        : base("The call reached the invoker.")
    {
    }

    public ReachedException(string message)
        : base(message)
    {
    }

    public ReachedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>The route guard on every kind of call, then over real Kestrel HTTP/2, and the declared service set of a server.</summary>
[Collection(LocalRpcCollection.Name)]
public sealed class LocalRpcRoutingWireTests
{
    private static readonly Marshaller<byte[]> Bytes = Marshallers.Create(value => value, value => value);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static Method<byte[], byte[]> Method(MethodType type, string service, string name = "M") => new(type, service, name, Bytes, Bytes);

    private static void CallEveryKind(CallInvoker invoker, string service, Action<RpcException?> check)
    {
        Action[] calls =
        [
            () => _ = invoker.BlockingUnaryCall(Method(MethodType.Unary, service), null, default, []),
            () => _ = invoker.AsyncUnaryCall(Method(MethodType.Unary, service), null, default, []),
            () => _ = invoker.AsyncServerStreamingCall(Method(MethodType.ServerStreaming, service), null, default, []),
            () => _ = invoker.AsyncClientStreamingCall(Method(MethodType.ClientStreaming, service), null, default),
            () => _ = invoker.AsyncDuplexStreamingCall(Method(MethodType.DuplexStreaming, service), null, default),
        ];
        foreach (var call in calls)
        {
            try
            {
                call();
                Assert.Fail("The call must not complete.");
            }
            catch (RpcException exception)
            {
                check(exception);
            }
            catch (ReachedException)
            {
                check(null);
            }
        }
    }

    [Fact]
    public void TheGuardRefusesEveryKindOfCallToAnotherServiceBeforeItReachesTheChannelAndPassesTheRoutedOne()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        _ = RouteFixtures.AddRegistered(world, router);
        var route = RouteFixtures.Resolve(router, RouteFixtures.Request());
        var inner = new ReachedInvoker();
        var guarded = inner.Intercept(route.CreateGuard());
        var refused = 0;

        CallEveryKind(guarded, RouteFixtures.OtherService, exception =>
        {
            Assert.NotNull(exception);
            Assert.Equal(StatusCode.Unimplemented, exception.StatusCode);
            Assert.True(LocalRpcRefusal.TryRead(exception, out var refusal));
            Assert.Equal(LocalRpcRefusalReason.UnroutedService, refusal!.Reason);
            refused++;
        });
        Assert.Equal(5, refused);
        Assert.Equal(0, inner.Reached);

        var passed = 0;
        CallEveryKind(guarded, RouteFixtures.SandboxService, exception =>
        {
            Assert.Null(exception);
            passed++;
        });
        Assert.Equal(5, passed);
        Assert.Equal(5, inner.Reached);
        // The service name is compared exactly: a longer or differently cased name is another service.
        CallEveryKind(guarded, RouteFixtures.SandboxService + "X", exception => Assert.Equal(LocalRpcRefusalReason.UnroutedService, LocalRpcRefusal.TryRead(exception!, out var refusal) ? refusal!.Reason : default));
        CallEveryKind(guarded, RouteFixtures.SandboxService.ToUpperInvariant(), exception => Assert.NotNull(exception));
        Assert.Equal(5, inner.Reached);
    }

    [Fact]
    public void TheGuardRefusesEveryKindOfCallOnceTheChildIsNoLongerRegistered()
    {
        using var world = new RegWorld();
        var router = new LocalRpcRouter();
        var session = RouteFixtures.AddRegistered(world, router);
        var route = RouteFixtures.Resolve(router, RouteFixtures.Request());
        var inner = new ReachedInvoker();
        var guarded = inner.Intercept(route.CreateGuard());
        world.Clock.SuspendTimers = true;
        world.Clock.Advance(LocalRpcRegistration.LeaseDuration);
        var refused = 0;

        CallEveryKind(guarded, RouteFixtures.SandboxService, exception =>
        {
            Assert.NotNull(exception);
            Assert.Equal(StatusCode.FailedPrecondition, exception.StatusCode);
            Assert.True(LocalRpcRefusal.TryRead(exception, out var refusal));
            Assert.Equal(LocalRpcRefusalReason.RouteNotLive, refusal!.Reason);
            refused++;
        });

        Assert.Equal(5, refused);
        Assert.Equal(0, inner.Reached);
        Assert.Equal(LocalRpcRegistrationState.Ended, session.Registration.State);
        // A wrong service is still answered as one: the route-service check comes first.
        CallEveryKind(guarded, RouteFixtures.OtherService, exception => Assert.Equal(LocalRpcRefusalReason.UnroutedService, LocalRpcRefusal.TryRead(exception!, out var refusal) ? refusal!.Reason : default));
        Assert.Equal(0, inner.Reached);
    }

    [Fact]
    public async Task ARoutedCallIsServedAndANonRoutedOneNeverReachesTheServerThenTheRouteStopsWithTheLease()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        var router = new LocalRpcRouter();
        router.Add(harness.Registration, new LocalRpcChildDeclaration(
            LocalRpcChildKind.ContentSandbox,
            [new LocalRpcServiceDeclaration(RouteFixtures.BrokerService, [1u]), new LocalRpcServiceDeclaration(RouteFixtures.BootstrapService, [1u])]));
        var route = RouteFixtures.Resolve(router, new LocalRpcRouteRequest("slot-a", RouteFixtures.BrokerService, 1));
        var invoker = channel.CallInvoker.Intercept(child.Credentials).Intercept(route.CreateGuard());
        var renewsBefore = harness.Adapter.Renews;

        Assert.Equal(StatusCode.OK, (await ChildClient.ListStatusAsync(invoker, Ct)).StatusCode);
        Assert.Equal(1, harness.Probe.Dispatched);
        var wrong = await Assert.ThrowsAsync<RpcException>(async () => _ = await new LocalBootstrapService.LocalBootstrapServiceClient(invoker).RenewAsync(
            new LocalBootstrapServiceRenewRequest { Meta = new() { CommandId = Wire.ToId(Guid.NewGuid()), CorrelationId = Wire.ToId(Guid.NewGuid()) } }, cancellationToken: Ct));
        Assert.True(LocalRpcRefusal.TryRead(wrong, out var unrouted));
        Assert.Equal(LocalRpcRefusalReason.UnroutedService, unrouted!.Reason);
        Assert.Equal(renewsBefore, harness.Adapter.Renews);

        world.Clock.SuspendTimers = true;
        world.Clock.Advance(LocalRpcRegistration.LeaseDuration);
        var status = await ChildClient.ListStatusAsync(invoker, Ct);

        Assert.Equal(StatusCode.FailedPrecondition, status.StatusCode);
        Assert.Equal(1, harness.Probe.Dispatched);
        Assert.Equal(LocalRpcRouteRefusal.ChildEnded, router.TryResolve(new LocalRpcRouteRequest("slot-a", RouteFixtures.BrokerService, 1), out _));
    }

    [Fact]
    public async Task AServiceThatIsNotRegisteredIsRefusedByTheServerBeforeAnyAdmissionOrDispatch()
    {
        using var world = new RegWorld();
        await using var harness = await GateHarness.StartAsync(world, Ct);
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);
        var admittedBefore = harness.Server.GetBoundsSnapshot().DataAdmitted;
        var invoker = child.Authenticated;

        var failure = await Assert.ThrowsAsync<RpcException>(async () => _ = await invoker.AsyncUnaryCall(
            Method(MethodType.Unary, "arcforges.local.sandbox.v1.NeverRegistered", "Open"), null, new CallOptions(deadline: DateTime.UtcNow + TimeSpan.FromSeconds(20), cancellationToken: Ct), []).ResponseAsync);

        Assert.Equal(StatusCode.Unimplemented, failure.StatusCode);
        Assert.False(LocalRpcRefusal.TryRead(failure, out _));
        Assert.Equal(0, harness.Probe.Dispatched);
        Assert.Equal(admittedBefore, harness.Server.GetBoundsSnapshot().DataAdmitted);
    }

    // ---- the declared set of a server

    private static LocalRpcChildDeclaration Declared(params string[] services) =>
        new(LocalRpcChildKind.ContentSandbox, services.Select(name => new LocalRpcServiceDeclaration(name, [1u])));

    [Fact]
    public async Task AServerServesExactlyTheDeclaredServices()
    {
        using var world = new RegWorld();

        await using var harness = await GateHarness.StartAsync(
            world,
            Ct,
            configure: builder => builder.RequireDeclaredServices(Declared(RouteFixtures.BootstrapService, RouteFixtures.BrokerService)));
        await using var channel = harness.NewChannel();
        var child = await harness.RegisterAsync(channel, Ct);

        Assert.Equal(StatusCode.OK, (await ChildClient.ListStatusAsync(child.Authenticated, Ct)).StatusCode);
    }

    [Fact]
    public async Task AServiceServedButNotDeclaredStopsTheServerFromStartingAndIsNamed()
    {
        using var world = new RegWorld();

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => GateHarness.StartAsync(
            world,
            Ct,
            configure: builder => builder.RequireDeclaredServices(Declared(RouteFixtures.BootstrapService))));

        Assert.Contains(RouteFixtures.BrokerService, failure.Message, StringComparison.Ordinal);
        Assert.Contains("did not declare", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("not served", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AServiceDeclaredButNotServedStopsTheServerFromStartingAndIsNamed()
    {
        using var world = new RegWorld();

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => GateHarness.StartAsync(
            world,
            Ct,
            configure: builder => builder.RequireDeclaredServices(Declared(RouteFixtures.BootstrapService, RouteFixtures.BrokerService, RouteFixtures.SandboxService))));

        Assert.Contains(RouteFixtures.SandboxService, failure.Message, StringComparison.Ordinal);
        Assert.Contains("is not served", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("did not declare", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BothKindsOfMismatchAreReportedTogether()
    {
        using var world = new RegWorld();

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => GateHarness.StartAsync(
            world,
            Ct,
            configure: builder => builder.RequireDeclaredServices(Declared(RouteFixtures.BootstrapService, RouteFixtures.OtherService))));

        Assert.Contains(RouteFixtures.BrokerService, failure.Message, StringComparison.Ordinal);
        Assert.Contains(RouteFixtures.OtherService, failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADeclarationIsTakenOnceBeforeBuildAndMustBeForTheRegistrationsKind()
    {
        using var world = new RegWorld();
        var declaration = Declared(RouteFixtures.BootstrapService, RouteFixtures.BrokerService);
        var builder = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ProbeBrokerService());

        _ = Assert.Throws<ArgumentNullException>(() => builder.RequireDeclaredServices(null!));
        _ = builder.RequireDeclaredServices(declaration);
        _ = Assert.Throws<InvalidOperationException>(() => builder.RequireDeclaredServices(declaration));
        await using var server = builder.Build();
        _ = Assert.Throws<InvalidOperationException>(() => builder.RequireDeclaredServices(declaration));
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => server.StartAsync(Ct));
        Assert.Contains(RouteFixtures.BootstrapService, failure.Message, StringComparison.Ordinal);

        var session = world.Start("slot-a");
        var wrongKind = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier())
            .AddService(new BootstrapAdapter())
            .RequireRegistration(session.Registration)
            .RequireDeclaredServices(new LocalRpcChildDeclaration(LocalRpcChildKind.Connector, [new LocalRpcServiceDeclaration(RouteFixtures.BootstrapService, [1u])]));
        _ = Assert.Throws<InvalidOperationException>(() => wrongKind.Build());
    }

    [Fact]
    public async Task AServerWithoutADeclarationStartsAsBefore()
    {
        var plain = LocalRpcServer.CreateBuilder(new LocalRpcStreamSupplier()).AddService(new ProbeBrokerService());
        await using var server = plain.Build();

        await server.StartAsync(Ct);
    }
}
