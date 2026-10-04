// SPDX-License-Identifier: AGPL-3.0-only
#pragma warning disable CA2007 // Test code has no synchronization context to preserve.
#pragma warning disable CA1859 // Tests deliberately use the port interfaces to exercise their contracts.
#pragma warning disable CA2000 // Sessions and hosts here are in-memory test doubles that own no resources.
using ArcForges.Assistant.Abstractions;
using ArcForges.Foundation.Errors;

namespace AssistantAbstractionsTests;

public sealed class CompositionTests
{
    private static readonly Func<FrozenHostContext?, ActionAvailability> Available = _ => new ActionAvailability(true);

    /// <summary>One fully composed application: identity, ports, action registry, options and session.</summary>
    private sealed class Application
    {
        public Application(AssistantProductIdentity product, int installation, int instance = 1)
        {
            Identity = TestData.Host(TestData.Installed(product, installation), instance);
            Host = FakeHost.For(Identity);
            Registry = TestData.Registry(Identity);
            Options = TestData.Options(Identity);
            Factory = new FakeSessionFactory(Identity);
            Services = Composition.Services(Host, Registry, Factory);
        }

        public AssistantHostIdentity Identity { get; }
        public FakeHost Host { get; }
        public AssistantActionRegistry Registry { get; }
        public AssistantHostOptions Options { get; }
        public FakeSessionFactory Factory { get; }
        public AssistantHostServices Services { get; }
        public int Invocations { get; set; }
    }

    [Xunit.Fact]
    public async Task TwoIndependentApplicationIdentitiesShareNoStoreRegistrationOrPort()
    {
        var arcScope = new Application(AssistantProductIdentity.ArcScope, installation: 1);
        var companion = new Application(AssistantProductIdentity.Companion, installation: 1);
        var secondArcScope = new Application(AssistantProductIdentity.ArcScope, installation: 2);
        Application[] all = [arcScope, companion, secondArcScope];

        // The same operation is registered in every application; each registration is private to its composition.
        var tokens = all.Select(application => application.Registry.Register<string, string>(TestData.Descriptor(),
            (request, _) =>
            {
                application.Invocations++;
                return ValueTask.FromResult(Outcome.Success(application.Identity.Product.ProductId + ":" + request));
            }, Available)).ToArray();

        await using var arcSession = AssistantHost.Create(arcScope.Options, arcScope.Services);
        await using var companionSession = AssistantHost.Create(companion.Options, companion.Services);
        await using var secondSession = AssistantHost.Create(secondArcScope.Options, secondArcScope.Services);
        IAssistantSession[] sessions = [arcSession, companionSession, secondSession];

        // Stores: partitions and directories are pairwise distinct, even for the same profile id.
        Xunit.Assert.Equal(3, sessions.Select(session => session.Services.Store.Partition).Distinct().Count());
        Xunit.Assert.Equal(3, all.Select(application => application.Options.DataRoot.InstallationDirectory)
            .Distinct(StringComparer.Ordinal).Count());
        Xunit.Assert.Equal(3, all.Select(application => application.Options.DataRoot.GetProfileDirectory(
            application.Options.InitialStorePartition)).Distinct(StringComparer.Ordinal).Count());
        for (int i = 0; i < all.Length; i++)
        {
            Xunit.Assert.Equal(all[i].Identity, sessions[i].Identity);
            for (int j = 0; j < all.Length; j++)
            {
                if (i == j)
                {
                    continue;
                }

                Xunit.Assert.Throws<ArgumentException>(() => all[i].Options.DataRoot.GetProfileDirectory(all[j].Options.InitialStorePartition));
            }
        }

        // Registration: another application's registry, token or target identity is refused and runs nothing.
        for (int i = 0; i < all.Length; i++)
        {
            for (int j = 0; j < all.Length; j++)
            {
                if (i == j)
                {
                    continue;
                }

                var crossRegistry = await all[i].Registry.InvokeAsync(tokens[j], all[i].Identity, "x",
                    cancellationToken: Xunit.TestContext.Current.CancellationToken);
                Xunit.Assert.True(crossRegistry.TryGetFailure(out var failure));
                Xunit.Assert.Equal("perm.capability_denied", failure.Code);
                var crossTarget = await all[i].Registry.InvokeAsync(tokens[i], all[j].Identity, "x",
                    cancellationToken: Xunit.TestContext.Current.CancellationToken);
                Xunit.Assert.True(crossTarget.TryGetFailure(out failure));
                Xunit.Assert.Equal("perm.capability_denied", failure.Code);
            }
        }

        Xunit.Assert.All(all, application => Xunit.Assert.Equal(0, application.Invocations));
        var own = await arcScope.Registry.InvokeAsync(tokens[0], arcScope.Identity, "x",
            cancellationToken: Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.True(own.TryGetValue(out var text));
        Xunit.Assert.Equal("arcscope:x", text);
        Xunit.Assert.Equal([1, 0, 0], all.Select(application => application.Invocations).ToArray());

        // A frozen context minted for one application cannot drive another application's actions.
        var arcContext = new FrozenHostContext(arcScope.Identity, new AssistantContextBudget(1, 10), []);
        Xunit.Assert.True(companion.Registry.GetAvailability("measurements.read", arcContext).TryGetFailure(out var contextFailure));
        Xunit.Assert.Equal("perm.capability_denied", contextFailure.Code);

        // Ports, store scopes and session factories cannot be swapped between applications.
        Xunit.Assert.Throws<ArgumentException>(() => Composition.Services(companion.Host, arcScope.Registry));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostServices(arcScope.Identity, arcScope.Host,
            arcScope.Registry, arcScope.Host, arcScope.Host, arcScope.Host, arcScope.Host, companion.Host,
            new FakeSessionFactory(arcScope.Identity)));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostServices(arcScope.Identity, arcScope.Host,
            arcScope.Registry, arcScope.Host, arcScope.Host, arcScope.Host, arcScope.Host, arcScope.Host,
            new FakeSessionFactory(companion.Identity)));
        Xunit.Assert.Throws<ArgumentException>(() => AssistantHost.Create(arcScope.Options, companion.Services));
        Xunit.Assert.Throws<ArgumentException>(() => AssistantHost.Create(companion.Options, secondArcScope.Services));
    }

    [Xunit.Fact]
    public void EveryInjectedPortAndSubPortMustBelongToTheSameApplicationInstance()
    {
        var arc = FakeHost.For(TestData.Host());
        var companion = FakeHost.For(TestData.Host(TestData.Installed(AssistantProductIdentity.Companion)));
        var registry = TestData.Registry(arc.Owner);

        Xunit.Assert.NotNull(Composition.Services(arc, registry));
        Xunit.Assert.NotNull(Composition.Services(arc, registry).Context);
        Xunit.Assert.Same(arc, Composition.Services(arc, registry).Navigation);
        Xunit.Assert.Same(registry, Composition.Services(arc, registry).Actions);

        var foreignRegistry = TestData.Registry(companion.Owner);
        Xunit.Assert.Throws<ArgumentException>(() => Composition.Services(arc, foreignRegistry));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostServices(arc.Owner, companion, registry, arc, arc, arc, arc, arc,
            new FakeSessionFactory(arc.Owner)));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostServices(arc.Owner, arc, registry, companion, arc, arc, arc, arc,
            new FakeSessionFactory(arc.Owner)));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostServices(arc.Owner, arc, registry, arc, companion, arc, arc, arc,
            new FakeSessionFactory(arc.Owner)));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostServices(arc.Owner, arc, registry, arc, arc, companion, arc, arc,
            new FakeSessionFactory(arc.Owner)));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostServices(arc.Owner, arc, registry, arc, arc, arc, companion, arc,
            new FakeSessionFactory(arc.Owner)));

        IHostPlatformServices[] mixed =
        [
            new FakeHost(arc.Owner, arc.Partition, dispatcher: companion),
            new FakeHost(arc.Owner, arc.Partition, secureStorage: companion),
            new FakeHost(arc.Owner, arc.Partition, filePicker: companion),
            new FakeHost(arc.Owner, arc.Partition, clipboard: companion),
            new FakeHost(arc.Owner, arc.Partition, environment: companion),
        ];
        foreach (var platform in mixed)
        {
            Xunit.Assert.Throws<ArgumentException>(() => Composition.Services(arc, registry, platform: platform));
        }

        // A same-product, same-installation port from another process instance or epoch is stale, not shared.
        var otherInstance = FakeHost.For(TestData.Host(arc.Owner.Installation, instance: 2));
        var otherEpoch = FakeHost.For(TestData.Host(arc.Owner.Installation, epoch: 99));
        Xunit.Assert.Throws<ArgumentException>(() => Composition.Services(otherInstance, registry));
        Xunit.Assert.Throws<ArgumentException>(() => Composition.Services(otherEpoch, registry));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostServices(arc.Owner, arc, registry, arc, arc,
            otherInstance, arc, arc, new FakeSessionFactory(arc.Owner)));
    }

    [Xunit.Fact]
    public void ServicesRejectNullPortsAndAStoreOfAnotherInstallation()
    {
        var arc = FakeHost.For(TestData.Host());
        var registry = TestData.Registry(arc.Owner);
        var factory = new FakeSessionFactory(arc.Owner);
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantHostServices(null!, arc, registry, arc, arc, arc, arc, arc, factory));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantHostServices(arc.Owner, null!, registry, arc, arc, arc, arc, arc, factory));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantHostServices(arc.Owner, arc, null!, arc, arc, arc, arc, arc, factory));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantHostServices(arc.Owner, arc, registry, null!, arc, arc, arc, arc, factory));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantHostServices(arc.Owner, arc, registry, arc, null!, arc, arc, arc, factory));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantHostServices(arc.Owner, arc, registry, arc, arc, null!, arc, arc, factory));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantHostServices(arc.Owner, arc, registry, arc, arc, arc, null!, arc, factory));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantHostServices(arc.Owner, arc, registry, arc, arc, arc, arc, null!, factory));
        Xunit.Assert.Throws<ArgumentNullException>(() => new AssistantHostServices(arc.Owner, arc, registry, arc, arc, arc, arc, arc, null!));

        var secondInstallation = TestData.Installed(installation: 2);
        var foreignStore = new FakeHost(arc.Owner, new AssistantStorePartition(secondInstallation, TestData.Profile));
        Xunit.Assert.Throws<ArgumentException>(() => Composition.Services(arc, registry, store: foreignStore));
    }

    [Xunit.Fact]
    public void CreateRequiresMatchingIdentityAndProfilePartitionAndSealsRegistrationOnSuccess()
    {
        var application = new Application(AssistantProductIdentity.ArcScope, 1);
        application.Registry.Register<string, string>(TestData.Descriptor(),
            (request, _) => ValueTask.FromResult(Outcome.Success(request)), Available);

        foreach (var wrong in new[]
        {
            TestData.Host(application.Identity.Installation, instance: 2),
            TestData.Host(application.Identity.Installation, epoch: 99),
            TestData.Host(TestData.Installed(installation: 2)),
            TestData.Host(TestData.Installed(AssistantProductIdentity.Companion)),
        })
        {
            Xunit.Assert.Throws<ArgumentException>(() => AssistantHost.Create(TestData.Options(wrong), application.Services));
        }

        // A profile other than the one the store scope is bound to is refused.
        Xunit.Assert.Throws<ArgumentException>(() => AssistantHost.Create(
            TestData.Options(application.Identity, TestData.OtherProfile), application.Services));
        Xunit.Assert.Throws<ArgumentNullException>(() => AssistantHost.Create(null!, application.Services));
        Xunit.Assert.Throws<ArgumentNullException>(() => AssistantHost.Create(application.Options, null!));
        Xunit.Assert.Equal(0, application.Factory.Calls);

        // Registration stays open until the composition has produced its session.
        application.Registry.Register<string, string>(TestData.Descriptor("annotations.append", "annotations.write"),
            (request, _) => ValueTask.FromResult(Outcome.Success(request)), Available);
        var session = AssistantHost.Create(application.Options, application.Services);
        Xunit.Assert.Equal(1, application.Factory.Calls);
        Xunit.Assert.Same(application.Options, session.Options);
        Xunit.Assert.Same(application.Services, session.Services);
        Xunit.Assert.Equal(TestData.Profile, session.CurrentProfile);
        Xunit.Assert.Throws<InvalidOperationException>(() => AssistantHost.Create(application.Options, application.Services));
        Xunit.Assert.Throws<InvalidOperationException>(() => application.Registry.Register<string, string>(
            new AssistantActionDescriptor("measurements.read", "t", "d", [], [], "a"),
            (request, _) => ValueTask.FromResult(Outcome.Success(request)), Available));
        Xunit.Assert.Equal(1, application.Factory.Calls);
    }

    [Xunit.Fact]
    public async Task OneCompositionCreatesOneSessionEvenAfterDisposalAndSessionsAreDisposedByTheirOwner()
    {
        var application = new Application(AssistantProductIdentity.ArcScope, 1);
        var session = (FakeSession)AssistantHost.Create(application.Options, application.Services);
        Xunit.Assert.False(session.Disposed);

        await session.DisposeAsync();
        Xunit.Assert.True(session.Disposed);
        // Disposal ends the session; the same services never mint a second session for the same instance.
        Xunit.Assert.Throws<InvalidOperationException>(() => AssistantHost.Create(application.Options, application.Services));
        Xunit.Assert.Equal(1, application.Factory.Calls);
    }

    [Xunit.Fact]
    public void FailedOrMismatchedSessionCreationIsNotCommittedAndCanBeRetried()
    {
        var host = FakeHost.For(TestData.Host());
        var registry = TestData.Registry(host.Owner);
        var options = TestData.Options(host.Owner);
        var otherIdentity = TestData.Host(host.Owner.Installation, instance: 2);
        int attempt = 0;
        var factory = new FakeSessionFactory(host.Owner, (opts, services) =>
        {
            attempt++;
            var real = new FakeSession(opts, services);
            return attempt switch
            {
                1 => throw new InvalidOperationException("factory failed"),
                2 => null!,
                3 => new ForgedSession(real, identity: otherIdentity),
                4 => new ForgedSession(real, options: TestData.Options(host.Owner)),
                5 => new ForgedSession(real, services: Composition.Services(host, TestData.Registry(host.Owner))),
                6 => new ForgedSession(real, profile: TestData.OtherProfile),
                _ => real,
            };
        });
        var services = Composition.Services(host, registry, factory);

        for (int i = 1; i <= 6; i++)
        {
            Xunit.Assert.Throws<InvalidOperationException>(() => AssistantHost.Create(options, services));
            Xunit.Assert.Equal(i, factory.Calls);
        }

        // None of the failed attempts consumed the composition or sealed its registry.
        registry.Register<string, string>(TestData.Descriptor(),
            (request, _) => ValueTask.FromResult(Outcome.Success(request)), Available);
        Xunit.Assert.Same(services, AssistantHost.Create(options, services).Services);
        Xunit.Assert.Equal(7, factory.Calls);
        Xunit.Assert.Throws<InvalidOperationException>(() => AssistantHost.Create(options, services));
    }

    [Xunit.Fact]
    public async Task ConcurrentCreationOfOneCompositionYieldsExactlyOneSession()
    {
        var host = FakeHost.For(TestData.Host());
        var registry = TestData.Registry(host.Owner);
        var options = TestData.Options(host.Owner);
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var factory = new FakeSessionFactory(host.Owner, (opts, services) =>
        {
            entered.Set();
            release.Wait(TimeSpan.FromSeconds(30));
            return new FakeSession(opts, services);
        });
        var services = Composition.Services(host, registry, factory);

        var first = Task.Run(() => AssistantHost.Create(options, services), Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.True(entered.Wait(TimeSpan.FromSeconds(30), Xunit.TestContext.Current.CancellationToken));
        // The first creation is in flight; a competing creation must be refused rather than build a second session.
        Xunit.Assert.Throws<InvalidOperationException>(() => AssistantHost.Create(options, services));
        release.Set();
        var session = await first;
        Xunit.Assert.Same(services, session.Services);
        Xunit.Assert.Equal(1, factory.Calls);
    }
}
