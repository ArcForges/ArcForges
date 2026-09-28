// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Assistant.Abstractions;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;

namespace AssistantAbstractionsTests;

public sealed class CompositionTests
{
    private static readonly AssistantProfileId Profile = new(new Guid("30000000-0000-0000-0000-000000000001"));

    [Xunit.Fact]
    public void ProductAndProfileIdentityAreClosedAndInstallationOwned()
    {
        Xunit.Assert.Same(AssistantProductIdentity.ArcScope, AssistantProductIdentity.Parse("arcscope"));
        Xunit.Assert.Same(AssistantProductIdentity.Companion, AssistantProductIdentity.Parse("companion"));
        foreach (string invalid in new[] { "", "ArcScope", "companion-android", "companion-web", "arcscope-v2" })
        {
            Xunit.Assert.Throws<ArgumentException>(() => AssistantProductIdentity.Parse(invalid));
        }

        Xunit.Assert.Throws<ArgumentException>(() => new AssistantProfileId(Guid.Empty));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantInstallationIdentity(
            AssistantProductIdentity.ArcScope, default));
        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostIdentity(Installed(), default, 1));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new AssistantHostIdentity(Installed(),
            new InstanceId(new Guid("40000000-0000-0000-0000-000000000001")), 0));
        Xunit.Assert.Throws<ArgumentException>(() => Options(Host(), (AssistantProfileId?)default(AssistantProfileId)));
    }

    [Xunit.Fact]
    public void PublicGeneratedIdentityAndPresentationFactoriesAreStable()
    {
        var window = AssistantWindowId.New();
        var conversation = AssistantConversationId.New();
        var selection = ContextSelectionId.New();
        var profile = AssistantProfileId.New();
        Guid[] generated = [window.Value, conversation.Value, selection.Value, profile.Value];

        Xunit.Assert.All(generated, value => Xunit.Assert.NotEqual(Guid.Empty, value));
        Xunit.Assert.Equal(generated.Length, generated.Distinct().Count());

        var options = Options(Host());
        Xunit.Assert.True(options.Supports(AssistantPresentationMode.Docked));
        Xunit.Assert.False(options.Supports(AssistantPresentationMode.Expanded));
    }

    [Xunit.Fact]
    public void ProductDataRootsAndProfilePartitionsCannotAliasBySelection()
    {
        var arcScope = Installed(AssistantProductIdentity.ArcScope,
            new InstallationId(new Guid("20000000-0000-0000-0000-000000000001")));
        var companion = Installed(AssistantProductIdentity.Companion,
            new InstallationId(new Guid("20000000-0000-0000-0000-000000000002")));
        var rootA = AssistantDataRoot.ForApplication("C:\\ArcForgesData", arcScope);
        var rootB = AssistantDataRoot.ForApplication("C:\\ArcForgesData", companion);
        var otherProfile = new AssistantProfileId(new Guid("30000000-0000-0000-0000-000000000002"));

        Xunit.Assert.NotEqual(rootA.Product, rootB.Product);
        Xunit.Assert.NotEqual(rootA.ForProfile(Profile), rootB.ForProfile(Profile));
        Xunit.Assert.NotEqual(rootA.ForProfile(Profile), rootA.ForProfile(otherProfile));
        Xunit.Assert.Equal(arcScope, rootA.Installation);
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() =>
            new AssistantContextBudget(1, AssistantContextBudget.AbsoluteMaximumBytes + 1));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new AssistantContextBudget(129, 1));
    }

    [Xunit.Fact]
    public async Task HostCompositionRejectsForeignPortsAndAStoreOrRegistrationCannotCrossProducts()
    {
        var arcInstall = Installed(AssistantProductIdentity.ArcScope,
            new InstallationId(new Guid("20000000-0000-0000-0000-000000000001")));
        var companionInstall = Installed(AssistantProductIdentity.Companion,
            new InstallationId(new Guid("20000000-0000-0000-0000-000000000002")));
        var arcIdentity = Host(arcInstall);
        var companionIdentity = Host(companionInstall);
        var arcFixture = new PortFixture(arcIdentity, new AssistantStorePartition(arcInstall, Profile));
        var companionFixture = new PortFixture(companionIdentity, new AssistantStorePartition(companionInstall, Profile));
        var wrongProfile = new AssistantProfileId(new Guid("30000000-0000-0000-0000-000000000002"));
        var wrongProfileFixture = new PortFixture(arcIdentity, new AssistantStorePartition(arcInstall, wrongProfile));
        var arcRegistry = Registry(arcIdentity);
        var companionRegistry = Registry(companionIdentity);
        var arcServices = Services(arcFixture, arcRegistry);
        var companionServices = Services(companionFixture, companionRegistry);
        var arcOptions = Options(arcIdentity);
        var companionOptions = Options(companionIdentity);

        int invoked = 0;
        var descriptor = new AssistantActionDescriptor("measurements.read", "measurements.read.title",
            "measurements.read.description", ["resource.selection"], ["measurements.read"], "availability.measurements.read");
        var binding = arcRegistry.Register<string, string>(descriptor,
            (request, _) =>
            {
                invoked++;
                return ValueTask.FromResult(Outcome.Success(request));
            }, _ => new ActionAvailability(true));
        await using var arcSession = AssistantHost.Create(arcOptions, arcServices);
        await using var companionSession = AssistantHost.Create(companionOptions, companionServices);
        Xunit.Assert.NotSame(arcSession, companionSession);
        Xunit.Assert.NotEqual(arcSession.Services.Store.Partition, companionSession.Services.Store.Partition);
        Xunit.Assert.Equal(arcIdentity, arcSession.Identity);
        Xunit.Assert.Equal(companionIdentity, companionSession.Identity);

        Xunit.Assert.Throws<ArgumentException>(() => AssistantHost.Create(companionOptions, arcServices));
        Xunit.Assert.Throws<ArgumentException>(() => AssistantHost.Create(arcOptions,
            Services(wrongProfileFixture, Registry(arcIdentity))));
        Xunit.Assert.Throws<ArgumentException>(() => Services(companionFixture, arcRegistry));
        IHostPlatformServices[] mixedPlatformServices =
        [
            new PortFixture(arcIdentity, arcFixture.Partition, dispatcher: companionFixture),
            new PortFixture(arcIdentity, arcFixture.Partition, secureStorage: companionFixture),
            new PortFixture(arcIdentity, arcFixture.Partition, filePicker: companionFixture),
            new PortFixture(arcIdentity, arcFixture.Partition, clipboard: companionFixture),
            new PortFixture(arcIdentity, arcFixture.Partition, environment: companionFixture),
        ];
        foreach (IHostPlatformServices mixedPlatform in mixedPlatformServices)
        {
            Xunit.Assert.Throws<ArgumentException>(() => Services(arcFixture, arcRegistry, mixedPlatform));
        }

        Xunit.Assert.Throws<ArgumentException>(() => new AssistantHostServices(companionIdentity,
            companionFixture, companionRegistry, companionFixture, companionFixture, companionFixture,
            companionFixture, arcFixture, new SessionFactoryFixture(companionIdentity)));
        Xunit.Assert.Throws<InvalidOperationException>(() => AssistantHost.Create(arcOptions, arcServices));

        var foreign = await arcRegistry.InvokeAsync(binding, companionIdentity, "must not run",
            cancellationToken: Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.True(foreign.TryGetFailure(out var failure));
        Xunit.Assert.Equal("perm.capability_denied", failure.Code);
        var wrongRegistry = await companionRegistry.InvokeAsync(binding, companionIdentity, "must not run",
            cancellationToken: Xunit.TestContext.Current.CancellationToken);
        Xunit.Assert.True(wrongRegistry.TryGetFailure(out failure));
        Xunit.Assert.Equal("perm.capability_denied", failure.Code);
        Xunit.Assert.Equal(0, invoked);
        Xunit.Assert.Equal("measurements.read", binding.Descriptor.OperationId);
        Xunit.Assert.True(arcRegistry.GetAvailability("measurements.read").TryGetValue(out var availability));
        Xunit.Assert.True(availability.IsAvailable);
        Xunit.Assert.True(arcRegistry.GetAvailability("missing.action").TryGetFailure(out failure));
        Xunit.Assert.Equal("state.not_found", failure.Code);
        Xunit.Assert.Throws<InvalidOperationException>(() => arcRegistry.Register<string, string>(
            new AssistantActionDescriptor("measurements.read", "measurements.read.title", "measurements.read.description",
                [], [], "availability.measurements.read"), (_, _) => ValueTask.FromResult(Outcome.Success("")),
            _ => new ActionAvailability(true)));
    }

    [Xunit.Fact]
    public async Task HostContextAndResourcePortsReturnOwnedTypedResults()
    {
        var identity = Host();
        var installation = identity.Installation;
        var fixture = new PortFixture(identity, new AssistantStorePartition(installation, Profile));
        IHostContext context = fixture;
        IHostResources resources = fixture;
        var cancellationToken = Xunit.TestContext.Current.CancellationToken;

        Xunit.Assert.Empty(context.DescribeSelection());
        var selected = ContextSelectionId.New();
        var frozenResult = await context.FreezeAsync([selected], new AssistantContextBudget(4, 4096), cancellationToken);
        Xunit.Assert.True(frozenResult.TryGetValue(out var frozen));
        Xunit.Assert.Equal(identity, frozen!.Owner);

        var reference = new AssistantResourceReference(ResourceVersion());
        var readGrant = new HostResourceReadGrant(identity, Guid.NewGuid(), reference);
        Xunit.Assert.True(resources.Resolve(reference).TryGetFailure(out var resolveFailure));
        Xunit.Assert.Equal("state.not_found", resolveFailure!.Code);

        var openResult = await resources.OpenReadAsync(readGrant, new HostByteRange(0, 16), cancellationToken);
        Xunit.Assert.True(openResult.TryGetFailure(out var openFailure));
        Xunit.Assert.Equal("state.not_found", openFailure!.Code);

        Xunit.Assert.True(resources.Present(reference, HostPreviewMode.Inline).TryGetFailure(out var presentFailure));
        Xunit.Assert.Equal("state.not_found", presentFailure!.Code);

        var destination = new HostFileGrant(identity, Guid.NewGuid(), canRead: false, canWrite: true);
        var saveResult = await resources.SaveAsAsync(reference, destination, cancellationToken);
        Xunit.Assert.True(saveResult.TryGetFailure(out var saveFailure));
        Xunit.Assert.Equal("state.not_found", saveFailure!.Code);
    }

    [Xunit.Fact]
    public async Task NavigationLifecycleAndPlatformPortsRemainHostBound()
    {
        var identity = Host();
        var installation = identity.Installation;
        var fixture = new PortFixture(identity, new AssistantStorePartition(installation, Profile));
        var cancellationToken = Xunit.TestContext.Current.CancellationToken;
        var reference = new AssistantResourceReference(ResourceVersion());
        IHostNavigation navigation = fixture;

        Xunit.Assert.True(navigation.OpenOwnedResource(reference).TryGetValue(out var opened));
        Xunit.Assert.False(opened);
        Xunit.Assert.True(navigation.RequestPanel(AssistantPresentationMode.Docked, AssistantWindowId.New())
            .TryGetValue(out var requested));
        Xunit.Assert.False(requested);
        Xunit.Assert.True(navigation.ShowAttention(new AssistantAttentionRequest("attention.sample", "attention.sample"))
            .TryGetValue(out var shown));
        Xunit.Assert.False(shown);

        IHostLifecycle lifecycle = fixture;
        Xunit.Assert.Equal(HostBusyKind.Idle, lifecycle.GetBusyState().Kind);
        var shutdown = await lifecycle.PrepareShutdownAsync(cancellationToken);
        Xunit.Assert.True(shutdown.TryGetValue(out var shutdownSummary));
        Xunit.Assert.True(shutdownSummary!.CanClose);
        var nextProfile = AssistantProfileId.New();
        var profileChange = await lifecycle.OnProfileChangingAsync(nextProfile, cancellationToken);
        Xunit.Assert.True(profileChange.TryGetValue(out var changedProfile));
        Xunit.Assert.Equal(nextProfile, changedProfile);
        lifecycle.OnResumed();

        IHostPlatformServices platform = fixture;
        Xunit.Assert.Equal("en-US", platform.Environment.Locale);
        Xunit.Assert.Equal(HostThemeMode.System, platform.Environment.Theme);
        Xunit.Assert.Equal(new HostAccessibilityPreferences(false, false, 1.0), platform.Environment.Accessibility);
        Xunit.Assert.False(platform.DiagnosticsConsent);

        bool dispatched = false;
        await platform.Dispatcher.InvokeAsync(() => dispatched = true, cancellationToken);
        Xunit.Assert.True(dispatched);

        var handleResult = await platform.SecureStorage.GetOrCreateHandleAsync("assistant.test", cancellationToken);
        Xunit.Assert.True(handleResult.TryGetFailure(out var handleFailure));
        Xunit.Assert.Equal("state.not_found", handleFailure!.Code);
        var deleteResult = await platform.SecureStorage.DeleteAsync(
            new AssistantSecretHandle(identity, Guid.NewGuid()), cancellationToken);
        Xunit.Assert.True(deleteResult.TryGetValue(out var deleted));
        Xunit.Assert.False(deleted);

        var readGrantResult = await platform.FilePicker.RequestReadAsync(cancellationToken);
        Xunit.Assert.True(readGrantResult.TryGetFailure(out var readGrantFailure));
        Xunit.Assert.Equal("state.not_found", readGrantFailure!.Code);
        var writeGrantResult = await platform.FilePicker.RequestWriteAsync("sample.txt", cancellationToken);
        Xunit.Assert.True(writeGrantResult.TryGetFailure(out var writeGrantFailure));
        Xunit.Assert.Equal("state.not_found", writeGrantFailure!.Code);

        var copyResult = await platform.Clipboard.CopyTextAsync("sample", cancellationToken);
        Xunit.Assert.True(copyResult.TryGetValue(out var copied));
        Xunit.Assert.False(copied);
        var clipboardResult = await platform.Clipboard.ReadTextAfterUserGestureAsync(cancellationToken);
        Xunit.Assert.True(clipboardResult.TryGetFailure(out var clipboardFailure));
        Xunit.Assert.Equal("state.not_found", clipboardFailure!.Code);
    }

    [Xunit.Fact]
    public async Task ActionRegistryIsUsableThroughItsHostPortContract()
    {
        var identity = Host();
        var registry = Registry(identity);
        var cancellationToken = Xunit.TestContext.Current.CancellationToken;
        int invocationCount = 0;
        var descriptor = new AssistantActionDescriptor("measurements.read", "measurements.read.title",
            "measurements.read.description", ["resource.selection"], ["measurements.read"], "availability.measurements.read");
        var registration = ((IHostActions)registry).Register<string, string>(descriptor,
            (request, _) =>
            {
                invocationCount++;
                return ValueTask.FromResult(Outcome.Success(request));
            }, _ => new ActionAvailability(true));

        Xunit.Assert.True(((IHostActions)registry).GetAvailability("measurements.read")
            .TryGetValue(out var availability));
        Xunit.Assert.True(availability!.IsAvailable);
        var invoked = await ((IHostActions)registry).InvokeAsync(registration, identity, "ok",
            cancellationToken: cancellationToken);
        Xunit.Assert.True(invoked.TryGetValue(out var value));
        Xunit.Assert.Equal("ok", value);

        Xunit.Assert.True(registry.GetAvailability("measurements.read").TryGetValue(out availability));
        Xunit.Assert.True(availability!.IsAvailable);
        var directInvocation = await registry.InvokeAsync(registration, identity, "direct",
            cancellationToken: cancellationToken);
        Xunit.Assert.True(directInvocation.TryGetValue(out value));
        Xunit.Assert.Equal("direct", value);
        Xunit.Assert.Equal(2, invocationCount);

        var concreteRegistry = Registry(identity);
        var concreteRegistration = concreteRegistry.Register<string, string>(descriptor,
            (request, _) => ValueTask.FromResult(Outcome.Success(request)), _ => new ActionAvailability(true));
        Xunit.Assert.Equal("measurements.read", concreteRegistration.Descriptor.OperationId);
    }

    [Xunit.Fact]
    public async Task SessionSurfaceRemainsWithinOneHostComposition()
    {
        var installed = Installed();
        var identity = Host(installed);
        var fixture = new PortFixture(identity, new AssistantStorePartition(installed, Profile));
        var registry = Registry(identity);
        var services = Services(fixture, registry);
        var options = Options(identity);
        await using IAssistantSession session = AssistantHost.Create(options, services);
        var cancellationToken = Xunit.TestContext.Current.CancellationToken;

        var window = AssistantWindowId.New();
        var surfaceResult = session.OpenSurface(new AssistantSurfaceRequest(AssistantPresentationMode.Docked, window));
        Xunit.Assert.True(surfaceResult.TryGetValue(out var surface));
        Xunit.Assert.Equal(window, surface!.Window);

        var createdConversation = await session.CreateConversationAsync(AssistantHistoryMode.Ephemeral, cancellationToken);
        Xunit.Assert.True(createdConversation.TryGetValue(out var conversation));
        var openedConversation = await session.OpenConversationAsync(conversation, cancellationToken);
        Xunit.Assert.True(openedConversation.TryGetValue(out var reopened));
        Xunit.Assert.Equal(conversation, reopened);

        var selection = ContextSelectionId.New();
        var attachedContext = await session.AttachContextAsync([selection], new AssistantContextBudget(4, 4096), cancellationToken);
        Xunit.Assert.True(attachedContext.TryGetValue(out var frozen));
        Xunit.Assert.Equal(identity, frozen!.Owner);

        int attentionCount = 0;
        await foreach (var attention in session.ObserveAttentionAsync(cancellationToken))
        {
            _ = attention;
            attentionCount++;
        }
        Xunit.Assert.Equal(0, attentionCount);

        var nextProfile = AssistantProfileId.New();
        var switched = await session.SwitchProfileAsync(nextProfile, cancellationToken);
        Xunit.Assert.True(switched.TryGetValue(out var currentProfile));
        Xunit.Assert.Equal(nextProfile, currentProfile);
        var shutdown = await session.PrepareShutdownAsync(cancellationToken);
        Xunit.Assert.True(shutdown.TryGetValue(out var summary));
        Xunit.Assert.True(summary!.CanClose);
    }

    [Xunit.Fact]
    public void ResourceReferencesAndFrozenContextAreOwnedImmutableCopies()
    {
        var identity = Host(Installed());
        var resource = new ResourceVersionRef
        {
            Resource = new ResourceRef(),
            Native = new NativeContentRev(),
            ContentHash = new string('a', 64),
        };
        var reference = new AssistantResourceReference(resource);
        resource.ContentHash = "changed";
        Xunit.Assert.Equal(new string('a', 64), reference.ToWire().ContentHash);

        var selection = new HostContextSelection(ContextSelectionId.New(), reference, "resource.sample", 3, 512);
        var frozen = new FrozenHostContext(identity, [selection]);
        Xunit.Assert.Equal(identity, frozen.Owner);
        Xunit.Assert.Single(frozen.Included);
        Xunit.Assert.False(frozen.IsPartial);

        var partial = new FrozenHostContext(identity, [selection], [ContextSelectionId.New()]);
        Xunit.Assert.True(partial.IsPartial);
        Xunit.Assert.Throws<ArgumentException>(() => new FrozenHostContext(identity, [selection, selection]));
        Xunit.Assert.Throws<ArgumentOutOfRangeException>(() => new HostByteRange(-1, null));
    }

    private static AssistantInstallationIdentity Installed(AssistantProductIdentity? product = null,
        InstallationId? installationId = null)
        => new(product ?? AssistantProductIdentity.ArcScope,
            installationId ?? new InstallationId(new Guid("20000000-0000-0000-0000-000000000001")));

    private static AssistantHostIdentity Host(AssistantInstallationIdentity? installation = null)
        => new(installation ?? Installed(),
            new InstanceId(new Guid("40000000-0000-0000-0000-000000000001")), 7);

    private static AssistantHostOptions Options(AssistantHostIdentity owner, AssistantProfileId? profile = null)
        => new(owner, profile ?? Profile, "C:\\ArcForgesData", "ArcScope", "assistant.arcscope",
            [AssistantPresentationMode.Docked, AssistantPresentationMode.Floating]);

    private static AssistantActionRegistry Registry(AssistantHostIdentity owner)
        => new(owner, ["measurements.read"], ["measurements.read"]);

    private static ResourceVersionRef ResourceVersion()
        => new()
        {
            Resource = new ResourceRef(),
            Native = new NativeContentRev(),
            ContentHash = new string('a', 64),
        };

    private static AssistantHostServices Services(PortFixture fixture, IHostActions actions,
        IHostPlatformServices? platform = null)
        => new(fixture.Owner, fixture, actions, fixture, fixture, fixture, platform ?? fixture,
            fixture, new SessionFactoryFixture(fixture.Owner));

    private sealed class PortFixture :
        IHostContext, IHostResources, IHostNavigation, IHostLifecycle, IHostPlatformServices,
        IHostDispatcher, IHostSecureStorage, IHostFilePicker, IHostClipboard, IHostEnvironment,
        IAssistantStoreScope
    {
        public PortFixture(AssistantHostIdentity owner, AssistantStorePartition partition,
            IHostDispatcher? dispatcher = null, IHostSecureStorage? secureStorage = null,
            IHostFilePicker? filePicker = null, IHostClipboard? clipboard = null,
            IHostEnvironment? environment = null)
        {
            Owner = owner;
            Partition = partition;
            Dispatcher = dispatcher ?? this;
            SecureStorage = secureStorage ?? this;
            FilePicker = filePicker ?? this;
            Clipboard = clipboard ?? this;
            Environment = environment ?? this;
        }

        public AssistantHostIdentity Owner { get; }
        public AssistantStorePartition Partition { get; }
        public IClock Clock => ArcForges.Foundation.Clock.System;
        public IHostDispatcher Dispatcher { get; }
        public IHostSecureStorage SecureStorage { get; }
        public IHostFilePicker FilePicker { get; }
        public IHostClipboard Clipboard { get; }
        public IHostEnvironment Environment { get; }
        public bool DiagnosticsConsent => false;
        public string Locale => "en-US";
        public HostThemeMode Theme => HostThemeMode.System;
        public HostAccessibilityPreferences Accessibility => new(false, false, 1.0);
        public CancellationToken Stopping => CancellationToken.None;

        public IReadOnlyList<HostContextSelection> DescribeSelection() => [];

        public ValueTask<Outcome<FrozenHostContext>> FreezeAsync(IReadOnlyCollection<ContextSelectionId> selectionIds,
            AssistantContextBudget budget, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Success(new FrozenHostContext(Owner, [])));

        public Outcome<ResolvedHostResource> Resolve(AssistantResourceReference reference)
            => Outcome.Failure<ResolvedHostResource>(TypedFailure.Create("state.not_found"));

        public ValueTask<Outcome<Stream>> OpenReadAsync(HostResourceReadGrant grant, HostByteRange range,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Failure<Stream>(TypedFailure.Create("state.not_found")));

        public Outcome<HostPreview> Present(AssistantResourceReference reference, HostPreviewMode previewMode)
            => Outcome.Failure<HostPreview>(TypedFailure.Create("state.not_found"));

        public ValueTask<Outcome<HostSaveReceipt>> SaveAsAsync(AssistantResourceReference reference,
            HostFileGrant destination, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Failure<HostSaveReceipt>(TypedFailure.Create("state.not_found")));

        public Outcome<bool> OpenOwnedResource(AssistantResourceReference reference, string? anchor = null)
            => Outcome.Success(false);

        public Outcome<bool> RequestPanel(AssistantPresentationMode presentation, AssistantWindowId window)
            => Outcome.Success(false);

        public Outcome<bool> ShowAttention(AssistantAttentionRequest attention) => Outcome.Success(false);
        public HostBusyState GetBusyState() => new(HostBusyKind.Idle, 0);

        public ValueTask<Outcome<AssistantShutdownSummary>> PrepareShutdownAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Success(new AssistantShutdownSummary(true, 0, [])));

        public ValueTask<Outcome<AssistantProfileId>> OnProfileChangingAsync(AssistantProfileId nextProfile,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Success(nextProfile));

        public void OnResumed() { }

        public ValueTask<Outcome<bool>> RequestStopAsync(CancellationToken cancellationToken)
            => ValueTask.FromResult(Outcome.Success(true));

        public ValueTask InvokeAsync(Action callback, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            callback();
            return ValueTask.CompletedTask;
        }

        public ValueTask<Outcome<AssistantSecretHandle>> GetOrCreateHandleAsync(string purpose,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Failure<AssistantSecretHandle>(TypedFailure.Create("state.not_found")));

        public ValueTask<Outcome<bool>> DeleteAsync(AssistantSecretHandle handle,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Success(false));

        public ValueTask<Outcome<HostFileGrant>> RequestReadAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Failure<HostFileGrant>(TypedFailure.Create("state.not_found")));

        public ValueTask<Outcome<HostFileGrant>> RequestWriteAsync(string suggestedName,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Failure<HostFileGrant>(TypedFailure.Create("state.not_found")));

        public ValueTask<Outcome<bool>> CopyTextAsync(string text, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Success(false));

        public ValueTask<Outcome<string>> ReadTextAfterUserGestureAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Failure<string>(TypedFailure.Create("state.not_found")));

    }

    private sealed class SessionFactoryFixture(AssistantHostIdentity owner) : IAssistantSessionFactory
    {
        public AssistantHostIdentity Owner { get; } = owner;

        public IAssistantSession Create(AssistantHostOptions options, AssistantHostServices services)
            => new SessionFixture(options, services);
    }

    private sealed class SessionFixture : IAssistantSession
    {
        public SessionFixture(AssistantHostOptions options, AssistantHostServices services)
        {
            Options = options;
            Services = services;
        }

        public AssistantHostIdentity Identity => Options.Identity;
        public AssistantHostOptions Options { get; }
        public AssistantHostServices Services { get; }
        public AssistantProfileId CurrentProfile => Options.InitialProfile;

        public Outcome<AssistantSurfaceHandle> OpenSurface(AssistantSurfaceRequest request)
            => Outcome.Success(new AssistantSurfaceHandle(request.Mode, request.Window, request.Conversation));

        public ValueTask<Outcome<AssistantConversationId>> CreateConversationAsync(AssistantHistoryMode historyMode,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Success(AssistantConversationId.New()));

        public ValueTask<Outcome<AssistantConversationId>> OpenConversationAsync(AssistantConversationId conversation,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Success(conversation));

        public ValueTask<Outcome<FrozenHostContext>> AttachContextAsync(IReadOnlyCollection<ContextSelectionId> selectionIds,
            AssistantContextBudget budget, CancellationToken cancellationToken = default)
            => Services.Context.FreezeAsync(selectionIds, budget, cancellationToken);

        public async IAsyncEnumerable<AssistantAttention> ObserveAttentionAsync(
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask.ConfigureAwait(false);
            yield break;
        }

        public ValueTask<Outcome<AssistantProfileId>> SwitchProfileAsync(AssistantProfileId profile,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Outcome.Success(profile));

        public ValueTask<Outcome<AssistantShutdownSummary>> PrepareShutdownAsync(CancellationToken cancellationToken = default)
            => Services.Lifecycle.PrepareShutdownAsync(cancellationToken);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
