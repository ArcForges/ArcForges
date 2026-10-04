// SPDX-License-Identifier: AGPL-3.0-only
#pragma warning disable CA2007 // Test code has no synchronization context to preserve.
#pragma warning disable CA1859 // Tests deliberately use the port interfaces to exercise their contracts.
using ArcForges.Assistant.Abstractions;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;

namespace AssistantAbstractionsTests;

/// <summary>
/// Port-shape tests: the typed values defined by the package flow through each host port as a product
/// implementation (here, a test-only host) must use them. They prove the signatures compose and that the
/// package's value types carry the owner checks; they do not prove any real product host.
/// </summary>
public sealed class PortContractTests
{
    private static readonly AssistantContextBudget Budget = new(2, 1000);

    [Xunit.Fact]
    public async Task ContextPortDescribesSelectionsAndFreezesWithinTheBudgetReportingPartialResults()
    {
        var owner = TestData.Host();
        var host = FakeHost.For(owner);
        IHostContext context = host;
        var a = host.AddSelection(TestData.Selection(bytes: 600));
        var b = host.AddSelection(TestData.Selection(bytes: 600));
        var c = host.AddSelection(TestData.Selection(bytes: 100));
        var token = Xunit.TestContext.Current.CancellationToken;

        Xunit.Assert.Equal(3, context.DescribeSelection().Count);
        var frozen = await context.FreezeAsync([a.Id, b.Id, c.Id], Budget, token);
        Xunit.Assert.True(frozen.TryGetValue(out var snapshot));
        Xunit.Assert.Equal([a.Id, c.Id], snapshot.Included.Select(item => item.Id).ToArray());
        Xunit.Assert.Equal([b.Id], snapshot.Excluded);
        Xunit.Assert.True(snapshot.IsPartial);
        Xunit.Assert.Equal(700UL, snapshot.TotalEstimatedBytes);

        var unknown = await context.FreezeAsync([ContextSelectionId.New()], Budget, token);
        Xunit.Assert.True(unknown.TryGetFailure(out var failure));
        Xunit.Assert.Equal("state.not_found", failure.Code);

        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var result = await context.FreezeAsync([a.Id], Budget, cancelled.Token);
        Xunit.Assert.Equal(OutcomeKind.Cancelled, result.Kind);
        Xunit.Assert.Equal(EffectCertainty.DidNotHappen, result.CancellationEffect);

        // Later selection changes never alter a context that was already frozen.
        host.AddSelection(TestData.Selection(bytes: 1));
        Xunit.Assert.Equal(2, snapshot.Included.Count);
    }

    [Xunit.Fact]
    public async Task ResourcePortResolvesOpensPresentsAndSavesOnlyOwnedResourcesWithGrants()
    {
        var owner = TestData.Host();
        var host = FakeHost.For(owner);
        IHostResources resources = host;
        var token = Xunit.TestContext.Current.CancellationToken;
        var reference = host.AddContent(TestData.Reference(), [0x41, 0x42, 0x43, 0x44]);

        Xunit.Assert.True(resources.Resolve(reference).TryGetValue(out var resolved));
        Xunit.Assert.NotNull(resolved.ReadGrant);
        var open = await resources.OpenReadAsync(resolved.ReadGrant, new HostByteRange(1, 2), token);
        Xunit.Assert.True(open.TryGetValue(out var stream));
        await using (stream)
        {
            var bytes = new byte[4];
            Xunit.Assert.Equal(2, await stream.ReadAsync(bytes, token));
            Xunit.Assert.Equal([0x42, 0x43], bytes.Take(2).ToArray());
        }

        Xunit.Assert.True(resources.Present(reference, HostPreviewMode.Inline).TryGetValue(out var preview));
        Xunit.Assert.Equal(HostPreviewMode.Inline, preview.Mode);
        Xunit.Assert.True(resources.Present(TestData.Reference(), HostPreviewMode.Inline).TryGetFailure(out var missing));
        Xunit.Assert.Equal("resource.unavailable", missing.Code);

        // Reading never implies export: saving needs a separate, write-permissioned destination grant.
        Xunit.Assert.True((await resources.SaveAsAsync(reference,
            new HostFileGrant(owner, Guid.NewGuid(), canRead: true, canWrite: false), token)).TryGetFailure(out var readOnly));
        Xunit.Assert.Equal("perm.resource_denied", readOnly.Code);
        Xunit.Assert.True((await host.FilePicker.RequestWriteAsync("export.csv", token)).TryGetValue(out var destination));
        Xunit.Assert.True((await resources.SaveAsAsync(reference, destination, token)).TryGetValue(out var receipt));
        Xunit.Assert.Equal(destination.GrantId, receipt.GrantId);
        Xunit.Assert.Equal(reference.ToWire(), receipt.SavedResource.ToWire());
    }

    [Xunit.Fact]
    public async Task ResolvedReadGrantIsRejectedWhenOnlyTheResourceOrOnlyTheOwnerChanges()
    {
        var owner = TestData.Host();
        var host = FakeHost.For(owner);
        IHostResources resources = host;
        var token = Xunit.TestContext.Current.CancellationToken;
        var reference = host.AddContent(TestData.Reference(), [1, 2, 3]);
        var other = host.AddContent(TestData.Reference(), [9, 9, 9]);
        Xunit.Assert.True(resources.Resolve(reference).TryGetValue(out var resolved));
        var grant = resolved.ReadGrant!;

        // Reuse the genuinely issued grant identifier and change exactly one other element.
        var changedResource = new HostResourceReadGrant(owner, grant.GrantId, other);
        var foreignOwner = new HostResourceReadGrant(TestData.Host(owner.Installation, instance: 2), grant.GrantId, reference);
        var unissued = new HostResourceReadGrant(owner, Guid.NewGuid(), reference);
        foreach (var forged in new[] { changedResource, foreignOwner, unissued })
        {
            var result = await resources.OpenReadAsync(forged, new HostByteRange(0, 1), token);
            Xunit.Assert.True(result.TryGetFailure(out var failure));
            Xunit.Assert.Equal("perm.resource_denied", failure.Code);
        }

        var outOfRange = await resources.OpenReadAsync(grant, new HostByteRange(99, 1), token);
        Xunit.Assert.True(outOfRange.TryGetFailure(out var rangeFailure));
        Xunit.Assert.Equal("validation.invalid_request", rangeFailure.Code);
        Xunit.Assert.True((await resources.OpenReadAsync(grant, new HostByteRange(0, null), token)).TryGetValue(out var whole));
        await whole.DisposeAsync();
    }

    [Xunit.Fact]
    public void ForeignProductResourcesAreRefusedByResolveNavigationAndPresentation()
    {
        var host = FakeHost.For(TestData.Host());
        var companionResource = TestData.Reference("companion");
        host.AddContent(companionResource, [1]);

        Xunit.Assert.True(((IHostResources)host).Resolve(companionResource).TryGetFailure(out var failure));
        Xunit.Assert.Equal("perm.resource_denied", failure.Code);
        Xunit.Assert.True(((IHostResources)host).Present(companionResource, HostPreviewMode.Inline).TryGetFailure(out failure));
        Xunit.Assert.Equal("resource.unavailable", failure.Code);
        Xunit.Assert.True(((IHostNavigation)host).OpenOwnedResource(companionResource).TryGetFailure(out failure));
        Xunit.Assert.Equal("perm.resource_denied", failure.Code);
        Xunit.Assert.Empty(host.Navigated);
    }

    [Xunit.Fact]
    public void NavigationOpensOwnedResourcesPanelsAndAttentionAndReportsMissingResources()
    {
        var host = FakeHost.For(TestData.Host());
        IHostNavigation navigation = host;
        var known = host.AddContent(TestData.Reference(), [1]);

        Xunit.Assert.True(navigation.OpenOwnedResource(known, "row-4").TryGetValue(out bool opened));
        Xunit.Assert.True(opened);
        Xunit.Assert.True(navigation.OpenOwnedResource(TestData.Reference()).TryGetValue(out opened));
        Xunit.Assert.False(opened);
        var window = AssistantWindowId.New();
        Xunit.Assert.True(navigation.RequestPanel(AssistantPresentationMode.Docked, window).TryGetValue(out opened));
        Xunit.Assert.True(opened);
        Xunit.Assert.True(navigation.ShowAttention(new AssistantAttentionRequest("attention.a", "attention.a.message")).TryGetValue(out opened));
        Xunit.Assert.Equal(3, host.Navigated.Count);
        Xunit.Assert.EndsWith("#row-4", host.Navigated[0], StringComparison.Ordinal);
        Xunit.Assert.Contains(window.Value.ToString(), host.Navigated[1], StringComparison.Ordinal);
    }

    [Xunit.Fact]
    public async Task LifecyclePortRefusesShutdownAndProfileChangesWhileLocalWorkRuns()
    {
        var host = FakeHost.For(TestData.Host());
        IHostLifecycle lifecycle = host;
        var token = Xunit.TestContext.Current.CancellationToken;

        Xunit.Assert.Equal(HostBusyKind.Idle, lifecycle.GetBusyState().Kind);
        Xunit.Assert.True((await lifecycle.PrepareShutdownAsync(token)).TryGetValue(out var idle));
        Xunit.Assert.True(idle.CanClose);
        Xunit.Assert.True((await lifecycle.OnProfileChangingAsync(TestData.OtherProfile, token)).TryGetValue(out var next));
        Xunit.Assert.Equal(TestData.OtherProfile, next);
        lifecycle.OnResumed();
        Xunit.Assert.Equal(1, host.Resumed);

        host.ActiveLocalOperations = 2;
        var busy = lifecycle.GetBusyState();
        Xunit.Assert.Equal(HostBusyKind.LocalWork, busy.Kind);
        Xunit.Assert.Equal(2, busy.ActiveLocalOperations);
        Xunit.Assert.True((await lifecycle.PrepareShutdownAsync(token)).TryGetValue(out var refused));
        Xunit.Assert.False(refused.CanClose);
        Xunit.Assert.Equal(["shutdown.local_work"], refused.RefusalMessageKeys);
        Xunit.Assert.True((await lifecycle.OnProfileChangingAsync(AssistantProfileId.New(), token)).TryGetFailure(out var failure));
        Xunit.Assert.Equal("state.invalid_transition", failure.Code);

        // Stopping is an explicit command with a typed outcome; cancellation before it ran is not failure.
        Xunit.Assert.True((await lifecycle.RequestStopAsync(token)).TryGetValue(out bool stopped));
        Xunit.Assert.True(stopped);
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var cancelledStop = await lifecycle.RequestStopAsync(cancelled.Token);
        Xunit.Assert.Equal(OutcomeKind.Cancelled, cancelledStop.Kind);
    }

    [Xunit.Fact]
    public async Task PlatformServicesExposeBoundedOwnerScopedAbstractions()
    {
        var owner = TestData.Host();
        var host = FakeHost.For(owner);
        IHostPlatformServices platform = host;
        var token = Xunit.TestContext.Current.CancellationToken;

        var start = platform.Clock.GetTimestamp();
        Xunit.Assert.True(platform.Clock.GetElapsedTime(start, platform.Clock.GetTimestamp()) >= TimeSpan.Zero);
        Xunit.Assert.Equal("en-US", platform.Environment.Locale);
        Xunit.Assert.Equal(HostThemeMode.System, platform.Environment.Theme);
        Xunit.Assert.Equal(1.0, platform.Environment.Accessibility.TextScale);
        Xunit.Assert.False(platform.DiagnosticsConsent);
        host.DiagnosticsConsent = true;
        Xunit.Assert.True(platform.DiagnosticsConsent);

        bool ran = false;
        await platform.Dispatcher.InvokeAsync(() => ran = true, token);
        Xunit.Assert.True(ran);
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Xunit.Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await platform.Dispatcher.InvokeAsync(() => ran = false, cancelled.Token));
        Xunit.Assert.True(ran);

        // Secure storage hands out opaque, owner-bound handles; another owner's handle is refused.
        Xunit.Assert.True((await platform.SecureStorage.GetOrCreateHandleAsync("assistant.credentials", token)).TryGetValue(out var handle));
        Xunit.Assert.Equal(owner, handle.Owner);
        var foreignHandle = new AssistantSecretHandle(TestData.Host(TestData.Installed(AssistantProductIdentity.Companion)), handle.HandleId);
        Xunit.Assert.True((await platform.SecureStorage.DeleteAsync(foreignHandle, token)).TryGetFailure(out var denied));
        Xunit.Assert.Equal("perm.capability_denied", denied.Code);
        Xunit.Assert.True((await platform.SecureStorage.DeleteAsync(handle, token)).TryGetValue(out bool deleted));
        Xunit.Assert.True(deleted);
        Xunit.Assert.True((await platform.SecureStorage.DeleteAsync(handle, token)).TryGetValue(out deleted));
        Xunit.Assert.False(deleted);

        Xunit.Assert.True((await platform.FilePicker.RequestReadAsync(token)).TryGetValue(out var read));
        Xunit.Assert.True(read.CanRead && !read.CanWrite);
        Xunit.Assert.True((await platform.FilePicker.RequestWriteAsync("name.txt", token)).TryGetValue(out var write));
        Xunit.Assert.True(write.CanWrite && !write.CanRead);

        Xunit.Assert.True((await platform.Clipboard.CopyTextAsync("copied", token)).TryGetValue(out bool copied));
        Xunit.Assert.True(copied);
        Xunit.Assert.True((await platform.Clipboard.ReadTextAfterUserGestureAsync(token)).TryGetValue(out var text));
        Xunit.Assert.Equal("copied", text);
    }

    [Xunit.Fact]
    public async Task SessionSurfaceReusesOneSessionForSeveralWindowsAndRefusesUnsupportedModes()
    {
        var owner = TestData.Host();
        var host = FakeHost.For(owner);
        var registry = TestData.Registry(owner);
        var services = Composition.Services(host, registry);
        await using var session = AssistantHost.Create(TestData.Options(owner), services);
        var token = Xunit.TestContext.Current.CancellationToken;
        var fake = (FakeSession)session;

        var windowA = AssistantWindowId.New();
        var windowB = AssistantWindowId.New();
        Xunit.Assert.True(session.OpenSurface(new AssistantSurfaceRequest(AssistantPresentationMode.Docked, windowA)).TryGetValue(out var surfaceA));
        Xunit.Assert.True(session.OpenSurface(new AssistantSurfaceRequest(AssistantPresentationMode.Floating, windowB)).TryGetValue(out var surfaceB));
        Xunit.Assert.NotEqual(surfaceA.Window, surfaceB.Window);
        Xunit.Assert.Equal(2, fake.Surfaces.Count);
        Xunit.Assert.True(session.OpenSurface(new AssistantSurfaceRequest(AssistantPresentationMode.Expanded, AssistantWindowId.New()))
            .TryGetFailure(out var unsupported));
        Xunit.Assert.Equal("validation.invalid_request", unsupported.Code);

        Xunit.Assert.True((await session.CreateConversationAsync(AssistantHistoryMode.Local, token)).TryGetValue(out var conversation));
        Xunit.Assert.True((await session.OpenConversationAsync(conversation, token)).TryGetValue(out var reopened));
        Xunit.Assert.Equal(conversation, reopened);

        var selection = host.AddSelection(TestData.Selection());
        Xunit.Assert.True((await session.AttachContextAsync([selection.Id], Budget, token)).TryGetValue(out var context));
        Xunit.Assert.Equal(owner, context.Owner);
        var attention = new List<AssistantAttention>();
        await foreach (var item in session.ObserveAttentionAsync(token))
        {
            attention.Add(item);
        }

        Xunit.Assert.Single(attention);
        Xunit.Assert.True((await session.PrepareShutdownAsync(token)).TryGetValue(out var shutdown));
        Xunit.Assert.True(shutdown.CanClose);

        Xunit.Assert.True((await session.SwitchProfileAsync(TestData.OtherProfile, token)).TryGetValue(out var switched));
        Xunit.Assert.Equal(TestData.OtherProfile, switched);
        Xunit.Assert.Equal(TestData.OtherProfile, session.CurrentProfile);
        host.ActiveLocalOperations = 1;
        Xunit.Assert.True((await session.SwitchProfileAsync(TestData.Profile, token)).TryGetFailure(out var busy));
        Xunit.Assert.Equal("state.invalid_transition", busy.Code);
        Xunit.Assert.Equal(TestData.OtherProfile, session.CurrentProfile);
        Xunit.Assert.True((await session.PrepareShutdownAsync(token)).TryGetValue(out shutdown));
        Xunit.Assert.False(shutdown.CanClose);
    }
}
