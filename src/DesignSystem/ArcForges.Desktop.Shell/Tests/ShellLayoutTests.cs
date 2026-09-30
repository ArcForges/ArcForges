// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.DesignSystem;
using ArcForges.Foundation;
using Xunit;

namespace ArcForges.Desktop.Shell.Tests;

public sealed class ShellLayoutTests
{
    [Fact]
    public void OneLaunchInstanceOwnsMultipleDistinctWindowsAndRejectsDuplicateIds()
    {
        var instance = IdentityGeneration.NewInstance();
        var registry = new WindowRegistry(instance);
        var primary = Placement("main", "display-one", new WindowBounds(20, 30, 1200, 800));
        var inspector = Placement("inspector", "display-one", new WindowBounds(40, 50, 500, 600));

        Assert.True(registry.TryOpen(primary));
        Assert.True(registry.TryOpen(inspector));
        Assert.False(registry.TryOpen(primary));
        Assert.Equal(instance, registry.Instance);
        Assert.Equal(2, registry.Count);
        Assert.True(registry.TryClose(WindowId.Parse("inspector")));
        Assert.False(registry.TryClose(WindowId.Parse("inspector")));
        Assert.Equal([primary], registry.Snapshot());
        Assert.Throws<ArgumentException>(() => new WindowRegistry(default));

        var nextLaunch = new WindowRegistry(IdentityGeneration.NewInstance());
        Assert.True(nextLaunch.TryOpen(primary));
    }

    [Fact]
    public async Task RunStartupAsyncRunsLocalWorkBeforeBackgroundAndReturnsMeasurement()
    {
        var sequence = new List<string>();
        var coordinator = new ShellLifecycleCoordinator(
            LifecycleOperations(
                makeWorkspaceUsableAsync: _ =>
                {
                    sequence.Add("workspace-usable");
                    return ValueTask.FromResult(true);
                },
                startBackgroundWorkAsync: _ =>
                {
                    sequence.Add("background-started");
                    return ValueTask.CompletedTask;
                }),
            TimeSpan.FromSeconds(2.5));

        var measurement = await coordinator.RunStartupAsync(TestContext.Current.CancellationToken);
        var repeated = await coordinator.RunStartupAsync(TestContext.Current.CancellationToken);

        Assert.Equal(["workspace-usable", "background-started"], sequence);
        Assert.Same(measurement, repeated);
        Assert.True(measurement.BackgroundStartedAfterWorkspaceReady);
        Assert.True(measurement.WithinConfiguredBudget);
        Assert.True(measurement.BackgroundStartedAfter >= measurement.WorkspaceReadyAfter);

        int backgroundStarts = 0;
        var blocked = new ShellLifecycleCoordinator(
            LifecycleOperations(
                makeWorkspaceUsableAsync: _ => ValueTask.FromResult(false),
                startBackgroundWorkAsync: _ =>
                {
                    backgroundStarts++;
                    return ValueTask.CompletedTask;
                }),
            TimeSpan.FromSeconds(2.5));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await blocked.RunStartupAsync(TestContext.Current.CancellationToken).ConfigureAwait(false));
        Assert.Equal(0, backgroundStarts);
    }

    [Fact]
    public async Task RouteActivationAsyncForwardsSecondaryLaunchToPrimaryExactlyOnce()
    {
        int forwards = 0;
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var coordinator = new ShellLifecycleCoordinator(
            LifecycleOperations(forwardActivationToPrimaryAsync: async (_, cancellationToken) =>
            {
                Interlocked.Increment(ref forwards);
                entered.TrySetResult(true);
                await release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }),
            TimeSpan.FromSeconds(2.5));
        var request = new ShellActivationRequest(Guid.NewGuid(), ShellActivationKind.OpenTarget, "workspace:one");

        Task<ShellActivationRouteDisposition> first = coordinator
            .RouteActivationAsync(request, TestContext.Current.CancellationToken)
            .AsTask();
        await entered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Task<ShellActivationRouteDisposition> duplicate = coordinator
            .RouteActivationAsync(request, TestContext.Current.CancellationToken)
            .AsTask();
        release.TrySetResult(true);

        ShellActivationRouteDisposition[] results = await Task.WhenAll(first, duplicate);
        Assert.Equal(ShellActivationRouteDisposition.Forwarded, results[0]);
        Assert.Equal(ShellActivationRouteDisposition.AlreadyForwarded, results[1]);
        Assert.Equal(1, forwards);
        Assert.Equal(
            ShellActivationRouteDisposition.IdentityConflict,
            await coordinator.RouteActivationAsync(
                new ShellActivationRequest(request.RequestId, ShellActivationKind.OpenTarget, "workspace:two"),
                TestContext.Current.CancellationToken));
        Assert.Equal(1, forwards);
        Assert.Throws<ArgumentException>(() => new ShellActivationRequest(Guid.Empty, ShellActivationKind.Activate));
    }

    [Fact]
    public void CreateShutdownPromptStatesRunningAndUnsavedConsequences()
    {
        var state = new ShellShutdownState(generation: 7, activeWorkCount: 2, unsavedItemCount: 1);

        ShellShutdownPrompt prompt = ShellLifecycleCoordinator.CreateShutdownPrompt(state);

        Assert.Equal(7, prompt.Generation);
        Assert.Contains("2 active item(s)", prompt.Consequences, StringComparison.Ordinal);
        Assert.Contains("reach a safe point", prompt.Consequences, StringComparison.Ordinal);
        Assert.Contains("1 unsaved item(s)", prompt.Consequences, StringComparison.Ordinal);
        Assert.Contains("saved before writes are flushed", prompt.Consequences, StringComparison.Ordinal);
        Assert.Equal(
            [ShellShutdownDecision.KeepWorking, ShellShutdownDecision.SaveThenQuit],
            prompt.Decisions);
    }

    [Fact]
    public async Task ExecuteShutdownAsyncRequiresChoiceAndRunsDrainInOrderWithoutLosingWork()
    {
        var promptedState = new ShellShutdownState(generation: 10, activeWorkCount: 0, unsavedItemCount: 0);
        ShellShutdownPrompt originalPrompt = ShellLifecycleCoordinator.CreateShutdownPrompt(promptedState);
        var changedState = new ShellShutdownState(generation: 11, activeWorkCount: 1, unsavedItemCount: 1);
        var staleOperations = new List<string>();
        var stale = new ShellLifecycleCoordinator(
            LifecycleOperations(
                captureShutdownStateAsync: _ => ValueTask.FromResult(changedState),
                stopAcceptingWritesAsync: _ =>
                {
                    staleOperations.Add("stop-writes");
                    return ValueTask.CompletedTask;
                },
                reachSafePointsAsync: _ =>
                {
                    staleOperations.Add("safe-points");
                    return ValueTask.CompletedTask;
                }),
            TimeSpan.FromSeconds(2.5));

        ShellShutdownExecutionResult reconfirm = await stale.ExecuteShutdownAsync(
            promptedState,
            ShellShutdownDecision.WaitForSafePointAndQuit,
            TestContext.Current.CancellationToken);

        Assert.Equal(10, originalPrompt.Generation);
        Assert.Equal(ShellShutdownDisposition.ReconfirmationRequired, reconfirm.Disposition);
        Assert.Equal(11, reconfirm.ReconfirmationPrompt!.Generation);
        Assert.Contains("1 active item(s)", reconfirm.ReconfirmationPrompt.Consequences, StringComparison.Ordinal);
        Assert.Contains("1 unsaved item(s)", reconfirm.ReconfirmationPrompt.Consequences, StringComparison.Ordinal);
        Assert.Empty(staleOperations);

        var sameCountsNewGeneration = new ShellShutdownState(generation: 11, activeWorkCount: 0, unsavedItemCount: 0);
        var generationOnlyOperations = new List<string>();
        var generationOnlyStale = new ShellLifecycleCoordinator(
            LifecycleOperations(
                captureShutdownStateAsync: _ => ValueTask.FromResult(sameCountsNewGeneration),
                stopAcceptingWritesAsync: _ => Record(generationOnlyOperations, "stop-writes")),
            TimeSpan.FromSeconds(2.5));
        ShellShutdownExecutionResult generationOnlyReconfirm = await generationOnlyStale.ExecuteShutdownAsync(
            promptedState,
            ShellShutdownDecision.WaitForSafePointAndQuit,
            TestContext.Current.CancellationToken);
        Assert.Equal(ShellShutdownDisposition.ReconfirmationRequired, generationOnlyReconfirm.Disposition);
        Assert.Equal(11, generationOnlyReconfirm.ReconfirmationPrompt!.Generation);
        Assert.Empty(generationOnlyOperations);

        var invalidDecisionCalls = new List<string>();
        var invalidDecisionCoordinator = new ShellLifecycleCoordinator(
            LifecycleOperations(
                captureShutdownStateAsync: _ => ValueTask.FromResult(promptedState),
                stopAcceptingWritesAsync: _ => Record(invalidDecisionCalls, "stop-writes")),
            TimeSpan.FromSeconds(2.5));
        ShellShutdownExecutionResult invalidDecision = await invalidDecisionCoordinator.ExecuteShutdownAsync(
            promptedState,
            ShellShutdownDecision.SaveThenQuit,
            TestContext.Current.CancellationToken);
        Assert.Equal(ShellShutdownDisposition.ReconfirmationRequired, invalidDecision.Disposition);
        Assert.Empty(invalidDecisionCalls);

        var calls = new List<string>();
        var expected = new ShellShutdownState(generation: 20, activeWorkCount: 1, unsavedItemCount: 1);
        var reachedSafePoint = new ShellShutdownState(generation: 21, activeWorkCount: 0, unsavedItemCount: 1);
        var saved = new ShellShutdownState(generation: 22, activeWorkCount: 0, unsavedItemCount: 0);
        int captureCount = 0;
        var draining = new ShellLifecycleCoordinator(
            LifecycleOperations(
                captureShutdownStateAsync: _ =>
                {
                    captureCount++;
                    return ValueTask.FromResult(captureCount switch
                    {
                        1 => expected,
                        2 => reachedSafePoint,
                        _ => saved,
                    });
                },
                stopAcceptingWritesAsync: _ => Record(calls, "stop-writes"),
                reachSafePointsAsync: _ => Record(calls, "safe-points"),
                saveUnsavedWorkAsync: (_, _) => Record(calls, "save-unsaved"),
                flushWritesAsync: _ => Record(calls, "flush-writes"),
                disconnectServicesAsync: _ => Record(calls, "disconnect-services"),
                drainWorkAsync: _ => Record(calls, "drain-work"),
                stopNativeRuntimeAsync: _ => Record(calls, "stop-runtime")),
            TimeSpan.FromSeconds(2.5));

        ShellShutdownExecutionResult stopped = await draining.ExecuteShutdownAsync(
            expected,
            ShellShutdownDecision.SaveThenQuit,
            TestContext.Current.CancellationToken);

        Assert.Equal(ShellShutdownDisposition.Stopped, stopped.Disposition);
        Assert.Equal(
            ["stop-writes", "safe-points", "save-unsaved", "flush-writes", "disconnect-services", "drain-work", "stop-runtime"],
            calls);
        Assert.Equal(3, captureCount);
    }

    [Fact]
    public void PanelHostSupportsDockingCollapsingAndSemanticDensityMetrics()
    {
        var left = PanelKey.Parse("navigation");
        var right = PanelKey.Parse("inspector");
        var host = new PanelHost(DensityMode.Compact,
        [
            new PanelDefinition(left),
            new PanelDefinition(right, DockRegion.Right)
        ]);

        Assert.Equal(DesignTokens.Get(ThemeMode.Light, DensityMode.Compact).Measurements, host.Measurements);
        Assert.True(host.Dock(left, DockRegion.Bottom, 4));
        Assert.True(host.SetCollapsed(left, true));
        Assert.False(host.Dock(PanelKey.Parse("renamed-panel"), DockRegion.Left, 0));
        Assert.Contains(host.Snapshot(), panel => panel.Key == left && panel.Region == DockRegion.Bottom && panel.IsCollapsed);

        var report = host.Restore(
        [
            new PanelPlacement(right, DockRegion.Top, true, 1),
            new PanelPlacement(PanelKey.Parse("old-inspector"), DockRegion.Left, false, 0)
        ]);

        Assert.Equal(1, report.AppliedCount);
        Assert.Equal([PanelKey.Parse("old-inspector")], report.MissingPanels);
        Assert.Contains(host.Snapshot(), panel => panel.Key == right && panel.Region == DockRegion.Top && panel.IsCollapsed);
        Assert.Contains(host.Snapshot(), panel => panel.Key == left && panel.Region == DockRegion.Left && !panel.IsCollapsed);
    }

    [Fact]
    public void PanelHostBoundsDefinitionsAndValidatesRestoreBeforeApplyingAnyState()
    {
        var tooManyPanels = Enumerable.Range(0, 257)
            .Select(index => new PanelDefinition(PanelKey.Parse($"panel-{index}")));
        Assert.Throws<ArgumentOutOfRangeException>(() => new PanelHost(DensityMode.Comfortable, tooManyPanels));

        var key = PanelKey.Parse("navigation");
        var host = new PanelHost(DensityMode.Comfortable, [new PanelDefinition(key)]);
        Assert.Throws<ArgumentException>(() => host.Restore(
        [
            new PanelPlacement(key, DockRegion.Right, true, 1),
            new PanelPlacement(PanelKey.Parse("inspector"), DockRegion.Left, false, -1)
        ]));
        Assert.Equal(new PanelPlacement(key, DockRegion.Left, false, 0), Assert.Single(host.Snapshot()));
    }

    [Fact]
    public void ApplicationAndLayoutKeysAreClosedAndCannotBecomePathSegments()
    {
        Assert.Equal("editor", ApplicationKey.Parse("editor").Value);
        Assert.Equal("editor", ApplicationKey.TryParse("editor")!.Value);
        Assert.Equal("default", LayoutKey.Parse("default").Value);
        Assert.Equal("default", LayoutKey.TryParse("default")!.Value);
        Assert.Equal("inspector", PanelKey.Parse("inspector").Value);
        Assert.Equal("inspector", PanelKey.TryParse("inspector")!.Value);
        Assert.Equal("main", WindowId.Parse("main").Value);
        Assert.Equal("main", WindowId.TryParse("main")!.Value);
        Assert.Equal("display-one", DisplayId.Parse("display-one").Value);
        Assert.Equal("display-one", DisplayId.TryParse("display-one")!.Value);
        Assert.Null(ApplicationKey.TryParse("../outside"));
        Assert.Null(ApplicationKey.TryParse("Uppercase"));
        Assert.Null(LayoutKey.TryParse("layout/name"));
        Assert.Null(PanelKey.TryParse("two--separators"));
        Assert.Throws<ArgumentException>(() => WindowId.Parse("../main"));
        Assert.Throws<ArgumentException>(() => DisplayId.Parse("C:\\screen"));
        Assert.Null(WindowId.TryParse("../main"));
        Assert.Null(DisplayId.TryParse("C:\\screen"));
        Assert.Empty(LayoutSnapshot.Create(ApplicationKey.Parse("editor"), LayoutKey.Parse("default"), [], []).Windows);

        var root = NewTemporaryRoot();
        try
        {
            Directory.CreateDirectory(root);
            var store = NewStore(root, "editor", "default");
            var path = Path.GetFullPath(store.StoragePath);
            Assert.StartsWith(Path.GetFullPath(root), path, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("editor", path, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("default", path, StringComparison.OrdinalIgnoreCase);

            var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            Assert.False(string.IsNullOrWhiteSpace(localApplicationData));
            var currentUserStore = DeviceLocalLayoutStore.ForCurrentUser(ApplicationKey.Parse("editor"), LayoutKey.Parse("default"));
            Assert.StartsWith(Path.GetFullPath(localApplicationData), Path.GetFullPath(currentUserStore.StoragePath), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void SnapshotCreationBoundsWindowAndPanelCollections()
    {
        var application = ApplicationKey.Parse("editor");
        var layout = LayoutKey.Parse("default");
        var window = Placement("main", "display-one", new WindowBounds(10, 20, 640, 480));
        var tooManyWindows = Assert.Throws<ArgumentOutOfRangeException>(() =>
            LayoutSnapshot.Create(application, layout, Enumerable.Repeat(window, 65), []));
        Assert.Equal("windows", tooManyWindows.ParamName);

        var panel = new PanelPlacement(PanelKey.Parse("inspector"), DockRegion.Left, false, 0);
        var tooManyPanels = Assert.Throws<ArgumentOutOfRangeException>(() =>
            LayoutSnapshot.Create(application, layout, [], Enumerable.Repeat(panel, 257)));
        Assert.Equal("panels", tooManyPanels.ParamName);
    }

    [Fact]
    public void DeviceLocalStoreRestoresAcrossLaunchesAndIsolatesApplicationsAndLayouts()
    {
        var root = NewTemporaryRoot();
        try
        {
            var store = NewStore(root, "editor", "default");
            var snapshot = Snapshot("editor", "default", [Placement("main", "display-one", new WindowBounds(10, 20, 900, 700))]);
            store.Save(snapshot);

            var nextLaunchRegistry = new WindowRegistry(IdentityGeneration.NewInstance());
            var reloaded = NewStore(root, "editor", "default").Load();
            Assert.Equal(LayoutLoadStatus.Loaded, reloaded.Status);
            Assert.NotNull(reloaded.Snapshot);
            var topology = Displays(new DisplayWorkArea(DisplayId.Parse("display-one"), new WindowBounds(0, 0, 1920, 1080), true));
            var host = new PanelHost(DensityMode.Comfortable, []);
            var restored = LayoutRestorer.Restore(reloaded.Snapshot, nextLaunchRegistry, host, topology);
            Assert.Equal("main", Assert.Single(restored.RestoredWindows).Id.Value);
            Assert.Equal(1, nextLaunchRegistry.Count);
            Assert.Equal(snapshot.Windows, nextLaunchRegistry.Snapshot());

            Assert.Equal(LayoutLoadStatus.Missing, NewStore(root, "editor", "review").Load().Status);
            Assert.Equal(LayoutLoadStatus.Missing, NewStore(root, "media", "default").Load().Status);
            Assert.Throws<ArgumentException>(() => NewStore(root, "media", "default").Save(snapshot));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void RestoreDropsMissingOrRenamedPanelsAndAdaptsDisplayTopologyChanges()
    {
        var snapshot = Snapshot(
            "editor",
            "default",
            [
                Placement("main", "removed-screen", new WindowBounds(2300, 1100, 1920, 1080)),
                Placement("inspector-window", "studio-screen", new WindowBounds(-900, 80, 1500, 1000))
            ],
            [
                new PanelPlacement(PanelKey.Parse("inspector"), DockRegion.Right, true, 1),
                new PanelPlacement(PanelKey.Parse("old-output"), DockRegion.Bottom, false, 2)
            ]);
        var registry = new WindowRegistry(IdentityGeneration.NewInstance());
        var current = Displays(
            new DisplayWorkArea(DisplayId.Parse("laptop"), new WindowBounds(0, 0, 1280, 720), true),
            new DisplayWorkArea(DisplayId.Parse("studio-screen"), new WindowBounds(-1024, 0, 1024, 768)));
        Assert.True(current.TryGet(DisplayId.Parse("studio-screen"), out var currentStudio));
        Assert.Equal(new WindowBounds(-1024, 0, 1024, 768), currentStudio!.Bounds);
        var host = new PanelHost(DensityMode.ProfessionalDense, [new PanelDefinition(PanelKey.Parse("inspector"))]);

        var report = LayoutRestorer.Restore(snapshot, registry, host, current);

        Assert.Equal(2, report.RestoredWindows.Count);
        Assert.Equal([DisplayId.Parse("removed-screen")], report.UnavailableDisplays);
        Assert.Equal(DisplayId.Parse("laptop"), report.RestoredWindows[0].Display);
        Assert.Equal(new WindowBounds(0, 0, 1280, 720), report.RestoredWindows[0].Bounds);
        Assert.Equal(new WindowBounds(-1024, 0, 1024, 768), report.RestoredWindows[1].Bounds);
        Assert.Equal([PanelKey.Parse("old-output")], report.MissingPanels);
        Assert.Contains(host.Snapshot(), panel => panel.Key.Value == "inspector" && panel.Region == DockRegion.Right && panel.IsCollapsed);
    }

    [Fact]
    public void RestoreRaisesSmallWindowsToUsableMinimumAndClampsThemToTheWorkArea()
    {
        var snapshot = Snapshot("editor", "default", [Placement("main", "laptop", new WindowBounds(2000, 2000, 100, 80))]);
        var registry = new WindowRegistry(IdentityGeneration.NewInstance());
        var panels = new PanelHost(DensityMode.Comfortable, []);
        var displays = Displays(new DisplayWorkArea(DisplayId.Parse("laptop"), new WindowBounds(0, 0, 640, 480), true));

        var report = LayoutRestorer.Restore(snapshot, registry, panels, displays);

        Assert.Equal(new WindowBounds(320, 280, 320, 200), Assert.Single(report.RestoredWindows).Bounds);
    }

    [Fact]
    public void CorruptAndTruncatedLayoutJsonReturnsSafeDefaultResult()
    {
        var root = NewTemporaryRoot();
        try
        {
            var store = NewStore(root, "editor", "default");
            Directory.CreateDirectory(Path.GetDirectoryName(store.StoragePath)!);
            File.WriteAllText(store.StoragePath, "{\"schemaVersion\":1,\"windows\":[");
            var result = store.Load();
            Assert.Equal(LayoutLoadStatus.Corrupt, result.Status);
            Assert.Null(result.Snapshot);

            var defaults = new WindowRegistry(IdentityGeneration.NewInstance());
            Assert.Empty(defaults.Snapshot());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void NumericPanelRegionInPersistedJsonIsRejectedAsCorrupt()
    {
        var root = NewTemporaryRoot();
        try
        {
            var store = NewStore(root, "editor", "default");
            Directory.CreateDirectory(Path.GetDirectoryName(store.StoragePath)!);
            File.WriteAllText(store.StoragePath,
                """{"schemaVersion":1,"applicationKey":"editor","layoutKey":"default","windows":[],"panels":[{"key":"navigation","region":"1","isCollapsed":false,"order":0}]}""");

            var loaded = store.Load();
            Assert.Equal(LayoutLoadStatus.Corrupt, loaded.Status);
            Assert.Null(loaded.Snapshot);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void DuplicateWindowsInPersistedJsonAreDeduplicatedBeforeRestore()
    {
        var root = NewTemporaryRoot();
        try
        {
            var store = NewStore(root, "editor", "default");
            Directory.CreateDirectory(Path.GetDirectoryName(store.StoragePath)!);
            File.WriteAllText(store.StoragePath,
                """{"schemaVersion":1,"applicationKey":"editor","layoutKey":"default","windows":[{"id":"main","display":"display-one","x":1,"y":2,"width":640,"height":480},{"id":"main","display":"display-one","x":3,"y":4,"width":640,"height":480}],"panels":[]}""");

            var loaded = store.Load();
            Assert.Equal(LayoutLoadStatus.Recovered, loaded.Status);
            Assert.Equal(1, loaded.DiscardedDuplicateCount);
            Assert.NotNull(loaded.Snapshot);

            var registry = new WindowRegistry(IdentityGeneration.NewInstance());
            var host = new PanelHost(DensityMode.Comfortable, []);
            var report = LayoutRestorer.Restore(
                loaded.Snapshot,
                registry,
                host,
                Displays(new DisplayWorkArea(DisplayId.Parse("display-one"), new WindowBounds(0, 0, 1920, 1080), true)));
            Assert.Single(report.RestoredWindows);
            Assert.Equal(1, registry.Count);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void InterruptedWriteLeavesTheLastCommittedLayoutIntact()
    {
        var root = NewTemporaryRoot();
        try
        {
            var committed = NewStore(root, "editor", "default");
            committed.Save(Snapshot("editor", "default", [Placement("main", "display-one", new WindowBounds(1, 2, 640, 480))]));

            var interrupted = new DeviceLocalLayoutStore(
                ApplicationKey.Parse("editor"),
                LayoutKey.Parse("default"),
                root,
                new AtomicLayoutFileWriter(static () => throw new IOException("Simulated interruption before atomic replace.")));
            Assert.Throws<IOException>(() => interrupted.Save(
                Snapshot("editor", "default", [Placement("main", "display-one", new WindowBounds(90, 80, 700, 500))])));

            var reloaded = committed.Load();
            Assert.Equal(LayoutLoadStatus.Loaded, reloaded.Status);
            Assert.Equal(new WindowBounds(1, 2, 640, 480), Assert.Single(reloaded.Snapshot!.Windows).Bounds);
            Assert.Equal([Path.GetFileName(committed.StoragePath)], Directory.GetFiles(Path.GetDirectoryName(committed.StoragePath)!).Select(Path.GetFileName));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static DeviceLocalLayoutStore NewStore(string root, string application, string layout)
        => new(ApplicationKey.Parse(application), LayoutKey.Parse(layout), root);

    private static LayoutSnapshot Snapshot(
        string application,
        string layout,
        IEnumerable<WindowPlacement> windows,
        IEnumerable<PanelPlacement>? panels = null)
        => LayoutSnapshot.Create(ApplicationKey.Parse(application), LayoutKey.Parse(layout), windows, panels ?? []);

    private static WindowPlacement Placement(string id, string display, WindowBounds bounds)
        => new(WindowId.Parse(id), DisplayId.Parse(display), bounds);

    private static DisplayTopology Displays(params DisplayWorkArea[] displays)
        => new(displays);

    private static string NewTemporaryRoot()
        => Path.Combine(Path.GetTempPath(), "arcf-or-plt27-" + Guid.NewGuid().ToString("N"));

    private static ShellLifecycleOperations LifecycleOperations(
        Func<CancellationToken, ValueTask<bool>>? makeWorkspaceUsableAsync = null,
        Func<CancellationToken, ValueTask>? startBackgroundWorkAsync = null,
        Func<ShellActivationRequest, CancellationToken, ValueTask>? forwardActivationToPrimaryAsync = null,
        Func<CancellationToken, ValueTask<ShellShutdownState>>? captureShutdownStateAsync = null,
        Func<CancellationToken, ValueTask>? stopAcceptingWritesAsync = null,
        Func<CancellationToken, ValueTask>? resumeAcceptingWritesAsync = null,
        Func<CancellationToken, ValueTask>? reachSafePointsAsync = null,
        Func<ShellShutdownState, CancellationToken, ValueTask>? saveUnsavedWorkAsync = null,
        Func<CancellationToken, ValueTask>? flushWritesAsync = null,
        Func<CancellationToken, ValueTask>? disconnectServicesAsync = null,
        Func<CancellationToken, ValueTask>? drainWorkAsync = null,
        Func<CancellationToken, ValueTask>? stopNativeRuntimeAsync = null) =>
        new(
            makeWorkspaceUsableAsync ?? (static _ => ValueTask.FromResult(true)),
            startBackgroundWorkAsync ?? (static _ => ValueTask.CompletedTask),
            forwardActivationToPrimaryAsync ?? (static (_, _) => ValueTask.CompletedTask),
            captureShutdownStateAsync ?? (static _ => ValueTask.FromResult(new ShellShutdownState(0, 0, 0))),
            stopAcceptingWritesAsync ?? (static _ => ValueTask.CompletedTask),
            resumeAcceptingWritesAsync ?? (static _ => ValueTask.CompletedTask),
            reachSafePointsAsync ?? (static _ => ValueTask.CompletedTask),
            saveUnsavedWorkAsync ?? (static (_, _) => ValueTask.CompletedTask),
            flushWritesAsync ?? (static _ => ValueTask.CompletedTask),
            disconnectServicesAsync ?? (static _ => ValueTask.CompletedTask),
            drainWorkAsync ?? (static _ => ValueTask.CompletedTask),
            stopNativeRuntimeAsync ?? (static _ => ValueTask.CompletedTask));

    private static ValueTask Record(List<string> calls, string step)
    {
        calls.Add(step);
        return ValueTask.CompletedTask;
    }
}
