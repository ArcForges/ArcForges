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
}
