// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real native metadata-only planning. These tests do not assert cleanup or namespace exclusion.</summary>
public sealed class WorkspaceRemovalPlanTests
{
    private static readonly string[] ExpectedPaths = ["tree", "tree/first.txt", "tree/nested", "tree/nested/second.txt"];
    private static readonly string[] CheckedRootPaths = ["", "inside.txt"];

    [Fact]
    public void ExactTreeCapturesNativeIdentityAndSizeWithoutChangingAnyEntry()
    {
        using var fixture = new OwnedDirectory();
        var tree = Directory.CreateDirectory(Path.Combine(fixture.Path, "tree")).FullName;
        Directory.CreateDirectory(Path.Combine(tree, "nested"));
        File.WriteAllText(Path.Combine(tree, "first.txt"), "first");
        File.WriteAllText(Path.Combine(tree, "nested", "second.txt"), "second");
        using var workspace = WorkspacePath.OpenRoot(fixture.Path);

        var plan = WorkspaceRemovalPlan.Capture(workspace, "tree", TestContext.Current.CancellationToken);
        Assert.Equal(ExpectedPaths, plan.Entries.Select(x => x.Path));
        Assert.Equal(11UL, plan.TotalBytes);
        Assert.All(plan.Entries, entry =>
        {
            Assert.Equal(32, entry.IdentitySha256.Length);
            Assert.Equal(32, entry.FingerprintSha256.Length);
            Assert.NotEmpty(entry.NativeIdentity.Bytes);
        });
        Assert.Equal("first", File.ReadAllText(Path.Combine(tree, "first.txt")));
        Assert.Equal("second", File.ReadAllText(Path.Combine(tree, "nested", "second.txt")));
        var repeated = WorkspaceRemovalPlan.Capture(workspace, "tree", TestContext.Current.CancellationToken);
        Assert.Equal(plan.Entries.Select(x => Convert.ToHexString(x.FingerprintSha256)),
            repeated.Entries.Select(x => Convert.ToHexString(x.FingerprintSha256)));
    }

    [Fact]
    public void CheckedRootUsesTheHeldDirectoryAndRejectsASeparateIdentity()
    {
        using var fixture = new OwnedDirectory();
        var tree = Directory.CreateDirectory(Path.Combine(fixture.Path, "tree")).FullName;
        var other = Directory.CreateDirectory(Path.Combine(fixture.Path, "other")).FullName;
        File.WriteAllText(Path.Combine(tree, "inside.txt"), "test content");
        using var target = WorkspacePath.OpenRoot(tree);
        using var unrelated = WorkspacePath.OpenRoot(other);
        var expected = RegisteredWorkspaces.RootIdentity.Encode(target.RootIdentity);
        var different = RegisteredWorkspaces.RootIdentity.Encode(unrelated.RootIdentity);

        var result = WorkspaceRemovalPlan.CaptureCheckedRoot(target, expected.Platform, expected.Bytes,
            TestContext.Current.CancellationToken);
        Assert.Equal(CheckedRootPaths, result.Entries.Select(entry => entry.Path));
        Assert.Equal(expected.Bytes, result.Entries[0].NativeIdentity.Bytes);
        var refusal = Assert.Throws<WorkspaceRemovalPlanException>(() =>
            WorkspaceRemovalPlan.CaptureCheckedRoot(target, different.Platform, different.Bytes,
                TestContext.Current.CancellationToken));
        Assert.Equal("planned_tree_changed", refusal.Reason);
        Assert.Equal("test content", File.ReadAllText(Path.Combine(tree, "inside.txt")));
    }

    [Fact]
    public void CheckedRootRejectsWrongIdentityBeforeAnEnumerationLimit()
    {
        using var fixture = new OwnedDirectory();
        var tree = Directory.CreateDirectory(Path.Combine(fixture.Path, "tree")).FullName;
        var other = Directory.CreateDirectory(Path.Combine(fixture.Path, "other")).FullName;
        for (var index = 0; index < 1002; index++)
            File.WriteAllBytes(Path.Combine(tree, index.ToString(System.Globalization.CultureInfo.InvariantCulture)), []);
        using var target = WorkspacePath.OpenRoot(tree);
        using var unrelated = WorkspacePath.OpenRoot(other);
        var different = RegisteredWorkspaces.RootIdentity.Encode(unrelated.RootIdentity);
        var refusal = Assert.Throws<WorkspaceRemovalPlanException>(() => WorkspaceRemovalPlan.CaptureCheckedRoot(
            target, different.Platform, different.Bytes, TestContext.Current.CancellationToken));
        Assert.Equal("planned_tree_changed", refusal.Reason);
    }

    [Fact]
    [Trait("env", "linux-real")]
    public void CheckedRootRechecksTheNameWhenCaptureThrowsAfterEnumeration()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "This real rename/error case runs on Linux.");
        using var fixture = new OwnedDirectory();
        var tree = Directory.CreateDirectory(Path.Combine(fixture.Path, "tree")).FullName;
        var moved = tree + "-moved";
        using var target = WorkspacePath.OpenRoot(tree);
        var expected = RegisteredWorkspaces.RootIdentity.Encode(target.RootIdentity);
        var refusal = Assert.Throws<WorkspaceRemovalPlanException>(() => WorkspaceRemovalPlan.CaptureCheckedRoot(
            target, expected.Platform, expected.Bytes, () =>
            {
                Directory.Move(tree, moved);
                Directory.CreateDirectory(tree);
                throw new IOException("test-owned capture failure");
            }, TestContext.Current.CancellationToken));
        Assert.Equal("planned_tree_changed", refusal.Reason);
        Assert.True(Directory.Exists(tree));
        Assert.True(Directory.Exists(moved));
    }

    [Fact]
    [Trait("env", "windows-real")]
    public void WindowsHeldChildIsTheCheckedTraversalRoot()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The held-child root uses Windows native directory handles.");
        using var fixture = new OwnedDirectory();
        var tree = Directory.CreateDirectory(Path.Combine(fixture.Path, "tree")).FullName;
        File.WriteAllText(Path.Combine(tree, "inside.txt"), "test content");
        using var parent = WorkspacePath.OpenRoot(fixture.Path);
        using var target = parent.OpenWindowsHeldChildRoot("tree");
        var expected = RegisteredWorkspaces.RootIdentity.Encode(target.RootIdentity);

        var result = WorkspaceRemovalPlan.CaptureCheckedRoot(target, expected.Platform, expected.Bytes,
            TestContext.Current.CancellationToken);
        Assert.Equal(CheckedRootPaths, result.Entries.Select(entry => entry.Path));
        Assert.Equal(expected.Bytes, result.Entries[0].NativeIdentity.Bytes);
        Assert.Equal("test content", File.ReadAllText(Path.Combine(tree, "inside.txt")));
    }

    [Fact(Timeout = 120_000)]
    public void SelectedRootIsNotCountedAgainstTheDescendantLimit()
    {
        using var fixture = new OwnedDirectory();
        var tree = Directory.CreateDirectory(Path.Combine(fixture.Path, "tree")).FullName;
        for (var index = 0; index < 1000; index++)
            File.WriteAllBytes(Path.Combine(tree, index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);
        using (var workspace = WorkspacePath.OpenRoot(fixture.Path))
        {
            var plan = WorkspaceRemovalPlan.Capture(workspace, "tree", TestContext.Current.CancellationToken);
            Assert.Equal(1001, plan.Entries.Count);
            Assert.Equal(0UL, plan.TotalBytes);
        }

        File.WriteAllBytes(Path.Combine(tree, "extra"), []);
        using var second = WorkspacePath.OpenRoot(fixture.Path);
        Assert.Equal("removal_descendants", Assert.Throws<WorkspaceRemovalPlanException>(
            () => WorkspaceRemovalPlan.Capture(second, "tree", TestContext.Current.CancellationToken)).Reason);
        Assert.True(File.Exists(Path.Combine(tree, "extra")));
    }

    [Fact]
    public void LogicalSizeBoundaryAndObservedChangeRefuseWithoutRemovingFiles()
    {
        using var fixture = new OwnedDirectory();
        var file = Path.Combine(fixture.Path, "target");
        using (var stream = File.Create(file)) stream.SetLength(67_108_864);
        using (var workspace = WorkspacePath.OpenRoot(fixture.Path))
        {
            Assert.Equal(67_108_864UL, WorkspaceRemovalPlan.Capture(workspace, "target", TestContext.Current.CancellationToken).TotalBytes);
        }

        using (var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) stream.SetLength(67_108_865);
        using (var workspace = WorkspacePath.OpenRoot(fixture.Path))
        {
            Assert.Equal("removal_total_bytes", Assert.Throws<WorkspaceRemovalPlanException>(
                () => WorkspaceRemovalPlan.Capture(workspace, "target", TestContext.Current.CancellationToken)).Reason);
        }

        using (var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) stream.SetLength(3);
        using var changed = WorkspacePath.OpenRoot(fixture.Path);
        var error = Assert.Throws<WorkspaceRemovalPlanException>(() => WorkspaceRemovalPlan.Capture(changed, "target",
            () => { using var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); stream.SetLength(4); },
            TestContext.Current.CancellationToken));
        Assert.Equal("planned_tree_changed", error.Reason);
        Assert.Equal(4, new FileInfo(file).Length);
    }

    [Fact]
    public void FinalLinkIsRefusedAndWorkspaceRootCannotBeSelected()
    {
        using var fixture = new OwnedDirectory();
        using var workspace = WorkspacePath.OpenRoot(fixture.Path);
        Assert.Throws<WorkspacePathException>(() => WorkspaceRemovalPlan.Capture(workspace, "", TestContext.Current.CancellationToken));
        var outside = Path.Combine(fixture.Path, "outside");
        File.WriteAllText(outside, "outside");
        try
        {
            File.CreateSymbolicLink(Path.Combine(fixture.Path, "alias"), outside);
        }
        catch (Exception exception) when (OperatingSystem.IsWindows() && exception is UnauthorizedAccessException or IOException)
        {
            Assert.SkipWhen(true, "Windows native symlink privilege unavailable.");
        }

        Assert.Equal("path_link_or_special", Assert.Throws<WorkspaceRemovalPlanException>(
            () => WorkspaceRemovalPlan.Capture(workspace, "alias", TestContext.Current.CancellationToken)).Reason);
        Assert.Equal("outside", File.ReadAllText(outside));
    }

    [Fact]
    [Trait("env", "linux-real")]
    public void NonportableObservedChildRefusesTheWholePlanInsteadOfBlamingTheInput()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "This fixture uses a Linux filename containing a backslash.");
        using var fixture = new OwnedDirectory();
        var tree = Directory.CreateDirectory(Path.Combine(fixture.Path, "tree")).FullName;
        var child = Path.Combine(tree, "nonportable\\name");
        File.WriteAllText(child, "unchanged");
        using var workspace = WorkspacePath.OpenRoot(fixture.Path);
        var refusal = Assert.Throws<WorkspaceRemovalPlanException>(() =>
            WorkspaceRemovalPlan.Capture(workspace, "tree", TestContext.Current.CancellationToken));
        Assert.Equal("path_enforcement_unavailable", refusal.Reason);
        Assert.Equal("unchanged", File.ReadAllText(child));
    }

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-removal-plan-");
        internal string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
