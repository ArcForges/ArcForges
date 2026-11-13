// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real native directory handles and files; these tests do not claim an API list or a namespace lock.</summary>
public sealed class WorkspaceDirectoryEntriesTests
{
    private static readonly string[] RootNames = ["first", "nested"];
    private static readonly string[] NestedNames = ["second"];

    [Fact]
    public void HandleEnumerationIsRepeatableBoundedAndNeverOpensAReportedLink()
    {
        using var directory = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(directory.Path, "root")).FullName;
        Directory.CreateDirectory(Path.Combine(root, "nested"));
        File.WriteAllText(Path.Combine(root, "first"), "first content");
        File.WriteAllText(Path.Combine(root, "nested", "second"), "second content");
        using var workspace = WorkspacePath.OpenRoot(root);

        var all = WorkspaceDirectoryEntries.Read(workspace, "", 100, TestContext.Current.CancellationToken);
        Assert.False(all.Truncated);
        Assert.Equal(RootNames, all.Names);
        Assert.Equal(all.Names, WorkspaceDirectoryEntries.Read(workspace, "", 100, TestContext.Current.CancellationToken).Names);
        Assert.Equal(NestedNames, WorkspaceDirectoryEntries.Read(workspace, "nested", 100, TestContext.Current.CancellationToken).Names);
        var limited = WorkspaceDirectoryEntries.Read(workspace, "", 1, TestContext.Current.CancellationToken);
        Assert.True(limited.Truncated);
        Assert.Single(limited.Names);

    }

    [Fact]
    public void AReportedLinkIsNotFollowedWhenOpeningTheNamedObject()
    {
        using var directory = new OwnedDirectory();
        var root = Directory.CreateDirectory(Path.Combine(directory.Path, "root")).FullName;
        var outside = Directory.CreateDirectory(Path.Combine(directory.Path, "outside")).FullName;
        File.WriteAllText(Path.Combine(outside, "outside-marker"), "outside content");
        using var workspace = WorkspacePath.OpenRoot(root);
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(root, "link"), outside);
        }
        catch (Exception exception) when (OperatingSystem.IsWindows() && exception is UnauthorizedAccessException or IOException)
        {
            Assert.SkipWhen(true, "Windows cannot create a test symlink without its native link privilege.");
        }

        Assert.Contains("link", WorkspaceDirectoryEntries.Read(workspace, "", 100, TestContext.Current.CancellationToken).Names);
        Assert.Throws<WorkspacePathException>(() => workspace.OpenRead("link/outside-marker"));
        Assert.Equal("outside content", File.ReadAllText(Path.Combine(outside, "outside-marker")));
    }

    [Fact]
    public void CancellationAndInvalidBoundsRefuseWithoutAnEnumeration()
    {
        using var directory = new OwnedDirectory();
        using var workspace = WorkspacePath.OpenRoot(directory.Path);
        Assert.Throws<ArgumentOutOfRangeException>(() => WorkspaceDirectoryEntries.Read(workspace, "", 0, TestContext.Current.CancellationToken));
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        Assert.Throws<OperationCanceledException>(() => WorkspaceDirectoryEntries.Read(workspace, "", 10, cancel.Token));
    }
    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-workspace-directory-");
        public string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
