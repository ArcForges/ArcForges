// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real native parent references and namespace replacement; no component result grants creation authority.</summary>
[Trait("env", "linux-real")]
public sealed class WorkspaceLinuxCreationSelectionTests
{
    [Fact]
    public void ReplacingAnAncestorCannotBeAcceptedByRecapturingTheSameRelativeParentName()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Linux checked creation-parent references."); return; }
        var directory = Directory.CreateTempSubdirectory("af-create-chain-");
        try
        {
            var rootPath = Directory.CreateDirectory(Path.Combine(directory.FullName, "root")).FullName;
            Directory.CreateDirectory(Path.Combine(rootPath, "a", "b"));
            using var root = WorkspacePath.OpenRoot(rootPath);
            var selection = root.PrepareLinuxCreation("a/b/new.txt", TestContext.Current.CancellationToken);
            Directory.Move(Path.Combine(rootPath, "a"), Path.Combine(rootPath, "original-a"));
            Directory.CreateDirectory(Path.Combine(rootPath, "a", "b"));
            var failure = Assert.Throws<WorkspacePathException>(() => selection.CheckNames(null));
            Assert.Equal("directory_identity_changed", failure.Reason);
            Assert.False(File.Exists(Path.Combine(rootPath, "a", "b", "new.txt")));
            Assert.False(File.Exists(Path.Combine(rootPath, "original-a", "b", "new.txt")));
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    public void CreatedObjectRechecksRejectAReplacementAndAnAddedHardLink()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Linux checked creation-parent references."); return; }
        var directory = Directory.CreateTempSubdirectory("af-create-result-");
        try
        {
            using var root = WorkspacePath.OpenRoot(directory.FullName);
            var selection = root.PrepareLinuxCreation("new.txt", TestContext.Current.CancellationToken);
            var path = Path.Combine(directory.FullName, "new.txt");
            File.WriteAllText(path, "first");
            var actual = root.InspectEntry("new.txt").Identity;
            var identity = RegisteredWorkspaces.RootIdentity.Encode(actual, directory: false).Bytes;
            selection.CheckNames(identity);
            File.Move(path, Path.Combine(directory.FullName, "original.txt"));
            File.WriteAllText(path, "second");
            Assert.Equal("file_identity_changed", Assert.Throws<WorkspacePathException>(() => selection.CheckNames(identity)).Reason);
            File.Delete(path);
            File.Move(Path.Combine(directory.FullName, "original.txt"), path);
            selection.CheckNames(identity);
            using var link = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("/usr/bin/ln",
                [path, Path.Combine(directory.FullName, "alias.txt")]) { UseShellExecute = false })
                ?? throw new InvalidOperationException("The owned hard-link fixture did not start.");
            Assert.True(link.WaitForExit(5000));
            Assert.Equal(0, link.ExitCode);
            Assert.Equal("file_identity_changed", Assert.Throws<WorkspacePathException>(() => selection.CheckNames(identity)).Reason);
        }
        finally { directory.Delete(recursive: true); }
    }
}
