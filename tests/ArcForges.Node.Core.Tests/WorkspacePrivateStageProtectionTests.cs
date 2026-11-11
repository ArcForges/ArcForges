// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using N = ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Native identity filtering with manually supplied identities. This is a component test, not a durable registry,
/// actual approval, stage creation, startup recovery, or real FileService acceptance.
/// </summary>
public sealed class WorkspacePrivateStageProtectionTests
{
    [Fact(Timeout = 60_000)]
    public void StageIdentityBlocksReadWriteSearchAndListAcrossRenameAndHardLink()
    {
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new OwnedDirectory();
        var initialDir = Directory.CreateDirectory(Path.Combine(fixture.Path, "private-a")).FullName;
        var initialFile = Path.Combine(initialDir, "stage.txt");
        var marker = "private-staged-body-91d41";
        File.WriteAllText(initialFile, marker);
        File.WriteAllText(Path.Combine(fixture.Path, "ordinary.txt"), "ordinary-safe");
        RegisteredWorkspaces.RootIdentity identity;
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        {
            var stage = root.InspectEntry("private-a/stage.txt");
            identity = RegisteredWorkspaces.RootIdentity.Encode(stage.Identity, directory: false);
            root.ProtectPrivateStageFiles([identity]);
            Assert.Equal("file_access_denied",
                Assert.Throws<WorkspacePathException>(() => root.OpenRead("private-a/stage.txt")).Reason);
            Assert.Equal("file_access_denied",
                Assert.Throws<WorkspacePathException>(() => root.OpenExistingWriteGuard("private-a/stage.txt")).Reason);
            using var query = new WorkspaceFileQueries();
            var search = query.Search(root, "", marker, N.FileSearchMode.Literal, cancellationToken: ct);
            Assert.Empty(search.Value.Matches);
            Assert.Equal((ulong)"ordinary-safe".Length, search.Value.ScannedBytes);
            Assert.Equal("file_access_denied",
                Assert.Throws<WorkspaceQueryException>(() => query.Search(root, "private-a/stage.txt", marker,
                    N.FileSearchMode.Literal, cancellationToken: ct)).Reason);
            var listing = query.ListDirectory(root, Guid.NewGuid().ToByteArray(), SHA256.HashData("caller"u8), "private-a", cancellationToken: ct);
            Assert.Empty(listing.Value.Entries);
        }

        // Reopen a parent root after the private directory and its file have changed names.
        var movedDir = Path.Combine(fixture.Path, "private-b");
        Directory.Move(initialDir, movedDir);
        var renamed = Path.Combine(movedDir, "renamed.txt");
        File.Move(Path.Combine(movedDir, "stage.txt"), renamed);
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        {
            root.ProtectPrivateStageFiles([identity]);
            Assert.True(root.IsPrivateStageFile(root.InspectEntry("private-b/renamed.txt").Identity));
            Assert.Equal("file_access_denied",
                Assert.Throws<WorkspacePathException>(() => root.OpenRead("private-b/renamed.txt")).Reason);
            using var query = new WorkspaceFileQueries();
            Assert.Empty(query.Search(root, "", marker, N.FileSearchMode.Literal, cancellationToken: ct).Value.Matches);
            Assert.Empty(query.ListDirectory(root, Guid.NewGuid().ToByteArray(), SHA256.HashData("caller"u8), "private-b",
                cancellationToken: ct).Value.Entries);
        }

        // An independently created second name remains the same protected object even after its link count changes.
        var alias = Path.Combine(fixture.Path, "alias.txt");
        NativeHardLink(renamed, alias);
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        {
            root.ProtectPrivateStageFiles([identity]);
            Assert.True(root.IsPrivateStageFile(root.InspectEntry("alias.txt").Identity));
            Assert.True(root.IsPrivateStageFile(root.InspectEntry("private-b/renamed.txt").Identity));
            Assert.Throws<WorkspacePathException>(() => root.OpenRead("alias.txt"));
            using var query = new WorkspaceFileQueries();
            Assert.Empty(query.Search(root, "", marker, N.FileSearchMode.Literal, cancellationToken: ct).Value.Matches);
            var page = query.ListDirectory(root, Guid.NewGuid().ToByteArray(), SHA256.HashData("caller"u8), "",
                cancellationToken: ct);
            Assert.DoesNotContain(page.Value.Entries, item => item.Name == "alias.txt");
            Assert.Contains(page.Value.Entries, item => item.Name == "ordinary.txt");
        }
        Assert.Equal(marker, File.ReadAllText(renamed)); // fixture-owned data was not modified
    }

    private static void NativeHardLink(string source, string destination)
    {
        var windows = OperatingSystem.IsWindows();
        var executable = windows ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe") : "ln";
        string[] args = windows ? ["/d", "/c", "mklink", "/H", destination, source] : [source, destination];
        using var process = Process.Start(new ProcessStartInfo(executable, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        })!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(10_000) && process.ExitCode == 0, "native hardlink setup failed: " + output);
    }

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-private-stage-");
        public string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
