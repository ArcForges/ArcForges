// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Native Windows stage and held-handle component cases only. They do not exercise journal orchestration, policy,
/// approval, the full request deadline, strict cleanup, or prior independent mappings.
/// </summary>
[Trait("env", "windows-real")]
[Trait("feature", "workspace-guarded-mutation")]
public sealed class WorkspaceWindowsStageTests
{
    [Fact]
    public void StageChecksOwnerAndProtectedAclAndClosesItsOwnLastHandle()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows delete-on-close stage.");
        using var fixture = new Fixture();
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        using (var stage = root.CreateAnonymousStage("stage fixture content"u8, TestContext.Current.CancellationToken))
        {
            Assert.Equal(1, stage.Identity.Platform);
            Assert.Equal(33, stage.Identity.Bytes.Length);
            Assert.Equal(SHA256.HashData("stage fixture content"u8), stage.Sha256.ToArray());
            Assert.True(stage.Verify(TestContext.Current.CancellationToken)); // includes owner/DACL recheck on this handle
        }
        Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Root));
    }

    [Fact]
    public void VisibleDeleteOnCloseStageCannotBeOpenedThroughWorkspaceRead()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows delete-on-close stage.");
        using var fixture = new Fixture();
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        using (var stage = root.CreateAnonymousStage("unapproved-fixture-body"u8, TestContext.Current.CancellationToken))
        {
            // Observe the real directory entry; this exercises the same no-follow data open used by file reads.
            var name = Path.GetFileName(Assert.Single(Directory.EnumerateFileSystemEntries(fixture.Root)));
            Assert.StartsWith(".arcforges-stage-", name, StringComparison.Ordinal);
            Assert.Throws<WorkspacePathException>(() => root.OpenRead(name));
            Assert.True(stage.Verify(TestContext.Current.CancellationToken));
        }
        Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Root));
    }

    [Theory]
    [InlineData("windows replacement bytes")]
    [InlineData("")]
    public void HeldTargetGetsExactFlushedStageBytesAndSameIdentity(string text)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows no-sharing and delete-on-close stage.");
        using var fixture = new Fixture();
        var directory = Directory.CreateDirectory(Path.Combine(fixture.Root, "child")).FullName;
        var path = Path.Combine(directory, "target");
        var original = "original fixture bytes"u8.ToArray();
        var intended = Encoding.UTF8.GetBytes(text);
        File.WriteAllBytes(path, original);
        WorkspaceObjectIdentity before;
        using (var root = WorkspacePath.OpenRoot(fixture.Root))
        using (var target = root.OpenExistingWriteGuard("child/target"))
        using (var stage = root.CreateAnonymousStage(intended, TestContext.Current.CancellationToken))
        {
            before = target.ObjectIdentity;
            var result = root.ApplyExistingGuardedStage("child/target", target, stage, SHA256.HashData(original),
                TestContext.Current.CancellationToken);
            Assert.Equal(intended.Length, result.Size);
            Assert.Equal(SHA256.HashData(intended), result.Sha256);
        }
        using var checkedRoot = WorkspacePath.OpenRoot(fixture.Root);
        Assert.True(before.SameObject(checkedRoot.InspectEntry("child/target").Identity));
        Assert.Equal(intended, File.ReadAllBytes(path));
        Assert.Single(Directory.EnumerateFileSystemEntries(fixture.Root));
    }

    [Fact]
    public void StaleHashDoesNotChangeTheActualTarget()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows no-sharing and delete-on-close stage.");
        using var fixture = new Fixture();
        var path = Path.Combine(fixture.Root, "target");
        var original = "original fixture bytes"u8.ToArray();
        File.WriteAllBytes(path, original);
        using (var root = WorkspacePath.OpenRoot(fixture.Root))
        using (var target = root.OpenExistingWriteGuard("target"))
        using (var stage = root.CreateAnonymousStage("replacement"u8, TestContext.Current.CancellationToken))
        {
            var error = Assert.Throws<WorkspaceGuardedMutationException>(() => root.ApplyExistingGuardedStage(
                "target", target, stage, SHA256.HashData("stale"u8), TestContext.Current.CancellationToken));
            Assert.False(error.PossibleEffect);
            Assert.Equal("hash_mismatch", Assert.IsType<WorkspacePathException>(error.InnerException).Reason);
        }
        Assert.Equal(original, File.ReadAllBytes(path));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-win-stage-");

        internal Fixture() => Root = Directory.CreateDirectory(Path.Combine(_directory.FullName, "workspace")).FullName;

        internal string Root { get; }

        public void Dispose() => _directory.Delete(recursive: true);
    }
}
