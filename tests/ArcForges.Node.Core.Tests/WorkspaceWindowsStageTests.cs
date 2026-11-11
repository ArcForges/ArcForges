// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.AccessControl;
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
    public void ActualGuardedWritePreservesObservedSecurityAttributesAndAlternateStream()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows security and alternate streams."); return; }
        using var fixture = new Fixture();
        var path = Path.Combine(fixture.Root, "target");
        var alternate = path + ":af-owned-test";
        var original = "original synthetic data"u8.ToArray();
        var intended = "replacement synthetic data"u8.ToArray();
        var streamBytes = "alternate synthetic marker"u8.ToArray();
        File.WriteAllBytes(path, original);
        File.WriteAllBytes(alternate, streamBytes);
        File.SetAttributes(path, FileAttributes.Archive); // supported case: the operation must retain this existing bit
        var attributes = File.GetAttributes(path);
        var created = File.GetCreationTimeUtc(path);
        var sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;
        var security = new FileInfo(path).GetAccessControl(sections).GetSecurityDescriptorBinaryForm();
        WorkspaceObjectIdentity originalIdentity;
        using (var root = WorkspacePath.OpenRoot(fixture.Root))
        using (var target = root.OpenExistingWriteGuard("target"))
        using (var stage = root.CreateAnonymousStage(intended, TestContext.Current.CancellationToken))
        {
            originalIdentity = target.ObjectIdentity;
            var result = root.ApplyExistingGuardedStage("target", target, stage, SHA256.HashData(original),
                TestContext.Current.CancellationToken);
            Assert.Equal(SHA256.HashData(intended), result.Sha256);
        }
        using (var checkRoot = WorkspacePath.OpenRoot(fixture.Root))
            Assert.True(originalIdentity.SameObject(checkRoot.InspectEntry("target").Identity));
        Assert.Equal(attributes, File.GetAttributes(path));
        Assert.Equal(created, File.GetCreationTimeUtc(path));
        Assert.Equal(security, new FileInfo(path).GetAccessControl(sections).GetSecurityDescriptorBinaryForm());
        Assert.Equal(streamBytes, File.ReadAllBytes(alternate));
        Assert.Equal(intended, File.ReadAllBytes(path));
    }

    [Fact]
    public void MissingArchiveCapabilityRefusesBeforeEffectAndPreservesTheActualFile()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows basic file attributes."); return; }
        using var fixture = new Fixture();
        var path = Path.Combine(fixture.Root, "target");
        var alternate = path + ":af-owned-test";
        var original = "original synthetic data"u8.ToArray();
        var stream = "alternate synthetic data"u8.ToArray();
        File.WriteAllBytes(path, original);
        File.WriteAllBytes(alternate, stream);
        File.SetAttributes(path, FileAttributes.Normal);
        var attributes = File.GetAttributes(path);
        Assert.Equal(FileAttributes.Normal, attributes);
        using (var root = WorkspacePath.OpenRoot(fixture.Root))
        using (var target = root.OpenExistingWriteGuard("target"))
        using (var stage = root.CreateAnonymousStage("replacement"u8, TestContext.Current.CancellationToken))
        {
            var failure = Assert.Throws<WorkspaceGuardedMutationException>(() => root.ApplyExistingGuardedStage(
                "target", target, stage, SHA256.HashData(original), TestContext.Current.CancellationToken));
            Assert.False(failure.PossibleEffect);
            Assert.IsType<WorkspacePreservationUnavailableException>(failure.InnerException);
        }
        Assert.Equal(attributes, File.GetAttributes(path));
        Assert.Equal(original, File.ReadAllBytes(path));
        Assert.Equal(stream, File.ReadAllBytes(alternate));
    }

    [Fact]
    public void ReadOnlySetAfterOpeningTheGuardRefusesBeforeEffect()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows basic file attributes."); return; }
        using var fixture = new Fixture();
        var path = Path.Combine(fixture.Root, "target");
        var original = "original synthetic data"u8.ToArray();
        File.WriteAllBytes(path, original);
        File.SetAttributes(path, FileAttributes.Archive);
        try
        {
            using (var root = WorkspacePath.OpenRoot(fixture.Root))
            using (var target = root.OpenExistingWriteGuard("target"))
            using (var stage = root.CreateAnonymousStage("replacement"u8, TestContext.Current.CancellationToken))
            {
                File.SetAttributes(path, FileAttributes.Archive | FileAttributes.ReadOnly);
                var failure = Assert.Throws<WorkspaceGuardedMutationException>(() => root.ApplyExistingGuardedStage(
                    "target", target, stage, SHA256.HashData(original), TestContext.Current.CancellationToken));
                Assert.False(failure.PossibleEffect);
                Assert.IsType<WorkspacePreservationUnavailableException>(failure.InnerException);
            }
            Assert.True((File.GetAttributes(path) & FileAttributes.ReadOnly) != 0);
            Assert.Equal(original, File.ReadAllBytes(path));
        }
        finally
        {
            File.SetAttributes(path, FileAttributes.Archive); // test-owned fixture cleanup
        }
    }

    [Fact]
    public void ObservedAttributeChangeAfterFirstWriteIsUnknownAndNeverRestoredOver()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows basic file attributes."); return; }
        using var fixture = new Fixture();
        var path = Path.Combine(fixture.Root, "target");
        var original = "old-data-000"u8.ToArray();
        var intended = "new-data-111"u8.ToArray();
        File.WriteAllBytes(path, original);
        File.SetAttributes(path, FileAttributes.Archive);
        try
        {
            using (var root = WorkspacePath.OpenRoot(fixture.Root))
            using (var target = root.OpenExistingWriteGuard("target"))
            using (var stage = root.CreateAnonymousStage(intended, TestContext.Current.CancellationToken))
            {
                var failure = Assert.Throws<WorkspaceGuardedMutationException>(() => root.ApplyExistingGuardedStage(
                    "target", target, stage, SHA256.HashData(original),
                    () => File.SetAttributes(path, FileAttributes.Archive | FileAttributes.ReadOnly), TestContext.Current.CancellationToken));
                Assert.True(failure.PossibleEffect);
                Assert.IsType<WorkspacePreservationUnavailableException>(failure.InnerException);
            }
            Assert.True((File.GetAttributes(path) & FileAttributes.ReadOnly) != 0);
            Assert.Equal(intended, File.ReadAllBytes(path));
        }
        finally
        {
            File.SetAttributes(path, FileAttributes.Archive); // test-owned fixture cleanup, after the assertion
        }
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
