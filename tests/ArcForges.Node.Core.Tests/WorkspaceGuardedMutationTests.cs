// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Platform;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Real Linux held-descriptor and anonymous-stage component cases on owned files. They do not exercise authority,
/// durable journal coordination, a complete 10-second request, Windows, approvals, or strict cleanup.
/// </summary>
[Trait("feature", "workspace-guarded-mutation")]
[Trait("env", "linux-real")]
public sealed class WorkspaceGuardedMutationTests
{
    [Theory]
    [InlineData("new bytes")]
    [InlineData("")]
    public void SameHeldHandleWritesFlushesAndRehashesExactStage(string text)
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux O_TMPFILE stage is required by this component.");
        using var fixture = new Fixture();
        var intendedBytes = Encoding.UTF8.GetBytes(text);
        WorkspaceObjectIdentity before;
        WorkspaceGuardedMutationResult result;
        using (var root = WorkspacePath.OpenRoot(fixture.Root))
        using (var target = root.OpenExistingWriteGuard("child/target"))
        using (var stage = root.CreateAnonymousStage(intendedBytes, TestContext.Current.CancellationToken))
        {
            before = target.ObjectIdentity;
            result = root.ApplyExistingGuardedStage("child/target", target, stage, SHA256.HashData(fixture.Original),
                TestContext.Current.CancellationToken);
            Assert.True(before.SameObject(target.ObjectIdentity));
            Assert.Equal(intendedBytes.Length, result.Size);
            Assert.Equal(SHA256.HashData(intendedBytes), result.Sha256);
        }
        using var checkRoot = WorkspacePath.OpenRoot(fixture.Root);
        var observed = checkRoot.InspectEntry("child/target");
        Assert.True(before.SameObject(observed.Identity));
        Assert.Equal(intendedBytes, File.ReadAllBytes(fixture.Target));
    }

    [Fact]
    public void StaleOriginalOrTamperedStageRefusesBeforeEffect()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux O_TMPFILE stage is required by this component.");
        using var fixture = new Fixture();
        using (var root = WorkspacePath.OpenRoot(fixture.Root))
        using (var target = root.OpenExistingWriteGuard("child/target"))
        using (var stage = root.CreateAnonymousStage("intended"u8, TestContext.Current.CancellationToken))
        {
            var stale = Assert.Throws<WorkspaceGuardedMutationException>(() => root.ApplyExistingGuardedStage(
                "child/target", target, stage, SHA256.HashData("stale"u8), TestContext.Current.CancellationToken));
            Assert.False(stale.PossibleEffect);
            Assert.Equal("hash_mismatch", Assert.IsType<WorkspacePathException>(stale.InnerException).Reason);

            // Tamper with this test-owned anonymous object through its actual held descriptor, not a substitute filesystem.
            using var descriptor = new SafeFileHandle(stage.DescriptorForTests(), ownsHandle: false);
            RandomAccess.Write(descriptor, "X"u8, 0);
            var tampered = Assert.Throws<WorkspaceGuardedMutationException>(() => root.ApplyExistingGuardedStage(
                "child/target", target, stage, SHA256.HashData(fixture.Original), TestContext.Current.CancellationToken));
            Assert.False(tampered.PossibleEffect);
            Assert.Equal("file_identity_changed", Assert.IsType<WorkspacePathException>(tampered.InnerException).Reason);
        }
        Assert.Equal(fixture.Original, File.ReadAllBytes(fixture.Target));
    }

    [Fact]
    public void ARealReplacementAfterFirstWriteIsUncertainAndNeverTouchesTheNewName()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux rename during a held file lease.");
        using var fixture = new Fixture();
        var intendedBytes = Encoding.UTF8.GetBytes("new intended bytes");
        var substituted = Encoding.UTF8.GetBytes("unplanned replacement");
        var moved = Path.Combine(Path.GetDirectoryName(fixture.Target)!, "moved-original");
        using (var root = WorkspacePath.OpenRoot(fixture.Root))
        using (var target = root.OpenExistingWriteGuard("child/target"))
        using (var stage = root.CreateAnonymousStage(intendedBytes, TestContext.Current.CancellationToken))
        {
            var failure = Assert.Throws<WorkspaceGuardedMutationException>(() => root.ApplyExistingGuardedStage(
                "child/target", target, stage, SHA256.HashData(fixture.Original), () =>
                {
                    File.Move(fixture.Target, moved);
                    File.WriteAllBytes(fixture.Target, substituted);
                }, TestContext.Current.CancellationToken));
            Assert.True(failure.PossibleEffect);
            Assert.Equal("file_identity_changed", Assert.IsType<WorkspacePathException>(failure.InnerException).Reason);
        }
        Assert.Equal(substituted, File.ReadAllBytes(fixture.Target));
        Assert.Equal(intendedBytes, File.ReadAllBytes(moved));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-guarded-mutation-");

        internal Fixture()
        {
            Root = Directory.CreateDirectory(Path.Combine(_directory.FullName, "workspace")).FullName;
            var child = Directory.CreateDirectory(Path.Combine(Root, "child")).FullName;
            Target = Path.Combine(child, "target");
            File.WriteAllBytes(Target, Original);
        }

        internal string Root { get; }

        internal string Target { get; }

        internal byte[] Original { get; } = Encoding.UTF8.GetBytes("original test-owned bytes");

        public void Dispose() => _directory.Delete(recursive: true);
    }
}
