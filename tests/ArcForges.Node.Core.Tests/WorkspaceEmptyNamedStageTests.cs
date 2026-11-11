// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Native creation of empty private named objects; no stage body, approval, power-loss or recovery claim.</summary>
public sealed class WorkspaceEmptyNamedStageTests
{
    [Fact(Timeout = 30_000)]
    public void EmptyNamedObjectIsExclusiveIdentityBoundAndSurvivesOurHandleClose()
    {
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new OwnedDirectory();
        RegisteredWorkspaces.RootIdentity identity;
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        using (var stage = root.CreateEmptyPrivateNamedStage("stage.tmp", ct))
        {
            Assert.Equal("stage.tmp", stage.Name);
            Assert.Equal(0, stage.Guard.ObserveLength(ct));
            Assert.True(stage.Guard.ObjectIdentity.SameObject(root.InspectEntry("stage.tmp").Identity));
            identity = stage.Identity;
            Assert.Throws<WorkspacePathException>(() => root.CreateEmptyPrivateNamedStage("stage.tmp", ct));
            if (OperatingSystem.IsLinux()) Assert.Equal(NamedStageDurabilityEvidence.LinuxFileAndDirectoryFsync, stage.DurabilityEvidence);
            if (OperatingSystem.IsWindows()) Assert.Equal(NamedStageDurabilityEvidence.WindowsNtfsWriteThroughAndFileFlush, stage.DurabilityEvidence);
            // Neither is a power-cut test; the Windows path does not claim flushed ancestors.
        }

        Assert.True(File.Exists(Path.Combine(fixture.Path, "stage.tmp")));
        Assert.Empty(File.ReadAllBytes(Path.Combine(fixture.Path, "stage.tmp")));
        using var reopened = WorkspacePath.OpenRoot(fixture.Path);
        var after = RegisteredWorkspaces.RootIdentity.Encode(reopened.InspectEntry("stage.tmp").Identity, directory: false);
        Assert.Equal(identity.Platform, after.Platform);
        Assert.Equal(identity.Bytes, after.Bytes);
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxPrivateModeChangeBreaksTheHeldStageGuard()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Linux private owner and mode check."); return; }
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new OwnedDirectory();
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var stage = root.CreateEmptyPrivateNamedStage("stage.tmp", ct);
        var file = Path.Combine(fixture.Path, "stage.tmp");
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
        Assert.Throws<WorkspacePathException>(() => stage.Guard.CheckIntact());
        Assert.Empty(File.ReadAllBytes(file));
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-empty-stage-");
        public string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
