// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Sandboxes;

namespace ArcForges.Node.Core.Tests;

public sealed partial class SandboxPrivateRootsTests
{
    [Theory(Timeout = 30_000)]
    [Trait("env", "windows-real")]
    [InlineData(false)]
    [InlineData(true)]
    public void WindowsDirectoryDataStreamRefusesRemovalBeforeAnEntryIsDeleted(bool keepReader)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows NTFS directory stream semantics.");
        var token = TestContext.Current.CancellationToken;
        using var fixture = new SandboxRootFixture();
        var roots = new SandboxPrivateRoots(fixture.DataRoot);
        roots.PrepareControlPaths();
        var created = roots.Provision(SandboxId);
        var streamPath = Path.Combine(fixture.Root(SandboxId), "cache") + ":retained-data";
        File.WriteAllText(streamPath, "retained directory data");
        string deletionId = Guid.NewGuid().ToString("N");
        string quarantineIdentity = roots.QuarantineDeletion(SandboxId, created.Identity, deletionId, () => { }, token);
        var quarantined = Path.Combine(fixture.DataRoot, "control", "deletion-quarantine", deletionId);
        var movedStream = Path.Combine(quarantined, "cache") + ":retained-data";
        using var reader = keepReader
            ? new FileStream(movedStream, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)
            : null;
        int effects = 0;

        var error = Assert.Throws<WorkspacePathException>(() => roots.RemoveDeletionBatch(SandboxId,
            created.Identity, deletionId, quarantineIdentity, 128, () => effects++, token));

        Assert.Equal("directory_streams_unconfirmed", error.Reason);
        Assert.Equal(0, effects);
        Assert.True(Directory.Exists(quarantined));
        Assert.Equal("retained directory data", File.ReadAllText(movedStream));
        reader?.Dispose();
        File.Delete(movedStream);

        var completed = roots.RemoveDeletionBatch(SandboxId, created.Identity, deletionId,
            quarantineIdentity, 128, () => effects++, token);
        Assert.True(completed.RootAbsent);
        Assert.True(effects > 0);
        Assert.False(Directory.Exists(quarantined));
    }
}
