// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real native anonymous staging only, not a target effect or an approval-stage implementation.</summary>
[Trait("env", "linux-real")]
public sealed partial class WorkspaceAnonymousStageTests
{
    [Fact(Timeout = 30_000)]
    public void AnonymousStageIsFlushedGuardedAndNeverNamesAnObject()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux O_TMPFILE and file lease");
        var cancellationToken = TestContext.Current.CancellationToken;
        using var fixture = new OwnedDirectory();
        var content = Encoding.UTF8.GetBytes("owned anonymous stage content");
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using (var stage = root.CreateAnonymousStage(content, cancellationToken))
        {
            Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Path));
            Assert.Equal(content.Length, stage.Length);
            Assert.Equal(SHA256.HashData(content), stage.Sha256.ToArray());
            Assert.Equal(2, stage.Identity.Platform);
            Assert.Equal(53, stage.Identity.Bytes.Length);
            Assert.True(stage.Verify(cancellationToken));
            stage.CheckIntact();
        }
        Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Path));
    }

    [Fact(Timeout = 30_000)]
    public void IndependentDescriptionBreaksTheActualStageLeaseBeforeFurtherUse()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux O_TMPFILE, procfs and file lease");
        var cancellationToken = TestContext.Current.CancellationToken;
        using var fixture = new OwnedDirectory();
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var stage = root.CreateAnonymousStage("original stage"u8, cancellationToken);
        var descriptor = stage.DescriptorForTests();
        var other = OpenLinux($"/proc/self/fd/{descriptor}", 0x800 | 0x80000);
        var error = Marshal.GetLastPInvokeError();
        if (other >= 0) _ = CloseLinux(other);
        Assert.True(other < 0 && error == 11, "an independent nonblocking data open must conflict with the held lease");
        var broken = Assert.Throws<WorkspacePathException>(stage.CheckIntact);
        Assert.Equal("file_guard_breaking", broken.Reason);
        Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Path));
    }

    [Fact(Timeout = 30_000)]
    public void APreviouslyOpenedPathDescriptionCanKeepTheStageAfterNodeHandleCloses()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux O_PATH on an O_TMPFILE object");
        using var fixture = new OwnedDirectory();
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var content = "retained-stage-synthetic-data"u8.ToArray();
        using var stage = root.CreateAnonymousStage(content, TestContext.Current.CancellationToken);
        var metadata = OpenLinux($"/proc/self/fd/{stage.DescriptorForTests()}", 0x200000 | 0x80000);
        Assert.True(metadata >= 0);
        try
        {
            stage.Dispose();
            var data = OpenLinux($"/proc/self/fd/{metadata}", 0x80000);
            Assert.True(data >= 0);
            using var reopened = new Microsoft.Win32.SafeHandles.SafeFileHandle(data, ownsHandle: true);
            var buffer = new byte[content.Length];
            Assert.Equal(content.Length, RandomAccess.Read(reopened, buffer, 0));
            Assert.Equal(content, buffer);
            Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Path));
        }
        finally
        {
            _ = CloseLinux(metadata);
        }
    }

    [Fact(Timeout = 30_000)]
    public void OversizeAndCanceledStagesRefuseWithoutCreatingANamedEntry()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux O_TMPFILE and file lease");
        using var fixture = new OwnedDirectory();
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        Assert.Throws<ArgumentOutOfRangeException>(() => root.CreateAnonymousStage(new byte[4 * 1024 * 1024 + 1],
            TestContext.Current.CancellationToken));
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => root.CreateAnonymousStage("unused"u8, canceled.Token));
        Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Path));
    }

    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int OpenLinux(string name, int flags);

    [LibraryImport("libc", EntryPoint = "close")]
    private static partial int CloseLinux(int fd);

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("arcforges-anonymous-stage-");
        internal string Path => _root.FullName;
        public void Dispose() => _root.Delete(recursive: true);
    }
}
