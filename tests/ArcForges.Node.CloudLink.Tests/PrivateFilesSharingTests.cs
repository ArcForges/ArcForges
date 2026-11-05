// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// The cloud link's private files when another handle holds one of them (a Windows defect seen on the Windows leg: a read of
/// <c>run/cloud-link.json</c> refused with a sharing violation while the node replaced it, and a replace refused while a reader held the
/// file, which left the reported name unrecorded). Each test holds the file itself, so the conflict is deterministic: on Windows through
/// the OS's sharing modes, on Linux through the runtime's emulation of <see cref="FileShare.None"/>. REAL files.
/// </summary>
public sealed class PrivateFilesSharingTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("arcforges-private-files-").FullName;

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    private string FilePath => Path.Combine(_root, "run", "cloud-link.json");

    [Fact]
    public async Task AReadWaitsOutAnotherHandleThatRefusesSharing()
    {
        PrivateFiles.WriteAtomic(FilePath, "first"u8);
        var holder = new FileStream(FilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        try
        {
            // The premise: while the holder is open, an open for reading is refused, and that refusal is the transient kind.
            var refused = Assert.ThrowsAny<IOException>(() => new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete).Dispose());
            Assert.True(PrivateFiles.Transient(refused, replacing: false), refused.GetType().Name + " " + refused.HResult);
            var read = Task.Run(() => PrivateFiles.ReadOrNull(FilePath), Cancel);
            await Task.Delay(150, Cancel);
            Assert.False(read.IsCompleted);
            holder.Dispose();
            Assert.Equal("first"u8.ToArray(), await read.WaitAsync(TimeSpan.FromSeconds(5), Cancel));
        }
        finally
        {
            holder.Dispose();
        }
    }

    [Fact]
    public void ARefusalThatOutlastsTheRetriesIsReportedWithinItsBound()
    {
        PrivateFiles.WriteAtomic(FilePath, "first"u8);
        using var holder = new FileStream(FilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var watch = Stopwatch.StartNew();
        Assert.ThrowsAny<IOException>(() => PrivateFiles.ReadOrNull(FilePath));
        Assert.InRange(watch.Elapsed, PrivateFiles.RetryDelays.Aggregate(TimeSpan.Zero, (sum, delay) => sum + delay), TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task TheAtomicReplaceWaitsOutAReaderThatRefusesDeleteSharing()
    {
        // File.ReadAllBytes opens with FileShare.Read only: on Windows the replace is refused until it closes (on Linux a rename never is).
        PrivateFiles.WriteAtomic(FilePath, "first"u8);
        var holder = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            var write = Task.Run(() => PrivateFiles.WriteAtomic(FilePath, "second"u8), Cancel);
            await Task.Delay(150, Cancel);
            holder.Dispose();
            await write.WaitAsync(TimeSpan.FromSeconds(5), Cancel);
        }
        finally
        {
            holder.Dispose();
        }

        Assert.Equal("second"u8.ToArray(), PrivateFiles.ReadOrNull(FilePath));
        Assert.Equal([FilePath], Directory.GetFiles(Path.GetDirectoryName(FilePath)!));
    }

    [Fact]
    public async Task ADeleteWaitsOutAnotherHandleThatRefusesSharing()
    {
        PrivateFiles.WriteAtomic(FilePath, "first"u8);
        var holder = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            var delete = Task.Run(() => PrivateFiles.Delete(FilePath), Cancel);
            await Task.Delay(150, Cancel);
            holder.Dispose();
            Assert.True(await delete.WaitAsync(TimeSpan.FromSeconds(5), Cancel));
        }
        finally
        {
            holder.Dispose();
        }

        Assert.False(File.Exists(FilePath));
    }

    [Fact]
    public void APermissionDenialOnUnixIsNotRetried()
    {
        Assert.False(PrivateFiles.Transient(new UnauthorizedAccessException(), replacing: false));
        Assert.Equal(OperatingSystem.IsWindows(), PrivateFiles.Transient(new UnauthorizedAccessException(), replacing: true));
        Assert.False(PrivateFiles.Transient(new FileNotFoundException(), replacing: true));
    }

    [Fact]
    public async Task AReportWhoseRecordFailsIsRecordedByTheNextReport()
    {
        // ReporterAndHookTests' timeout on Windows: the report reached the center, the link write was refused, and the name was set in memory
        // only, so no later report ever recorded it. Here the write is made to fail by a read-only run/ directory (Unix permissions).
        Assert.SkipWhen(OperatingSystem.IsWindows() || Environment.UserName == "root", "needs Unix permissions that bind the test's user");
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var hold = new TaskCompletionSource();
        link.Center.Script("ReportNodeInfo", new FakeFault.Hold(hold));
        await link.SignInAsync();
        await Eventually.TrueAsync(() => link.Center.CallsOf("ReportNodeInfo").Count == 1, "the report in flight");
        var run = Path.GetDirectoryName(link.Storage.LinkPath)!;
        var mode = File.GetUnixFileMode(run);
        File.SetUnixFileMode(run, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            hold.SetResult();
            await Eventually.TrueAsync(() => SignInFlowTests.ReadLog(link).Contains("cloud.report.record_failed", StringComparison.Ordinal), "the failed record");
        }
        finally
        {
            File.SetUnixFileMode(run, mode);
        }

        Assert.Null(link.Storage.ReadLink()!.ReportedName);
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(5), () => link.Storage.ReadLink()!.ReportedName == "buildbox", "the name recorded");
        Assert.Equal(2, link.Center.CallsOf("ReportNodeInfo").Count);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
