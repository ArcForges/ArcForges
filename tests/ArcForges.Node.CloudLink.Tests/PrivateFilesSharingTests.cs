// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.ExceptionServices;

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

    private string FilePath => Path.Combine(_root, "run", "cloud-link.json");

    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public void AReadWaitsOutAnotherHandleThatRefusesSharing()
    {
        PrivateFiles.WriteAtomic(FilePath, "first"u8);
        using var holder = new FileStream(FilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        // The premise: while the holder is open, an open for reading is refused, and that refusal is transient.
        var refused = Assert.ThrowsAny<IOException>(() => new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete).Dispose());
        Assert.True(PrivateFiles.Transient(refused, replacing: false), refused.GetType().Name + " " + refused.HResult);
        var read = ReleaseOnRefusal(holder, replacing: false, () => PrivateFiles.ReadOrNull(FilePath));
        Assert.Equal("first"u8.ToArray(), read);
    }

    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public void AnUnrelatedRefusalCannotReleaseTheOwnedFile()
    {
        PrivateFiles.WriteAtomic(FilePath, "first"u8);
        // A prefix-related path must not count as the file held by this test.
        var unrelatedPath = FilePath + ".other";
        PrivateFiles.WriteAtomic(unrelatedPath, "other"u8);
        using var holder = new FileStream(FilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        using var unrelated = new FileStream(unrelatedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var read = ReleaseOnRefusal(holder, replacing: false, () =>
        {
            var refusal = Assert.ThrowsAny<IOException>(() =>
                new FileStream(unrelatedPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete).Dispose());
            Assert.True(PrivateFiles.Transient(refusal, replacing: false));
            Assert.True(holder.CanRead, "A refusal on another file must not release the owned holder.");
            Assert.Throws<FileNotFoundException>(() => File.ReadAllBytes(FilePath + ".missing"));
            Assert.True(holder.CanRead, "A nontransient error must not release the owned holder.");
            return PrivateFiles.ReadOrNull(FilePath);
        });
        Assert.Equal("first"u8.ToArray(), read);
        Assert.False(holder.CanRead);
    }

    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public void ARefusalThatOutlastsTheRetriesIsReportedWithinItsBound()
    {
        PrivateFiles.WriteAtomic(FilePath, "first"u8);
        using var holder = new FileStream(FilePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var watch = Stopwatch.StartNew();
        Assert.ThrowsAny<IOException>(() => PrivateFiles.ReadOrNull(FilePath));
        // A sleep may end up to one timer tick (about 16 ms on Windows) early.
        var bound = PrivateFiles.RetryDelays.Aggregate(TimeSpan.Zero, (sum, delay) => sum + delay);
        Assert.InRange(watch.Elapsed, bound - (PrivateFiles.RetryDelays.Length * TimeSpan.FromMilliseconds(16)), TimeSpan.FromSeconds(5));
    }

    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public void TheAtomicReplaceWaitsOutAReaderThatRefusesDeleteSharing()
    {
        // File.ReadAllBytes opens with FileShare.Read only: on Windows the replace is refused until it closes (on Linux a rename never is).
        PrivateFiles.WriteAtomic(FilePath, "first"u8);
        using var holder = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (OperatingSystem.IsWindows())
        {
            // The replace exception can omit the path, so prove this exact target refuses a real replacement while held.
            var probe = Path.Combine(_root, "replace-probe");
            File.WriteAllText(probe, "probe");
            try
            {
                var refused = Record.Exception(() => File.Move(probe, FilePath, overwrite: true));
                Assert.NotNull(refused);
                Assert.True(PrivateFiles.Transient(refused, replacing: true));
                Assert.True(File.Exists(probe));
            }
            finally
            {
                File.Delete(probe);
            }

            ReleaseOnRefusal(holder, replacing: true, () =>
            {
                PrivateFiles.WriteAtomic(FilePath, "second"u8);
                return true;
            });
        }
        else
        {
            PrivateFiles.WriteAtomic(FilePath, "second"u8);
            Assert.True(holder.CanRead);
        }

        Assert.Equal("second"u8.ToArray(), PrivateFiles.ReadOrNull(FilePath));
        Assert.Equal([FilePath], Directory.GetFiles(Path.GetDirectoryName(FilePath)!));
    }

    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public void ADeleteWaitsOutAnotherHandleThatRefusesSharing()
    {
        PrivateFiles.WriteAtomic(FilePath, "first"u8);
        using var holder = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (OperatingSystem.IsWindows())
        {
            var refused = Record.Exception(() => File.Delete(FilePath));
            Assert.NotNull(refused);
            Assert.True(PrivateFiles.Transient(refused, replacing: true));
            Assert.True(File.Exists(FilePath));
        }

        var deleted = OperatingSystem.IsWindows()
            ? ReleaseOnRefusal(holder, replacing: true, () => PrivateFiles.Delete(FilePath))
            : PrivateFiles.Delete(FilePath);
        Assert.True(deleted);
        Assert.False(File.Exists(FilePath));
    }

    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public void AReplaceRefusalThatOutlastsTheRetriesLeavesTheOriginalFile()
    {
        PrivateFiles.WriteAtomic(FilePath, "first"u8);
        using var holder = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (OperatingSystem.IsWindows())
        {
            var watch = Stopwatch.StartNew();
            var refusal = Record.Exception(() => PrivateFiles.WriteAtomic(FilePath, "second"u8));
            Assert.NotNull(refusal);
            Assert.True(PrivateFiles.Transient(refusal, replacing: true), refusal.GetType().Name + " " + refusal.HResult);
            var bound = PrivateFiles.RetryDelays.Aggregate(TimeSpan.Zero, (sum, delay) => sum + delay);
            Assert.InRange(watch.Elapsed, bound - (PrivateFiles.RetryDelays.Length * TimeSpan.FromMilliseconds(16)), TimeSpan.FromSeconds(5));
            Assert.Equal("first"u8.ToArray(), PrivateFiles.ReadOrNull(FilePath));
        }
        else
        {
            // A Linux rename is allowed even with this reader held open.
            PrivateFiles.WriteAtomic(FilePath, "second"u8);
            Assert.True(holder.CanRead);
            Assert.Equal("second"u8.ToArray(), PrivateFiles.ReadOrNull(FilePath));
        }

        Assert.Equal([FilePath], Directory.GetFiles(Path.GetDirectoryName(FilePath)!));
    }

    [Fact]
    public void APermissionDenialOnUnixIsNotRetried()
    {
        Assert.False(PrivateFiles.Transient(new UnauthorizedAccessException(), replacing: false));
        Assert.Equal(OperatingSystem.IsWindows(), PrivateFiles.Transient(new UnauthorizedAccessException(), replacing: true));
        Assert.False(PrivateFiles.Transient(new FileNotFoundException(), replacing: true));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(121)]
    [InlineData(4096)]
    [InlineData(100_000)]
    public void AReadReturnsTheExactBytesInOneArray(int length)
    {
        // PR #71 review B-2: one array of the file's exact size, read straight into it (no pooled, stream or growing buffer of a private key).
        var content = System.Security.Cryptography.RandomNumberGenerator.GetBytes(length);
        PrivateFiles.WriteAtomic(FilePath, content);
        var read = PrivateFiles.ReadOrNull(FilePath)!;
        Assert.Equal(content.Length, read.Length);
        Assert.Equal(content, read);
        Assert.Null(PrivateFiles.ReadOrNull(FilePath + ".absent"));
    }

    [Fact]
    public async Task AReportWhoseRecordFailsIsWrittenAtALaterLoopTurnWithoutAnotherReport()
    {
        // ReporterAndHookTests' timeout on Windows: the report reached the center, the link write was refused, and nothing ever wrote the
        // name. Now the values stay pending and the loop writes the file again; the center is not called again (PR #71 review N-5). Here
        // the write is made to fail by a read-only run/ directory (Unix permissions).
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
        Assert.Single(link.Center.CallsOf("ReportNodeInfo"));
    }

    private static bool NamesHeldFile(IOException exception, FileStream holder)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var path = holder.Name;
        // The exact quoted path prevents a prefix-related file from satisfying the owned-file check. Never log the exception message.
        return exception.Message.Contains("'" + path + "'", comparison) || exception.Message.Contains("\"" + path + "\"", comparison);
    }

    private static T ReleaseOnRefusal<T>(FileStream holder, bool replacing, Func<T> action)
    {
        var threadId = Environment.CurrentManagedThreadId;
        var observed = false;
        var checking = false;
        EventHandler<FirstChanceExceptionEventArgs> onException = (_, args) =>
        {
            if (Environment.CurrentManagedThreadId != threadId || observed || checking)
            {
                return;
            }

            checking = true;
            try
            {
                // The subscription surrounds only the synchronous operation on this test's unique file and thread.
                if (!PrivateFiles.Transient(args.Exception, replacing)
                    || (args.Exception is IOException io && !NamesHeldFile(io, holder)))
                {
                    return;
                }

                // Set the flag before disposal: even an exception during cleanup must not recurse through this handler.
                observed = true;
                holder.Dispose();
            }
            finally
            {
                checking = false;
            }
        };

        AppDomain.CurrentDomain.FirstChanceException += onException;
        T result;
        try
        {
            result = action();
        }
        finally
        {
            AppDomain.CurrentDomain.FirstChanceException -= onException;
        }

        Assert.True(observed, "The operation did not encounter the expected file-sharing refusal.");
        return result;
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
