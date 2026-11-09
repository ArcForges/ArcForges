// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real kernel open guards on test-owned files; these tests do not implement a file mutation service.</summary>
[Trait("feature", "workspace-write-guard")]
public sealed partial class WorkspaceWriteGuardTests
{
    [Fact(Timeout = 30_000)]
    public void CheckedFileHashAndCanceledOrStalePreconditionsDoNotWrite()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "data");
        var bytes = Encoding.UTF8.GetBytes("test-owned original");
        File.WriteAllBytes(path, bytes);
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        using (var guard = root.OpenExistingWriteGuard("data"))
        {
            guard.CheckIntact();
            Assert.True(guard.MatchesExpectedHash(SHA256.HashData(bytes), CancellationToken.None));
            Assert.False(guard.MatchesExpectedHash(SHA256.HashData("stale"u8), CancellationToken.None));
            using var canceled = new CancellationTokenSource();
            canceled.Cancel();
            Assert.ThrowsAny<OperationCanceledException>(() => guard.MatchesExpectedHash(SHA256.HashData(bytes), canceled.Token));
            guard.CheckIntact();
        }

        Assert.Equal(bytes, File.ReadAllBytes(path));
    }

    [Theory(Timeout = 30_000)]
    [InlineData("read")]
    [InlineData("write")]
    [InlineData("mapping")]
    public async Task PriorIndependentDataHandleOrMappingRefuses(string kind)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "data");
        File.WriteAllText(path, "test-owned original");
        using var process = StartPython(HolderScript, path, kind);
        try
        {
            Assert.Equal("READY", await ReadLine(process));
            using var root = WorkspacePath.OpenRoot(fixture.Path);
            var error = Assert.Throws<WorkspacePathException>(() => root.OpenExistingWriteGuard("data"));
            Assert.Equal("file_in_use", error.Reason);
        }
        finally
        {
            Stop(process);
        }

        Assert.Equal("test-owned original", File.ReadAllText(path));
        using var reopened = WorkspacePath.OpenRoot(fixture.Path);
        using var guard = reopened.OpenExistingWriteGuard("data");
        Assert.True(guard.MatchesExpectedHash(SHA256.HashData("test-owned original"u8), CancellationToken.None));
    }

    [Theory(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    [InlineData("open")]
    [InlineData("truncate")]
    public async Task LinuxLaterConflictingOpenOrTruncateBreaksAndReleasesGuard(string action)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux kernel lease and SIGIO semantics");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "data");
        File.WriteAllText(path, "test-owned original");
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var guard = root.OpenExistingWriteGuard("data");
        guard.CheckIntact();
        var before = LinuxLeaseNotifications.NotificationCount;
        using var process = StartPython(BreakerScript, path, action);
        try
        {
            Assert.Equal("READY", await ReadLine(process));
            await process.StandardInput.WriteLineAsync("go");
            Assert.Equal("DONE", await ReadLine(process));
            Assert.True(process.WaitForExit(5000) && process.ExitCode == 0, await process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken));
            Assert.True(LinuxLeaseNotifications.NotificationCount > before, "the real kernel SIGIO must reach the dedicated receiver");
            var error = Assert.Throws<WorkspacePathException>(guard.CheckIntact);
            Assert.Equal("file_guard_breaking", error.Reason);
        }
        finally
        {
            Stop(process);
        }

        // The external process is intentionally allowed to proceed only after the broken guard is released.
        Assert.Equal(action == "truncate" ? string.Empty : "test-owned original", File.ReadAllText(path));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public async Task LinuxSlowGuardDoesNotBlockAnotherFilesBreakNotification()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux independent lease notifications");
        using var fixture = new OwnedDirectory();
        var first = Path.Combine(fixture.Path, "first");
        var second = Path.Combine(fixture.Path, "second");
        File.WriteAllText(first, "first original");
        File.WriteAllText(second, "second original");
        using var root = WorkspacePath.OpenRoot(fixture.Path);
        using var firstGuard = root.OpenExistingWriteGuard("first");
        using var secondGuard = root.OpenExistingWriteGuard("second");
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var held = Task.Run(() =>
        {
            try
            {
                firstGuard.CheckIntact(() =>
                {
                    entered.Set();
                    if (!release.Wait(TimeSpan.FromSeconds(15), cancellationToken))
                    {
                        throw new TimeoutException("Test did not release the coordinated identity check.");
                    }
                });
                return "unexpected_intact";
            }
            catch (WorkspacePathException exception)
            {
                return exception.Reason;
            }
        });

        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(5), cancellationToken));
            var before = LinuxLeaseNotifications.NotificationCount;
            using (var trigger = StartPython(NonblockingBreakerScript, first, "unused"))
            {
                try
                {
                    Assert.True(trigger.WaitForExit(5000));
                    Assert.Equal(0, trigger.ExitCode);
                    Assert.Equal("EAGAIN:11", trigger.StandardOutput.ReadToEnd().Trim());
                }
                finally
                {
                    Stop(trigger);
                }
            }

            var wait = Stopwatch.StartNew();
            while (LinuxLeaseNotifications.NotificationCount <= before && wait.Elapsed < TimeSpan.FromSeconds(5))
            {
                await Task.Delay(10, cancellationToken);
            }

            Assert.True(LinuxLeaseNotifications.NotificationCount > before, "the first real SIGIO must arrive while its check is held");
            using var other = StartPython(BreakerScript, second, "open");
            try
            {
                Assert.Equal("READY", await ReadLine(other));
                await other.StandardInput.WriteLineAsync("go");
                Assert.Equal("DONE", await ReadLine(other));
                Assert.True(other.WaitForExit(5000) && other.ExitCode == 0, await other.StandardError.ReadToEndAsync(cancellationToken));
                Assert.Equal("file_guard_breaking", Assert.Throws<WorkspacePathException>(secondGuard.CheckIntact).Reason);
            }
            finally
            {
                Stop(other);
            }
        }
        finally
        {
            release.Set();
        }

        Assert.Equal("file_guard_breaking", await held.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken));
        firstGuard.Dispose();
        secondGuard.Dispose();
        Assert.Equal("first original", File.ReadAllText(first));
        Assert.Equal("second original", File.ReadAllText(second));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxBreakDuringIdentityCheckCannotReturnAnIntactGuard()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux lease-break observation");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "data");
        File.WriteAllText(path, "test-owned original");
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        using (var guard = root.OpenExistingWriteGuard("data"))
        {
            var error = Assert.Throws<WorkspacePathException>(() => guard.CheckIntact(() =>
            {
                using var process = StartPython(NonblockingBreakerScript, path, "unused");
                try
                {
                    Assert.True(process.WaitForExit(5000), "independent nonblocking open must terminate");
                    Assert.Equal(0, process.ExitCode);
                    Assert.Equal("EAGAIN:11", process.StandardOutput.ReadToEnd().Trim());
                }
                finally
                {
                    Stop(process);
                }
            }));
            Assert.Equal("file_guard_breaking", error.Reason);
        }

        Assert.Equal("test-owned original", File.ReadAllText(path));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public async Task LinuxMetadataOnlyHandleCoexistsButItsDataReopenBreaksTheLease()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux O_PATH and kernel lease semantics");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "data");
        File.WriteAllText(path, "test-owned original");
        using var process = StartPython(MetadataBreakerScript, path, "unused");
        try
        {
            Assert.Equal("READY", await ReadLine(process));
            using var root = WorkspacePath.OpenRoot(fixture.Path);
            using var guard = root.OpenExistingWriteGuard("data");
            guard.CheckIntact(); // The external O_PATH handle itself is not a data-open conflict.
            var before = LinuxLeaseNotifications.NotificationCount;
            await process.StandardInput.WriteLineAsync("go");
            Assert.Equal("DONE", await ReadLine(process));
            Assert.True(process.WaitForExit(5000) && process.ExitCode == 0, await process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken));
            Assert.True(LinuxLeaseNotifications.NotificationCount > before);
            Assert.Equal("file_guard_breaking", Assert.Throws<WorkspacePathException>(guard.CheckIntact).Reason);
        }
        finally
        {
            Stop(process);
        }

        Assert.Equal("test-owned original", File.ReadAllText(path));
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxRefusesFifoBeforeOpeningAnyDataHandle()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux FIFO native open semantics");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "fifo");
        using (var make = Process.Start(new ProcessStartInfo("mkfifo", [path]) { CreateNoWindow = true })!)
        {
            Assert.True(make.WaitForExit(5000) && make.ExitCode == 0);
        }

        using var root = WorkspacePath.OpenRoot(fixture.Path);
        var reached = false;
        var error = Assert.Throws<WorkspacePathException>(() => root.OpenExistingWriteGuard("fifo", () =>
        {
            reached = true;
            AssertNoFifoReader(path);
        }));
        Assert.True(reached);
        Assert.Equal("path_link_or_special", error.Reason);
        AssertNoFifoReader(path);
    }

    [Fact(Timeout = 30_000)]
    [Trait("env", "linux-real")]
    public void LinuxGuardReopensTheVerifiedObjectWhenItsNameIsReplaced()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux verified procfs descriptor reopening");
        using var fixture = new OwnedDirectory();
        var path = Path.Combine(fixture.Path, "data");
        var moved = Path.Combine(fixture.Path, "moved");
        var outside = Path.Combine(fixture.Path, "other");
        File.WriteAllText(path, "checked object");
        File.WriteAllText(outside, "other object");
        using (var root = WorkspacePath.OpenRoot(fixture.Path))
        using (var guard = root.OpenExistingWriteGuard("data", () =>
        {
            File.Move(path, moved);
            File.CreateSymbolicLink(path, outside);
        }))
        {
            Assert.True(guard.MatchesExpectedHash(SHA256.HashData("checked object"u8), CancellationToken.None));
            Assert.False(guard.MatchesExpectedHash(SHA256.HashData("other object"u8), CancellationToken.None));
        }

        Assert.Equal("checked object", File.ReadAllText(moved));
        Assert.Equal("other object", File.ReadAllText(outside));
    }

    private static void AssertNoFifoReader(string path)
    {
        var fd = OpenLinux(path, 1 | 0x800 | 0x80000);
        var error = Marshal.GetLastPInvokeError();
        if (fd >= 0)
        {
            CloseLinux(fd);
        }

        Assert.True(fd < 0 && error == 6, "nonblocking FIFO writer must receive ENXIO with no reader");
    }

    private static Process StartPython(string script, string path, string action)
    {
        var info = new ProcessStartInfo(OperatingSystem.IsWindows() ? "python" : "python3")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            UseShellExecute = false,
        };
        info.ArgumentList.Add("-u");
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add(script);
        info.ArgumentList.Add(path);
        info.ArgumentList.Add(action);
        return Process.Start(info) ?? throw new InvalidOperationException("Could not start independent native fixture process.");
    }

    private static async Task<string?> ReadLine(Process process) =>
        await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(8));

    private static void Stop(Process process)
    {
        if (process.HasExited)
        {
            return;
        }

        try
        {
            process.StandardInput.WriteLine();
            if (!process.WaitForExit(3000))
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
            }
        }
        catch (InvalidOperationException)
        {
            // The test-owned child exited between the state check and the cleanup.
        }
        catch (IOException)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
            }
        }
    }

    private const string HolderScript = """
        import mmap, sys
        path, kind = sys.argv[1:]
        file = open(path, "r+b" if kind == "write" else "rb", buffering=0)
        mapping = None
        if kind == "mapping":
            mapping = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
            file.close()
        print("READY", flush=True)
        sys.stdin.readline()
        if mapping is not None:
            mapping.close()
        if not file.closed:
            file.close()
        """;

    private const string NonblockingBreakerScript = """
        import os, sys
        try:
            fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NONBLOCK)
            os.close(fd)
            print("OPENED", flush=True)
        except BlockingIOError as error:
            print("EAGAIN:" + str(error.errno), flush=True)
        """;

    private const string MetadataBreakerScript = """
        import os, sys
        path = sys.argv[1]
        fd = os.open(path, os.O_PATH | os.O_NOFOLLOW)
        print("READY", flush=True)
        sys.stdin.readline()
        data = os.open("/proc/self/fd/" + str(fd), os.O_RDONLY)
        os.close(data)
        os.close(fd)
        print("DONE", flush=True)
        """;

    private const string BreakerScript = """
        import os, sys
        path, action = sys.argv[1:]
        print("READY", flush=True)
        sys.stdin.readline()
        if action == "open":
            fd = os.open(path, os.O_RDONLY)
            os.close(fd)
        else:
            os.truncate(path, 0)
        print("DONE", flush=True)
        """;

    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int OpenLinux(string name, int flags);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int CloseLinux(int descriptor);

    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-workspace-guard-");
        internal string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
