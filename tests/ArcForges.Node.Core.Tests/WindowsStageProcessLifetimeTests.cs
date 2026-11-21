// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

public sealed class WindowsStageBootEvidenceTests
{
    [Fact]
    public void OnlyTheRecordedWindowsBootCanQueryTheRecordedProcess()
    {
        const string machine = "af01ef4b-ebac-4958-8613-8cb936658a30";
        const string boot = "windows:" + machine + ":100";
        const int processId = 42;
        const long creationTime = 1_000_000_001;
        var unknown = WindowsStageProcessObservation.Unknown;
        var cases = new (string Recorded, string? Current, WindowsStageProcessObservation Expected)[]
        {
            (boot, "windows:" + machine + ":200", WindowsStageProcessObservation.Ended),
            (boot, "windows:4287aee6-1317-4dc8-a002-7a4fa68f94fb:200", unknown),
            (boot, "windows:unknown:200", unknown),
            ("windows:unknown:100", boot, unknown),
            ("windows:00000000-0000-0000-0000-000000000000:100", boot, unknown),
            ("windows:" + machine + ":0", boot, unknown),
            ("windows:" + machine + ":9223372036854775807", boot, unknown),
            ("windows:" + machine + ":+100", boot, unknown),
            (boot + "\0", boot, unknown),
            (boot, "windows:" + machine + ":200\0", unknown),
            (boot + "\0", boot + "\0", unknown),
            ("linux:" + machine, boot, unknown),
            (boot, null, unknown),
        };

        static WindowsStageProcessObservation UnexpectedLookup(int _, long __) =>
            throw new NotSupportedException("An unproved or earlier boot cannot query this process.");

        foreach (var (recorded, current, expected) in cases)
        {
            var historical = new WindowsOwnedStageIdentity(recorded, processId, creationTime);
            Assert.Equal(expected, historical.Observe(() => current, UnexpectedLookup));
        }

        var owned = new WindowsOwnedStageIdentity(boot, processId, creationTime);
        Assert.Equal(unknown, owned.Observe(() => throw new UnauthorizedAccessException(), UnexpectedLookup));
        Assert.Equal(unknown, (owned with { ProcessId = 0 }).Observe(() => boot, UnexpectedLookup));
        Assert.Equal(unknown, (owned with { CreationTime = 0 }).Observe(() => boot, UnexpectedLookup));
        foreach (var expected in Enum.GetValues<WindowsStageProcessObservation>())
        {
            var calls = 0;
            Assert.Equal(expected, owned.Observe(() => boot, (pid, created) =>
            {
                Assert.Equal((processId, creationTime), (pid, created));
                calls++;
                return expected;
            }));
            Assert.Equal(1, calls);
        }
    }
}

/// <summary>Actual owned processes and native job lifetimes; no file-body or application journal qualification.</summary>
[Trait("env", "windows-real")]
public sealed class WindowsStageProcessLifetimeTests
{
    private const string ChildVariable = "ARCFORGES_CTR06_OWNED_STAGE_LIFETIME_TEST";

    [Fact(Timeout = 30_000)]
    [SupportedOSPlatform("windows")]
    public async Task OwnedProcessIdentityAndTerminationUseTheActualGeneration()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native process lifetime."); return; }
        var token = TestContext.Current.CancellationToken;
        if (Environment.GetEnvironmentVariable(ChildVariable) is { Length: > 0 } encoded)
        {
            await RunChildAsync(encoded, token);
            return;
        }
        using var fixture = new OwnedDirectory();
        using var process = StartChild(fixture.Path, "leaf");
        using var owned = new WindowsOwnedStageProcess(process);
        try
        {
            await WaitForFileAsync(fixture.Path, "leaf-ready.json", process, token);
            var identity = owned.SealedIdentity();
            Assert.Equal(WindowsStageProcessObservation.Running, identity.Observe());
            Assert.Equal(WindowsStageProcessObservation.Ended, (identity with { CreationTime = identity.CreationTime + 1 }).Observe());
            Assert.False(owned.WaitForActualExit(TimeSpan.Zero));
            owned.TerminateOwnedProcess();
            Assert.True(owned.WaitForActualExit(TimeSpan.FromSeconds(5)));
            Assert.Equal(WindowsStageProcessObservation.Ended, identity.Observe());
        }
        finally
        {
            owned.TerminateOwnedProcess();
            Assert.True(owned.WaitForActualExit(TimeSpan.FromSeconds(5)), "The actual owned child did not exit.");
        }
    }

    [Fact(Timeout = 30_000)]
    [SupportedOSPlatform("windows")]
    public async Task ClosingTheNativeJobEndsItsActualAssignedChild()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native stage job."); return; }
        var token = TestContext.Current.CancellationToken;
        using var fixture = new OwnedDirectory();
        using var process = StartChild(fixture.Path, "leaf");
        using var owned = new WindowsOwnedStageProcess(process);
        using var job = new WindowsStageJob();
        try
        {
            job.Assign(owned);
            await WaitForFileAsync(fixture.Path, "leaf-ready.json", process, token);
            var identity = owned.SealedIdentity();
            job.Dispose();
            Assert.True(owned.WaitForActualExit(TimeSpan.FromSeconds(5)));
            Assert.Equal(WindowsStageProcessObservation.Ended, identity.Observe());
        }
        finally
        {
            owned.TerminateOwnedProcess();
            Assert.True(owned.WaitForActualExit(TimeSpan.FromSeconds(5)), "The actual job child did not exit.");
        }
    }

    [Fact(Timeout = 30_000)]
    [SupportedOSPlatform("windows")]
    public async Task ActualParentDeathClosesTheUninheritedJobAndEndsTheChild()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native parent-death job lifetime."); return; }
        var token = TestContext.Current.CancellationToken;
        using var fixture = new OwnedDirectory();
        using var parentProcess = StartChild(fixture.Path, "owner");
        using var parent = new WindowsOwnedStageProcess(parentProcess);
        try
        {
            await WaitForFileAsync(fixture.Path, "owner-ready.json", parentProcess, token);
            var identity = JsonSerializer.Deserialize<WindowsOwnedStageIdentity>(
                await File.ReadAllTextAsync(System.IO.Path.Combine(fixture.Path, "owner-ready.json"), token))!;
            using var actualChild = Process.GetProcessById(identity.ProcessId);
            Assert.Equal(identity.CreationTime, WindowsOwnedStageProcess.CreationTimeOf(actualChild.SafeHandle));
            Assert.Equal(WindowsStageProcessObservation.Running, WindowsOwnedStageProcess.ObserveHandle(actualChild.SafeHandle));
            using var ownedDescendant = new WindowsOwnedStageProcess(actualChild);
            parent.TerminateOwnedProcess();
            Assert.True(parent.WaitForActualExit(TimeSpan.FromSeconds(5)));
            // A managed exit notification may precede the actual native process becoming signaled.
            Assert.True(ownedDescendant.WaitForActualExit(TimeSpan.FromSeconds(5)), "The actual descendant did not exit.");
            Assert.Equal(WindowsStageProcessObservation.Ended, WindowsOwnedStageProcess.ObserveHandle(actualChild.SafeHandle));
            Assert.Equal(WindowsStageProcessObservation.Ended, identity.Observe());
        }
        finally
        {
            parent.TerminateOwnedProcess();
            Assert.True(parent.WaitForActualExit(TimeSpan.FromSeconds(5)), "The actual owner process did not exit.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task RunChildAsync(string encoded, CancellationToken token)
    {
        var request = JsonSerializer.Deserialize<ChildRequest>(encoded)!;
        var full = System.IO.Path.GetFullPath(request.Path);
        if (!full.StartsWith(System.IO.Path.GetFullPath(System.IO.Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) ||
            !System.IO.Path.GetFileName(full).StartsWith("arcforges-windows-stage-lifetime-", StringComparison.Ordinal) ||
            !File.Exists(System.IO.Path.Combine(full, "owned-parent.marker")))
            throw new InvalidOperationException("The owned process fixture is unavailable.");
        if (request.Mode == "leaf")
        {
            using var self = Process.GetCurrentProcess();
            var identity = new WindowsOwnedStageIdentity(BootIdentity.Read(), Environment.ProcessId,
                WindowsOwnedStageProcess.CreationTimeOf(self.SafeHandle));
            WriteReady(full, "leaf-ready.json", identity);
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return;
        }
        if (request.Mode != "owner") throw new InvalidDataException("Unknown owned test role.");
        using var process = StartChild(full, "leaf");
        using var child = new WindowsOwnedStageProcess(process);
        using var job = new WindowsStageJob();
        try
        {
            job.Assign(child);
            await WaitForFileAsync(full, "leaf-ready.json", process, token);
            WriteReady(full, "owner-ready.json", child.SealedIdentity());
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
        }
        finally
        {
            job.Dispose();
            Assert.True(child.WaitForActualExit(TimeSpan.FromSeconds(5)), "The owned fixture child did not exit.");
        }
    }

    private static Process StartChild(string path, string mode)
    {
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(typeof(WindowsStageProcessLifetimeTests).Assembly.Location);
        start.ArgumentList.Add("-method");
        start.ArgumentList.Add(typeof(WindowsStageProcessLifetimeTests).FullName + "." + nameof(OwnedProcessIdentityAndTerminationUseTheActualGeneration));
        start.Environment[ChildVariable] = JsonSerializer.Serialize(new ChildRequest(path, mode));
        return Process.Start(start) ?? throw new IOException("The owned fixture process could not start.");
    }

    private static async Task WaitForFileAsync(string path, string name, Process process, CancellationToken token)
    {
        var timer = Stopwatch.StartNew();
        var file = System.IO.Path.Combine(path, name);
        while (!File.Exists(file) && !process.HasExited && timer.Elapsed < TimeSpan.FromSeconds(10))
            await Task.Delay(20, token);
        Assert.True(File.Exists(file), "The actual fixture process did not become ready.");
    }

    [SupportedOSPlatform("windows")]
    private static void WriteReady(string path, string name, WindowsOwnedStageIdentity identity)
    {
        var temporary = System.IO.Path.Combine(path, name + ".tmp");
        using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, identity);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, System.IO.Path.Combine(path, name));
    }

    private sealed record ChildRequest(string Path, string Mode);
    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-windows-stage-lifetime-");
        internal OwnedDirectory() => File.WriteAllText(System.IO.Path.Combine(Path, "owned-parent.marker"), "owned fixture");
        internal string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
