// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

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
