// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual suspension of a test-owned process using the product transaction primitive; not Host/journal acceptance.</summary>
[Trait("env", "windows-real")]
public sealed partial class WindowsPrivateStageSuspensionTests
{
    private const string ChildVariable = "ARCFORGES_CTR06_STAGE_SUSPENSION_TEST";

    [Fact(Timeout = 30_000)]
    [SupportedOSPlatform("windows")]
    public async Task KernelExpiryRejectsDirectWriteAfterActualProducerSuspension()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows kernel transaction and process suspension."); return; }
        var token = TestContext.Current.CancellationToken;
        if (Environment.GetEnvironmentVariable(ChildVariable) is { Length: > 0 } path)
        {
            await RunChildAsync(path, token);
            return;
        }

        using var fixture = new OwnedDirectory();
        using var child = StartChild(fixture.Path);
        using var owned = new WindowsOwnedStageProcess(child);
        var suspended = false;
        try
        {
            await WaitForFileAsync(fixture.Path, "ready.json", child, token);
            var ready = JsonSerializer.Deserialize<Ready>(
                await File.ReadAllTextAsync(Path.Combine(fixture.Path, "ready.json"), token))!;
            Assert.Equal(owned.SealedIdentity(), ready.Worker);
            owned.RequireLive();
            Assert.Equal(0, NtSuspendProcess(child.SafeHandle));
            suspended = true;
            // The child has no runnable thread during this wait. Neither this parent nor any watchdog calls rollback.
            await Task.Delay(TimeSpan.FromMilliseconds(ready.TimeoutMilliseconds + 300), token);
            Assert.False(owned.WaitForActualExit(TimeSpan.Zero));
            Assert.Equal(WindowsStageProcessObservation.Running, ready.Worker.Observe());
            Assert.False(File.Exists(Path.Combine(fixture.Path, "result.json")));
            File.WriteAllText(Path.Combine(fixture.Path, "continue.marker"), "attempt unchecked write after native expiry");
            Assert.Equal(0, NtResumeProcess(child.SafeHandle));
            suspended = false;
            await WaitForFileAsync(fixture.Path, "result.json", child, token);
            var result = JsonSerializer.Deserialize<Result>(
                await File.ReadAllTextAsync(Path.Combine(fixture.Path, "result.json"), token))!;
            Assert.False(result.WriteSucceeded);
            Assert.NotEqual(0, result.WriteHResult);
            Assert.False(result.CommitSucceeded);
            Assert.False(result.FinalNameExists);
            Assert.True(owned.WaitForActualExit(TimeSpan.FromSeconds(5)));
            var output = await child.StandardOutput.ReadToEndAsync(token) + await child.StandardError.ReadToEndAsync(token);
            Assert.True(child.ExitCode == 0, output);
            Assert.Empty(Directory.EnumerateFiles(fixture.Path, ".arcforges-stage-*"));
        }
        finally
        {
            if (suspended && !owned.WaitForActualExit(TimeSpan.Zero)) _ = NtResumeProcess(child.SafeHandle);
            owned.TerminateOwnedProcess();
            Assert.True(owned.WaitForActualExit(TimeSpan.FromSeconds(5)), "The owned suspended fixture process did not exit.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task RunChildAsync(string path, CancellationToken token)
    {
        path = Path.GetFullPath(path);
        if (!path.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(path).StartsWith("arcforges-stage-suspension-", StringComparison.Ordinal) ||
            !File.Exists(Path.Combine(path, "owned-parent.marker")))
            throw new InvalidOperationException("The owned suspension fixture is unavailable.");
        using var root = WorkspacePath.OpenRoot(path);
        using var self = Process.GetCurrentProcess();
        var command = Guid.NewGuid().ToByteArray();
        var identity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity).Bytes;
        var worker = new WindowsOwnedStageIdentity(BootIdentity.Read(), Environment.ProcessId,
            WindowsOwnedStageProcess.CreationTimeOf(self.SafeHandle));
        var binding = new WindowsPrivateStageBinding(command, RandomNumberGenerator.GetBytes(16),
            RandomNumberGenerator.GetBytes(16), SHA256.HashData("owned-fixture-request"u8),
            SHA256.HashData("owned-fixture-caller"u8), Guid.NewGuid().ToByteArray(), Guid.NewGuid().ToByteArray(),
            2, identity, identity, ".arcforges-stage-" + Convert.ToHexStringLower(command) + "-2",
            0, SHA256.HashData([]), checked(Stopwatch.GetTimestamp() + 8 * Stopwatch.Frequency),
            checked((DateTime.UtcNow.Ticks - DateTime.UnixEpoch.Ticks) / 10 + 8_000_000), worker);
        using var transaction = WindowsPrivateStageTransaction.Arm(binding.Deadline, binding.ExpiryMicroseconds);
        using var file = WorkspacePath.CreateWindowsTransactionalEmptyStage(root.RootHandle, binding, transaction);
        WriteJson(path, "ready.json", new Ready(worker, transaction.TimeoutMilliseconds));
        var wait = Stopwatch.StartNew();
        while (!File.Exists(Path.Combine(path, "continue.marker")) && wait.Elapsed < TimeSpan.FromSeconds(15))
            await Task.Delay(20, token);
        Assert.True(File.Exists(Path.Combine(path, "continue.marker")));

        // Intentionally bypass all product RequireActive and controller checks: the real kernel must reject this I/O.
        var writeSucceeded = false;
        var writeHResult = 0;
        try { RandomAccess.Write(file, "must-not-write-after-expiry"u8, 0); writeSucceeded = true; }
        catch (IOException error) { writeHResult = error.HResult; }
        // Likewise bypass the managed Commit method's budget check.
        var commitSucceeded = CommitTransaction(transaction.Handle);
        WriteJson(path, "result.json", new Result(writeSucceeded, writeHResult, commitSucceeded,
            File.Exists(Path.Combine(path, binding.Name))));
        Assert.False(writeSucceeded);
        Assert.False(commitSucceeded);
    }

    private static Process StartChild(string path)
    {
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(typeof(WindowsPrivateStageSuspensionTests).Assembly.Location);
        start.ArgumentList.Add("-method");
        start.ArgumentList.Add(typeof(WindowsPrivateStageSuspensionTests).FullName + "." +
            nameof(KernelExpiryRejectsDirectWriteAfterActualProducerSuspension));
        start.Environment[ChildVariable] = path;
        return Process.Start(start) ?? throw new IOException("The owned suspension fixture could not start.");
    }

    private static async Task WaitForFileAsync(string path, string name, Process child, CancellationToken token)
    {
        var timer = Stopwatch.StartNew();
        while (!File.Exists(Path.Combine(path, name)) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(10))
            await Task.Delay(20, token);
        Assert.True(File.Exists(Path.Combine(path, name)), "The owned process did not produce " + name);
    }

    private static void WriteJson<T>(string path, string name, T value)
    {
        var temporary = Path.Combine(path, name + ".tmp");
        using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, value);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, Path.Combine(path, name));
    }

    [LibraryImport("ntdll.dll")]
    private static partial int NtSuspendProcess(SafeProcessHandle process);

    [LibraryImport("ntdll.dll")]
    private static partial int NtResumeProcess(SafeProcessHandle process);

    [LibraryImport("KtmW32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CommitTransaction(SafeFileHandle transaction);

    private sealed record Ready(WindowsOwnedStageIdentity Worker, uint TimeoutMilliseconds);
    private sealed record Result(bool WriteSucceeded, int WriteHResult, bool CommitSucceeded, bool FinalNameExists);
    private sealed class OwnedDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("arcforges-stage-suspension-");
        internal OwnedDirectory() => File.WriteAllText(System.IO.Path.Combine(Path, "owned-parent.marker"), "owned fixture");
        internal string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
