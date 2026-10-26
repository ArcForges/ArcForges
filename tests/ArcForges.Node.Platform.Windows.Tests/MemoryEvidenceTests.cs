// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Runtime.Versioning;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>Only the attempt's own job evidence can turn a real memory packet into MemoryLimitHit (MR-18).</summary>
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class MemoryEvidenceTests
{
    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task ARealNestedJobLimitPacketDoesNotAttributeItsLimitToTheAttempt()
    {
        var cancellation = TestContext.Current.CancellationToken;
        cancellation.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows nested job memory messages.");
        var bound = TimeSpan.FromSeconds(30);
        const long MiB = 1024 * 1024;
        const long OwnNotification = 256 * MiB;
        using var harness = PlatformHarness.Start();
        var packets = new ConcurrentQueue<(uint Message, nuint Key, int Pid)>();
        var rawMemory = new TaskCompletionSource<(uint Message, nuint Key, int Pid)>(TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Platform.JobMessageObserved = (message, key, pid) =>
        {
            packets.Enqueue((message, key, pid));
            if (message is Native.JobMsgJobMemoryLimit or Native.JobMsgProcessMemoryLimit)
            {
                rawMemory.TrySetResult((message, key, pid));
            }
        };
        var handle = harness.Launch([TestPrograms.TestLoad, "hold", "--hold-ms", "120000"],
            new ContainerLimits { CommitLimitBytes = 384 * MiB, CommitNotificationBytes = OwnNotification });
        var root = await handle.Started.WaitAsync(bound, cancellation);
        Assert.NotNull(root);
        PlatformHarness.WaitFor(() => packets.Any(p => p.Message == Native.JobMsgNewProcess && p.Pid == root.Pid), bound,
            "the real root process completion key");
        var attemptKey = packets.First(p => p.Message == Native.JobMsgNewProcess && p.Pid == root.Pid).Key;
        using var nested = JobObject.Create("Local\\ArcForges.Tests.Nested." + Guid.NewGuid().ToString("N"));
        nested.SetLimits(96 * MiB, activeProcessLimit: null, killOnClose: true);
        // A real common port makes the best-effort forwarding case deterministic for the attribution handler.
        // The operating system generates every packet; nothing is posted or passed to the handler by this test.
        nested.AssociateCompletionPort(harness.Platform.JobCompletionPort, attemptKey, clearFirst: false);
        var environment = new List<string>
        {
            "DOTNET_GCHeapHardLimit=C0000000",
            "SystemRoot=" + Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "TEMP=" + harness.Root,
            "TMP=" + harness.Root,
        };
        foreach (var name in new[] { "DOTNET_ROOT", "DOTNET_ROOT_X64" })
        {
            if (Environment.GetEnvironmentVariable(name) is { Length: > 0 } value)
            {
                environment.Add(name + "=" + value);
            }
        }

        var allEnded = true;
        // Hard-limit packets are best effort (V-W03). This bounded workload provides up to four real packet opportunities;
        // success still requires observing one actual hard-limit packet, never a synthetic signal or an unobserved pass.
        for (var attempt = 0; attempt < 4 && !rawMemory.Task.IsCompleted; attempt++)
        {
            using var child = ProcessLauncher.Start(new LaunchOptions
            {
                Application = TestPrograms.TestLoad,
                CommandLine = WindowsCommandLine.Build([TestPrograms.TestLoad, "mem-ramp", "--target-mb", "512", "--step-mb", "16"]),
                WorkingDirectory = harness.Root,
                Environment = environment,
                Flags = Native.CreateSuspended | Native.CreateNoWindow,
            });
            try
            {
                harness.Platform.RootJob!.Assign(child.Process);
                handle.Job.Assign(child.Process);
                nested.Assign(child.Process);
                Assert.True(nested.Contains(child.Process));
                Assert.True(handle.Job.Contains(child.Process));
                PlatformHarness.WaitFor(() => packets.Any(p => p.Message == Native.JobMsgNewProcess && p.Pid == child.ProcessId),
                    bound, "the suspended child's real process packet before allocation");
                child.Resume();
                harness.Track(handle);
                Assert.True(child.WaitForExit(bound), "The constrained child must exit within the workload bound.");
                Assert.NotEqual(0u, child.ExitCode);
                TestContext.Current.TestOutputHelper?.WriteLine(
                    $"child {child.ProcessId}, exit {child.ExitCode}, nested peak {nested.Accounting().PeakJobMemory}, attempt peak {handle.Job.Accounting().PeakJobMemory}");
            }
            finally
            {
                if (!child.WaitForExit(TimeSpan.Zero))
                {
                    child.Kill(1);
                    allEnded &= child.WaitForExit(bound);
                }
            }

            try
            {
                await rawMemory.Task.WaitAsync(TimeSpan.FromMilliseconds(500), cancellation);
            }
            catch (TimeoutException)
            {
                // A new bounded allocation is the next real event opportunity; no test or product retry policy is changed.
            }
        }

        Assert.True(allEnded, "The test's own child process was left running.");
        foreach (var item in packets)
        {
            TestContext.Current.TestOutputHelper?.WriteLine($"parent raw packet {item.Message}, key {item.Key}, pid {item.Pid}, attempt key {attemptKey}");
        }

        var packet = await rawMemory.Task.WaitAsync(bound, cancellation);
        TestContext.Current.TestOutputHelper?.WriteLine($"raw hard packet {packet.Message}, key {packet.Key}, pid {packet.Pid}");
        Assert.Contains(packet.Message, new[] { Native.JobMsgJobMemoryLimit, Native.JobMsgProcessMemoryLimit });
        Assert.True(nested.Accounting().PeakJobMemory > 0);
        Assert.True(handle.Job.Accounting().PeakJobMemory < OwnNotification,
            "The attempt must never cross its own notification threshold.");
        Assert.DoesNotContain("job_memory", handle.Job.LimitViolations());
        TestContext.Current.TestOutputHelper?.WriteLine(
            $"actual packet {packet.Message}, pid {packet.Pid}, own notification {OwnNotification}, own hit {handle.MemoryLimitHit}");
        Assert.False(handle.MemoryLimitHit, "A nested job's real hard-limit message must not blame the attempt's own limit.");
    }
}
