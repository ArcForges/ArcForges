// SPDX-License-Identifier: AGPL-3.0-only
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
        var handle = harness.Launch([TestPrograms.TestLoad, "hold", "--hold-ms", "120000"],
            new ContainerLimits { CommitLimitBytes = 384 * MiB, CommitNotificationBytes = OwnNotification });
        await handle.Started.WaitAsync(bound, cancellation);
        var received = new TaskCompletionSource<(uint Message, int Pid)>(TaskCreationOptions.RunContinuationsAsynchronously);
        handle.MemoryLimitMessageObserved = (message, pid) =>
        {
            if (message is Native.JobMsgJobMemoryLimit or Native.JobMsgProcessMemoryLimit)
            {
                received.TrySetResult((message, pid));
            }
        };
        using var nested = JobObject.Create("Local\\ArcForges.Tests.Nested." + Guid.NewGuid().ToString("N"));
        nested.SetLimits(96 * MiB, activeProcessLimit: null, killOnClose: true);
        using var nestedPort = Native.CreateIoCompletionPort(new nint(-1), 0, 0, 1);
        Assert.False(nestedPort.IsInvalid);
        nested.AssociateCompletionPort(nestedPort, 1, clearFirst: false);
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
        for (var attempt = 0; attempt < 4 && !received.Task.IsCompleted; attempt++)
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
                var reported = false;
                var reportWait = System.Diagnostics.Stopwatch.StartNew();
                while (!reported && reportWait.Elapsed < bound)
                {
                    if (Native.GetQueuedCompletionStatus(nestedPort, out var message, out var key, out var data, 1000))
                    {
                        TestContext.Current.TestOutputHelper?.WriteLine($"nested port packet {message}, key {key}, pid {(int)data}");
                        reported = message == Native.JobMsgNewProcess && (int)data == child.ProcessId;
                    }
                }

                Assert.True(reported, "The real nested job must report the suspended child before allocation begins.");
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
                await received.Task.WaitAsync(TimeSpan.FromMilliseconds(500), cancellation);
            }
            catch (TimeoutException)
            {
                // A new bounded allocation is the next real event opportunity; no test or product retry policy is changed.
            }
        }

        Assert.True(allEnded, "The test's own child process was left running.");
        var packet = await received.Task.WaitAsync(bound, cancellation);
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
