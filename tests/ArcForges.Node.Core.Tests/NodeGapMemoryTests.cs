// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real NodeHost stop/restart and holder accounting preserve an attempt's own notification crossing (MR-17).</summary>
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class NodeGapMemoryTests
{
    [Theory(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [InlineData(272, 17, 256, true)]
    [InlineData(272, 0, 256, true)]
    [InlineData(16, 17, 256, false)]
    [InlineData(192, 17, 160, true)]
    public async Task ANotificationCrossedWhileTheNodeIsDownIsRecoveredWithItsExitCondition(
        int targetMiB, int exitCode, int notificationMiB, bool crossed)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job accounting and memory notification limits.");
        const long MiB = 1024 * 1024;
        const long InitialNotification = 256 * MiB;
        const long HardLimit = 384 * MiB;
        await using var node = await InProcessNode.Create().StartAsync();
        var go = Path.Combine(node.Root, "memory-go");
        var ready = Path.Combine(node.Root, "memory-ready");
        var script = Path.Combine(node.Root, "memory.cmd");
        var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");
        var wait = string.Create(CultureInfo.InvariantCulture,
            $"[System.IO.File]::WriteAllText('{Escape(ready)}','ready'); while (-not [System.IO.File]::Exists('{Escape(go)}')) {{ Start-Sleep -Milliseconds 20 }}");
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(wait));
        File.WriteAllText(script, "@echo off\r\n"
            + WindowsCommandLine.Build([powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]) + "\r\n"
            + "if errorlevel 1 exit /b 98\r\n"
            + WindowsCommandLine.Build([Tasks.TestLoad, "mem-ramp", "--target-mb", targetMiB.ToString(CultureInfo.InvariantCulture),
                "--step-mb", "16"]) + "\r\n"
            + "if errorlevel 1 exit /b 99\r\n"
            + string.Create(CultureInfo.InvariantCulture, $"exit /b {exitCode}\r\n"));
        Id taskId, attemptId;
        await using (var channel = await node.ChannelAsync())
        {
            var spec = Tasks.Argv(node.Root, script);
            spec.Environment.Set["DOTNET_GCHeapHardLimit"] = "C0000000";
            spec.Resources = new ResourceSpec
            {
                Hint = new ResourceDemand { MemExpectedBytes = 64 * MiB, MemCeilingBytes = InitialNotification },
            };
            taskId = await Tasks.SubmitAsync(channel, spec);
            attemptId = (await Tasks.RunningAsync(channel, taskId)).AttemptId;
            await Tasks.WaitForAsync(() => File.Exists(ready), Tasks.Bound, "the command's pre-ramp gate");
        }

        var nodeName = IdText.Format(node.Runtime.NodeId.Span);
        using var job = JobObject.Open(WindowsExecutionPlatform.JobName(nodeName, IdText.Format(attemptId)))
            ?? throw new InvalidOperationException("The attempt job is missing.");
        Assert.Equal(HardLimit, job.Limits().JobMemoryLimit);
        Assert.True(job.Accounting().PeakJobMemory < Math.Min(InitialNotification, notificationMiB * MiB),
            "The gate alone must not reach either notification threshold.");
        Assert.Equal(0, await node.StopAsync());
        // Exercise the actual current job limit, including a changed value; no holder-spec copy can answer this case.
        job.SetMemoryNotification(notificationMiB * MiB);
        File.WriteAllText(go, "go");
        var files = Tasks.Files(node, attemptId);
        await Tasks.WaitForAsync(() => File.Exists(files.ExitPath), Tasks.Bound, "the holder's exit record while the node is down");
        var exit = Assert.IsType<ExitRecord>(ExitRecord.TryRead(files.ExitPath));
        Assert.Equal(exitCode, exit.ExitStatus);
        Assert.Equal(0, job.Accounting().ActiveProcesses);
        Assert.Equal(0, job.CurrentCommit());
        Assert.DoesNotContain("job_memory", job.LimitViolations());
        Assert.True(exit.MemPeakBytes < HardLimit - (64 * 1024),
            "This case must not be classified by the old near-hard-limit fallback.");
        Assert.Equal(crossed, exit.MemPeakBytes > notificationMiB * MiB);
        if (notificationMiB != 256)
        {
            Assert.True(exit.MemPeakBytes < InitialNotification, "The changed-limit case must stay below the startup threshold.");
        }

        await node.StartAsync();
        await using var after = await node.ChannelAsync();
        var finished = await Tasks.WaitAsync(after, taskId);
        Assert.True(finished.CurrentAttempt.NodeGap);
        Assert.Equal(exitCode == 0 ? TaskState.Succeeded : TaskState.Failed, finished.State);
        Assert.Equal(exitCode, finished.CurrentAttempt.Result.ExitCode);
        Assert.Equal(EffectCertainty.Happened, finished.CurrentAttempt.Result.Effect);
        var expected = crossed && exitCode != 0 ? TerminationReason.MemoryLimit : TerminationReason.Exited;
        Assert.Equal(expected, finished.CurrentAttempt.Result.TerminationReason);
        if (expected == TerminationReason.MemoryLimit)
        {
            Assert.Contains("job_memory", exit.LimitViolations);
        }
        else if (!crossed)
        {
            Assert.DoesNotContain("job_memory", exit.LimitViolations);
        }

        TestContext.Current.TestOutputHelper?.WriteLine(
            $"target {targetMiB} MiB, notification {notificationMiB} MiB, peak {exit.MemPeakBytes}, hard {HardLimit}, exit {exitCode}, recovered {expected}");
    }

    private static string Escape(string path) => path.Replace("'", "''", StringComparison.Ordinal);
}
