// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Core.Tests;

public sealed partial class LaunchFaultTests
{
    /// <summary>
    /// MR-102: the running command's final nonzero exit and empty job end the attempt before its process object is signaled.
    /// Holding the real root's EXIT_PROCESS debug event reproduces delayed run-down without CPU starvation. The root ignores
    /// CTRL_BREAK so the forced phase terminates it, and has actually executed before the hold, exercising the root wait.
    /// </summary>
    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    [SupportedOSPlatform("windows")]
    public async Task AForcedRootStopDoesNotWaitForItsProcessToRunDownOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows process run-down follows its final exit code and empty job.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var marker = Path.Combine(node.Root, "root.txt");
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "120000", "--on-break", "ignore", "--marker", marker);
        spec.Resources = new ResourceSpec { CancelGraceMs = 0 };
        var id = await Tasks.SubmitAsync(channel, spec);
        var attempt = await Tasks.RunningAsync(channel, id);
        await Tasks.WaitForAsync(() => Tasks.Marker(marker).Any(line => line.Event == "ready"), Tasks.Bound, "the command to execute");
        using var hold = ExitHold.Attach(Tasks.Marker(marker).First(line => line.Event == "ready").Pid, TimeSpan.FromSeconds(30));
        using var job = JobObject.Open(WindowsExecutionPlatform.JobName(IdText.Format(node.Runtime.NodeId.Span), IdText.Format(attempt.AttemptId)));
        Assert.NotNull(job);
        var stopped = Stopwatch.StartNew();
        var response = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "root run-down" }, cancellationToken: Ct);
        Assert.Null(response.Error);

        var task = await Tasks.WaitAsync(channel, id, bound: TimeSpan.FromSeconds(10));
        var toFinal = stopped.Elapsed;
        Assert.False(hold.RanDown, "The task waited for its root's held process object.");
        Assert.True(toFinal < TimeSpan.FromSeconds(5), $"The root exit took {toFinal} to end the task.");
        var files = new AttemptFiles(node.DataRoot, IdText.Format(attempt.AttemptId));
        var exit = ExitRecord.TryRead(files.ExitPath);
        Assert.NotNull(exit);
        Assert.Equal((int)AttemptRunner.TerminatedExitCode, exit.ExitStatus);
        Assert.Empty(exit.LeftoversTerminated);
        Assert.Equal(0, job.Accounting().ActiveProcesses);
        AssertCancelled(task);
        Assert.Equal((int)AttemptRunner.TerminatedExitCode, task.CurrentAttempt.Result.ExitCode);

        TestContext.Current.TestOutputHelper?.WriteLine($"root forced stop: terminal in {toFinal.TotalMilliseconds:F0} ms before run-down");
        hold.Release();
        await hold.Exit.WaitAsync(Tasks.Bound, Ct);
        await hold.WaitForRundownAsync();
    }

    /// <summary>
    /// A successful root must finish closing its resources before the holder starts end steps or writes exit.json.
    /// A final zero exit code and empty job alone do not authorize the early completion used for stopped roots.
    /// </summary>
    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    [SupportedOSPlatform("windows")]
    public async Task ASuccessfulRootStillWaitsForItsProcessToRunDownOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows process run-down follows its final exit code and empty job.");
        string? endMarker = null;
        var steps = new Tasks.FixedSteps(_ => [], _ => [Step("end", endMarker!, 100)]);
        await using var node = await InProcessNode.Create(steps: steps).StartAsync();
        endMarker = Path.Combine(node.Root, "end.txt");
        await using var channel = await node.ChannelAsync();
        var marker = Path.Combine(node.Root, "root.txt");
        var go = Path.Combine(node.Root, "go");
        var id = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "120000",
            "--until-file", go, "--marker", marker));
        var attempt = await Tasks.RunningAsync(channel, id);
        await Tasks.WaitForAsync(() => Tasks.Marker(marker).Any(line => line.Event == "ready"), Tasks.Bound, "the command to execute");
        using var hold = ExitHold.Attach(Tasks.Marker(marker).First(line => line.Event == "ready").Pid, TimeSpan.FromSeconds(30));
        await File.WriteAllTextAsync(go, "go", Ct);
        await hold.Exit.WaitAsync(Tasks.Bound, Ct);
        using var job = JobObject.Open(WindowsExecutionPlatform.JobName(IdText.Format(node.Runtime.NodeId.Span), IdText.Format(attempt.AttemptId)));
        Assert.NotNull(job);
        TestContext.Current.TestOutputHelper?.WriteLine($"natural zero: active before emptying {job.Accounting().ActiveProcesses}, members {string.Join(",", job.ProcessIds())}");
        // The windowless console can outlive its root. Empty it while the already exited root's debug event stays held:
        // zero must still await its process object even when both early-completion conditions except the code are met.
        job.Terminate(AttemptRunner.TerminatedExitCode);
        await Tasks.WaitForAsync(() => job.Accounting().ActiveProcesses == 0, Tasks.Bound, "the successful root's job to empty");
        using var root = ProcessInfo.Open(Tasks.Marker(marker).First(line => line.Event == "ready").Pid);
        Assert.NotNull(root);
        Assert.True(Native.GetExitCodeProcess(root, out var code));
        TestContext.Current.TestOutputHelper?.WriteLine($"natural zero after emptying: exit {code}");
        Assert.Equal(0u, code);
        var files = new AttemptFiles(node.DataRoot, IdText.Format(attempt.AttemptId));
        // Give the holder multiple root-check intervals while the exact process object remains unsignaled.
        await Task.Delay(TimeSpan.FromSeconds(2), Ct);
        Assert.False(hold.RanDown);
        Assert.False(File.Exists(endMarker), "The end step started before the successful root finished running down.");
        Assert.False(File.Exists(files.ExitPath), "The holder recorded success before the root finished running down.");
        Assert.Equal(TaskState.Running, (await Tasks.GetAsync(channel, id)).State);
        // The test's TerminateJobObject also blocks new assignments until every terminated process has run down. Only after
        // the early-completion guards above, hold this fixture's holder while releasing the root and resetting the now-empty job.
        // Otherwise that artificial termination can reject the real end step, independently of the successful-root wait under test.
        var holder = ExecutionCleanup.Holders([IdText.Format(attempt.AttemptId)]).Single();
        Suspension.Suspend(holder);
        try
        {
            hold.Release();
            await hold.WaitForRundownAsync();
            job.Terminate(AttemptRunner.TerminatedExitCode);
        }
        finally
        {
            Suspension.Resume(holder);
        }
        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, id)).State);
        Assert.Contains(Tasks.Marker(endMarker), line => line.Event == "ready");
    }
}
