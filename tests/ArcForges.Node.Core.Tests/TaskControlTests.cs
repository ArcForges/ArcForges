// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Execution control with a real node, real holders and real processes (env=windows-real): timeouts and CPU-time limits (R-EXE-007),
/// the cancellation sequence (R-EXE-006), the interim global FIFO admission, the output limit under TERMINATE and NOTIFY (R-STOR-009),
/// commit limits in the mem-ramp scenario (R-RES-014), launch and end steps and SPAWN_FAILED, <c>kill_with_node</c>, recovery after a node
/// restart (R-EXE-008, R-EXE-018), LOST after a reboot or a vanished container (R-EXE-009), and <c>cancel_when_caller_gone</c> with
/// <c>ReleaseCallerBinding</c> (R-AI-010).
/// </summary>
[Trait("env", "windows-real")]
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class TaskControlTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 120_000)]
    public async Task ATimeoutAndACpuTimeLimitStopTheTreeWithTheirReasons()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var marker = Path.Combine(node.Root, "timeout.txt");
        var timed = Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "60000", "--child", "same", "--marker", marker);
        timed.TimeoutMs = 2_000;
        var watch = Stopwatch.StartNew();
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, timed));
        Assert.Equal(TaskState.Failed, task.State);
        Assert.Equal(TerminationReason.TimedOut, task.CurrentAttempt.Result.TerminationReason);
        Assert.Equal(3, task.CurrentAttempt.Result.ExitCode);
        // A generous safety bound, not a timing contract (so the test stays in the parallel suites): the 2 s timeout and the stop take a
        // few seconds; the bound only catches a timeout that does not fire (the command holds 60 s).
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(15), $"The timeout took {watch.Elapsed}.");
        Assert.Equal(2, Tasks.Marker(marker).Count(line => line.Event == "break"));

        var cpu = Tasks.Argv(node.Root, Tasks.TestLoad, "cpu", "--threads", "2", "--iterations", "20000000000");
        cpu.CpuTimeLimitMs = 1_500;
        var cpuTask = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, cpu));
        Assert.Equal(TerminationReason.CpuTimeExceeded, cpuTask.CurrentAttempt.Result.TerminationReason);
        Assert.True(cpuTask.CurrentAttempt.Usage.CpuTimeMs >= 1_500);
    }

    [Fact(Timeout = 120_000)]
    public async Task CancellationSignalsGracefullyThenForcesATreeThatIgnoresIt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var marker = Path.Combine(node.Root, "ignore.txt");
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "60000", "--on-break", "ignore", "--child", "same", "--marker", marker);
        spec.Resources = new ResourceSpec { CancelGraceMs = 1_000 };
        var taskId = await Tasks.SubmitAsync(channel, spec);
        await Tasks.RunningAsync(channel, taskId);
        await Tasks.WaitForAsync(() => Tasks.Marker(marker).Count(line => line.Event == "ready") == 2, Tasks.Bound, "the tree");
        var processes = Tasks.Processes(marker);

        var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId, Reason = "test" }, cancellationToken: Ct);
        Assert.Equal(TaskState.Running, cancel.Value.State);
        var task = await Tasks.WaitAsync(channel, taskId);
        Assert.Equal(TaskState.Cancelled, task.State);
        Assert.Equal(TerminationReason.Cancelled, task.CurrentAttempt.Result.TerminationReason);
        Assert.Contains("CTRL_BREAK_EVENT delivered", task.CurrentAttempt.Result.Detail, StringComparison.Ordinal);
        Assert.Equal(2, Tasks.Marker(marker).Count(line => line.Event == "break"));
        Assert.All(processes, process => Assert.False(process.IsRunning(), $"{process} is still running."));

        // Cancelling a terminal task returns its state.
        var again = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.Equal(TaskState.Cancelled, again.Value.State);
    }

    [Fact(Timeout = 180_000)]
    public async Task TasksOfOneOwnerAndClassRunInSubmissionOrderWithinTheGlobalLimit()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy => policy.Resources.GlobalMaxRunning = 2)).StartAsync();
        await using var channel = await node.ChannelAsync();
        var markers = Enumerable.Range(0, 4).Select(index => Path.Combine(node.Root, $"fifo-{index}.txt")).ToList();
        var ids = new List<Id>();
        foreach (var marker in markers)
        {
            ids.Add(await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "1500", "--marker", marker)));
        }

        var queued = await Tasks.GetAsync(channel, ids[3]);
        if (queued.State == TaskState.Queued)
        {
            Assert.Equal("global_limit", queued.Queue.BlockingReason);
            Assert.InRange(queued.Queue.Position, 1u, 4u);
        }

        foreach (var id in ids)
        {
            Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, id)).State);
        }

        var starts = markers.Select(marker => Tasks.Marker(marker).Single(line => line.Event == "ready").At).ToList();
        Assert.True(starts[2] >= Math.Min(starts[0], starts[1]) + 1_000, "The third task waited for a running one to finish.");
        Assert.True(starts[3] >= Math.Min(starts[0], starts[1]) + 1_000, "The fourth task waited for a running one to finish.");
        Assert.True(starts[2] <= starts[3] + 200, "Queued tasks start in submission order.");
    }

    [Fact(Timeout = 120_000)]
    public async Task AQueuedTaskIsCancelledWithoutAnAttempt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy => policy.Resources.GlobalMaxRunning = 1)).StartAsync();
        await using var channel = await node.ChannelAsync();
        var running = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "60000", "--marker", Path.Combine(node.Root, "m.txt")));
        await Tasks.RunningAsync(channel, running);
        var waiting = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "exit 0"));
        var queued = await Tasks.GetAsync(channel, waiting);
        Assert.Equal(TaskState.Queued, queued.State);
        Assert.Equal(1u, queued.Queue.Position);
        var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = waiting }, cancellationToken: Ct);
        Assert.Equal(TaskState.Cancelled, cancel.Value.State);
        Assert.Equal(0u, (await Tasks.GetAsync(channel, waiting)).AttemptCount);
        await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = running }, cancellationToken: Ct);
        Assert.Equal(TaskState.Cancelled, (await Tasks.WaitAsync(channel, running)).State);
    }

    // isolation=exclusive: the overshoot (rate over 500 ms) is a timing bound of the enforcement loop.
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task OutputBeyondTheLimitStopsTheAttemptAtOnceWithinTheStatedBound()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        const long Limit = 2L << 20;
        const long Rate = 8L << 20;
        await using var node = await InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy => policy.Storage.MaxAttemptOutputBytes = Limit)).StartAsync();
        await using var channel = await node.ChannelAsync();
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "output", "--bytes", "67108864", "--rate", Rate.ToString(CultureInfo.InvariantCulture));
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, spec));
        var attempt = task.CurrentAttempt;
        var output = (long)(await Tasks.ReadAllAsync(channel, attempt.AttemptId, OutputStream.Stdout)).Length;
        TestContext.Current.TestOutputHelper?.WriteLine($"limit {Limit}, output {output}, overshoot {output - Limit} bytes at {Rate} B/s");
        Assert.Equal(TaskState.Failed, task.State);
        Assert.Equal(TerminationReason.OutputLimit, attempt.Result.TerminationReason);
        Assert.Equal("NODE", attempt.LimitEnforcedBy);
        Assert.True(output > Limit);

        // The bound: the write rate over one tailer interval (100 ms) plus the stop latency (allowed 400 ms here).
        Assert.True(output - Limit <= Rate / 2, $"The overshoot {output - Limit} exceeds the rate over 500 ms ({Rate / 2}).");
    }

    /// <summary>
    /// Under NOTIFY the attempt runs on and gets one finding, whether an enforcement pass sees the output cross the limit while it runs
    /// (6 MiB/s: about half a second) or the attempt ends before any pass does (unthrottled: the final tail at finalization finds it).
    /// </summary>
    [Theory(Timeout = 120_000)]
    [InlineData(6_291_456)]
    [InlineData(0)]
    public async Task UnderNotifyTheAttemptContinuesWithAFindingAndKeepsItsOutput(int rate)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy =>
        {
            policy.Storage.MaxAttemptOutputBytes = 1L << 20;
            policy.Storage.DiskLimitAction = DiskLimitAction.Notify;
        })).StartAsync();
        await using var channel = await node.ChannelAsync();
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "output", "--bytes", "3145728", "--rate", rate.ToString(System.Globalization.CultureInfo.InvariantCulture))));
        Assert.Equal(TaskState.Succeeded, task.State);
        Assert.Equal(3_145_728, (await Tasks.ReadAllAsync(channel, task.CurrentAttempt.AttemptId, OutputStream.Stdout)).Length);
        var findings = node.Runtime.Store.Read(reader => Execution.ExecutionFindings.OpenFor(reader, "attempt", task.CurrentAttempt.AttemptId.Value.Span));
        var finding = Assert.Single(findings);
        Assert.Equal(FindingKind.QuotaExceeded, finding.Kind);
        Assert.Contains(finding.Evidence, item => item.Name == "detected_by" && item.Value == "NODE");
    }

    /// <summary>
    /// The attempt's commit limit in the mem-ramp scenario, through the node. The root's commit limit is <c>commit_factor x (C_mem - R_mem)</c>
    /// (03 section 5.1), checked here; that it bounds all attempts together is proven with real jobs by the platform test
    /// <c>JobTests.TheRootCommitLimitBoundsAllAttemptsTogether</c>: since admission (AF-SCHED-01) counts against <c>B_mem = C_mem - R_mem -
    /// U_mem</c>, a node whose managed share is shrunk below the machine's unmanaged use admits nothing (<c>exceeds_budget</c>), so a node-level
    /// scenario can no longer push two admitted attempts into a small root.
    /// </summary>
    [Fact(Timeout = 180_000)]
    public async Task NoAttemptExceedsItsCommitLimitInTheMemRampScenario()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows commit limits.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var nodeName = IdText.Format(node.Runtime.NodeId.Span);
        using var root = JobObject.Open(WindowsExecutionPlatform.JobName(nodeName, "root"))!;
        var settings = node.Runtime.Execution!.Settings;
        // The job rounds its limit down to a page.
        var rootLimit = (long)(settings.CommitFactor * settings.ManagedMemory);
        Assert.InRange(root.Limits().JobMemoryLimit, rootLimit - 4095, rootLimit);

        // One attempt with a 128 MiB ceiling: its commit limit is 192 MiB, its notification limit 128 MiB. The workload's heap limit is
        // lifted (hex without 0x, read by the JIT runtime and Native AOT): inside a job the .NET GC would otherwise refuse at 75% of the
        // commit limit (144 MiB) itself, and the job's limit would never be exercised.
        var single = Tasks.Argv(node.Root, Tasks.TestLoad, "mem-ramp", "--target-mb", "512", "--step-mb", "16");
        single.Environment.Set["DOTNET_GCHeapHardLimit"] = "C0000000";
        single.Resources = new ResourceSpec { Hint = new ResourceDemand { MemExpectedBytes = 64L << 20, MemCeilingBytes = 128L << 20 } };
        var singleId = await Tasks.SubmitAsync(channel, single);
        var attempt = await Tasks.RunningAsync(channel, singleId);
        using var job = JobObject.Open(WindowsExecutionPlatform.JobName(nodeName, IdText.Format(attempt.AttemptId)));
        var attemptMax = Sample(job);
        var finished = await Tasks.WaitAsync(channel, singleId);
        Assert.Equal(TerminationReason.MemoryLimit, finished.CurrentAttempt.Result.TerminationReason);
        Assert.True(attemptMax.Max <= 192L << 20, $"The attempt committed {attemptMax.Max}.");

        // The job refused: its peak (which counts the refused request) reached the commit limit, within one 16 MiB step.
        Assert.InRange((long)finished.CurrentAttempt.Usage.MemPeakBytes, (192L - 16) << 20, (192L + 16) << 20);
        attemptMax.Stop();
        TestContext.Current.TestOutputHelper?.WriteLine($"attempt committed at most {attemptMax.Max} of {192L << 20}");
    }

    [Fact(Timeout = 120_000)]
    public async Task LaunchStepsRunBeforeTheRootEndStepsBeforeLeftoversAndAFailingStepIsSpawnFailed()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        var steps = new Tasks.FixedSteps(
            files => files.AttemptName.Length > 0 && File.Exists(Path.Combine(Path.GetTempPath(), "arcforges-fail-" + files.DataRoot.GetHashCode(StringComparison.Ordinal)))
                ? [Step("failing-launch", Tasks.Cmd, "/d", "/c", "exit 9")]
                : [Step("synthetic-launch", Tasks.TestLoad, "signal", "--hold-ms", "500", "--marker", files.Directory + "-launch.txt")],
            files => [Step("synthetic-end", Tasks.TestLoad, "signal", "--hold-ms", "100", "--marker", files.Directory + "-end.txt")]);
        await using var node = await InProcessNode.Create(steps: steps).StartAsync();
        await using var channel = await node.ChannelAsync();
        var marker = Path.Combine(node.Root, "root.txt");
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "200", "--marker", marker)));
        Assert.Equal(TaskState.Succeeded, task.State);
        var files = Tasks.Files(node, task.CurrentAttempt.AttemptId);
        var launch = Tasks.Marker(files.Directory + "-launch.txt").Single();
        var root = Tasks.Marker(marker).Single();
        var end = Tasks.Marker(files.Directory + "-end.txt").Single();
        Assert.True(root.At >= launch.At + 400, "The root started after the launch step.");
        Assert.True(end.At >= root.At + 150, "The end step ran after the root exited.");

        var flag = Path.Combine(Path.GetTempPath(), "arcforges-fail-" + node.DataRoot.GetHashCode(StringComparison.Ordinal));
        File.WriteAllText(flag, "fail");
        try
        {
            var failed = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "200", "--marker", marker)));
            Assert.Equal(TaskState.Failed, failed.State);
            Assert.Equal(TerminationReason.SpawnFailed, failed.CurrentAttempt.Result.TerminationReason);
            Assert.Equal(EffectCertainty.DidNotHappen, failed.CurrentAttempt.Result.Effect);
            Assert.Contains("failing-launch", failed.CurrentAttempt.Result.Detail, StringComparison.Ordinal);
            Assert.Single(Tasks.Marker(marker));
        }
        finally
        {
            File.Delete(flag);
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task AKillWithNodeTaskEndsWithTheNode()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        Id taskId;
        ArcForges.Tests.ProcessIdentity root;
        await using (var channel = await node.ChannelAsync())
        {
            var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "60000", "--marker", Path.Combine(node.Root, "m.txt"));
            spec.Resources = new ResourceSpec { KillWithNode = true };
            taskId = await Tasks.SubmitAsync(channel, spec);
            await Tasks.RunningAsync(channel, taskId);
            root = node.Runtime.Store.Read(reader =>
            {
                using var command = reader.CreateCommand("SELECT root_pid, root_start FROM attempt WHERE task_id = $id;");
                command.Parameters.AddWithValue("$id", taskId.Value.ToByteArray());
                using var rows = command.ExecuteReader();
                Assert.True(rows.Read());
                return ArcForges.Tests.ProcessIdentity.CreatedNoLaterThan(rows.GetInt32(0), ArcForges.Node.Store.StoreTime.FromMicroseconds(rows.GetInt64(1)));
            });
            Assert.Empty(ExecutionCleanup.Holders(InProcessNode.AttemptNames(node.Runtime.Store)));
        }

        await node.StopAsync();
        Assert.False(root.IsRunning(), "A kill_with_node attempt does not outlive the node.");
        await node.StartAsync();
        await using var after = await node.ChannelAsync();
        var task = await Tasks.GetAsync(after, taskId);
        Assert.Equal(TaskState.Cancelled, task.State);
        Assert.Equal(TerminationReason.NodeShutdown, task.CurrentAttempt.Result.TerminationReason);
    }

    [Fact(Timeout = 180_000)]
    public async Task AttemptsSurviveANodeRestartAndAreRecoveredCancelledAndAccounted()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        var longMarker = Path.Combine(node.Root, "long.txt");

        // The short attempt runs until the test writes the go file once the node stopped, so it cannot finish before the stop however
        // slowly the test runs (a fixed 2 s hold raced with it under load).
        var go = Path.Combine(node.Root, "go");
        Id longId, shortId, shortAttempt;
        await using (var channel = await node.ChannelAsync())
        {
            longId = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "120000", "--marker", longMarker));
            shortId = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.WaitForFile(go)));
            await Tasks.RunningAsync(channel, longId);
            shortAttempt = (await Tasks.RunningAsync(channel, shortId)).AttemptId;

            // RUNNING records the root process; its marker follows once the workload started.
            await Tasks.WaitForAsync(() => Tasks.Marker(longMarker).Count > 0, Tasks.Bound, "the workload to start");
        }

        await node.StopAsync();
        File.WriteAllText(go, "go");
        var longProcess = Tasks.Processes(longMarker).Single();
        Assert.True(longProcess.IsRunning(), "The attempt keeps running while the node is stopped.");
        await Tasks.WaitForAsync(() => File.Exists(Tasks.Files(node, shortAttempt).ExitPath), Tasks.Bound, "the short attempt to finish while the node is down, recorded by its holder");

        await node.StartAsync();
        await using var after = await node.ChannelAsync();

        // The attempt that finished while the node was down is finalized from its holder's exit record.
        var finished = await Tasks.WaitAsync(after, shortId);
        Assert.Equal(TaskState.Succeeded, finished.State);
        Assert.True(finished.CurrentAttempt.NodeGap);

        // The running one was re-opened by name through its holder; cancelling it uses the restarted node's handles.
        var running = await Tasks.GetAsync(after, longId);
        Assert.Equal(TaskState.Running, running.State);
        Assert.True(running.CurrentAttempt.NodeGap);
        var cancel = await after.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = longId }, cancellationToken: Ct);
        Assert.Null(cancel.Error);
        var cancelled = await Tasks.WaitAsync(after, longId);
        Assert.Equal(TaskState.Cancelled, cancelled.State);
        Assert.Equal(3, cancelled.CurrentAttempt.Result.ExitCode);
        Assert.True(cancelled.CurrentAttempt.Usage.MemPeakBytes > 0, "The recovered attempt's accounting was read.");
        Assert.False(longProcess.IsRunning());
        var segments = node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM timeline_segment WHERE category = 'node_gap';"));
        Assert.Equal(2L, segments);
        using var logStream = new FileStream(Path.Combine(node.DataRoot, "logs", "node", "node.log"), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var log = new StreamReader(logStream).ReadToEnd();
        Assert.Contains("\"portReassociated\":true", log, StringComparison.Ordinal);
    }

    [Fact(Timeout = 180_000)]
    public async Task AnAttemptOfAnEarlierBootIsLostWithEvidence()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        Id taskId;
        await using (var channel = await node.ChannelAsync())
        {
            taskId = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "120000", "--marker", Path.Combine(node.Root, "m.txt")));
            await Tasks.RunningAsync(channel, taskId);
        }

        await node.StopAsync();

        // A simulated reboot: the store and the attempt record another boot identity than this boot's (AD-0006 section 3).
        using (var store = ArcForges.Node.Store.NodeStore.Open(new ArcForges.Node.Store.NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "previous-boot" }))
        {
            store.Write(transaction => transaction.Execute("UPDATE attempt SET boot_identity = 'previous-boot' WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray())));
        }

        await node.StartAsync();
        await using var after = await node.ChannelAsync();
        var task = await Tasks.GetAsync(after, taskId);
        Assert.Equal(TaskState.Lost, task.State);
        Assert.Equal(TerminationReason.Lost, task.CurrentAttempt.Result.TerminationReason);
        Assert.Equal(EffectCertainty.Unknown, task.CurrentAttempt.Result.Effect);
        Assert.Contains("boot_id_old=previous-boot", task.CurrentAttempt.Result.Detail, StringComparison.Ordinal);
    }

    [Fact(Timeout = 180_000)]
    public async Task AnAttemptWhoseContainerWasDestroyedOutsideTheNodeIsLost()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        var marker = Path.Combine(node.Root, "m.txt");
        Id taskId;
        await using (var channel = await node.ChannelAsync())
        {
            taskId = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "120000", "--marker", marker));
            await Tasks.RunningAsync(channel, taskId);

            // RUNNING records the root process; its marker (which names it) follows once the workload started: under load, later.
            await Tasks.WaitForAsync(() => Tasks.Marker(marker).Count > 0, Tasks.Bound, "the workload to start");
        }

        var holders = ExecutionCleanup.Holders(InProcessNode.AttemptNames(node.Runtime.Store)).ToList();
        Assert.Single(holders);
        await node.StopAsync();

        // The tree is destroyed outside the node: the holder first (so no exit record is written), then the process.
        using (var holder = Process.GetProcessById(holders[0]))
        {
            holder.Kill();
            holder.WaitForExit(5_000);
        }

        using (var root = Process.GetProcessById(Tasks.Marker(marker).Single().Pid))
        {
            root.Kill();
            root.WaitForExit(5_000);
        }

        await node.StartAsync();
        await using var after = await node.ChannelAsync();
        var task = await Tasks.GetAsync(after, taskId);
        Assert.Equal(TaskState.Lost, task.State);
        Assert.StartsWith("container_missing", task.CurrentAttempt.Result.Detail, StringComparison.Ordinal);

        // A LOST task waits for a decision: a manual retry runs it again.
        var retry = await after.Tasks.RetryTaskAsync(new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.Null(retry.Error);
        await Tasks.RunningAsync(after, taskId);
        await after.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId }, cancellationToken: Ct);
        Assert.Equal(TaskState.Cancelled, (await Tasks.WaitAsync(after, taskId)).State);
    }

    [Fact(Timeout = 120_000)]
    public async Task ABindingSurvivesALostConnectionOfALiveCallerAndReleaseIsIdempotent()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows execution platform.");
        await using var node = await InProcessNode.Create().StartAsync();
        Id bound, released;
        await using (var channel = await node.ChannelAsync())
        {
            bound = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "60000", "--marker", Path.Combine(node.Root, "a.txt")), cancelWhenCallerGone: true);
            released = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "60000", "--marker", Path.Combine(node.Root, "b.txt")), cancelWhenCallerGone: true);
            await Tasks.RunningAsync(channel, bound);
            await Tasks.RunningAsync(channel, released);
            var release = await channel.Tasks.ReleaseCallerBindingAsync(new TaskServiceReleaseCallerBindingRequest { Meta = Tasks.Meta(), TaskId = released }, cancellationToken: Ct);
            Assert.Null(release.Error);
            Assert.Equal(TaskState.Running, release.Value.State);
            var twice = await channel.Tasks.ReleaseCallerBindingAsync(new TaskServiceReleaseCallerBindingRequest { Meta = Tasks.Meta(), TaskId = released }, cancellationToken: Ct);
            Assert.Null(twice.Error);
        }

        // The binding is to the caller's process (08 section 4; AD-0006 section 7): this process lost its only connection but is alive
        // (a client reconnecting after a lost connection), so nothing is cancelled. A caller whose process ends is cancelled within 5 s:
        // ExecutionTests.AClientTimeoutHandsOffWithExit124AndAnInterruptBeforeItCancels kills a real CLI process.
        TaskState State(Id id) => (TaskState)node.Runtime.Store.Read(reader => Convert.ToInt32(reader.Scalar("SELECT state FROM task WHERE task_id = $id;", ("$id", id.Value.ToByteArray())), CultureInfo.InvariantCulture));

        // A deliberate hold longer than the 5 s caller-gone window: the absence of a cancellation cannot be awaited.
        await Task.Delay(TimeSpan.FromSeconds(6), Ct);
        Assert.Equal(TaskState.Running, State(bound));
        Assert.Equal(TaskState.Running, State(released));
        await using var after = await node.ChannelAsync();
        foreach (var id in (Id[])[bound, released])
        {
            await after.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id }, cancellationToken: Ct);
            await Tasks.WaitAsync(after, id);
        }
    }

    private static StepSpec Step(string name, params string[] argv) => new()
    {
        Name = name,
        Application = argv[0],
        CommandLine = WindowsCommandLine.Build(argv),
        TimeoutMs = 30_000,
    };

    private static Sampler Sample(JobObject? job) => new(job);

    private sealed class Sampler
    {
        private readonly Thread _thread;
        private volatile bool _stop;

        public Sampler(JobObject? job)
        {
            _thread = new Thread(() =>
            {
                while (!_stop && job is not null)
                {
                    try
                    {
                        Max = Math.Max(Max, job.CurrentCommit());
                    }
                    catch (ObjectDisposedException)
                    {
                        return;
                    }

                    Thread.Sleep(2);
                }
            })
            { IsBackground = true };
            _thread.Start();
        }

        public long Max { get; private set; }

        public void Stop()
        {
            _stop = true;
            _thread.Join();
        }
    }
}
