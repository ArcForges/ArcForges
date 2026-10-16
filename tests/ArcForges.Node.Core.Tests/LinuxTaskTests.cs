// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using ArcForges.Tests;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Linux execution through the node with real transient units of the user manager (env=linux-real; AD-0005 Linux; 04 sections 3, 6, 7
/// and 9): timeouts and CPU-time limits (R-EXE-007), the cancellation sequence with the task's stop signal (R-EXE-006), the output limit
/// under TERMINATE (the unit frozen before it is killed) and NOTIFY (R-STOR-009), memory bounds in the mem-ramp scenario (R-RES-014),
/// launch steps inside the unit before the command and end steps as ExecStop with SPAWN_FAILED for a failing launch step (L-13),
/// <c>kill_with_node</c>, recovery after a node restart (R-EXE-008, R-EXE-018), STREAM stdin, and the observe-only and partial modes that
/// refuse tasks requiring enforcement and label the others (R-RES-008). Each node has its own slice.
/// </summary>
[Trait("env", "linux-real")]
[Collection(SerialNodeTests.Name)]
[SupportedOSPlatform("linux")]
public sealed class LinuxTaskTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RequireUnits() => Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);

    [Fact(Timeout = 120_000)]
    public async Task ATimeoutAndACpuTimeLimitStopTheTreeWithTheirReasons()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var pids = Path.Combine(node.Root, "pids.txt");
        var timed = Tasks.Argv(node.Root, "/bin/sh", "-c", "sleep 60 & echo $! >> \"$1\"; echo $$ >> \"$1\"; wait", "sh", pids);
        timed.TimeoutMs = 2_000;
        var watch = Stopwatch.StartNew();
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, timed));
        Assert.Equal(TaskState.Failed, task.State);
        Assert.Equal(TerminationReason.TimedOut, task.CurrentAttempt.Result.TerminationReason);
        Assert.Equal(15, task.CurrentAttempt.Result.Signal);
        Assert.False(task.CurrentAttempt.Result.HasExitCode);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(15), $"The timeout took {watch.Elapsed}.");
        Assert.All(File.ReadAllLines(pids), pid => Assert.False(Directory.Exists("/proc/" + pid), $"Process {pid} survived."));

        var cpu = Tasks.Argv(node.Root, Tasks.TestLoad, "cpu", "--threads", "2", "--iterations", "20000000000");
        cpu.CpuTimeLimitMs = 1_500;
        var cpuTask = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, cpu));
        Assert.Equal(TerminationReason.CpuTimeExceeded, cpuTask.CurrentAttempt.Result.TerminationReason);
        Assert.True(cpuTask.CurrentAttempt.Usage.CpuTimeMs >= 1_500);
    }

    [Fact(Timeout = 120_000)]
    public async Task CancellationSignalsEveryProcessWithTheStopSignalThenForcesATreeThatIgnoresIt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();

        // A tree that ignores the stop signal: the graceful phase reaches every process, the forced phase ends them after the grace.
        var pids = Path.Combine(node.Root, "stubborn.txt");
        var spec = Tasks.Argv(node.Root, "/bin/sh", "-c", "trap '' INT TERM; sleep 60 & echo $! >> \"$1\"; echo $$ >> \"$1\"; wait", "sh", pids);
        spec.Resources = new ResourceSpec { CancelGraceMs = 1_000, StopSignal = "SIGINT" };
        var taskId = await Tasks.SubmitAsync(channel, spec);
        await Tasks.RunningAsync(channel, taskId);
        await Tasks.WaitForAsync(() => File.Exists(pids) && File.ReadAllLines(pids).Length == 2, Tasks.Bound, "the tree");
        await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId, Reason = "test" }, cancellationToken: Ct);
        var task = await Tasks.WaitAsync(channel, taskId);
        Assert.Equal(TaskState.Cancelled, task.State);
        Assert.Equal(TerminationReason.Cancelled, task.CurrentAttempt.Result.TerminationReason);
        Assert.Contains("SIGINT sent to every process", task.CurrentAttempt.Result.Detail, StringComparison.Ordinal);
        Assert.Equal(9, task.CurrentAttempt.Result.Signal);
        Assert.All(File.ReadAllLines(pids), pid => Assert.False(Directory.Exists("/proc/" + pid), $"Process {pid} survived."));

        // A tree that ends on the stop signal ends in the graceful phase.
        var marker = Path.Combine(node.Root, "polite.txt");
        var polite = Tasks.Argv(node.Root, "/bin/sh", "-c", "trap 'echo int > \"$1\"; exit 7' INT; sleep 60 & wait", "sh", marker);
        polite.Resources = new ResourceSpec { StopSignal = "SIGINT" };
        var politeId = await Tasks.SubmitAsync(channel, polite);
        await Tasks.RunningAsync(channel, politeId);
        await Task.Delay(300, Ct);
        await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = politeId }, cancellationToken: Ct);
        var ended = await Tasks.WaitAsync(channel, politeId);
        Assert.Equal(TaskState.Cancelled, ended.State);
        Assert.Equal(7, ended.CurrentAttempt.Result.ExitCode);
        Assert.Equal("int", File.ReadAllText(marker).Trim());
    }

    [Fact(Timeout = 120_000)]
    public async Task OutputBeyondTheLimitFreezesAndStopsTheAttemptAtOnceWithinTheStatedBound()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
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
        Assert.True(output - Limit <= Rate / 2, $"The overshoot {output - Limit} exceeds the rate over 500 ms ({Rate / 2}).");

        // 04 section 6 step 4: the unit was frozen before its processes were killed.
        var stop = LogEvents(node, "execution.limit_stop").Single();
        Assert.Contains("frozen at", stop.GetProperty("fields").GetProperty("stop").GetString(), StringComparison.Ordinal);
        Assert.StartsWith("arcforges-a-", stop.GetProperty("fields").GetProperty("container").GetString(), StringComparison.Ordinal);
    }

    [Fact(Timeout = 120_000)]
    public async Task UnderNotifyTheAttemptContinuesWithAFindingAndKeepsItsOutput()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = await InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy =>
        {
            policy.Storage.MaxAttemptOutputBytes = 1L << 20;
            policy.Storage.DiskLimitAction = DiskLimitAction.Notify;
        })).StartAsync();
        await using var channel = await node.ChannelAsync();
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "output", "--bytes", "3145728", "--rate", "6291456")));
        Assert.Equal(TaskState.Succeeded, task.State);
        Assert.Equal(3_145_728, (await Tasks.ReadAllAsync(channel, task.CurrentAttempt.AttemptId, OutputStream.Stdout)).Length);
        var finding = Assert.Single(node.Runtime.Store.Read(reader => Execution.ExecutionFindings.OpenFor(reader, "attempt", task.CurrentAttempt.AttemptId.Value.Span)));
        Assert.Equal(FindingKind.QuotaExceeded, finding.Kind);
    }

    [Fact(Timeout = 240_000)]
    public async Task NoAttemptOrTheSliceExceedsItsMemoryMaxAndNothingSwapsInTheMemRampScenario()
    {
        // R-RES-014, 15 section 4: the slice's MemoryMax = C_mem - R_mem is a hard bound for managed work alone, attempts are stopped at
        // their own MemoryMax, and MemorySwapMax = swap_allowance (0) keeps managed work out of swap, under saturating managed load.
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        const long Managed = 768L << 20;
        var physical = ArcForges.Node.Platform.Linux.ProcFs.PhysicalMemory();
        await using var node = await InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy =>
        {
            policy.Resources.ReserveMemFixedBytes = (ulong)(physical - Managed);
            policy.Resources.ReserveMemFraction = 0;
        })).StartAsync();
        await using var channel = await node.ChannelAsync();
        var slice = SystemdTestEnvironment.CgroupDirectory(node.Slice)!;
        var sliceMax = long.Parse(File.ReadAllText(Path.Combine(slice, "memory.max")), CultureInfo.InvariantCulture);
        Assert.Equal(Managed - (Managed % Environment.SystemPageSize), sliceMax);
        Assert.Equal("0", File.ReadAllText(Path.Combine(slice, "memory.swap.max")).Trim());

        // Three attempts expecting 400 MiB (MemoryHigh 500 MiB) with 512 MiB ceilings, ramping to 600 MiB each: 1.8 GiB of demand on a
        // 768 MiB slice (the interim admission does not count memory yet, AF-SCHED-01). The .NET workload's own heap limit (75% of its
        // cgroup's) is lifted to 3 GiB (hex without 0x, the form both the JIT runtime and Native AOT accept), so the kernel bounds stop it.
        var ids = new List<Id>();
        for (var index = 0; index < 3; index++)
        {
            var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "mem-ramp", "--target-mb", "600", "--step-mb", "16", "--step-ms", "20", "--hold-ms", "3000");
            spec.Environment.Set["DOTNET_GCHeapHardLimit"] = "C0000000";
            spec.Resources = new ResourceSpec { Hint = new ResourceDemand { MemExpectedBytes = 400L << 20, MemCeilingBytes = 512L << 20 } };
            ids.Add(await Tasks.SubmitAsync(channel, spec));
        }

        long sliceCurrent = 0, sliceSwap = 0;
        using var sampling = new CancellationTokenSource();
        var sampler = Task.Run(async () =>
        {
            while (!sampling.IsCancellationRequested)
            {
                sliceCurrent = Math.Max(sliceCurrent, Number(Path.Combine(slice, "memory.current")));
                sliceSwap = Math.Max(sliceSwap, Number(Path.Combine(slice, "memory.swap.current")));
                await Task.Delay(20, CancellationToken.None);
            }
        }, CancellationToken.None);
        var results = new List<ManagedTask>();
        foreach (var id in ids)
        {
            results.Add(await Tasks.WaitAsync(channel, id, bound: TimeSpan.FromSeconds(120)));
        }

        await sampling.CancelAsync();
        await sampler;
        var peak = Number(Path.Combine(slice, "memory.peak"));
        var swapPeak = Number(Path.Combine(slice, "memory.swap.peak"));
        var events = File.ReadAllText(Path.Combine(slice, "memory.events"));
        TestContext.Current.TestOutputHelper?.WriteLine($"slice max {sliceMax}, peak {peak}, sampled {sliceCurrent}, swap peak {swapPeak}; {events.ReplaceLineEndings(" ")}; "
            + string.Join("; ", results.Select(task => $"{task.CurrentAttempt.Result.TerminationReason} peak {task.CurrentAttempt.Usage.MemPeakBytes}")));
        Assert.True(peak <= sliceMax, $"The slice peaked at {peak} above its MemoryMax {sliceMax}.");
        Assert.Equal(0, swapPeak);
        Assert.Equal(0, sliceSwap);
        Assert.All(results, task => Assert.True((long)task.CurrentAttempt.Usage.MemPeakBytes <= 512L << 20, $"An attempt peaked at {task.CurrentAttempt.Usage.MemPeakBytes}."));
        Assert.Contains(results, task => task.CurrentAttempt.Result.TerminationReason == TerminationReason.OomKilled);
        Assert.False(node.Exit.IsCompleted, "The node (unmanaged) was not affected.");

        // The node unloads the failed (OOM-killed) units once it recorded them; none stays loaded as failed.
        foreach (var task in results)
        {
            var unit = SystemdTestEnvironment.AttemptUnit(Tasks.Files(node, task.CurrentAttempt.AttemptId).AttemptName);
            await Tasks.WaitForAsync(() => SystemdTestEnvironment.Property(unit, "ActiveState") != "failed", Tasks.Bound, $"{unit} to be unloaded");
        }
    }

    [Fact(Timeout = 180_000)]
    public async Task LaunchStepsRunInTheUnitBeforeTheCommandEndStepsBeforeLeftoversAndAFailingStepIsSpawnFailed()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        var steps = new LabelledSteps(
            files => [Step("synthetic-launch", 30_000, "/bin/sh", "-c", "cat /proc/self/cgroup > \"$1\"; date +%s%N >> \"$1\"; sleep 0.3", "sh", files.Directory + "-launch.txt")],
            files =>
            [
                Step("failing-end", 10_000, "/bin/sh", "-c", "exit 3"),
                Step("synthetic-end", 10_000, "/bin/sh", "-c", "cat /sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/cgroup.procs > \"$1\"; date +%s%N >> \"$1\"", "sh", files.Directory + "-end.txt"),
                Step("slow-end", 30_000, "/bin/sleep", "60"),
            ]);
        await using var node = await InProcessNode.Create(steps: steps).StartAsync();
        await using var channel = await node.ChannelAsync();
        var command = Path.Combine(node.Root, "command.txt");
        var watch = Stopwatch.StartNew();
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel,
            Tasks.Argv(node.Root, "/bin/sh", "-c", "echo $$ > \"$1\"; cat /proc/self/cgroup >> \"$1\"; date +%s%N >> \"$1\"; sleep 60 & echo $! >> \"$1\"; exit 0", "sh", command)));

        // The failing and the slow end step never change the result; the command's exit code is recorded unchanged.
        Assert.Equal(TaskState.Succeeded, task.State);
        Assert.Equal(TerminationReason.Exited, task.CurrentAttempt.Result.TerminationReason);
        Assert.Equal(0, task.CurrentAttempt.Result.ExitCode);
        Assert.Equal(["sleep"], task.CurrentAttempt.Result.LeftoverImages);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(40), $"The attempt took {watch.Elapsed}.");
        var files = Tasks.Files(node, task.CurrentAttempt.AttemptId);
        var launch = File.ReadAllLines(files.Directory + "-launch.txt");
        var root = File.ReadAllLines(command);
        var end = File.ReadAllLines(files.Directory + "-end.txt");

        // The launch step ran in the unit's cgroup, before the command; the command kept the unit's main PID (the recorded root).
        Assert.Equal(root[1], launch[0]);
        Assert.EndsWith("/" + ArcForges.Node.Platform.Linux.LinuxExecutionPlatform.UnitName(files.AttemptName), root[1], StringComparison.Ordinal);
        Assert.True(long.Parse(launch[1], CultureInfo.InvariantCulture) < long.Parse(root[2], CultureInfo.InvariantCulture));
        var recordedRoot = node.Runtime.Store.Read(reader =>
        {
            using var query = reader.CreateCommand("SELECT root_pid FROM attempt WHERE attempt_id = $id;");
            query.Parameters.AddWithValue("$id", task.CurrentAttempt.AttemptId.Value.ToByteArray());
            return Convert.ToInt32(query.ExecuteScalar(), CultureInfo.InvariantCulture);
        });
        Assert.Equal(recordedRoot.ToString(CultureInfo.InvariantCulture), root[0]);

        // The end step ran after the command exited and saw the leftover still running (ExecStop before the remaining processes stop).
        Assert.Contains(root[3], end);
        Assert.True(long.Parse(end[^1], CultureInfo.InvariantCulture) > long.Parse(root[2], CultureInfo.InvariantCulture));

        // A failing launch step: SPAWN_FAILED (effect DID_NOT_HAPPEN) with the step's error; the command never ran.
        File.Delete(command);
        var spec = Tasks.Argv(node.Root, "/bin/sh", "-c", "echo ran > \"$1\"", "sh", command);
        spec.Labels["test-launch"] = "fail";
        var flagged = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, spec));
        Assert.Equal(TaskState.Failed, flagged.State);
        Assert.Equal(TerminationReason.SpawnFailed, flagged.CurrentAttempt.Result.TerminationReason);
        Assert.Equal(EffectCertainty.DidNotHappen, flagged.CurrentAttempt.Result.Effect);
        Assert.Contains("failing-launch", flagged.CurrentAttempt.Result.Detail, StringComparison.Ordinal);
        Assert.False(File.Exists(command));
    }

    [Fact(Timeout = 120_000)]
    public async Task AKillWithNodeTaskEndsWithTheNode()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = await InProcessNode.Create().StartAsync();
        Id taskId;
        var pids = Path.Combine(node.Root, "pids.txt");
        await using (var channel = await node.ChannelAsync())
        {
            var spec = Tasks.Argv(node.Root, "/bin/sh", "-c", "echo $$ > \"$1\"; exec sleep 60", "sh", pids);
            spec.Resources = new ResourceSpec { KillWithNode = true };
            taskId = await Tasks.SubmitAsync(channel, spec);
            await Tasks.RunningAsync(channel, taskId);
            await Tasks.WaitForAsync(() => File.Exists(pids), Tasks.Bound, "the attempt");
        }

        await node.StopAsync();
        var pid = File.ReadAllText(pids).Trim();
        Assert.False(Directory.Exists("/proc/" + pid), "A kill_with_node attempt does not outlive the node.");
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
        RequireUnits();
        await using var node = await InProcessNode.Create().StartAsync();
        Id longId, shortId;
        var longPid = Path.Combine(node.Root, "long.txt");
        await using (var channel = await node.ChannelAsync())
        {
            longId = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, "/bin/sh", "-c", "echo $$ > \"$1\"; echo before; sleep 2; echo while-down; exec sleep 60", "sh", longPid));
            shortId = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, "/bin/sh", "-c", "sleep 2; echo done; exit 5"));
            await Tasks.RunningAsync(channel, longId);
            await Tasks.RunningAsync(channel, shortId);
        }

        await node.StopAsync();
        await Task.Delay(TimeSpan.FromSeconds(4), Ct);
        var pid = File.ReadAllText(longPid).Trim();
        Assert.True(Directory.Exists("/proc/" + pid), "The attempt survived the node.");
        await node.StartAsync();
        await using var after = await node.ChannelAsync();
        var shortTask = await Tasks.WaitAsync(after, shortId);
        Assert.Equal(5, shortTask.CurrentAttempt.Result.ExitCode);
        Assert.True(shortTask.CurrentAttempt.NodeGap);
        Assert.Equal("done\n", System.Text.Encoding.UTF8.GetString(await Tasks.ReadAllAsync(after, shortTask.CurrentAttempt.AttemptId, OutputStream.Stdout)));

        var running = await Tasks.GetAsync(after, longId);
        Assert.Equal(TaskState.Running, running.State);
        Assert.True(running.CurrentAttempt.NodeGap);
        await Tasks.WaitForAsync(() => File.Exists(Tasks.Files(node, running.CurrentAttempt.AttemptId).StdoutPath), Tasks.Bound, "the output");
        await after.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = longId }, cancellationToken: Ct);
        var cancelled = await Tasks.WaitAsync(after, longId);
        Assert.Equal(TaskState.Cancelled, cancelled.State);
        Assert.True(cancelled.CurrentAttempt.Usage.MemPeakBytes > 0);
        Assert.Equal("before\nwhile-down\n", System.Text.Encoding.UTF8.GetString(await Tasks.ReadAllAsync(after, cancelled.CurrentAttempt.AttemptId, OutputStream.Stdout)));
        Assert.False(Directory.Exists("/proc/" + pid));
    }

    [Fact(Timeout = 120_000)]
    public async Task StreamStdinReachesTheCommandThroughThePipe()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var bytes = Tasks.Argv(node.Root, "/bin/cat");
        bytes.Stdin = new StdinSpec { Mode = StdinMode.Bytes, Data = Tasks.Bytes("from bytes") };
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, bytes));
        Assert.Equal("from bytes", System.Text.Encoding.UTF8.GetString(await Tasks.ReadAllAsync(channel, task.CurrentAttempt.AttemptId, OutputStream.Stdout)));
        var none = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, "/bin/cat")));
        Assert.Equal(TaskState.Succeeded, none.State);
    }

    [Fact(Timeout = 120_000)]
    public async Task WithoutAUserManagerTasksRequiringEnforcementAreRefusedAndOthersRunLabelledUnenforced()
    {
        // R-RES-008, AD-0005 Linux section 4, simulated as the design allows: the node is configured with a user manager address where
        // nothing listens, so it runs as on a host without a user manager.
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux.");
        var node = InProcessNode.Create();
        node.SystemdAddress = "unix:path=" + Path.Combine(node.Root, "no-user-manager");
        await using (node)
        {
            await node.StartAsync();
            await using var channel = await node.ChannelAsync();
            Assert.Equal(NodeLifecycleState.Degraded, node.Runtime.Lifecycle.State);
            Assert.Equal(CpuControl.ObserveOnly, node.Runtime.Capabilities.Cpu);
            Assert.Contains("cannot be reached", node.Runtime.Capabilities.MemoryReason, StringComparison.Ordinal);
            Assert.False(node.Runtime.Capabilities.RestartSurvival);

            var required = Tasks.Argv(node.Root, "/bin/true");
            required.Resources = new ResourceSpec();
            required.Resources.RequireEnforcement.Add(EnforcedResource.Memory);
            var refused = await Tasks.SubmitRawAsync(channel, required);
            Assert.Equal(ErrorCategory.Resource, refused.Error.Category);
            Assert.Equal("enforcement_unavailable", refused.Error.Code);

            var plain = await Tasks.SubmitRawAsync(channel, Tasks.Argv(node.Root, "/bin/sh", "-c", "echo plain; exit 4"));
            Assert.Null(plain.Error);
            Assert.Contains(plain.Value.Warnings, warning => warning.Contains("unenforced", StringComparison.Ordinal));
            var task = await Tasks.WaitAsync(channel, plain.Value.TaskId);
            Assert.Equal(4, task.CurrentAttempt.Result.ExitCode);
            Assert.True(task.CurrentAttempt.Unenforced);
            Assert.StartsWith("pgid:", node.Runtime.Store.Read(reader =>
            {
                using var query = reader.CreateCommand("SELECT container_name FROM attempt;");
                return (string)query.ExecuteScalar()!;
            }), StringComparison.Ordinal);
        }

        // allow_unenforced = false refuses every task while enforcement is missing.
        var strict = InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy => policy.Resources.AllowUnenforced = false));
        strict.SystemdAddress = "unix:path=" + Path.Combine(strict.Root, "no-user-manager");
        await using (strict)
        {
            await strict.StartAsync();
            await using var channel = await strict.ChannelAsync();
            var refused = await Tasks.SubmitRawAsync(channel, Tasks.Argv(strict.Root, "/bin/true"));
            Assert.Equal("enforcement_unavailable", refused.Error.Code);
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task WithoutMemoryDelegationMemoryIsObserveOnlyAndRequiringItIsRefused()
    {
        // A user manager whose delegation lacks the memory controller (simulated: the node treats only cpu and pids as delegated).
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        var node = InProcessNode.Create();
        node.LinuxControllers = ["cpu", "pids"];
        await using (node)
        {
            await node.StartAsync();
            await using var channel = await node.ChannelAsync();
            var capabilities = node.Runtime.Capabilities;
            Assert.Equal(NodeLifecycleState.Degraded, node.Runtime.Lifecycle.State);
            Assert.Equal(CpuControl.EnforcedShareAndCap, capabilities.Cpu);
            Assert.Equal(MemoryControl.ObserveOnly, capabilities.Memory);
            Assert.Contains("no memory delegation", capabilities.MemoryReason, StringComparison.Ordinal);

            var memory = Tasks.Argv(node.Root, "/bin/true");
            memory.Resources = new ResourceSpec();
            memory.Resources.RequireEnforcement.Add(EnforcedResource.Memory);
            Assert.Equal("enforcement_unavailable", (await Tasks.SubmitRawAsync(channel, memory)).Error.Code);

            var cpu = Tasks.Argv(node.Root, "/bin/true");
            cpu.Resources = new ResourceSpec();
            cpu.Resources.RequireEnforcement.Add(EnforcedResource.Cpu);
            var accepted = await Tasks.SubmitRawAsync(channel, cpu);
            Assert.Null(accepted.Error);
            var task = await Tasks.WaitAsync(channel, accepted.Value.TaskId);
            Assert.Equal(TaskState.Succeeded, task.State);
            Assert.True(task.CurrentAttempt.Unenforced);
        }
    }

    /// <summary>Synthetic steps; a task labelled <c>test-launch=fail</c> gets a failing launch step instead.</summary>
    private sealed class LabelledSteps(Func<AttemptFiles, IReadOnlyList<StepSpec>> launch, Func<AttemptFiles, IReadOnlyList<StepSpec>> end) : Execution.ILaunchStepProvider
    {
        public (IReadOnlyList<StepSpec> Launch, IReadOnlyList<StepSpec> End) StepsFor(TaskSpec spec, AttemptFiles files) =>
            spec.Labels.TryGetValue("test-launch", out var mode) && mode == "fail"
                ? ([Step("failing-launch", 30_000, "/bin/sh", "-c", "exit 9")], [])
                : (launch(files), end(files));
    }

    private static StepSpec Step(string name, int timeoutMs, params string[] argv) => new()
    {
        Name = name,
        Application = argv[0],
        Argv = [.. argv],
        TimeoutMs = timeoutMs,
    };

    private static long Number(string path) => File.Exists(path) && long.TryParse(File.ReadAllText(path).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : 0;

    private static List<JsonElement> LogEvents(InProcessNode node, string name)
    {
        var events = new List<JsonElement>();
        var log = Path.Combine(node.DataRoot, "logs", "node", "node.log");
        using var stream = new FileStream(log, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        while (reader.ReadLine() is { } line)
        {
            using var document = JsonDocument.Parse(line);
            if (document.RootElement.GetProperty("event").GetString() == name)
            {
                events.Add(document.RootElement.Clone());
            }
        }

        return events;
    }
}
