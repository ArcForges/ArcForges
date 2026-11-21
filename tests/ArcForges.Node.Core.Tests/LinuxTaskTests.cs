// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Tests;

namespace ArcForges.Node.Core.Tests;

/// <summary>Linux host capability and data root checks, and retained legacy Attempt control scenarios.</summary>
[Trait("env", "linux-real")]
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
        // A generous safety bound, not a timing contract (so the test stays in the parallel suites): the 2 s timeout and the stop take a
        // few seconds; the bound only catches a timeout that does not fire (the command holds 60 s).
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
        var trapped = Path.Combine(node.Root, "trapped.txt");
        var polite = Tasks.Argv(node.Root, "/bin/sh", "-c", "trap 'echo int > \"$1\"; exit 7' INT; echo trapped > \"$2\"; sleep 60 & wait", "sh", marker, trapped);
        polite.Resources = new ResourceSpec { StopSignal = "SIGINT" };
        var politeId = await Tasks.SubmitAsync(channel, polite);
        await Tasks.RunningAsync(channel, politeId);
        await Tasks.WaitForAsync(() => File.Exists(trapped), Tasks.Bound, "the shell to install its trap");
        await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = politeId }, cancellationToken: Ct);
        var ended = await Tasks.WaitAsync(channel, politeId);
        Assert.Equal(TaskState.Cancelled, ended.State);
        Assert.Equal(7, ended.CurrentAttempt.Result.ExitCode);
        Assert.Equal("int", File.ReadAllText(marker).Trim());
    }

    // isolation=exclusive: the overshoot (rate over 500 ms) is a timing bound of the enforcement loop.
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
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
        RequireUnits();
        await using var node = await InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy =>
        {
            policy.Storage.MaxAttemptOutputBytes = 1L << 20;
            policy.Storage.DiskLimitAction = DiskLimitAction.Notify;
        })).StartAsync();
        await using var channel = await node.ChannelAsync();
        var task = await Tasks.WaitAsync(channel, await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, Tasks.TestLoad, "output", "--bytes", "3145728", "--rate", rate.ToString(System.Globalization.CultureInfo.InvariantCulture))));
        Assert.Equal(TaskState.Succeeded, task.State);
        Assert.Equal(3_145_728, (await Tasks.ReadAllAsync(channel, task.CurrentAttempt.AttemptId, OutputStream.Stdout)).Length);
        var finding = Assert.Single(node.Runtime.Store.Read(reader => Execution.ExecutionFindings.OpenFor(reader, "attempt", task.CurrentAttempt.AttemptId.Value.Span)));
        Assert.Equal(FindingKind.QuotaExceeded, finding.Kind);
    }

    [Fact(Timeout = 120_000)]
    public async Task AnInMemoryDataRootIsReportedAndADiskOneIsNot()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // tmpfs (/dev/shm, and /tmp in WSL Debian) keeps captured output in memory charged to the attempts: a capability fact and a log
        // warning say so; a disk-backed root (the test binaries' directory) reports "disk".
        Assert.SkipUnless(OperatingSystem.IsLinux() && Directory.Exists("/dev/shm"), "Linux tmpfs.");
        Assert.Equal("tmpfs", Core.Platform.MemoryFileSystems.KindOf("/dev/shm"));
        Assert.Null(Core.Platform.MemoryFileSystems.KindOf(AppContext.BaseDirectory));
        TestContext.Current.TestOutputHelper?.WriteLine($"/tmp: {Core.Platform.MemoryFileSystems.KindOf("/tmp") ?? "disk"}");

        await using (var inMemory = await InProcessNode.Create(parent: "/dev/shm").StartAsync())
        {
            var fact = inMemory.Runtime.Capabilities.PlatformFacts.Single(item => item.Name == "data_root_filesystem").Value;
            Assert.StartsWith("tmpfs (" + inMemory.DataRoot + ")", fact, StringComparison.Ordinal);
            Assert.Contains("node.data_root_in_memory", File.ReadAllText(Path.Combine(inMemory.DataRoot, "logs", "node", "node.log")), StringComparison.Ordinal);
        }

        await using var onDisk = await InProcessNode.Create(parent: AppContext.BaseDirectory).StartAsync();
        Assert.Equal("disk", onDisk.Runtime.Capabilities.PlatformFacts.Single(item => item.Name == "data_root_filesystem").Value);
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
        Id longId, shortId, longAttempt, shortAttempt;
        var longPid = Path.Combine(node.Root, "long.txt");

        // Both attempts wait for the go file the test writes once the node stopped, so neither can finish before the stop.
        var go = Path.Combine(node.Root, "go");
        await using (var channel = await node.ChannelAsync())
        {
            longId = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, "/bin/sh", "-c",
                "echo $$ > \"$1\"; echo before; while [ ! -e \"$2\" ]; do sleep 0.05; done; echo while-down; exec sleep 60", "sh", longPid, go));
            shortId = await Tasks.SubmitAsync(channel, Tasks.Argv(node.Root, "/bin/sh", "-c", "while [ ! -e \"$1\" ]; do sleep 0.05; done; echo done; exit 5", "sh", go));
            longAttempt = (await Tasks.RunningAsync(channel, longId)).AttemptId;
            shortAttempt = (await Tasks.RunningAsync(channel, shortId)).AttemptId;
        }

        // While the node is down the short attempt ends with a durable exit record, and the long one keeps running (its next line).
        await node.StopAsync();
        File.WriteAllText(go, "go");
        await Tasks.WaitForAsync(() => File.Exists(Tasks.Files(node, shortAttempt).ExitPath)
            && Tasks.ReadShared(Tasks.Files(node, longAttempt).StdoutPath).Contains("while-down", StringComparison.Ordinal), Tasks.Bound, "the attempts to progress while the node is down");
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
    public async Task WithoutAUserManagerTheNodeIsDegradedAndRefusesFreshLegacyTasks()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux.");
        var node = InProcessNode.Create();
        node.SystemdAddress = "unix:path=" + Path.Combine(node.Root, "no-user-manager");
        await using (node)
        {
            await node.StartAsync();
            await using var channel = await node.ChannelAsync(helloAsHuman: true);
            Assert.Equal(NodeLifecycleState.Degraded, node.Runtime.Lifecycle.State);
            Assert.Equal(CpuControl.ObserveOnly, node.Runtime.Capabilities.Cpu);
            Assert.Contains("cannot be reached", node.Runtime.Capabilities.MemoryReason, StringComparison.Ordinal);
            Assert.False(node.Runtime.Capabilities.RestartSurvival);

            await AssertFreshLegacyTaskRefusedAsync(node, channel, EnforcedResource.Memory);
            await AssertFreshLegacyTaskRefusedAsync(node, channel);
        }

        var strict = InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy => policy.Resources.AllowUnenforced = false));
        strict.SystemdAddress = "unix:path=" + Path.Combine(strict.Root, "no-user-manager");
        await using (strict)
        {
            await strict.StartAsync();
            await using var channel = await strict.ChannelAsync(helloAsHuman: true);
            await AssertFreshLegacyTaskRefusedAsync(strict, channel);
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task WithoutMemoryDelegationMemoryIsObserveOnlyAndFreshLegacyTasksAreRefused()
    {
        // A user manager whose delegation lacks the memory controller (simulated: the node treats only cpu and pids as delegated).
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        var node = InProcessNode.Create();
        node.LinuxControllers = ["cpu", "pids"];
        await using (node)
        {
            await node.StartAsync();
            await using var channel = await node.ChannelAsync(helloAsHuman: true);
            var capabilities = node.Runtime.Capabilities;
            Assert.Equal(NodeLifecycleState.Degraded, node.Runtime.Lifecycle.State);
            Assert.Equal(CpuControl.EnforcedShareAndCap, capabilities.Cpu);
            Assert.Equal(MemoryControl.ObserveOnly, capabilities.Memory);
            Assert.Contains("no memory delegation", capabilities.MemoryReason, StringComparison.Ordinal);

            await AssertFreshLegacyTaskRefusedAsync(node, channel, EnforcedResource.Memory);
            await AssertFreshLegacyTaskRefusedAsync(node, channel, EnforcedResource.Cpu);
        }
    }

    private static async Task AssertFreshLegacyTaskRefusedAsync(InProcessNode node, NodeChannel channel, EnforcedResource? required = null)
    {
        var spec = Tasks.Argv(node.Root, Path.Combine(node.Root, "missing-legacy-fixture-program"));
        if (required is { } resource)
        {
            spec.Resources = new ResourceSpec();
            spec.Resources.RequireEnforcement.Add(resource);
        }

        var response = await Tasks.SubmitRawAsync(channel, spec);
        Assert.Null(response.Value);
        Assert.Equal("operation_failed", response.Error.Code);
        Assert.Equal("LEGACY_DRAIN", response.Error.Details.State.State);
        Assert.Equal("legacy_task_outcome_unavailable", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, response.Error.Effect);
        Assert.Equal(RetryMode.Never, response.Error.Retry.Mode);
        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM task;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM attempt;"));
            return 0;
        });
    }

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
