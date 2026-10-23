// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Tests;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Resource observation, budgets and pressure end to end with real processes and the real samplers (loop=local; AF-RES-01; 03 sections
/// 1, 2, 3, 7 and 9): the snapshot against the operating system's own figures (R-RES-001, R-RES-003), the process labels of managed,
/// unmanaged, node and guest VM processes and a task that runs <c>wsl.exe</c> (R-RES-002), <c>peak_observed</c> without reclaimable page
/// cache that never decreases (03 section 3), and the pressure response to a synthetic unmanaged allocator (<c>arcforges-testload
/// mem-ramp</c>, a workload, not a fake) within 1 s of sampling plus 5 s of persistence (R-RES-009, R-RES-014). Each test runs on the OS
/// its env trait names and skips with a reason elsewhere.
/// </summary>
[Trait("loop", "local")]
public sealed partial class ResourceTests
{
    private const long MiB = 1024L * 1024;
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(90);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    // ------------------------------------------------------------------------------------------------- snapshot and labels

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task TheSnapshotAndLabelsMatchTheMachineOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        await SnapshotAndLabelsAsync();
    }

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task TheSnapshotAndLabelsMatchTheMachineOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job platform test.");
        await SnapshotAndLabelsAsync();
    }

    /// <summary>
    /// isolation=exclusive: memory figures are compared with the operating system's within 2% of capacity (R-RES-001), and a managed CPU
    /// load is measured. A managed attempt (two CPU threads) is MANAGED with its task; an <c>arcforges-testload</c> the test starts itself is
    /// UNMANAGED and observed only; the node is NODE_SELF; no process outside the attempt's container is MANAGED.
    /// </summary>
    private static async Task SnapshotAndLabelsAsync()
    {
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        await using var channel = await ChannelAsync(node);

        var snapshot = await SnapshotAsync(channel, snapshot => snapshot.HasBudgetCpuMillicores);
        var (total, available) = OsMemory();
        Assert.Equal((uint)(Environment.ProcessorCount * 1000), snapshot.CapacityCpuMillicores);
        Assert.InRange((double)snapshot.CapacityMemBytes, total * 0.98, total * 1.02);
        Assert.InRange((double)snapshot.AvailableMemBytes, available - (0.02 * total), available + (0.02 * total));

        // R-RES-003 defaults: 1 logical CPU + 10% of the CPUs, and 2 GiB + 10% of memory; B = C - R - U.
        Assert.Equal(1000 + (uint)(Environment.ProcessorCount * 100), snapshot.ReserveCpuMillicores);
        Assert.Equal((ulong)((2048 * MiB) + (0.10 * snapshot.CapacityMemBytes)), snapshot.ReserveMemBytes);
        Assert.Equal(Math.Max(1000, (long)snapshot.CapacityCpuMillicores - snapshot.ReserveCpuMillicores - snapshot.UnmanagedCpuMillicores), snapshot.BudgetCpuMillicores);
        Assert.Equal(snapshot.CapacityMemBytes - snapshot.ReserveMemBytes - snapshot.UnmanagedMemBytes, snapshot.BudgetMemBytes);

        // A managed CPU load (two threads) and an unmanaged one (the same workload, started by the test).
        var task = await SubmitAsync(channel, [TestNode.TestLoad, "cpu", "--threads", "2", "--iterations", "20000000000"]);
        var attempt = await RunningAttemptAsync(channel, task);
        var unmanaged = node.Start(TestNode.TestLoad, ["cpu", "--threads", "1", "--iterations", "20000000000"]);
        var busy = await SnapshotAsync(channel, snapshot => snapshot.Managed.CpuMillicores >= 1_500 && snapshot.RunningAttempts == 1);
        Assert.InRange(busy.Managed.CpuMillicores, 1_500u, 2_600u);
        Assert.InRange(busy.Managed.ProcessCount, 1u, 4u);

        var processes = await ProcessesAsync(channel, new ProcessFilter { TopN = 500 });
        var managed = processes.Where(process => process.Label == ProcessLabel.Managed).ToList();
        Assert.NotEmpty(managed);
        Assert.All(managed, process =>
        {
            Assert.Equal(task, process.TaskId);
            Assert.Equal(attempt, process.AttemptId);
            Assert.False(process.CrossesVmBoundary);
        });
        Assert.Contains(managed, process => process.Executable.StartsWith("arcforges-testload", StringComparison.OrdinalIgnoreCase)
            && process.Usage.CpuMillicores >= 1_000);
        var outside = processes.Single(process => process.Process.Pid == (uint)unmanaged.Id);
        Assert.Equal(ProcessLabel.Unmanaged, outside.Label);
        Assert.Null(outside.TaskId);
        Assert.Contains(processes, process => process.Process.Pid == (uint)node.NodePid() && process.Label == ProcessLabel.NodeSelf);
        Assert.Contains(processes, process => process.Process.Pid == (uint)Environment.ProcessId && process.Label == ProcessLabel.Unmanaged);

        // ps through the CLI: the task filter shows only its processes, all managed.
        var ps = (await node.CliAsync("ps", "--task", IdText.Format(task), "--json")).Json();
        var listed = ps.GetProperty("processes").EnumerateArray().ToList();
        Assert.NotEmpty(listed);
        Assert.All(listed, process => Assert.Equal("PROCESS_LABEL_MANAGED", process.GetProperty("label").GetString()));
        Assert.Equal(0, (await node.CliAsync("resources")).ExitCode);

        // The attempt's 1 s samples and the machine's 5 s samples.
        await TestNode.WaitAsync(async () => (await SamplesAsync(channel, SampleScope.Machine, null)).Samples.Count >= 1, Bound, "a machine sample");
        var samples = await SamplesAsync(channel, SampleScope.Attempt, attempt);
        Assert.Equal(1_000ul, samples.ResolutionMs);
        Assert.True(samples.Samples.Count >= 2, $"{samples.Samples.Count} attempt samples");
        var cli = await node.CliAsync("samples", "--attempt", IdText.Format(attempt), "--json");
        Assert.True(cli.ExitCode == 0, cli.ToString());
        unmanaged.Kill();
        await CancelAsync(channel, task);
    }

    // ------------------------------------------------------------------------------------------------- the VM boundary (Windows)

    /// <summary>
    /// R-RES-002 on Windows: a task that runs <c>wsl.exe</c> is flagged <c>crosses_vm_boundary</c> on every process of its attempt, and the
    /// processes it starts in the VM are never shown as controlled (the WSL VM's worker, when one runs, is GUEST_VM). The inbox
    /// <c>wsl.exe</c> runs even where WSL is not installed (it prints how to install it), so the launch itself is real either way.
    /// </summary>
    [Fact(Timeout = 300_000)]
    [Trait("env", "windows-real")]
    public async Task ATaskThatRunsWslCrossesTheVmBoundaryAndTheVmIsNeverControlled()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job platform test.");
        var wsl = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe");
        Assert.SkipUnless(File.Exists(wsl), "wsl.exe is not present on this Windows installation.");
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        await using var channel = await ChannelAsync(node);
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var crossing = await SubmitAsync(channel, [cmd, "/d", "/c", $"\"{wsl}\" --list --quiet & ping -n 60 127.0.0.1 >nul"]);
        var attempt = await RunningAttemptAsync(channel, crossing);
        var plain = await SubmitAsync(channel, [TestNode.TestLoad, "cpu", "--threads", "1", "--iterations", "20000000000"]);
        await RunningAttemptAsync(channel, plain);

        List<ProcessView> processes = [];
        await TestNode.WaitAsync(async () =>
        {
            processes = await ProcessesAsync(channel, new ProcessFilter { TaskId = crossing });
            return processes.Any(process => process.Process.ImageName.Equals("PING.EXE", StringComparison.OrdinalIgnoreCase));
        }, Bound, "the crossing task's processes");
        Assert.All(processes, process =>
        {
            Assert.Equal(ProcessLabel.Managed, process.Label);
            Assert.Equal(attempt, process.AttemptId);
            Assert.True(process.CrossesVmBoundary, $"{process.Process.ImageName} ({process.Process.Pid}) is not flagged");
        });
        Assert.All(await ProcessesAsync(channel, new ProcessFilter { TaskId = plain }), process => Assert.False(process.CrossesVmBoundary));

        // The VM's worker (vmmem or vmmemWSL) is GUEST_VM, never controlled and never attributed to the task; nothing outside the
        // attempts' jobs is MANAGED.
        var all = await ProcessesAsync(channel, new ProcessFilter { TopN = 500 });
        Assert.All(all.Where(process => process.Label == ProcessLabel.Managed), process => Assert.True(process.TaskId == crossing || process.TaskId == plain));
        var vm = all.Where(process => process.Process.ImageName.StartsWith("vmmem", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.All(vm, process =>
        {
            Assert.Equal(ProcessLabel.GuestVm, process.Label);
            Assert.Null(process.TaskId);
        });
        TestContext.Current.TestOutputHelper?.WriteLine(vm.Count == 0
            ? "No WSL VM worker runs on this machine: the GUEST_VM label was not observed (A-L01 stays unverified)."
            : $"WSL VM worker(s): {string.Join(", ", vm.Select(process => $"{process.Process.ImageName} ({process.Process.Pid}, {process.Usage.MemBytes} bytes)"))}");
        Assert.Contains("resources.crosses_vm_boundary", File.ReadAllText(node.NodeLog), StringComparison.Ordinal);
        await CancelAsync(channel, crossing);
        await CancelAsync(channel, plain);
    }

    // ------------------------------------------------------------------------------------------------- peak_observed

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task PeakObservedExcludesPageCacheAndNeverDecreasesOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        // The attempt writes its own file (dd): the node drops captured output from the cache itself, so stdout would leave no cache behind.
        await PeakObservedAsync(root => ["/bin/sh", "-c",
            "\"$1\" mem-ramp --target-mb 256 --step-mb 32 --hold-ms 4000 --report /dev/null && dd if=/dev/zero of=\"$2\" bs=1M count=768 status=none && sleep 6",
            "sh", TestNode.TestLoad, Path.Combine(root, "cache.bin")]);
    }

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task PeakObservedExcludesPageCacheAndNeverDecreasesOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job platform test.");
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        await PeakObservedAsync(_ => [cmd, "/d", "/c",
            $"\"{TestNode.TestLoad}\" mem-ramp --target-mb 256 --step-mb 32 --hold-ms 4000 --report nul && \"{TestNode.TestLoad}\" output --bytes 805306368 --line-bytes 4096 && ping -n 7 127.0.0.1 >nul"]);
    }

    /// <summary>
    /// isolation=exclusive (memory figures): the attempt holds 256 MiB of its own memory, frees it, then writes 768 MiB to a file (page
    /// cache: on Linux charged to the unit's cgroup, which the test reads directly to prove the cache was there; on Windows the file cache
    /// is never in a process's private working set). Its samples' peak reaches the 256 MiB, stays far below the cache, and never
    /// decreases, while the current memory falls after the ramp ends (03 section 3).
    /// </summary>
    private static async Task PeakObservedAsync(Func<string, string[]> argv)
    {
        // A disk-backed data root: on tmpfs the output would be shared memory, which is not reclaimable cache.
        await using var node = TestNode.Create(OperatingSystem.IsWindows() ? null : AppContext.BaseDirectory);
        await node.StartNodeAsync();
        await using var channel = await ChannelAsync(node);
        var task = await SubmitAsync(channel, argv(node.Root), memExpected: 1024 * MiB, memCeiling: 2048 * MiB);
        var attempt = await RunningAttemptAsync(channel, task);
        long cgroupMax = 0;
        var cgroup = OperatingSystem.IsLinux() ? SystemdTestEnvironment.CgroupDirectory(SystemdTestEnvironment.AttemptUnit(IdText.Format(attempt))) : null;
        var samples = new List<ResourceSample>();
        while (await TaskStateAsync(channel, task) is TaskState.Running)
        {
            if (cgroup is not null && File.Exists(Path.Combine(cgroup, "memory.current")))
            {
                cgroupMax = Math.Max(cgroupMax, long.Parse(File.ReadAllText(Path.Combine(cgroup, "memory.current")).Trim(), CultureInfo.InvariantCulture));
            }

            await Task.Delay(250, Ct);
        }

        samples.AddRange((await SamplesAsync(channel, SampleScope.Attempt, attempt)).Samples);
        Assert.True(samples.Count >= 5, $"{samples.Count} samples");
        var peaks = samples.Select(sample => (long)sample.Usage.MemPeakBytes).ToList();
        for (var index = 1; index < peaks.Count; index++)
        {
            Assert.True(peaks[index] >= peaks[index - 1], $"peak_observed fell from {peaks[index - 1]} to {peaks[index]} at sample {index}");
        }

        var peak = peaks[^1];
        var current = samples.Select(sample => (long)sample.Usage.MemBytes).ToList();
        Assert.InRange(peak, 256 * MiB, (256 + 192) * MiB);
        Assert.True(current[^1] < peak - (128 * MiB), $"the current memory {current[^1]} did not fall below the peak {peak} after the ramp ended");
        Assert.Equal(peak, current.Max());
        if (cgroup is not null)
        {
            // The cgroup held the output's page cache (memory.current), which peak_observed left out.
            Assert.True(cgroupMax > peak + (400 * MiB), $"memory.current peaked at {cgroupMax}, peak_observed {peak}");
        }

        TestContext.Current.TestOutputHelper?.WriteLine($"peak_observed {peak} bytes; last current {current[^1]}; cgroup memory.current max {cgroupMax}");
    }

    // ------------------------------------------------------------------------------------------------- pressure response

    [Fact(Timeout = 600_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task ThePressureResponseStopsPreemptibleWorkWithinTheStatedTimesOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        await PressureResponseAsync();
    }

    [Fact(Timeout = 600_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task ThePressureResponseStopsPreemptibleWorkWithinTheStatedTimesOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job platform test.");
        await PressureResponseAsync();
    }

    /// <summary>
    /// isolation=exclusive (memory and timing): the node's pressure thresholds are set relative to the memory available when the test
    /// starts (policy <c>resources.pressure</c>), so that a synthetic unmanaged allocator of about 2 GiB (<c>arcforges-testload
    /// mem-ramp</c>, started by the test outside every container) crosses Critical without starving the machine. From the moment the test
    /// itself reads available memory below the Critical threshold, the node must stop the preemptible BACKGROUND attempt within 1 s of
    /// sampling plus 5 s of persistence (03 section 5.4), journal it and notify; a non-preemptible attempt keeps running.
    /// </summary>
    private static async Task PressureResponseAsync()
    {
        const long Allocation = 2048 * MiB;
        var (total, available) = OsMemory();
        Assert.SkipWhen(available < Allocation + (2048 * MiB), $"Only {available / MiB} MiB available; the test needs {(Allocation + (2048 * MiB)) / MiB} MiB.");
        await using var node = TestNode.Create();
        var critical = (available - (Allocation * 3 / 4)) / (double)total;
        node.SeedPolicy(policy => policy.Resources.Pressure = new PressureThresholds
        {
            TightAvailableFraction = critical + (512.0 * MiB / total),
            PressureAvailableFraction = critical + (256.0 * MiB / total),
            CriticalAvailableFraction = critical,
            MemoryPsiSomeAvg10 = 99,
        });
        await node.StartNodeAsync();
        await using var channel = await ChannelAsync(node);
        var preemptible = await SubmitAsync(channel, [TestNode.TestLoad, "mem-ramp", "--target-mb", "32", "--hold-ms", "300000"],
            priority: Priority.Background, preemptible: true);
        var protectedTask = await SubmitAsync(channel, [TestNode.TestLoad, "mem-ramp", "--target-mb", "32", "--hold-ms", "300000"]);
        var preemptibleAttempt = await RunningAttemptAsync(channel, preemptible);
        await RunningAttemptAsync(channel, protectedTask);
        await SnapshotAsync(channel, snapshot => snapshot.Pressure == PressureLevel.Normal && snapshot.RunningAttempts == 2);

        // The unmanaged allocator: 2 GiB in 64 MiB steps, held. The test records when available memory first falls below Critical.
        var allocator = node.Start(TestNode.TestLoad, ["mem-ramp", "--target-mb", (Allocation / MiB).ToString(CultureInfo.InvariantCulture), "--step-mb", "64",
            "--step-ms", "20", "--hold-ms", "120000"]);
        var threshold = critical * total;
        DateTimeOffset? crossed = null;
        var watch = Stopwatch.StartNew();
        while (crossed is null)
        {
            if (OsMemory().Available < threshold)
            {
                crossed = DateTimeOffset.UtcNow;
            }
            else
            {
                Assert.True(watch.Elapsed < TimeSpan.FromSeconds(60) && !allocator.HasExited, $"available memory never fell below {threshold / MiB:0} MiB");
                await Task.Delay(50, Ct);
            }
        }

        await TestNode.WaitAsync(async () => await TaskStateAsync(channel, preemptible) is TaskState.Failed or TaskState.Cancelled, Bound, "the preemption");
        var preempted = TestNode.LogEvents(node.NodeLog, "execution.preempted").Single();
        var acted = DateTimeOffset.Parse(preempted.GetProperty("at").GetString()!, CultureInfo.InvariantCulture);
        var reaction = acted - crossed.Value;
        var changes = TestNode.LogEvents(node.NodeLog, "resources.pressure");
        var levels = changes.Select(item => item.GetProperty("fields").GetProperty("level").GetString()).ToList();
        TestContext.Current.TestOutputHelper?.WriteLine(
            $"available below critical ({threshold / MiB:0} MiB) at {crossed:O}; preempted at {acted:O}; reaction {reaction.TotalMilliseconds:0} ms; levels: "
            + string.Join("; ", changes.Select(item => $"{item.GetProperty("at").GetString()} {item.GetProperty("fields").GetProperty("level").GetString()} "
                + $"({item.GetProperty("fields").GetProperty("trigger").GetString()})")));

        // 03 section 5.4: detected within 1 s of sampling plus 5 s of persistence and acted on at once (the test polls every 50 ms).
        Assert.True(reaction <= TimeSpan.FromSeconds(6.25), $"the node acted {reaction.TotalMilliseconds:0} ms after available memory fell below Critical");
        Assert.True(reaction >= TimeSpan.FromSeconds(4), $"the node acted {reaction.TotalMilliseconds:0} ms after the crossing, before 5 s of persistence");
        Assert.Contains("Critical", levels);

        var record = await AttemptAsync(channel, preemptibleAttempt);
        Assert.Equal(TerminationReason.Preempted, record.Result.TerminationReason);
        Assert.Contains("critical memory pressure", record.Result.Detail, StringComparison.Ordinal);
        Assert.Equal(TaskState.Running, await TaskStateAsync(channel, protectedTask));
        var notifications = await channel.Node.ListNotificationsAsync(new NodeServiceListNotificationsRequest { Meta = new RequestMeta() },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
        Assert.Contains(notifications.Value.Notifications, item => item.Title == "Critical memory pressure");

        allocator.Kill();
        await allocator.WaitForExitAsync(Ct);
        await CancelAsync(channel, protectedTask);
    }

    // ------------------------------------------------------------------------------------------------- helpers

    private static async Task<NodeChannel> ChannelAsync(TestNode node)
    {
        var channel = NodeChannel.Create(OperatingSystem.IsWindows() ? LocalRpcEndpoint.NamedPipe(node.Endpoint) : LocalRpcEndpoint.UnixDomainSocket(node.Endpoint));
        var hello = ClientProcess.Hello(ClientKind.Cli);
        hello.CiMarkers.Clear();
        Assert.Null((await channel.Node.HelloAsync(new NodeServiceHelloRequest { Hello = hello }, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct)).Error);
        return channel;
    }

    private static RequestMeta Meta() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };

    private static async Task<Id> SubmitAsync(NodeChannel channel, string[] argv, Priority priority = Priority.Normal, bool preemptible = false,
        long memExpected = 0, long memCeiling = 0)
    {
        var command = new ArgvCommand();
        command.Argv.Add(argv);
        var spec = new TaskSpec
        {
            Command = new CommandSpec { Argv = command },
            WorkingDirectory = Path.GetTempPath(),
            Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
            Priority = priority,
            Resources = new ResourceSpec { Preemptible = preemptible },
        };
        if (memExpected > 0)
        {
            spec.Resources.Hint = new ResourceDemand { MemExpectedBytes = (ulong)memExpected, MemCeilingBytes = (ulong)memCeiling };
        }

        var submit = await channel.Tasks.SubmitTaskAsync(new TaskServiceSubmitTaskRequest { Meta = Meta(), Spec = spec },
            deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: Ct);
        Assert.True(submit.Error is null, $"SubmitTask: {submit.Error}");
        return submit.Value.TaskId;
    }

    private static async Task<ManagedTask> TaskAsync(NodeChannel channel, Id task) =>
        (await channel.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest { Meta = new RequestMeta(), TaskId = task }, deadline: DateTime.UtcNow.AddSeconds(10),
            cancellationToken: Ct)).Value.Task;

    private static async Task<TaskState> TaskStateAsync(NodeChannel channel, Id task) => (await TaskAsync(channel, task)).State;

    private static async Task<Id> RunningAttemptAsync(NodeChannel channel, Id task)
    {
        ManagedTask current = new();
        await TestNode.WaitAsync(async () =>
        {
            current = await TaskAsync(channel, task);
            return current.CurrentAttempt is { State: AttemptState.Running };
        }, Bound, "the attempt to run");
        return current.CurrentAttempt.AttemptId;
    }

    private static async Task<Attempt> AttemptAsync(NodeChannel channel, Id attempt) =>
        (await channel.Tasks.GetAttemptAsync(new TaskServiceGetAttemptRequest { Meta = new RequestMeta(), AttemptId = attempt },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct)).Value.Attempt;

    private static async Task CancelAsync(NodeChannel channel, Id task)
    {
        var cancel = await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Meta(), TaskId = task }, deadline: DateTime.UtcNow.AddSeconds(15),
            cancellationToken: Ct);
        Assert.Null(cancel.Error);
        await TestNode.WaitAsync(async () => await TaskStateAsync(channel, task) is TaskState.Cancelled or TaskState.Failed or TaskState.Succeeded, Bound, "the cancellation");
    }

    private static async Task<ResourceSnapshot> SnapshotAsync(NodeChannel channel, Func<ResourceSnapshot, bool> until)
    {
        ResourceSnapshot snapshot = new();
        await TestNode.WaitAsync(async () =>
        {
            var response = await channel.Resources.GetResourceSnapshotAsync(new ResourceServiceGetResourceSnapshotRequest { Meta = new RequestMeta() },
                deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: Ct);
            Assert.Null(response.Error);
            snapshot = response.Value.Snapshot;
            return until(snapshot);
        }, Bound, "the resource snapshot");
        return snapshot;
    }

    private static async Task<List<ProcessView>> ProcessesAsync(NodeChannel channel, ProcessFilter filter)
    {
        var response = await channel.Resources.ListProcessesAsync(new ResourceServiceListProcessesRequest { Meta = new RequestMeta(), Filter = filter },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
        Assert.Null(response.Error);
        return [.. response.Value.Processes];
    }

    private static async Task<ResourceServiceGetSamplesValue> SamplesAsync(NodeChannel channel, SampleScope scope, Id? attempt)
    {
        var response = await channel.Resources.GetSamplesAsync(new ResourceServiceGetSamplesRequest { Meta = new RequestMeta(), Scope = scope, AttemptId = attempt },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
        Assert.Null(response.Error);
        return response.Value;
    }

    /// <summary>The operating system's own total and available memory, read by the test (Linux <c>/proc/meminfo</c>; Windows <c>GlobalMemoryStatusEx</c>).</summary>
    private static (long Total, long Available) OsMemory()
    {
        if (OperatingSystem.IsWindows())
        {
            var status = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
            Assert.True(GlobalMemoryStatusEx(ref status));
            return ((long)status.TotalPhys, (long)status.AvailPhys);
        }

        long total = 0, available = 0;
        foreach (var line in File.ReadAllLines("/proc/meminfo"))
        {
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields[0] == "MemTotal:")
            {
                total = long.Parse(fields[1], CultureInfo.InvariantCulture) * 1024;
            }
            else if (fields[0] == "MemAvailable:")
            {
                available = long.Parse(fields[1], CultureInfo.InvariantCulture) * 1024;
            }
        }

        return (total, available);
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GlobalMemoryStatusEx(ref MemoryStatus status);

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }
}
