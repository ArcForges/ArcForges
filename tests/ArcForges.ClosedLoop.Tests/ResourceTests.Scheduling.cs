// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Tests;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// The resource-control quality targets of 15 section 4 with the scheduler (AF-SCHED-01), end to end with the real node and real
/// processes: headroom protection (an unmanaged interactive probe under a saturating managed CPU load misses at most 1% of its deadlines)
/// and memory admission in the standard <c>mem-ramp</c> scenario (no admission brings the accounted memory above <c>B_mem</c>, no attempt
/// or root exceeds its bound, and an unmanaged allocator running beside the managed load is never refused or OOM-killed).
/// </summary>
public sealed partial class ResourceTests
{
    // ------------------------------------------------------------------------------------------------- headroom protection

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task AnUnmanagedProbeMissesAtMostOnePercentOfDeadlinesUnderSaturatingManagedLoadOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job platform test.");
        await HeadroomAsync();
    }

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task AnUnmanagedProbeMissesAtMostOnePercentOfDeadlinesUnderSaturatingManagedLoadOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        await HeadroomAsync();
    }

    /// <summary>
    /// isolation=exclusive (CPU timing): two managed CPU workers with one thread per logical processor each demand twice the machine; the
    /// root CPU cap holds them to <c>B_cpu</c>, so the reserve stays free for unmanaged work. The probe (<c>arcforges-testload probe</c>:
    /// 2 ms of work with a 10 ms deadline every 100 ms, for 60 s), started by the test outside every container, misses at most 1% of its
    /// deadlines. The managed load is checked to saturate the budget while the probe runs.
    /// </summary>
    private static async Task HeadroomAsync()
    {
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        await using var channel = await ChannelAsync(node);
        var threads = (2 * Environment.ProcessorCount).ToString(CultureInfo.InvariantCulture);
        var workers = new List<Id> { await SubmitAsync(channel, [TestNode.TestLoad, "cpu", "--threads", threads, "--iterations", "20000000000"]) };
        await RunningAttemptAsync(channel, workers[0]);
        var history = new List<string>();
        ResourceSnapshot saturated;
        var saturating = Stopwatch.StartNew();
        while (true)
        {
            saturated = await SnapshotAsync(channel, snapshot => snapshot.HasBudgetCpuMillicores);
            history.Add($"managed {saturated.Managed.CpuMillicores} B_cpu {saturated.BudgetCpuMillicores} U_cpu {saturated.UnmanagedCpuMillicores} pressure {saturated.Pressure}");
            if (saturated.Managed.CpuMillicores >= saturated.BudgetCpuMillicores * 0.85)
            {
                break;
            }

            Assert.True(saturating.Elapsed < TimeSpan.FromSeconds(60), "the managed load did not saturate B_cpu: " + string.Join("; ", history.TakeLast(12)));
            await Task.Delay(1_000, Ct);
        }

        // Admission goes on under the saturating load: a second worker starts (the CPU budget counts grants, not the capped usage).
        workers.Add(await SubmitAsync(channel, [TestNode.TestLoad, "cpu", "--threads", "1", "--iterations", "20000000000"]));
        var started = Stopwatch.StartNew();
        while (await TaskStateAsync(channel, workers[1]) != TaskState.Running)
        {
            if (started.Elapsed > TimeSpan.FromSeconds(30))
            {
                var explained = await channel.Queue.ExplainTaskAsync(new QueueServiceExplainTaskRequest { Meta = Meta(), TaskId = workers[1] }, cancellationToken: Ct);
                var snapshot = await SnapshotAsync(channel, _ => true);
                Assert.Fail($"the second worker did not start under the managed load: {explained.Value?.Explanation} (pressure {snapshot.Pressure}, B_cpu {snapshot.BudgetCpuMillicores}, U_cpu {snapshot.UnmanagedCpuMillicores})");
            }

            await Task.Delay(200, Ct);
        }

        var report = Path.Combine(node.Root, "probe.json");
        var probe = node.Start(TestNode.TestLoad, ["probe", "--period-ms", "100", "--deadline-ms", "10", "--work-us", "2000", "--duration-ms", "60000", "--report", report]);
        var managed = new List<long>();
        var samples = new System.Text.Json.Nodes.JsonArray();
        while (!probe.HasExited)
        {
            var sample = await SnapshotAsync(channel, _ => true);
            managed.Add(sample.Managed.CpuMillicores);
            samples.Add(new System.Text.Json.Nodes.JsonObject
            {
                ["atMs"] = (long)(DateTime.Now - probe.StartTime).TotalMilliseconds,
                ["managed"] = sample.Managed.CpuMillicores,
                ["budget"] = sample.BudgetCpuMillicores,
                ["unmanaged"] = sample.UnmanagedCpuMillicores,
                ["node"] = sample.NodeSelf?.CpuMillicores ?? 0,
            });
            await Task.Delay(2_000, Ct);
        }

        Assert.Equal(0, probe.ExitCode);
        foreach (var worker in workers)
        {
            await CancelAsync(channel, worker);
        }

        var result = JsonDocument.Parse(File.ReadAllText(report)).RootElement;
        var periods = result.GetProperty("results").GetProperty("periods").GetInt64();
        var misses = result.GetProperty("results").GetProperty("misses").GetInt64();
        var measured = result.GetProperty("measured");
        var summary = new System.Text.Json.Nodes.JsonObject
        {
            ["name"] = "headroom-probe",
            ["os"] = OperatingSystem.IsWindows() ? "windows" : "linux",
            ["periods"] = periods,
            ["misses"] = misses,
            ["missFraction"] = Math.Round((double)misses / periods, 5),
            ["p50Us"] = measured.GetProperty("p50Us").GetInt64(),
            ["p99Us"] = measured.GetProperty("p99Us").GetInt64(),
            ["maxUs"] = measured.GetProperty("maxUs").GetInt64(),
            ["budgetCpuMillicores"] = saturated.BudgetCpuMillicores,
            ["capacityCpuMillicores"] = saturated.CapacityCpuMillicores,
            ["managedCpuMillicoresMedian"] = managed.Count == 0 ? 0 : managed.Order().ElementAt(managed.Count / 2),
            ["host"] = TestNode.Host,
            ["samples"] = samples,
        };

        // Where the missed and the longest periods fall (period N is scheduled at originMs + N x 100 ms of the probe's process time, the
        // samples' atMs), to line them up with the samples.
        foreach (var property in measured.EnumerateObject().Where(property => property.Name is "originMs" or "longestIndex" || property.Name.StartsWith("miss", StringComparison.Ordinal)))
        {
            summary[property.Name] = property.Value.GetInt64();
        }
        TestContext.Current.TestOutputHelper?.WriteLine(summary.ToJsonString());
        if (Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT") is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "headroom-probe-" + (OperatingSystem.IsWindows() ? "windows" : "linux") + ".json"),
                summary.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }

        Assert.True(periods >= 590, $"{periods} periods");
        Assert.True(misses <= periods / 100, $"the probe missed {misses} of {periods} deadlines (more than 1%)");
        Assert.True(managed.Count > 0 && managed.Order().ElementAt(managed.Count / 2) >= saturated.BudgetCpuMillicores * 0.85,
            $"the managed load did not saturate the budget while the probe ran ({string.Join(", ", managed)} of {saturated.BudgetCpuMillicores} millicores)");
    }

    // ------------------------------------------------------------------------------------------------- memory admission

    [Fact(Timeout = 600_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task TheStandardMemRampScenarioNeverOvercommitsAndHarmsNoUnmanagedProcessOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job platform test.");
        await MemoryScenarioAsync();
    }

    [Fact(Timeout = 600_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task TheStandardMemRampScenarioNeverOvercommitsAndHarmsNoUnmanagedProcessOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        await MemoryScenarioAsync();
    }

    /// <summary>
    /// isolation=exclusive (memory): eight managed <c>mem-ramp</c> tasks each expect a quarter of <c>B_mem</c> (their hints), so admission
    /// runs at most four at once and queues the rest with <c>budget_memory</c>; each ramps to at most 1.5 GiB of real memory (bounded so the
    /// scenario never strains the workstation) and holds it. Meanwhile an unmanaged allocator started by the test commits 512 MiB and holds
    /// it. Checked: every admission kept the accounted memory within <c>B_mem</c> (the node log's <c>execution.admitted</c>); every managed
    /// task succeeded; the unmanaged allocator succeeded; no attempt or the root exceeded its bound (Windows: the root's commit never above
    /// its limit; Linux: the slice's <c>memory.events</c> show no OOM kill, swap within <c>swap_allowance</c> = 0) and the kernel recorded no
    /// OOM kill (Linux <c>/proc/vmstat</c>).
    /// </summary>
    private static async Task MemoryScenarioAsync()
    {
        var oomBefore = OperatingSystem.IsLinux() ? VmStat("oom_kill") : 0;
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        await using var channel = await ChannelAsync(node);
        var snapshot = await SnapshotAsync(channel, snapshot => snapshot.HasBudgetMemBytes && snapshot.BudgetMemBytes > 0);
        var budget = (long)snapshot.BudgetMemBytes;
        var expected = budget / 4;
        var ramp = Math.Max(64, Math.Min(1536, expected * 9 / 10 / MiB));
        Assert.SkipWhen(expected < 256 * MiB, $"B_mem is {budget / MiB} MiB; the scenario needs at least 1 GiB.");
        var tasks = new List<Id>();
        for (var index = 0; index < 8; index++)
        {
            tasks.Add(await SubmitAsync(channel, [TestNode.TestLoad, "mem-ramp", "--target-mb", ramp.ToString(CultureInfo.InvariantCulture), "--step-mb", "64",
                "--hold-ms", "4000"], memExpected: expected, memCeiling: expected));
        }

        var allocator = node.Start(TestNode.TestLoad, ["mem-ramp", "--target-mb", "512", "--step-mb", "64", "--hold-ms", "15000"]);
        string? rootJob = null;
        if (OperatingSystem.IsWindows())
        {
            var info = (await node.CliAsync("node", "info", "--json")).Json();
            rootJob = ArcForges.Node.Platform.Windows.WindowsExecutionPlatform.JobName(info.GetProperty("node").GetProperty("node").GetProperty("nodeId").GetString()!, "root");
        }

        using var root = rootJob is not null && OperatingSystem.IsWindows() ? ArcForges.Node.Platform.Windows.JobObject.Open(rootJob) : null;
        long rootCommitMax = 0;
        var queuedSeen = false;
        var watch = Stopwatch.StartNew();
        while (true)
        {
            var states = new List<TaskState>();
            foreach (var task in tasks)
            {
                states.Add(await TaskStateAsync(channel, task));
            }

            queuedSeen |= states.Contains(TaskState.Queued) && states.Contains(TaskState.Running);
            if (root is not null && OperatingSystem.IsWindows())
            {
                rootCommitMax = Math.Max(rootCommitMax, root.CurrentCommit());
            }

            if (states.All(state => state is TaskState.Succeeded or TaskState.Failed or TaskState.Cancelled or TaskState.Lost))
            {
                Assert.All(states, state => Assert.Equal(TaskState.Succeeded, state));
                break;
            }

            Assert.True(watch.Elapsed < TimeSpan.FromMinutes(8), $"the scenario did not finish: {string.Join(", ", states)}");
            await Task.Delay(250, Ct);
        }

        var unmanaged = await TestNode.CompleteAsync(allocator, TimeSpan.FromSeconds(60));
        Assert.True(unmanaged.ExitCode == 0, $"the unmanaged allocator failed: {unmanaged}");
        Assert.True(queuedSeen, "admission queued the tasks that did not fit beside the running ones");

        var admitted = TestNode.LogEvents(node.NodeLog, "execution.admitted");
        Assert.Equal(8, admitted.Count);
        long maxAccounted = 0;
        foreach (var admission in admitted)
        {
            var fields = admission.GetProperty("fields");
            var accounted = fields.GetProperty("accountedAfter").GetInt64();
            var budgetAtAdmission = fields.GetProperty("budgetMemory").GetInt64();
            maxAccounted = Math.Max(maxAccounted, accounted);
            Assert.True(accounted <= budgetAtAdmission, $"an admission brought the accounted memory to {accounted} B above B_mem {budgetAtAdmission} B");
        }

        long oomKills = 0, swap = 0;
        if (OperatingSystem.IsLinux())
        {
            var slice = SystemdTestEnvironment.CgroupDirectory(node.Slice)!;
            var events = File.ReadAllLines(Path.Combine(slice, "memory.events")).Select(line => line.Split(' ')).ToDictionary(parts => parts[0], parts => long.Parse(parts[1], CultureInfo.InvariantCulture));
            oomKills = events.GetValueOrDefault("oom_kill");
            swap = long.Parse(File.ReadAllText(Path.Combine(slice, "memory.swap.current")).Trim(), CultureInfo.InvariantCulture);
            Assert.Equal(0, oomKills);
            Assert.Equal(0, swap);
            Assert.Equal(oomBefore, VmStat("oom_kill"));
        }
        else if (root is not null && OperatingSystem.IsWindows())
        {
            Assert.True(rootCommitMax <= root.Limits().JobMemoryLimit, $"the root committed {rootCommitMax} B above its limit {root.Limits().JobMemoryLimit} B");
        }

        var summary = new System.Text.Json.Nodes.JsonObject
        {
            ["name"] = "mem-ramp-standard",
            ["os"] = OperatingSystem.IsWindows() ? "windows" : "linux",
            ["budgetMemBytes"] = budget,
            ["expectedPerTaskBytes"] = expected,
            ["rampPerTaskMiB"] = ramp,
            ["maxAccountedBytes"] = maxAccounted,
            ["rootCommitMaxBytes"] = rootCommitMax,
            ["sliceOomKills"] = oomKills,
            ["sliceSwapBytes"] = swap,
            ["unmanagedAllocatorExit"] = unmanaged.ExitCode,
            ["seconds"] = Math.Round(watch.Elapsed.TotalSeconds, 1),
        };
        TestContext.Current.TestOutputHelper?.WriteLine(summary.ToJsonString());
        if (Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT") is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "mem-ramp-standard-" + (OperatingSystem.IsWindows() ? "windows" : "linux") + ".json"),
                summary.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    /// <summary>A counter of <c>/proc/vmstat</c>.</summary>
    private static long VmStat(string name) =>
        File.ReadAllLines("/proc/vmstat").Select(line => line.Split(' ')).Where(parts => parts.Length == 2 && parts[0] == name)
            .Select(parts => long.Parse(parts[1], CultureInfo.InvariantCulture)).FirstOrDefault();
}
