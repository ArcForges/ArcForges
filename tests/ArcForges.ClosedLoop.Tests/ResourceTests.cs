// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core.Security;
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
    private static readonly string[] SystemdRunPaths = ["/usr/bin/systemd-run", "/bin/systemd-run"];

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

        // Ordered by the CPU rate, then by the memory figure each view shows (the detailed one, not the table's).
        for (var index = 1; index < processes.Count; index++)
        {
            var (first, second) = (processes[index - 1].Usage, processes[index].Usage);
            var (firstCpu, secondCpu) = (first.HasCpuMillicores ? first.CpuMillicores : 0, second.HasCpuMillicores ? second.CpuMillicores : 0);
            Assert.True(firstCpu > secondCpu || (firstCpu == secondCpu && first.MemBytes >= second.MemBytes),
                $"process {index} ({processes[index].Process.ImageName}: {secondCpu} mc, {second.MemBytes} B) is out of order after {processes[index - 1].Process.ImageName} ({firstCpu} mc, {first.MemBytes} B)");
        }

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

        // A unique prefix names the attempt too (cli.md section 1: at least 6 characters); a shorter one is a usage error.
        var prefixed = await node.CliAsync("samples", "--attempt", IdText.Format(attempt)[..12], "--json");
        Assert.True(prefixed.ExitCode == 0, prefixed.ToString());
        Assert.Equal(cli.Json().GetProperty("resolutionMs").GetRawText(), prefixed.Json().GetProperty("resolutionMs").GetRawText());
        Assert.Equal(2, (await node.CliAsync("samples", "--attempt", IdText.Format(attempt)[..5])).ExitCode);
        unmanaged.Kill();
        await CancelAsync(channel, task);
    }

    // ------------------------------------------------------------------------------------------------- escaped processes (Linux)

    /// <summary>
    /// R-RES-002 and R-RES-012 end to end on Linux: the attempt's shell starts a child that leaves the attempt's unit for a scope of its
    /// own (<c>systemd-run --user --scope</c>: the child's parent is the attempt's shell, its cgroup is outside the unit, the Linux shape of
    /// an escape). The ancestry scan finds it, and <c>ListProcesses</c> labels it ESCAPED with its task and attempt (with the task filter
    /// too), never MANAGED. T-18 (AF-SEC-01): a SCRIPT caller's <c>TerminateProcess</c> of it raises an approval; once a HUMAN approves, the
    /// node terminates exactly that process (by ID and start time) under the original command ID, the retry receives the outcome, and the
    /// action is audited. An unrelated process is never terminated (<c>not_found</c>). On Windows a node attempt has no such
    /// shape: its jobs allow no breakaway and every child inherits its parent's job, so the platform test (EscapedProcessTests) makes the
    /// escape under a root that is not yet assigned, which only the launcher itself could do.
    /// </summary>
    [Fact(Timeout = 300_000)]
    [Trait("env", "linux-real")]
    public async Task AnEscapedProcessIsListedEscapedWithItsTaskOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        var systemdRun = SystemdRunPaths.FirstOrDefault(File.Exists);
        Assert.SkipWhen(systemdRun is null, "systemd-run is not installed.");
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        await using var channel = await ChannelAsync(node);
        var task = await SubmitAsync(channel, ["/bin/sh", "-c", "\"$1\" --user --scope --quiet --collect -- sleep 300 & sleep 300", "sh", systemdRun!]);
        var attempt = await RunningAttemptAsync(channel, task);
        ProcessView? escaped = null;
        try
        {
            await TestNode.WaitAsync(async () =>
            {
                escaped = (await ProcessesAsync(channel, new ProcessFilter { TopN = 500 })).FirstOrDefault(process => process.Label == ProcessLabel.Escaped);
                return escaped is not null;
            }, Bound, "an ESCAPED process");
            Assert.Equal(task, escaped!.TaskId);
            Assert.Equal(attempt, escaped.AttemptId);
            Assert.Equal("sleep", escaped.Executable);
            Assert.False(escaped.CrossesVmBoundary);

            // The task filter and the label filter show it; it is never among the controlled (MANAGED) processes.
            var ofTask = await ProcessesAsync(channel, new ProcessFilter { TaskId = task });
            Assert.Contains(ofTask, process => process.Process.Pid == escaped.Process.Pid && process.Label == ProcessLabel.Escaped);
            Assert.Contains(ofTask, process => process.Label == ProcessLabel.Managed);
            var byLabel = await ProcessesAsync(channel, new ProcessFilter { Labels = { ProcessLabel.Escaped } });
            Assert.Contains(byLabel, process => process.Process.Pid == escaped.Process.Pid);
            Assert.DoesNotContain(await ProcessesAsync(channel, new ProcessFilter { Labels = { ProcessLabel.Managed } }), process => process.Process.Pid == escaped.Process.Pid);
            Assert.NotEmpty(TestNode.LogEvents(node.NodeLog, "execution.escaped"));

            // T-18: the escaped process is terminated on request, through an approval (SCRIPT: P), never an unrelated one.
            var unrelated = await channel.Resources.TerminateProcessAsync(new ResourceServiceTerminateProcessRequest
            {
                Meta = Meta(),
                Process = ClientProcess.Current(),
            }, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
            Assert.Equal("not_found", unrelated.Error?.Code);
            var terminate = new ResourceServiceTerminateProcessRequest { Meta = Meta(), Process = escaped.Process, Reason = "escaped" };
            var raised = await channel.Resources.TerminateProcessAsync(terminate, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
            Assert.Equal("approval_required", raised.Error?.Code);
            Assert.True(Directory.Exists($"/proc/{escaped.Process.Pid}"), "nothing is terminated before the approval");
            await using (var human = await node.HumanChannelAsync())
            {
                var approved = await TestNode.ApproveNextAsync(human, Bound);
                Assert.Equal((ApprovalState.Executed, "ResourceService.TerminateProcess"), (approved.State, approved.Operation));
            }

            await TestNode.WaitAsync(() => Task.FromResult(!Directory.Exists($"/proc/{escaped.Process.Pid}")), Bound, "the escaped process to end");
            var retried = await channel.Resources.TerminateProcessAsync(terminate, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
            Assert.Null(retried.Error);
            Assert.Equal(EffectCertainty.Happened, retried.Value.Receipt.Effect);
            Assert.NotEmpty(TestNode.LogEvents(node.NodeLog, "api.process.terminated"));

            await CancelAsync(channel, task);

            // R-SEC-002: the request (SCRIPT, approval) and its execution after the approval are in the node's audit log.
            await node.StopNodeAsync();
            using var store = ArcForges.Node.Store.NodeStore.Open(new ArcForges.Node.Store.NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "audit" });
            var audit = store.Read(reader => AuditLog.Recent(reader));
            const string Operation = PermissionMatrix.ProcessTerminate + " ResourceService.TerminateProcess";
            Assert.Contains(audit, entry => entry.Operation == Operation && entry.Decision == PermissionDecision.Approval && entry.Actor.Origin == Origin.Script
                && entry.Outcome.StartsWith("approval requested", StringComparison.Ordinal));
            Assert.Contains(audit, entry => entry.Operation == Operation && entry.Outcome == "executed after approval");
        }
        finally
        {
            if (escaped is not null && Directory.Exists($"/proc/{escaped.Process.Pid}"))
            {
                try
                {
                    using var leftover = Process.GetProcessById((int)escaped.Process.Pid);
                    if (leftover.ProcessName == "sleep")
                    {
                        leftover.Kill();
                        leftover.WaitForExit(5_000);
                    }
                }
                catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                }
            }
        }
    }

    /// <summary>
    /// 04 section 6 step 4 on Linux with a real escape (repair MR-01): the attempt's shell starts a child in a scope of its own, as above,
    /// traps the stop signal and exits at once. The test cancels as soon as the child runs (its own marker), without waiting for the 5 s
    /// scan to label it, so the scan when the stop begins is what finds it unless a periodic scan came first (the output says which). The
    /// attempt ends CANCELLED in the graceful phase, without a forced phase; once the shell has exited, the user manager adopts the
    /// escaped child and a fresh ancestry scan no longer finds it, so the node terminates it by the identity it recorded when the stop
    /// sequence ends, and the stop's detail names it. The first record write meets a full command queue (the test fault
    /// <c>escaped-record-queue-full</c>): the stop still completes, and the record is written later, so the store holds it.
    /// </summary>
    [Fact(Timeout = 300_000)]
    [Trait("env", "linux-real")]
    public async Task AnEscapedProcessOfAnAttemptCancelledGracefullyIsTerminatedOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        var systemdRun = SystemdRunPaths.FirstOrDefault(File.Exists);
        Assert.SkipWhen(systemdRun is null, "systemd-run is not installed.");
        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_TEST_FAULT"] = "escaped-record-queue-full=0";
        await node.StartNodeAsync();
        var marker = Path.Combine(node.Root, "escaped.pid");
        int? pid = null;
        try
        {
            Id task, attempt;
            DateTimeOffset cancelledAt;
            await using (var channel = await ChannelAsync(node))
            {
                task = await SubmitAsync(channel, ["/bin/sh", "-c",
                    "trap 'exit 0' TERM; \"$1\" --user --scope --quiet --collect -- /bin/sh -c 'echo $$ > \"$0\"; exec sleep 300' \"$2\" & sleep 300 & wait",
                    "sh", systemdRun!, marker]);
                attempt = await RunningAttemptAsync(channel, task);
                await TestNode.WaitAsync(() => Task.FromResult(File.Exists(marker) && File.ReadAllText(marker).Trim().Length > 0), Bound, "the escaped child to run");
                pid = int.Parse(File.ReadAllText(marker).Trim(), CultureInfo.InvariantCulture);
                cancelledAt = DateTimeOffset.UtcNow;
                await CancelAsync(channel, task);
                Assert.Equal(TaskState.Cancelled, await TaskStateAsync(channel, task));
                var record = await AttemptAsync(channel, attempt);
                Assert.Equal(TerminationReason.Cancelled, record.Result.TerminationReason);
                Assert.Contains("SIGTERM sent to every process", record.Result.Detail, StringComparison.Ordinal);
                Assert.Contains("escaped processes terminated: ", record.Result.Detail, StringComparison.Ordinal);
                Assert.Contains(string.Create(CultureInfo.InvariantCulture, $"({pid})"), record.Result.Detail, StringComparison.Ordinal);
                await TestNode.WaitAsync(() => Task.FromResult(!Directory.Exists($"/proc/{pid}")), TimeSpan.FromSeconds(10), "the escaped process to end");
            }

            // The first record write found the queue full and was deferred, never thrown into the stop.
            Assert.NotEmpty(TestNode.LogEvents(node.NodeLog, "execution.escaped.record_deferred"));
            var found = TestNode.LogEvents(node.NodeLog, "execution.escaped")
                .Select(item => DateTimeOffset.Parse(item.GetProperty("at").GetString()!, CultureInfo.InvariantCulture)).Min();
            TestContext.Current.TestOutputHelper?.WriteLine(found >= cancelledAt
                ? $"The escaped child was found by the scan when the stop began ({found:O}; cancel sent {cancelledAt:O})."
                : $"A periodic scan found the escaped child before the cancel ({found:O}; cancel sent {cancelledAt:O}).");

            // The record was written after all, so a restarted node would know it.
            await node.StopNodeAsync();
            using var store = ArcForges.Node.Store.NodeStore.Open(new ArcForges.Node.Store.NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "records" });
            var label = store.Read(reader =>
            {
                using var command = reader.CreateCommand("SELECT label FROM process_record WHERE attempt_id = $attempt AND pid = $pid;");
                command.Parameters.AddWithValue("$attempt", attempt.Value.ToByteArray());
                command.Parameters.AddWithValue("$pid", pid.Value);
                return command.ExecuteScalar();
            });
            Assert.Equal((long)ProcessLabel.Escaped, label);
        }
        finally
        {
            if (pid is { } leftoverPid && Directory.Exists($"/proc/{leftoverPid}"))
            {
                try
                {
                    using var leftover = Process.GetProcessById(leftoverPid);
                    if (leftover.ProcessName == "sleep")
                    {
                        leftover.Kill();
                        leftover.WaitForExit(5_000);
                    }
                }
                catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                }
            }
        }
    }

    // ------------------------------------------------------------------------------------------------- process rates

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    public async Task AProcessRateFollowsItsRecentCpuWhileAnAttemptRunsOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        await RecentRatesAsync();
    }

    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    public async Task AProcessRateFollowsItsRecentCpuWhileAnAttemptRunsOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job platform test.");
        await RecentRatesAsync();
    }

    /// <summary>
    /// isolation=exclusive (CPU rates): a process that existed before the attempt started (this test's own process) idles for 20 s while
    /// the attempt runs, then spins two threads. Its <c>ListProcesses</c> rate must be that of the last few seconds (about two cores), not
    /// an average reaching back to a base taken when the attempt started: on Windows the monitor reads the table every second while an
    /// attempt runs, and the rate base must still move every 5 s.
    /// </summary>
    private static async Task RecentRatesAsync()
    {
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        await using var channel = await ChannelAsync(node);
        var task = await SubmitAsync(channel, [TestNode.TestLoad, "mem-ramp", "--target-mb", "16", "--hold-ms", "300000"]);
        await RunningAttemptAsync(channel, task);
        await Task.Delay(TimeSpan.FromSeconds(20), Ct);

        using var spin = new CancellationTokenSource();
        void Spin()
        {
            while (!spin.IsCancellationRequested)
            {
                Thread.SpinWait(1_000);
            }
        }

        var threads = Enumerable.Range(0, 2).Select(_ => new Thread(Spin) { IsBackground = true }).ToList();
        threads.ForEach(thread => thread.Start());
        var rates = new List<uint>();
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(8), Ct);
            for (var query = 0; query < 4; query++)
            {
                var self = (await ProcessesAsync(channel, new ProcessFilter { TopN = 500 })).Single(process => process.Process.Pid == (uint)Environment.ProcessId);
                rates.Add(self.Usage.HasCpuMillicores ? self.Usage.CpuMillicores : 0);
                await Task.Delay(600, Ct);
            }
        }
        finally
        {
            await spin.CancelAsync();
            threads.ForEach(thread => thread.Join());
        }

        TestContext.Current.TestOutputHelper?.WriteLine($"this process's rates while two threads spun: {string.Join(", ", rates)} millicores");
        await CancelAsync(channel, task);
        Assert.All(rates, rate => Assert.True(rate >= 1_500, $"a rate of {rate} millicores while two threads spun for 8 s ({string.Join(", ", rates)})"));
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
        var crossing = await SubmitAsync(channel, [], script: $"\"{wsl}\" --list --quiet & ping -n 60 127.0.0.1 >nul");
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
        Assert.All(all.Where(process => process.Label == ProcessLabel.Managed), process => Assert.True(crossing.Equals(process.TaskId) || plain.Equals(process.TaskId), $"{process.Process.ImageName} ({process.Process.Pid}) is MANAGED outside both tasks"));
        var vm = all.Where(process => process.Process.ImageName.StartsWith("vmmem", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.All(vm, process =>
        {
            Assert.Equal(ProcessLabel.GuestVm, process.Label);
            Assert.Null(process.TaskId);
        });
        TestContext.Current.TestOutputHelper?.WriteLine(vm.Count == 0
            ? "No WSL VM worker runs on this machine: the GUEST_VM label was not observed (A-L01 stays unverified)."
            : $"WSL VM worker(s): {string.Join(", ", vm.Select(process => $"{process.Process.ImageName} ({process.Process.Pid}, {process.Usage.MemBytes} bytes)"))}");
        await TestNode.WaitAsync(() => TestNode.LogEvents(node.NodeLog, "resources.crosses_vm_boundary").Count > 0, Bound, "the crossing in the node log");
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
        await PeakObservedAsync(_ => [], $"\"{TestNode.TestLoad}\" mem-ramp --target-mb 256 --step-mb 32 --hold-ms 4000 --report nul && "
            + $"\"{TestNode.TestLoad}\" output --bytes 805306368 --line-bytes 4096 && ping -n 7 127.0.0.1 >nul");
    }

    /// <summary>
    /// isolation=exclusive (memory figures): the attempt holds 256 MiB of its own memory, frees it, then writes 768 MiB to a file (page
    /// cache: on Linux charged to the unit's cgroup, which the test reads directly to prove the cache was there; on Windows the file cache
    /// is never in a process's private working set). Its samples' peak reaches the 256 MiB, stays far below the cache, and never
    /// decreases, while the current memory falls after the ramp ends (03 section 3).
    /// </summary>
    private static async Task PeakObservedAsync(Func<string, string[]> argv, string? script = null)
    {
        // A disk-backed data root: on tmpfs the output would be shared memory, which is not reclaimable cache.
        await using var node = TestNode.Create(OperatingSystem.IsWindows() ? null : TestNode.DiskParent);
        await node.StartNodeAsync();
        await using var channel = await ChannelAsync(node);
        var task = await SubmitAsync(channel, argv(node.Root), memExpected: 1024 * MiB, memCeiling: 2048 * MiB, script: script);
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
    /// itself reads available memory below the Critical threshold, the node must stop one of the three preemptible BACKGROUND attempts
    /// within 1 s of sampling plus 5 s of persistence (03 section 5.4), journal it and notify; a non-preemptible attempt keeps running.
    /// The test ends the allocator as soon as the node logs the first preemption: memory has recovered before the victim has finalized,
    /// so the node must stop no other attempt, neither then nor during the 5 s exit persistence of the Critical level (only as many as
    /// needed; CriticalShedding).
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
        var preemptibles = new List<Id>();
        for (var index = 0; index < 3; index++)
        {
            preemptibles.Add(await SubmitAsync(channel, [TestNode.TestLoad, "mem-ramp", "--target-mb", "32", "--hold-ms", "300000"],
                priority: Priority.Background, preemptible: true));
        }

        var protectedTask = await SubmitAsync(channel, [TestNode.TestLoad, "mem-ramp", "--target-mb", "32", "--hold-ms", "300000"]);
        var attempts = new List<Id>();
        foreach (var task in preemptibles)
        {
            attempts.Add(await RunningAttemptAsync(channel, task));
        }

        await RunningAttemptAsync(channel, protectedTask);
        await SnapshotAsync(channel, snapshot => snapshot.Pressure == PressureLevel.Normal && snapshot.RunningAttempts == 4);

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

        // The first preemption, read from the node log as soon as it is written; the allocator ends at once, so memory recovers before the
        // victim has finalized and before the node judges again.
        await TestNode.WaitAsync(() => TestNode.LogEvents(node.NodeLog, "execution.preempted").Count > 0, Bound, "the preemption");
        allocator.Kill();
        await allocator.WaitForExitAsync(Ct);
        var preempted = TestNode.LogEvents(node.NodeLog, "execution.preempted")[0];
        var victimName = preempted.GetProperty("fields").GetProperty("attempt").GetString();
        var acted = DateTimeOffset.Parse(preempted.GetProperty("at").GetString()!, CultureInfo.InvariantCulture);
        var reaction = acted - crossed.Value;
        var changes = TestNode.LogEvents(node.NodeLog, "resources.pressure");
        var levels = changes.Select(item => item.GetProperty("fields").GetProperty("level").GetString()).ToList();
        TestContext.Current.TestOutputHelper?.WriteLine(
            $"available below critical ({threshold / MiB:0} MiB) at {crossed:O}; preempted at {acted:O}; reaction {reaction.TotalMilliseconds:0} ms; levels: "
            + string.Join("; ", changes.Select(item => $"{item.GetProperty("at").GetString()} {item.GetProperty("fields").GetProperty("level").GetString()} "
                + $"({item.GetProperty("fields").GetProperty("trigger").GetString()})")));

        if (Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT") is { Length: > 0 } directory)
        {
            // Evidence for the record: the reaction time and the level changes of this run.
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "pressure-reaction-" + (OperatingSystem.IsWindows() ? "windows" : "linux") + ".json"),
                new System.Text.Json.Nodes.JsonObject
                {
                    ["crossedAt"] = crossed.Value.ToString("O", CultureInfo.InvariantCulture),
                    ["actedAt"] = acted.ToString("O", CultureInfo.InvariantCulture),
                    ["reactionMs"] = Math.Round(reaction.TotalMilliseconds),
                    ["criticalThresholdBytes"] = (long)threshold,
                    ["levels"] = new System.Text.Json.Nodes.JsonArray([.. levels.Select(level => (System.Text.Json.Nodes.JsonNode?)level)]),
                }.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }

        // 03 section 5.4: detected within 1 s of sampling plus 5 s of persistence and acted on at once (the test polls every 50 ms).
        Assert.True(reaction <= TimeSpan.FromSeconds(6.25), $"the node acted {reaction.TotalMilliseconds:0} ms after available memory fell below Critical");
        Assert.True(reaction >= TimeSpan.FromSeconds(4), $"the node acted {reaction.TotalMilliseconds:0} ms after the crossing, before 5 s of persistence");
        Assert.Contains("Critical", levels);

        var victim = attempts.FindIndex(attempt => IdText.Format(attempt) == victimName);
        Assert.True(victim >= 0, $"the preempted attempt {victimName} is not one of the preemptible ones");
        await TestNode.WaitAsync(async () => await TaskStateAsync(channel, preemptibles[victim]) is TaskState.Failed or TaskState.Cancelled, Bound, "the victim to end");
        var record = await AttemptAsync(channel, attempts[victim]);
        Assert.Equal(TerminationReason.Preempted, record.Result.TerminationReason);
        Assert.Contains("critical memory pressure", record.Result.Detail, StringComparison.Ordinal);

        // Past the exit persistence of the level (5 s) with a margin: the other two preemptible attempts and the protected one still run,
        // and the node stopped exactly one.
        await TestNode.WaitAsync(async () => (await SnapshotAsync(channel, _ => true)).Pressure != PressureLevel.Critical, Bound, "the level to leave Critical");
        await Task.Delay(TimeSpan.FromSeconds(3), Ct);
        Assert.Single(TestNode.LogEvents(node.NodeLog, "execution.preempted"));
        for (var index = 0; index < preemptibles.Count; index++)
        {
            if (index != victim)
            {
                Assert.Equal(TaskState.Running, await TaskStateAsync(channel, preemptibles[index]));
            }
        }

        Assert.Equal(TaskState.Running, await TaskStateAsync(channel, protectedTask));
        var notifications = await channel.Node.ListNotificationsAsync(new NodeServiceListNotificationsRequest { Meta = new RequestMeta() },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
        Assert.Contains(notifications.Value.Notifications, item => item.Title == "Critical memory pressure");

        await CancelAsync(channel, protectedTask);
        for (var index = 0; index < preemptibles.Count; index++)
        {
            if (index != victim)
            {
                await CancelAsync(channel, preemptibles[index]);
            }
        }
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

    /// <summary>Submits <paramref name="argv"/>, or with <paramref name="script"/> a <c>cmd</c> shell script (Windows quoting is the node's).</summary>
    private static async Task<Id> SubmitAsync(NodeChannel channel, string[] argv, Priority priority = Priority.Normal, bool preemptible = false,
        long memExpected = 0, long memCeiling = 0, string? script = null)
    {
        var command = new ArgvCommand();
        command.Argv.Add(argv);
        var spec = new TaskSpec
        {
            Command = script is null ? new CommandSpec { Argv = command } : new CommandSpec { Shell = new ShellCommand { Kind = ShellKind.Cmd, Script = script } },
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
