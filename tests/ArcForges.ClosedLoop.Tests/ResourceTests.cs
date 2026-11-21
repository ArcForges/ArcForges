// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Tests;

namespace ArcForges.ClosedLoop.Tests;

// The native V1 fresh-launch ResourceTests fixtures reproduce at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a
// with the native eng/verify.py run-and-report profile. They cover managed attempt sampling, WSL, escaped-process
// approval and cleanup, pressure timing, admission headroom, and process effects across a crash.
/// <summary>Machine resource snapshots, process attribution and samples from the local Node and CLI.</summary>
[Trait("loop", "local")]
public sealed partial class ResourceTests
{
    private const long MiB = 1024L * 1024;
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(90);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    // ------------------------------------------------------------------------------------------------- snapshot and labels

    /// <summary>
    /// The node of a closed-loop test sees only itself and its attempts on the machine (MachineIsolation): TestNode passes
    /// <c>ARCFORGES_TEST_MACHINE=isolated</c> and the executable under test (the JIT build, or the Native AOT host through
    /// <c>ARCFORGES_HOST_PATH</c>) reads it with <c>--test-mode</c>. Once the snapshot's evaluation time is 6 s past the first one (more
    /// evaluations than the 5 s pressure persistence) the CLI's snapshot shows <c>U = 0</c>, <c>B_cpu = max(min_managed_cpu, C - R)</c>,
    /// <c>B_mem = C - R</c> and Normal, whatever runs beside the test. This test process is outside the node and its attempts, so a node
    /// that read the live machine would count its memory in <c>U_mem</c>.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task ATestNodeSeesOnlyItselfOnTheMachineThroughTheCli()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        JsonElement snapshot = default;
        async Task<JsonElement> ReadAsync()
        {
            var run = await node.LegacyCliAsync("resources", "--json");
            Assert.Equal(0, run.ExitCode);
            return snapshot = run.Json();
        }

        static long Number(JsonElement element) =>
            element.ValueKind == JsonValueKind.String ? long.Parse(element.GetString()!, CultureInfo.InvariantCulture) : element.GetInt64();
        static long EvaluatedAtMs(JsonElement at) =>
            (Number(at.GetProperty("unixSeconds")) * 1000) + ((at.TryGetProperty("nanos", out var nanos) ? Number(nanos) : 0) / 1_000_000);
        await TestNode.WaitAsync(async () => (await ReadAsync()).TryGetProperty("budgetCpuMillicores", out _), Bound, "the first evaluation");
        var first = EvaluatedAtMs(snapshot.GetProperty("at"));
        await TestNode.WaitAsync(async () => EvaluatedAtMs((await ReadAsync()).GetProperty("at")) - first >= 6_000, Bound,
            "an evaluation 6 s after the first");
        long Value(string name) => Number(snapshot.GetProperty(name));
        Assert.Equal(0, Value("unmanagedCpuMillicores"));
        Assert.Equal(0, Value("unmanagedMemBytes"));
        Assert.Equal(Math.Max(1000, Value("capacityCpuMillicores") - Value("reserveCpuMillicores")), Value("budgetCpuMillicores"));
        Assert.Equal(Value("capacityMemBytes") - Value("reserveMemBytes"), Value("budgetMemBytes"));
        Assert.Equal("PRESSURE_LEVEL_NORMAL", snapshot.GetProperty("pressure").GetString());
    }

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
    /// Compare live memory to the OS, check the budget equations, and observe the Node and an unmanaged load.
    /// </summary>
    private static async Task SnapshotAndLabelsAsync()
    {
        await using var node = TestNode.Create();

        // The live machine (exclusive): the snapshot is compared with the operating system's figures.
        node.LiveMachine = true;
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

        var unmanaged = node.Start(TestNode.TestLoad, ["cpu", "--threads", "1", "--iterations", "20000000000"]);
        List<ProcessView> processes = [];
        await TestNode.WaitAsync(async () =>
        {
            processes = await ProcessesAsync(channel, new ProcessFilter { TopN = 500 });
            return processes.Any(process => process.Process.Pid == (uint)unmanaged.Id && process.Usage.CpuMillicores > 0);
        }, Bound, "the unmanaged fixture's sampled CPU rate");

        // Ordered by the CPU rate, then by the memory figure each view shows (the detailed one, not the table's).
        for (var index = 1; index < processes.Count; index++)
        {
            var (first, second) = (processes[index - 1].Usage, processes[index].Usage);
            var (firstCpu, secondCpu) = (first.HasCpuMillicores ? first.CpuMillicores : 0, second.HasCpuMillicores ? second.CpuMillicores : 0);
            Assert.True(firstCpu > secondCpu || (firstCpu == secondCpu && first.MemBytes >= second.MemBytes),
                $"process {index} ({processes[index].Process.ImageName}: {secondCpu} mc, {second.MemBytes} B) is out of order after {processes[index - 1].Process.ImageName} ({firstCpu} mc, {first.MemBytes} B)");
        }

        Assert.DoesNotContain(processes, process => process.Label == ProcessLabel.Managed);
        var outside = processes.Single(process => process.Process.Pid == (uint)unmanaged.Id);
        Assert.Equal(ProcessLabel.Unmanaged, outside.Label);
        Assert.Null(outside.TaskId);
        Assert.Contains(processes, process => process.Process.Pid == (uint)node.NodePid() && process.Label == ProcessLabel.NodeSelf);
        Assert.Contains(processes, process => process.Process.Pid == (uint)Environment.ProcessId && process.Label == ProcessLabel.Unmanaged);

        if (OperatingSystem.IsLinux())
        {
            // The process belongs to this fixture, outside Node custody.
            var refusal = await channel.Resources.TerminateProcessAsync(new ResourceServiceTerminateProcessRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                Process = outside.Process,
            }, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
            Assert.Equal("not_found", refusal.Error?.Code);
            Assert.False(unmanaged.HasExited);
        }

        Assert.Equal(0, (await node.LegacyCliAsync("resources")).ExitCode);
        await TestNode.WaitAsync(async () => (await MachineSamplesAsync(channel)).Samples.Count >= 1, Bound, "a machine sample");
        unmanaged.Kill();
    }

    private static async Task<NodeChannel> ChannelAsync(TestNode node)
    {
        var channel = NodeChannel.Create(OperatingSystem.IsWindows() ? LocalRpcEndpoint.NamedPipe(node.Endpoint) : LocalRpcEndpoint.UnixDomainSocket(node.Endpoint));
        var hello = ClientProcess.Hello(ClientKind.Cli);
        hello.CiMarkers.Clear();
        Assert.Null((await channel.Node.HelloAsync(new NodeServiceHelloRequest { Hello = hello }, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct)).Error);
        return channel;
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

    private static async Task<ResourceServiceGetSamplesValue> MachineSamplesAsync(NodeChannel channel)
    {
        var response = await channel.Resources.GetSamplesAsync(new ResourceServiceGetSamplesRequest { Meta = new RequestMeta(), Scope = SampleScope.Machine },
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
