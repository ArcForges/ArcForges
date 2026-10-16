// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text.Json;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Workstation benchmarks of 15-performance-targets section 1 (category=perf; never run by default): the CLI cold start
/// (<c>arcforges --version</c>, p50 at most 40 ms and p95 at most 80 ms) and the status round trip (<c>arcforges status --json</c> with
/// the node running, p50 at most 60 ms), each 50 runs after one warm-up, measured by <c>arcforges-bench startup</c>. Targets apply to
/// Release Native AOT builds: set ARCFORGES_HOST_PATH to the published binary. Results are written to ARCFORGES_BENCH_OUTPUT (a
/// directory) when it is set.
/// </summary>
[Trait("category", "perf")]
[Collection(SerialProcessTests.Name)]
public sealed class Benchmarks
{
    [Fact(Timeout = 300_000)]
    public async Task CliColdStart()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireNativeHost();
        var result = await BenchAsync("cli-cold-start", null, ["--arg", "--version"]);
        Assert.True(result.GetProperty("p50Ms").GetDouble() <= 40, Summary(result));
        Assert.True(result.GetProperty("p95Ms").GetDouble() <= 80, Summary(result));
    }

    [Fact(Timeout = 300_000)]
    public async Task StatusRoundTrip()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireNativeHost();
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        var result = await BenchAsync("status-round-trip", node, ["--arg", "status", "--arg", "--json", "--arg", "--test-mode"]);
        Assert.True(result.GetProperty("p50Ms").GetDouble() <= 60, Summary(result));
    }

    /// <summary>
    /// Admission latency (15 section 1: submit to <c>STARTED</c> when capacity exists, p95 at most 150 ms on Windows, 500 submissions): each
    /// task is submitted after the previous one finished, so capacity always exists; the latency is the attempt's <c>started_at</c> minus the
    /// task's <c>created_at</c>, both stamped by the node. While one attempt runs, the private bytes of its <c>exec-wrap</c> holder (which is
    /// also its disk guard) are measured against the 3 MB per-execution helper target.
    /// </summary>
    [Fact(Timeout = 600_000)]
    public async Task AdmissionLatencyAndHolderOverhead()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireNativeHost();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The Windows holder; Linux is AdmissionLatencyAndGuardFootprintOnLinux.");
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        await using var channel = ArcForges.Client.NodeChannel.Create(ArcForges.LocalRpc.LocalRpcEndpoint.NamedPipe(node.Endpoint));
        var hello = ArcForges.Client.ClientProcess.Hello(ArcForges.Contracts.Node.V1.ClientKind.Cli);
        hello.CiMarkers.Clear();
        Assert.Null((await channel.Node.HelloAsync(new ArcForges.Contracts.Node.V1.NodeServiceHelloRequest { Hello = hello }, deadline: DateTime.UtcNow.AddSeconds(10),
            cancellationToken: TestContext.Current.CancellationToken)).Error);
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var latencies = new List<double>();
        for (var index = 0; index < 510; index++)
        {
            var task = await RunAsync(channel, [cmd, "/d", "/c", "exit 0"]);
            var created = ArcForges.Client.ProtoTime.ToDateTimeOffset(task.CreatedAt)!.Value;
            var started = ArcForges.Client.ProtoTime.ToDateTimeOffset(task.CurrentAttempt.StartedAt)!.Value;
            if (index >= 10)
            {
                latencies.Add((started - created).TotalMilliseconds);
            }
        }

        latencies.Sort();
        var p50 = latencies[(int)Math.Ceiling(0.50 * latencies.Count) - 1];
        var p95 = latencies[(int)Math.Ceiling(0.95 * latencies.Count) - 1];

        // The holder of a running attempt: the arcforges process (not the node) whose command line runs exec-wrap.
        var marker = Path.Combine(node.Root, "holder.txt");
        var submit = await channel.Tasks.SubmitTaskAsync(new ArcForges.Contracts.Node.V1.TaskServiceSubmitTaskRequest
        {
            Meta = Meta(),
            Spec = Spec([TestNode.TestLoad, "signal", "--hold-ms", "30000", "--marker", marker]),
        }, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(submit.Error);
        await TestNode.WaitAsync(() => File.Exists(marker), TimeSpan.FromSeconds(30), "the held attempt");
        await Task.Delay(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        var nodePid = node.NodePid();
        var holders = node.LiveProcesses().Where(process => process.Id != nodePid).ToList();
        Assert.NotEmpty(holders);
        var holderPrivate = holders.Max(process =>
        {
            process.Refresh();
            return process.PrivateMemorySize64;
        });
        Assert.Null((await channel.Tasks.CancelTaskAsync(new ArcForges.Contracts.Node.V1.TaskServiceCancelTaskRequest { Meta = Meta(), TaskId = submit.Value.TaskId },
            deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: TestContext.Current.CancellationToken)).Error);

        var result = new System.Text.Json.Nodes.JsonObject
        {
            ["name"] = "admission-latency",
            ["runs"] = latencies.Count,
            ["p50Ms"] = Math.Round(p50, 2),
            ["p95Ms"] = Math.Round(p95, 2),
            ["maxMs"] = Math.Round(latencies[^1], 2),
            ["holderPrivateBytes"] = holderPrivate,
            ["host"] = TestNode.Host,
        };
        TestContext.Current.TestOutputHelper?.WriteLine(result.ToJsonString());
        if (Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT") is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "admission-latency-windows.json"), result.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }

        Assert.True(p95 <= 150, $"admission latency p95 {p95:0.0} ms (p50 {p50:0.0} ms) exceeds 150 ms");
        Assert.True(holderPrivate <= 3L << 20, $"the exec-wrap holder uses {holderPrivate} private bytes (target 3 MB)");
    }

    /// <summary>
    /// Linux admission latency (15 section 2: submit to <c>STARTED</c> when capacity exists, p95 at most 250 ms including the transient-unit
    /// job, 500 submissions) and the disk guard's footprint (<c>arcforges node guard</c>, at most 8 MB private, idle while the heartbeat is
    /// fresh): each task runs <c>/bin/true</c> after the previous one finished; the guard runs against the node's data root while it measures.
    /// </summary>
    [Fact(Timeout = 900_000)]
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    public async Task AdmissionLatencyAndGuardFootprintOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireNativeHost();
        Assert.SkipWhen(ArcForges.Tests.SystemdTestEnvironment.SkipReason is not null, ArcForges.Tests.SystemdTestEnvironment.SkipReason ?? string.Empty);
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        await using var channel = ArcForges.Client.NodeChannel.Create(ArcForges.LocalRpc.LocalRpcEndpoint.UnixDomainSocket(node.Endpoint));
        var hello = ArcForges.Client.ClientProcess.Hello(ArcForges.Contracts.Node.V1.ClientKind.Cli);
        hello.CiMarkers.Clear();
        Assert.Null((await channel.Node.HelloAsync(new ArcForges.Contracts.Node.V1.NodeServiceHelloRequest { Hello = hello }, deadline: DateTime.UtcNow.AddSeconds(10),
            cancellationToken: TestContext.Current.CancellationToken)).Error);
        using var guard = node.Start(TestNode.Host, ["node", "guard", "--test-mode"]);
        var latencies = new List<double>();
        for (var index = 0; index < 510; index++)
        {
            var task = await RunAsync(channel, ["/bin/true"]);
            var created = ArcForges.Client.ProtoTime.ToDateTimeOffset(task.CreatedAt)!.Value;
            var started = ArcForges.Client.ProtoTime.ToDateTimeOffset(task.CurrentAttempt.StartedAt)!.Value;
            if (index >= 10)
            {
                latencies.Add((started - created).TotalMilliseconds);
            }
        }

        latencies.Sort();
        var p50 = latencies[(int)Math.Ceiling(0.50 * latencies.Count) - 1];
        var p95 = latencies[(int)Math.Ceiling(0.95 * latencies.Count) - 1];
        var guardPrivate = PrivateBytes(guard.Id);
        var guardCpu = File.ReadAllText($"/proc/{guard.Id}/stat").Split(") ")[1].Split(' ');
        guard.Kill();
        await guard.WaitForExitAsync(TestContext.Current.CancellationToken);
        var result = new System.Text.Json.Nodes.JsonObject
        {
            ["name"] = "admission-latency-linux",
            ["runs"] = latencies.Count,
            ["p50Ms"] = Math.Round(p50, 2),
            ["p95Ms"] = Math.Round(p95, 2),
            ["maxMs"] = Math.Round(latencies[^1], 2),
            ["guardPrivateBytes"] = guardPrivate,
            ["guardCpuTicks"] = long.Parse(guardCpu[12], System.Globalization.CultureInfo.InvariantCulture) + long.Parse(guardCpu[13], System.Globalization.CultureInfo.InvariantCulture),
            ["host"] = TestNode.Host,
        };
        TestContext.Current.TestOutputHelper?.WriteLine(result.ToJsonString());
        if (Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT") is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "admission-latency-linux.json"), result.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }

        Assert.True(p95 <= 250, $"admission latency p95 {p95:0.0} ms (p50 {p50:0.0} ms) exceeds 250 ms");
        Assert.True(guardPrivate <= 8L << 20, $"the guard uses {guardPrivate} private bytes (target 8 MB)");
    }

    /// <summary>
    /// Private bytes of a Linux process, the counterpart of the Windows private bytes (commit charge): <c>Private_Dirty + Swap</c> of
    /// <c>smaps_rollup</c>. Clean pages of the executable image are left out; they are page cache the kernel can drop and re-read, shared
    /// with every other <c>arcforges</c> process (the Windows figure leaves the image out the same way).
    /// </summary>
    private static long PrivateBytes(int pid)
    {
        long total = 0;
        foreach (var line in File.ReadAllLines($"/proc/{pid}/smaps_rollup"))
        {
            if (line.StartsWith("Private_Dirty:", StringComparison.Ordinal) || line.StartsWith("Swap:", StringComparison.Ordinal))
            {
                total += long.Parse(line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1], System.Globalization.CultureInfo.InvariantCulture) * 1024;
            }
        }

        return total;
    }

    /// <summary>
    /// Output capture (15 section 1: at least 200 MB/s sustained, no loss): <c>arcforges-testload output</c> writes 1.5 GiB at the maximum
    /// rate under the node (below the default 2 GiB output limit); the captured <c>stdout.bin</c> must hash to the digest the writer computed
    /// itself, and the bytes over the attempt's run time give the sustained rate.
    /// </summary>
    [Fact(Timeout = 600_000)]
    public async Task OutputCapture()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireNativeHost();
        const long Bytes = 3L << 29;

        // On Linux the captured output lives on a disk-backed file system like a real data root: on tmpfs (/tmp in WSL Debian) the file's
        // pages are shared memory charged to the attempt's cgroup, which cannot reclaim them without swap and throttles at MemoryHigh.
        await using var node = TestNode.Create(OperatingSystem.IsWindows() ? null : AppContext.BaseDirectory);
        await node.StartNodeAsync();
        await using var channel = ArcForges.Client.NodeChannel.Create(OperatingSystem.IsWindows()
            ? ArcForges.LocalRpc.LocalRpcEndpoint.NamedPipe(node.Endpoint)
            : ArcForges.LocalRpc.LocalRpcEndpoint.UnixDomainSocket(node.Endpoint));
        var hello = ArcForges.Client.ClientProcess.Hello(ArcForges.Contracts.Node.V1.ClientKind.Cli);
        hello.CiMarkers.Clear();
        Assert.Null((await channel.Node.HelloAsync(new ArcForges.Contracts.Node.V1.NodeServiceHelloRequest { Hello = hello }, deadline: DateTime.UtcNow.AddSeconds(10),
            cancellationToken: TestContext.Current.CancellationToken)).Error);
        var report = Path.Combine(node.Root, "report.json");
        var task = await RunAsync(channel, [TestNode.TestLoad, "output", "--bytes", Bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--line-bytes", "4096", "--report", report]);
        var attempt = task.CurrentAttempt;
        var seconds = (ArcForges.Client.ProtoTime.ToDateTimeOffset(attempt.FinishedAt)!.Value - ArcForges.Client.ProtoTime.ToDateTimeOffset(attempt.StartedAt)!.Value).TotalSeconds;
        var captured = Path.Combine(node.DataRoot, "logs", ArcForges.Client.IdText.Format(attempt.AttemptId), "stdout.bin");
        Assert.Equal(Bytes, new FileInfo(captured).Length);
        string digest;
        using (var stream = new FileStream(captured, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20))
        {
            digest = Convert.ToHexStringLower(await System.Security.Cryptography.SHA256.HashDataAsync(stream, TestContext.Current.CancellationToken));
        }

        var expected = JsonDocument.Parse(File.ReadAllBytes(report)).RootElement.GetProperty("streamDigests").GetProperty("stdout").GetString();
        var rate = Bytes / 1e6 / seconds;
        var result = new System.Text.Json.Nodes.JsonObject
        {
            ["name"] = "output-capture",
            ["bytes"] = Bytes,
            ["seconds"] = Math.Round(seconds, 3),
            ["mbPerSecond"] = Math.Round(rate, 1),
            ["digestMatches"] = digest == expected,
            ["host"] = TestNode.Host,
        };
        TestContext.Current.TestOutputHelper?.WriteLine(result.ToJsonString());
        if (Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT") is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "output-capture-" + (OperatingSystem.IsWindows() ? "windows" : "linux") + ".json"), result.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }

        Assert.Equal(expected, digest);
        Assert.True(rate >= 200, $"output capture {rate:0.0} MB/s is below 200 MB/s");
    }

    private static ArcForges.Contracts.Node.V1.TaskSpec Spec(string[] argv)
    {
        var command = new ArcForges.Contracts.Node.V1.ArgvCommand();
        command.Argv.Add(argv);
        return new ArcForges.Contracts.Node.V1.TaskSpec
        {
            Command = new ArcForges.Contracts.Node.V1.CommandSpec { Argv = command },
            WorkingDirectory = Path.GetTempPath(),
            Environment = new ArcForges.Contracts.Node.V1.EnvironmentSpec { Inherit = ArcForges.Contracts.Node.V1.EnvironmentInherit.Node },
        };
    }

    private static ArcForges.Contracts.Foundation.V1.RequestMeta Meta() => new() { CommandId = ArcForges.Client.CommandIds.New(), CorrelationId = ArcForges.Client.CommandIds.New() };

    private static async Task<ArcForges.Contracts.Node.V1.ManagedTask> RunAsync(ArcForges.Client.NodeChannel channel, string[] argv)
    {
        var submit = await channel.Tasks.SubmitTaskAsync(new ArcForges.Contracts.Node.V1.TaskServiceSubmitTaskRequest { Meta = Meta(), Spec = Spec(argv) },
            deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(submit.Error is null, $"SubmitTask: {submit.Error}");
        while (true)
        {
            var wait = await channel.Tasks.WaitTaskAsync(new ArcForges.Contracts.Node.V1.TaskServiceWaitTaskRequest
            {
                Meta = Meta(),
                TaskId = submit.Value.TaskId,
                Target = ArcForges.Contracts.Node.V1.WaitTarget.Terminal,
                WaitMs = 10_000,
            }, deadline: DateTime.UtcNow.AddSeconds(20), cancellationToken: TestContext.Current.CancellationToken);
            Assert.Null(wait.Error);
            if (wait.Value.Reached)
            {
                Assert.Equal(ArcForges.Contracts.Node.V1.TaskState.Succeeded, wait.Value.Task.State);
                return wait.Value.Task;
            }
        }
    }

    private static async Task<JsonElement> BenchAsync(string name, TestNode? node, string[] arguments)
    {
        var bench = Environment.GetEnvironmentVariable("ARCFORGES_BENCH_PATH") is { Length: > 0 } configured
            ? configured
            : Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "arcforges-bench.exe" : "arcforges-bench");
        var output = Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT") is { Length: > 0 } directory
            ? Path.Combine(directory, name + "-" + (OperatingSystem.IsWindows() ? "windows" : "linux") + ".json")
            : Path.Combine(Path.GetTempPath(), "arcforges-" + name + "-" + Guid.NewGuid().ToString("N") + ".json");
        List<string> all = ["startup", "--exe", TestNode.Host, .. arguments, "--runs", "50", "--warmup", "1", "--name", name, "--output", output];
        var start = new ProcessStartInfo(bench) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in all)
        {
            start.ArgumentList.Add(argument);
        }

        if (node is not null)
        {
            foreach (var (key, value) in node.Environment)
            {
                if (value is null)
                {
                    start.Environment.Remove(key);
                }
                else
                {
                    start.Environment[key] = value;
                }
            }
        }

        using var process = Process.Start(start)!;
        var run = await TestNode.CompleteAsync(process, TimeSpan.FromMinutes(4));
        Assert.True(run.ExitCode == 0, run.ToString());
        return JsonDocument.Parse(File.ReadAllBytes(output)).RootElement.Clone();
    }

    private static void RequireNativeHost() => Assert.SkipWhen(string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ARCFORGES_HOST_PATH")),
        "The targets of 15 section 1 apply to Release Native AOT builds: set ARCFORGES_HOST_PATH to the published arcforges.");

    private static string Summary(JsonElement result) =>
        $"{result.GetProperty("name").GetString()}: p50 {result.GetProperty("p50Ms").GetDouble()} ms, p95 {result.GetProperty("p95Ms").GetDouble()} ms";
}
