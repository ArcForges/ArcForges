// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Workstation benchmarks of 15-performance-targets section 1 (category=perf; never run by default): the CLI cold start
/// (<c>arcforges --version</c>, p50 at most 40 ms and p95 at most 80 ms) and the status round trip (<c>arcforges status --json</c> with
/// the node running, p50 at most 60 ms), each 50 runs after one warm-up, measured by <c>arcforges-bench startup</c>, and the idle CPU while
/// the node samples resources (at most 0.5% of one core). Targets apply to
/// Release Native AOT builds: set ARCFORGES_HOST_PATH to the published binary. Results are written to ARCFORGES_BENCH_OUTPUT (a
/// directory) when it is set.
/// </summary>
/// <remarks>
/// The retired V1 Task admission, Windows holder, Linux guard, and output capture benchmarks remain in this file at
/// <c>eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a</c> with their original fixtures and limits.
/// </remarks>
[Trait("category", "perf")]
[Trait("isolation", "exclusive")]
[TestClass(DisableParallelization = true)]
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
    /// Measures the Node's idle CPU after a 30 s warm-up. V2 resource snapshots before and after the measurement
    /// show that the background sampler continued without a Run or a connected watcher.
    /// </summary>
    [Fact(Timeout = 1_500_000)]
    public async Task IdleCpuWhileSampling()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireNativeHost();
        var seconds = int.TryParse(Environment.GetEnvironmentVariable("ARCFORGES_IDLE_SECONDS"), System.Globalization.CultureInfo.InvariantCulture, out var configured)
            ? configured
            : 600;
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        using var process = Process.GetProcessById(node.NodePid());
        await Task.Delay(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        await using var channel = CloudLinkCenterControlTests.OpenChannel(node);
        var resources = new ResourceService.ResourceServiceClient(channel.CallInvoker);
        var firstSample = await SampleAsync(resources);
        process.Refresh();
        var before = process.TotalProcessorTime;
        var watch = Stopwatch.StartNew();
        await Task.Delay(TimeSpan.FromSeconds(seconds), TestContext.Current.CancellationToken);
        process.Refresh();
        var cpu = process.TotalProcessorTime - before;
        var elapsed = watch.Elapsed;
        var percent = cpu.TotalMilliseconds / elapsed.TotalMilliseconds * 100;
        var lastSample = await SampleAsync(resources);
        Assert.Equal(firstSample.SampleEpoch, lastSample.SampleEpoch);
        Assert.True(lastSample.SampleSequence >= firstSample.SampleSequence);
        var samples = lastSample.SampleSequence - firstSample.SampleSequence;
        var result = new System.Text.Json.Nodes.JsonObject
        {
            ["name"] = "idle-cpu",
            ["seconds"] = Math.Round(elapsed.TotalSeconds, 1),
            ["cpuMs"] = Math.Round(cpu.TotalMilliseconds, 1),
            ["percentOfOneCore"] = Math.Round(percent, 3),
            ["machineSamples"] = samples,
            ["host"] = TestNode.Host,
        };
        TestContext.Current.TestOutputHelper?.WriteLine(result.ToJsonString());
        if (Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT") is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "idle-cpu-" + (OperatingSystem.IsWindows() ? "windows" : "linux") + ".json"),
                result.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }

        Assert.True(samples >= (ulong)Math.Max(0, (seconds / 5) - 2), $"the Node produced {samples} samples in {seconds} s");
        Assert.True(percent <= 0.5, $"the idle node used {percent:0.000}% of one core ({cpu.TotalMilliseconds:0} ms in {elapsed.TotalSeconds:0} s)");
    }

    private static async Task<ResourceSnapshot> SampleAsync(ResourceService.ResourceServiceClient resources)
    {
        var reply = await resources.GetBudgetAsync(new ResourceServiceGetBudgetRequest
        {
            Meta = new() { CorrelationId = CommandIds.New() },
            ScopeKind = "node",
        }, deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(reply.Error);
        var sample = reply.Value.Snapshot;
        Assert.False(sample.Stale);
        Assert.True(sample.HasSampleSequence && sample.SampleSequence > 0);
        return sample;
    }

    private static async Task<JsonElement> BenchAsync(string name, TestNode? node, string[] arguments)
    {
        var bench = Environment.GetEnvironmentVariable("ARCFORGES_BENCH_PATH") is { Length: > 0 } configured
            ? configured
            : Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "arcforges-bench.exe" : "arcforges-bench");
        var keep = Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT") is { Length: > 0 };
        var output = keep
            ? Path.Combine(Environment.GetEnvironmentVariable("ARCFORGES_BENCH_OUTPUT")!, name + "-" + (OperatingSystem.IsWindows() ? "windows" : "linux") + ".json")
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
        try
        {
            Assert.True(run.ExitCode == 0, run.ToString());
            return JsonDocument.Parse(File.ReadAllBytes(output)).RootElement.Clone();
        }
        finally
        {
            if (!keep)
            {
                // Without ARCFORGES_BENCH_OUTPUT the result file is the test's own temporary file.
                File.Delete(output);
            }
        }
    }

    private static void RequireNativeHost() => Assert.SkipWhen(string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ARCFORGES_HOST_PATH")),
        "The targets of 15 section 1 apply to Release Native AOT builds: set ARCFORGES_HOST_PATH to the published arcforges.");

    private static string Summary(JsonElement result) =>
        $"{result.GetProperty("name").GetString()}: p50 {result.GetProperty("p50Ms").GetDouble()} ms, p95 {result.GetProperty("p95Ms").GetDouble()} ms";
}
