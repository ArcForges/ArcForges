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
