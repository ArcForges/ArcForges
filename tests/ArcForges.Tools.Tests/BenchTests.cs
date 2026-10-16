// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Bench;

namespace ArcForges.Tools.Tests;

public sealed class BenchTests
{
    [Theory]
    [InlineData(50, 10)]
    [InlineData(95, 19)]
    [InlineData(100, 20)]
    [InlineData(1, 1)]
    public void PercentilesUseTheNearestRank(double percent, double expected)
    {
        double[] samples = [.. Enumerable.Range(1, 20).Reverse().Select(value => (double)value)];

        Assert.Equal(expected, StartupBenchmark.Percentile(samples, percent));
    }

    [Fact]
    public void ASingleSampleIsEveryPercentile()
    {
        Assert.Equal(7.5, StartupBenchmark.Percentile([7.5], 50));
        Assert.Equal(7.5, StartupBenchmark.Percentile([7.5], 95));
    }

    [Fact]
    public void DesktopDirectorySizeExcludesOnlyNativeSkiaAndSymbols()
    {
        using var directory = new TemporaryDirectory();
        directory.File("arcforges-desktop.exe", 3000);
        directory.File("av_libglesv2.dll", 500);
        directory.File("libSkiaSharp.dll", 9000);
        directory.File("libHarfBuzzSharp.so", 7000);
        directory.File("arcforges-desktop.pdb", 4000);
        directory.File("nested/data.bin", 25);

        var (bytes, excluded) = SizeBenchmark.Measure(directory.Path, SizeBenchmark.Targets["arcforges-desktop"]);

        // 15 section 1: "without native Skia libraries"; HarfBuzz and ANGLE count.
        Assert.Equal(10525, bytes);
        Assert.Equal(["arcforges-desktop.pdb", "libSkiaSharp.dll"], excluded);
    }

    [Fact]
    public void SizeTargetsFollowThePerformanceTargets()
    {
        Assert.Equal(45_000_000, SizeBenchmark.Targets["arcforges"].LimitBytes);
        Assert.Equal(4_000_000, SizeBenchmark.Targets["arcforges-supervisor"].LimitBytes);
        Assert.Equal(60_000_000, SizeBenchmark.Targets["arcforges-desktop"].LimitBytes);
        Assert.True(SizeBenchmark.Targets["arcforges-desktop"].IsDirectory);
    }

    [Theory]
    [InlineData("3", 0, true)]
    [InlineData("1", 1, false)]
    public async Task SizeGateExitCodeFollowsTheLimit(string maxMegabytes, int exitCode, bool pass)
    {
        using var directory = new TemporaryDirectory();
        var file = directory.File("arcforges", 2_000_000);
        var output = Path.Combine(directory.Path, "size.json");

        var run = await ToolProcess.RunAsync(
            ToolProcess.Bench,
            ["size", "--path", file, "--max-mb", maxMegabytes, "--name", "fixture", "--output", output],
            TestContext.Current.CancellationToken);

        Assert.Equal(exitCode, run.ExitCode);
        using var written = JsonDocument.Parse(await File.ReadAllBytesAsync(output, TestContext.Current.CancellationToken));
        Assert.Equal(2_000_000, written.RootElement.GetProperty("bytes").GetInt64());
        Assert.Equal(pass, written.RootElement.GetProperty("pass").GetBoolean());
        Assert.Equal("file", written.RootElement.GetProperty("measurement").GetString());
    }

    [Fact]
    public async Task StartupMeasuresEachRunOfARealProcess()
    {
        using var directory = new TemporaryDirectory();
        var output = Path.Combine(directory.Path, "startup.json");
        var relative = Path.GetRelativePath(Environment.CurrentDirectory, ToolProcess.TestLoad).Replace('\\', '/');

        var run = await ToolProcess.RunAsync(
            ToolProcess.Bench,
            ["startup", "--exe", relative, "--arg", "cpu", "--arg", "--iterations", "--arg", "1",
             "--runs", "5", "--warmup", "1", "--name", "testload-cpu", "--output", output],
            TestContext.Current.CancellationToken);

        Assert.True(run.ExitCode == 0, run.StandardError);
        using var written = JsonDocument.Parse(await File.ReadAllBytesAsync(output, TestContext.Current.CancellationToken));
        var result = written.RootElement;
        var samples = result.GetProperty("samplesMs").EnumerateArray().Select(sample => sample.GetDouble()).ToList();
        Assert.Equal(5, samples.Count);
        Assert.All(samples, sample => Assert.True(sample > 0));
        Assert.True(result.GetProperty("p50Ms").GetDouble() <= result.GetProperty("p95Ms").GetDouble());
        Assert.Equal(samples.Min(), result.GetProperty("minMs").GetDouble());
        Assert.Equal(["cpu", "--iterations", "1"], result.GetProperty("command").EnumerateArray().Skip(1).Select(item => item.GetString()));
        Assert.Equal(Path.GetFullPath(ToolProcess.TestLoad), result.GetProperty("command")[0].GetString());
        Assert.True(result.GetProperty("pass").GetBoolean());
    }

    [Theory]
    [InlineData("store-growth --attempts 10", "At least one '--environment <captured environment JSON>' is required.")]
    [InlineData("store-growth --environment x.json --acks maybe", "Option '--acks' is true or false, found 'maybe'.")]
    [InlineData("store-growth --environment x.json --attempts 0", "Option '--attempts' must be a whole number between 1 and 1000000, found '0'.")]
    [InlineData("store-growth --environment x.json --unknown 1", "Unknown option(s): --unknown.")]
    public async Task StoreGrowthRejectsAnInvalidCommandLine(string commandLine, string message)
    {
        var run = await ToolProcess.RunAsync(ToolProcess.Bench, commandLine.Split(' '), TestContext.Current.CancellationToken);

        Assert.Equal(2, run.ExitCode);
        Assert.Contains(message, run.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StartupFailsWhenTheCommandExitsWithAnUnexpectedCode()
    {
        var run = await ToolProcess.RunAsync(
            ToolProcess.Bench,
            ["startup", "--exe", ToolProcess.TestLoad, "--arg", "no-such-scenario", "--runs", "1", "--warmup", "0"],
            TestContext.Current.CancellationToken);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("exited with 2, expected 0", run.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StartupKillsAndFailsARunThatDoesNotExitInTime()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();

        var run = await ToolProcess.RunAsync(
            ToolProcess.Bench,
            ["startup", "--exe", ToolProcess.TestLoad, "--arg", "fork", "--arg", "--width", "--arg", "1", "--arg", "--depth", "--arg", "1",
             "--arg", "--hold-ms", "--arg", "60000", "--runs", "1", "--warmup", "0", "--timeout-ms", "1500"],
            TestContext.Current.CancellationToken);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("did not exit within 1500 ms; the run was killed", run.StandardError, StringComparison.Ordinal);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(20), $"The hung run must be cut off at its timeout; it took {watch.Elapsed}.");
    }

    [Theory]
    [InlineData(10.0, 12.4, true, "pass")]      // +24%: below the relative limit
    [InlineData(10.0, 16.0, false, "regression")] // +60% and +6 ms
    [InlineData(2.0, 6.0, true, "pass")]        // +200% but only +4 ms: within the noise floor
    [InlineData(2.0, 7.5, false, "regression")]  // +275% and +5.5 ms
    [InlineData(40.0, 45.0, true, "pass")]      // +12.5%
    [InlineData(20.0, 25.0, true, "pass")]      // exactly +25% and +5 ms: not above either limit
    [InlineData(30.0, 20.0, true, "pass")]      // faster
    public void StartupRegressionMustExceedBothTheRelativeLimitAndTheNoiseFloor(double baseline, double current, bool pass, string status)
    {
        var result = StartupComparison.Compare("arcforges", baseline, current, 25, 5, "run 1", null);

        Assert.Equal(pass, result.Pass);
        Assert.Equal(status, result.Status);
        Assert.Equal(Math.Round(current - baseline, 3), result.DeltaMs);
    }

    [Fact]
    public void AMissingBaselinePassesWithItsReason()
    {
        var result = StartupComparison.Compare("arcforges", null, 9.5, 25, 5, null, "No successful main run yet.");

        Assert.True(result.Pass);
        Assert.Equal("no-baseline", result.Status);
        Assert.Equal("No successful main run yet.", result.Reason);
        Assert.Null(result.BaselineP50Ms);
    }

    [Theory]
    [InlineData("10", 0, "pass")]
    [InlineData("4", 1, "regression")]
    public async Task CompareStartupReadsBenchResultsAndGates(string baselineP50, int exitCode, string status)
    {
        using var directory = new TemporaryDirectory();
        var current = Path.Combine(directory.Path, "current.json");
        var baseline = Path.Combine(directory.Path, "baseline.json");
        var output = Path.Combine(directory.Path, "comparison.json");
        await File.WriteAllTextAsync(current, StartupJson("12"), TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(baseline, StartupJson(baselineP50), TestContext.Current.CancellationToken);

        var run = await ToolProcess.RunAsync(
            ToolProcess.Bench,
            ["compare-startup", "--current", current, "--baseline", baseline, "--baseline-source", "fixture", "--output", output],
            TestContext.Current.CancellationToken);

        Assert.Equal(exitCode, run.ExitCode);
        using var written = JsonDocument.Parse(await File.ReadAllBytesAsync(output, TestContext.Current.CancellationToken));
        Assert.Equal(status, written.RootElement.GetProperty("status").GetString());
        Assert.Equal(25, written.RootElement.GetProperty("maxRegressionPercent").GetDouble());
        Assert.Equal(5, written.RootElement.GetProperty("noiseFloorMs").GetDouble());
    }

    [Fact]
    public async Task CompareStartupRefusesResultsOfDifferentRuntimes()
    {
        using var directory = new TemporaryDirectory();
        var current = Path.Combine(directory.Path, "current.json");
        var baseline = Path.Combine(directory.Path, "baseline.json");
        await File.WriteAllTextAsync(current, StartupJson("12"), TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(baseline, StartupJson("12", "linux-arm64"), TestContext.Current.CancellationToken);

        var run = await ToolProcess.RunAsync(
            ToolProcess.Bench, ["compare-startup", "--current", current, "--baseline", baseline], TestContext.Current.CancellationToken);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("does not measure the same benchmark", run.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public void ThePairedRunsAlternateWhichExecutableGoesFirst()
    {
        // Round 0 baseline first, round 1 current first, and so on: neither executable always runs first.
        Assert.Equal([true, false, true, false, true, false], Enumerable.Range(0, 6).Select(StartupBenchmark.BaselineFirst));
    }

    [Fact]
    public async Task TheSameRunnerModeMeasuresBothExecutablesInterleavedAndRecordsBoth()
    {
        using var directory = new TemporaryDirectory();
        var output = Path.Combine(directory.Path, "comparison.json");

        // The same executable as baseline and current: the rule must see two measured results of the same command on this machine.
        var run = await ToolProcess.RunAsync(
            ToolProcess.Bench,
            ["compare-startup", "--baseline-exe", ToolProcess.TestLoad, "--current-exe", ToolProcess.TestLoad, "--arg", "cpu", "--arg", "--iterations",
             "--arg", "1", "--runs", "6", "--warmup", "1", "--name", "testload cpu", "--baseline-source", "fixture", "--noise-floor-ms", "60000",
             "--output", output],
            TestContext.Current.CancellationToken);

        Assert.True(run.ExitCode == 0, run.StandardError);
        using var written = JsonDocument.Parse(await File.ReadAllBytesAsync(output, TestContext.Current.CancellationToken));
        var root = written.RootElement;
        Assert.Equal("interleaved-same-runner", root.GetProperty("method").GetString());
        Assert.Equal("pass", root.GetProperty("status").GetString());
        Assert.Equal("fixture", root.GetProperty("baselineSource").GetString());
        Assert.Equal(25, root.GetProperty("maxRegressionPercent").GetDouble());
        foreach (var side in (string[])["baseline", "current"])
        {
            var result = root.GetProperty(side);
            Assert.Equal(6, result.GetProperty("samplesMs").GetArrayLength());
            Assert.Equal(1, result.GetProperty("warmup").GetInt32());
            Assert.Equal(["cpu", "--iterations", "1"], result.GetProperty("command").EnumerateArray().Skip(1).Select(item => item.GetString()));
            Assert.Equal(root.GetProperty(side + "P50Ms").GetDouble(), result.GetProperty("p50Ms").GetDouble());
            Assert.Equal(root.GetProperty(side + "P95Ms").GetDouble(), result.GetProperty("p95Ms").GetDouble());
        }

        Assert.Equal(Math.Round(root.GetProperty("currentP50Ms").GetDouble() - root.GetProperty("baselineP50Ms").GetDouble(), 3),
            root.GetProperty("deltaMs").GetDouble());
    }

    [Fact]
    public async Task TheRecordedModeKeepsBothPercentilesAndANoBaselineResultKeepsTheCurrentOnes()
    {
        using var directory = new TemporaryDirectory();
        var current = Path.Combine(directory.Path, "current.json");
        var output = Path.Combine(directory.Path, "comparison.json");
        await File.WriteAllTextAsync(current, StartupJson("12"), TestContext.Current.CancellationToken);

        var run = await ToolProcess.RunAsync(
            ToolProcess.Bench, ["compare-startup", "--current", current, "--reason", "No successful main run yet.", "--output", output],
            TestContext.Current.CancellationToken);

        Assert.Equal(0, run.ExitCode);
        using var written = JsonDocument.Parse(await File.ReadAllBytesAsync(output, TestContext.Current.CancellationToken));
        Assert.Equal("no-baseline", written.RootElement.GetProperty("status").GetString());
        Assert.Equal("recorded-results", written.RootElement.GetProperty("method").GetString());
        Assert.Equal(12, written.RootElement.GetProperty("currentP95Ms").GetDouble());
        Assert.False(written.RootElement.TryGetProperty("baselineP50Ms", out _));
    }

    [Theory]
    [InlineData("size", "--path", ".", "--target", "no-such-target")]
    [InlineData("compare-startup", "--current-exe", "x.exe")]
    [InlineData("compare-startup", "--current-exe", "x.exe", "--baseline-exe", "y.exe", "--current", "x.json")]
    [InlineData("compare-startup", "--baseline-exe", "y.exe", "--current", "x.json", "--reason", "none")]
    [InlineData("compare-startup", "--current", "x.json")]
    [InlineData("startup", "--exe", "x", "--timeout-ms", "0")]
    [InlineData("size", "--path", ".")]
    [InlineData("startup", "--runs", "3")]
    [InlineData("nothing")]
    public async Task InvalidCommandLinesExitWithTwo(params string[] arguments)
    {
        var run = await ToolProcess.RunAsync(ToolProcess.Bench, arguments, TestContext.Current.CancellationToken);

        Assert.Equal(2, run.ExitCode);
    }

    private static string StartupJson(string p50, string runtime = "linux-x64") => $$"""
        {"tool":"arcforges-bench","schemaVersion":1,"benchmark":"startup","name":"arcforges","command":["arcforges"],
         "runs":1,"warmup":0,"samplesMs":[{{p50}}],"p50Ms":{{p50}},"p95Ms":{{p50}},"minMs":{{p50}},"maxMs":{{p50}},"meanMs":{{p50}},
         "pass":true,"environment":{"os":"Linux","architecture":"X64","runtimeIdentifier":"{{runtime}}","processorCount":4,"framework":".NET 10"} }
        """;
}
