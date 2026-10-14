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
    public void DesktopDirectorySizeExcludesNativeSkiaHarfBuzzAndSymbols()
    {
        using var directory = new TemporaryDirectory();
        directory.File("arcforges-desktop.exe", 3000);
        directory.File("av_libglesv2.dll", 500);
        directory.File("libSkiaSharp.dll", 9000);
        directory.File("libHarfBuzzSharp.so", 7000);
        directory.File("arcforges-desktop.pdb", 4000);
        directory.File("nested/data.bin", 25);

        var (bytes, excluded) = SizeBenchmark.Measure(directory.Path, SizeBenchmark.Targets["arcforges-desktop"]);

        Assert.Equal(3525, bytes);
        Assert.Equal(["arcforges-desktop.pdb", "libHarfBuzzSharp.so", "libSkiaSharp.dll"], excluded);
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

    [Theory]
    [InlineData("size", "--path", ".", "--target", "no-such-target")]
    [InlineData("size", "--path", ".")]
    [InlineData("startup", "--runs", "3")]
    [InlineData("nothing")]
    public async Task InvalidCommandLinesExitWithTwo(params string[] arguments)
    {
        var run = await ToolProcess.RunAsync(ToolProcess.Bench, arguments, TestContext.Current.CancellationToken);

        Assert.Equal(2, run.ExitCode);
    }
}
