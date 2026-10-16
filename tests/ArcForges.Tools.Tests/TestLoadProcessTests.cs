// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.TestLoad;
using ArcForges.Tests;

namespace ArcForges.Tools.Tests;

/// <summary>The real arcforges-testload executable on the current OS: each scenario reproduces its result.</summary>
public sealed class TestLoadProcessTests
{
    [Theory]
    [InlineData("cpu --threads 4 --iterations 2000000 --seed 11")]
    [InlineData("mem-ramp --target-mb 48 --step-mb 16 --step-ms 10 --seed 11")]
    [InlineData("output --bytes 2000000 --line-bytes 120 --stream none --seed 11")]
    [InlineData("fork --width 3 --depth 2 --seed 11")]
    public async Task EveryScenarioReproducesItsReport(string commandLine)
    {
        var arguments = commandLine.Split(' ');
        var first = await RunAsync(arguments);
        var second = await RunAsync(arguments);

        Assert.Equal(arguments[0], first.GetProperty("scenario").GetString());
        Assert.Equal(first.GetProperty("parameters").GetRawText(), second.GetProperty("parameters").GetRawText());
        Assert.Equal(first.GetProperty("digest").GetString(), second.GetProperty("digest").GetString());
        Assert.Equal(first.GetProperty("results").GetRawText(), second.GetProperty("results").GetRawText());
        Assert.Matches("^[0-9a-f]{64}$", first.GetProperty("digest").GetString()!);
    }

    [Fact]
    public async Task OutputOnStandardOutputIsByteIdenticalToItsDigest()
    {
        using var directory = new TemporaryDirectory();
        var report = Path.Combine(directory.Path, "report.json");
        string[] arguments = ["output", "--bytes", "3000001", "--line-bytes", "4096", "--seed", "9"];

        var first = await ToolProcess.RunAsync(ToolProcess.TestLoad, [.. arguments, "--report", report], TestContext.Current.CancellationToken);
        var second = await ToolProcess.RunAsync(ToolProcess.TestLoad, arguments, TestContext.Current.CancellationToken);
        var expected = await RunAsync([.. arguments, "--stream", "none"]);

        Assert.Equal(0, first.ExitCode);
        Assert.Equal(3000001, first.StandardOutput.Length);
        Assert.Equal(first.StandardOutput, second.StandardOutput);
        var digest = Convert.ToHexStringLower(SHA256.HashData(first.StandardOutput));
        using var written = JsonDocument.Parse(await File.ReadAllBytesAsync(report, TestContext.Current.CancellationToken));
        Assert.Equal(digest, written.RootElement.GetProperty("digest").GetString());
        Assert.Equal(digest, written.RootElement.GetProperty("streamDigests").GetProperty("stdout").GetString());
        Assert.Equal(digest, expected.GetProperty("digest").GetString());
    }

    [Fact]
    public async Task OutputOnBothStreamsAlternatesLinesAndKeepsEveryByte()
    {
        using var directory = new TemporaryDirectory();
        var report = Path.Combine(directory.Path, "report.json");

        var run = await ToolProcess.RunAsync(
            ToolProcess.TestLoad,
            ["output", "--bytes", "100005", "--line-bytes", "50", "--stream", "both", "--seed", "4", "--report", report],
            TestContext.Current.CancellationToken);

        Assert.Equal(0, run.ExitCode);
        var whole = new byte[100005];
        OutputScenario.Fill(4, 50, 0, whole);
        var even = new List<byte>();
        var odd = new List<byte>();
        for (var line = 0; line * 50 < whole.Length; line++)
        {
            (line % 2 == 0 ? even : odd).AddRange(whole.AsSpan(line * 50, Math.Min(50, whole.Length - (line * 50))).ToArray());
        }

        Assert.Equal(even.ToArray(), run.StandardOutput);
        Assert.Equal(odd.ToArray(), System.Text.Encoding.ASCII.GetBytes(run.StandardError));
        using var written = JsonDocument.Parse(await File.ReadAllBytesAsync(report, TestContext.Current.CancellationToken));
        var streams = written.RootElement.GetProperty("streamDigests");
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(run.StandardOutput)), streams.GetProperty("stdout").GetString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(odd.ToArray())), streams.GetProperty("stderr").GetString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(whole)), written.RootElement.GetProperty("digest").GetString());
    }

    [Fact]
    public async Task ForkBuildsARealProcessTreeThatIsAliveDuringTheHold()
    {
        var (root, run) = ToolProcess.Start(
            ToolProcess.TestLoad, ["fork", "--width", "2", "--depth", "2", "--hold-ms", "3000", "--seed", "2"], TestContext.Current.CancellationToken);

        // Only descendants of the process this test started count, never other tests' trees.
        var (observed, seen) = await WatchDescendantsAsync(root, run);

        var result = await run;
        Assert.True(result.ExitCode == 0, result.StandardError);
        var report = result.Json();
        Assert.Equal(7, report.GetProperty("results").GetProperty("processes").GetInt64());
        Assert.Equal(7, report.GetProperty("results").GetProperty("expectedProcesses").GetInt64());
        Assert.True(observed >= 6, $"Expected the root's 6 descendants to be observable during the hold, saw at most {observed}.");
        AssertExited(seen);
    }

    [Theory]
    [InlineData("0.1")]
    [InlineData("0.1.0")]
    [InlineData("0")]
    public async Task AFailedNodeEndsTheWholeTreePromptly(string failNode)
    {
        var watch = Stopwatch.StartNew();
        var (root, run) = ToolProcess.Start(
            ToolProcess.TestLoad,
            ["fork", "--width", "2", "--depth", "2", "--hold-ms", "20000", "--fail-node", failNode],
            TestContext.Current.CancellationToken);

        var (_, seen) = await WatchDescendantsAsync(root, run);
        var result = await run;

        Assert.Equal(1, result.ExitCode);
        Assert.Contains($"Node {failNode} failed as requested by --fail-node.", result.StandardError, StringComparison.Ordinal);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"The tree must end long before the 20 s hold; it took {watch.Elapsed}.");
        AssertExited(seen);
    }

    [Fact]
    public async Task ForkDigestMatchesTheRecordedReference()
    {
        // Recorded once; the same value on Windows and Linux proves a platform-independent tree identity.
        var report = await RunAsync(["fork", "--width", "2", "--depth", "1", "--seed", "1"]);

        Assert.Equal("996a79f7971ed86ce3a9bd366044c0deee921dd43e5d6a5942a80a29ffd98924", report.GetProperty("digest").GetString());
    }

    [Fact]
    public async Task MemoryRampMakesItsMemoryResident()
    {
        var report = await RunAsync(["mem-ramp", "--target-mb", "96", "--step-mb", "32"]);

        Assert.Equal(96L * 1024 * 1024, report.GetProperty("results").GetProperty("allocatedBytes").GetInt64());
        Assert.True(
            report.GetProperty("measured").GetProperty("peakWorkingSetBytes").GetInt64() >= 96L * 1024 * 1024,
            "The ramped memory must be committed and resident, not only reserved.");
    }

    [Theory]
    [InlineData]
    [InlineData("no-such-scenario")]
    [InlineData("cpu", "--threads", "0")]
    [InlineData("mem-ramp", "--target-mb", "4096", "--step-mb", "2048")]
    [InlineData("mem-ramp", "--target-mb", "4096", "--step-mb", "99999999999")]
    public async Task InvalidCommandLinesExitWithTwo(params string[] arguments)
    {
        var run = await ToolProcess.RunAsync(ToolProcess.TestLoad, arguments, TestContext.Current.CancellationToken);

        Assert.Equal(2, run.ExitCode);
    }

    [Fact]
    public async Task AnUnwritableReportPathExitsWithOneAndAMessage()
    {
        using var directory = new TemporaryDirectory();

        // The report path is an existing directory, which cannot be written as a file.
        var run = await ToolProcess.RunAsync(
            ToolProcess.TestLoad, ["cpu", "--iterations", "1", "--report", directory.Path], TestContext.Current.CancellationToken);

        Assert.Equal(1, run.ExitCode);
        Assert.StartsWith("arcforges-testload: ", run.StandardError, StringComparison.Ordinal);
    }

    /// <summary>Polls the root's descendants until it completes: the largest count seen and every descendant seen (by identity).</summary>
    private static async Task<(int Largest, HashSet<ProcessIdentity> Seen)> WatchDescendantsAsync(int root, Task<ToolRun> run)
    {
        var largest = 0;
        var seen = new HashSet<ProcessIdentity>();
        var watch = Stopwatch.StartNew();
        while (!run.IsCompleted && watch.Elapsed < TimeSpan.FromSeconds(60))
        {
            var descendants = ProcessTree.Descendants(root);
            largest = Math.Max(largest, descendants.Count);
            seen.UnionWith(descendants);
            await Task.Delay(20, TestContext.Current.CancellationToken);
        }

        return (largest, seen);
    }

    /// <summary>
    /// Every observed descendant has exited (orphans are found by identity, not by parent link). A process that now holds a recorded ID
    /// but was created at another time is another process (the ID was reused) and does not count; the recorded process itself still
    /// running after 5 s fails.
    /// </summary>
    private static void AssertExited(IEnumerable<ProcessIdentity> processes)
    {
        foreach (var process in processes)
        {
            var watch = Stopwatch.StartNew();
            while (process.IsRunning() && watch.Elapsed < TimeSpan.FromSeconds(5))
            {
                Thread.Sleep(20);
            }

            Assert.False(process.IsRunning(), $"{process} of the tree is still running.");
        }
    }

    private static async Task<JsonElement> RunAsync(string[] arguments)
    {
        var run = await ToolProcess.RunAsync(ToolProcess.TestLoad, arguments, TestContext.Current.CancellationToken);
        Assert.True(run.ExitCode == 0, $"arcforges-testload {string.Join(' ', arguments)} exited with {run.ExitCode}: {run.StandardError}");
        return run.Json();
    }
}
