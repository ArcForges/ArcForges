// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;

namespace ArcForges.TestLoad;

/// <summary>
/// <c>fork</c>: builds a real process tree. Every process above depth <c>depth</c> starts
/// <c>width</c> child processes of this tool concurrently and waits for them; leaves stay alive for
/// <c>hold-ms</c>, so the whole tree is observable during that window. The tree shape, the process
/// count and the digest (over node identities and child digests, in order) are reproducible.
/// The first child that fails or outlives its bound fails its parent at once: the parent kills
/// the remaining children with their process trees and exits with 1, so a failure anywhere ends
/// the whole tree promptly. <c>fail-node</c> injects that fault: the node with the given identity
/// (<c>0</c> is the root, <c>0.1</c> its second child) exits with 1 as soon as it starts.
/// </summary>
internal static class ForkScenario
{
    public const long MaxWidth = 64;
    public const long MaxDepth = 8;
    public const long MaxProcesses = 1024;
    public const long MaxHoldMs = 600_000;
    private static readonly TimeSpan ChildGrace = TimeSpan.FromSeconds(60);

    public static long ExpectedProcesses(long width, long depth)
    {
        long total = 0, level = 1;
        for (var i = 0; i <= depth; i++)
        {
            total += level;
            level *= width;
            if (total > MaxProcesses)
            {
                return total;
            }
        }

        return total;
    }

    public static async Task<ScenarioReport> RunAsync(ScenarioOptions options)
    {
        var width = options.GetInt64("width", 2, 1, MaxWidth);
        var depth = options.GetInt64("depth", 2, 0, MaxDepth);
        var holdMs = options.GetInt64("hold-ms", 0, 0, MaxHoldMs);
        var seed = options.GetSeed();
        var level = options.GetInt64("level", 0, 0, MaxDepth, hidden: true);
        var failNode = options.GetOptional("fail-node");
        var node = options.GetUnrecorded("node") ?? "0";
        options.GetUnrecorded("report");
        options.EnsureAllUsed();

        var expected = ExpectedProcesses(width, depth);
        if (expected > MaxProcesses)
        {
            throw new UsageException(
                string.Create(CultureInfo.InvariantCulture, $"width {width} and depth {depth} need {expected} processes; the limit is {MaxProcesses}."));
        }

        if (level > depth)
        {
            throw new UsageException("Option '--level' must not exceed '--depth'.");
        }

        if (failNode == node)
        {
            throw new InvalidOperationException($"Node {node} failed as requested by --fail-node.");
        }

        var stopwatch = Stopwatch.StartNew();
        var children = level < depth
            ? await StartChildrenAsync(options, width, holdMs, depth - level, node, level).ConfigureAwait(false)
            : [];
        if (level == depth && holdMs > 0)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(holdMs)).ConfigureAwait(false);
        }

        stopwatch.Stop();
        using var digest = Deterministic.StartDigest(options.Canonical("fork"));
        digest.AppendData(System.Text.Encoding.UTF8.GetBytes(node));
        foreach (var child in children)
        {
            digest.AppendData(Convert.FromHexString(child.Digest));
        }

        return new ScenarioReport
        {
            Scenario = "fork",
            Parameters = options.Parameters,
            Digest = Deterministic.Hex(digest.GetHashAndReset()),
            Results = new Dictionary<string, long>(StringComparer.Ordinal)
            {
                ["processes"] = 1 + children.Sum(child => child.Results["processes"]),
                ["expectedProcesses"] = ExpectedProcesses(width, depth - level),
                ["maxDepth"] = depth - level,
            },
            Measured = Measurements.Collect(stopwatch),
        };
    }

    private static async Task<ScenarioReport[]> StartChildrenAsync(
        ScenarioOptions options, long width, long holdMs, long levelsBelow, string node, long level)
    {
        var (fileName, prefix) = SelfCommand();
        var started = new List<Process>();
        var runs = new List<Task<ScenarioReport>>();
        try
        {
            for (var i = 0; i < width; i++)
            {
                var start = new ProcessStartInfo(fileName)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };
                foreach (var argument in prefix)
                {
                    start.ArgumentList.Add(argument);
                }

                start.ArgumentList.Add("fork");
                foreach (var (name, value) in options.Parameters)
                {
                    start.ArgumentList.Add("--" + name);
                    start.ArgumentList.Add(value);
                }

                start.ArgumentList.Add("--level");
                start.ArgumentList.Add((level + 1).ToString(CultureInfo.InvariantCulture));
                start.ArgumentList.Add("--node");
                start.ArgumentList.Add(string.Create(CultureInfo.InvariantCulture, $"{node}.{i}"));

                var process = Process.Start(start) ?? throw new InvalidOperationException("A child process did not start.");
                started.Add(process);
                runs.Add(CollectAsync(process, TimeSpan.FromMilliseconds(holdMs) + (ChildGrace * levelsBelow)));
            }

            // Fail fast: the first failed child ends the wait; the finally block kills its siblings.
            var pending = new List<Task<ScenarioReport>>(runs);
            while (pending.Count > 0)
            {
                var finished = await Task.WhenAny(pending).ConfigureAwait(false);
                await finished.ConfigureAwait(false);
                pending.Remove(finished);
            }

            return [.. runs.Select(run => run.Result)];
        }
        finally
        {
            foreach (var process in started)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch (InvalidOperationException)
                {
                    // The process exited between the check and the kill.
                }
            }

            // Let the collectors observe the killed processes before their handles are released.
            await Task.WhenAny(Task.WhenAll(runs), Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
            foreach (var process in started)
            {
                process.Dispose();
            }
        }
    }

    private static async Task<ScenarioReport> CollectAsync(Process process, TimeSpan bound)
    {
        using var timeout = new CancellationTokenSource(bound);
        var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
        var error = process.StandardError.ReadToEndAsync(timeout.Token);
        await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        var text = await output.ConfigureAwait(false);
        var errorText = await error.ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                string.Create(CultureInfo.InvariantCulture, $"Child process {process.Id} exited with {process.ExitCode}: {errorText.Trim()}"));
        }

        return JsonSerializer.Deserialize(text, TestLoadJsonContext.Default.ScenarioReport)
            ?? throw new InvalidOperationException("A child process wrote no report.");
    }

    /// <summary>How to start this tool again: the native executable, or <c>dotnet tool.dll</c> under the JIT host.</summary>
    internal static (string FileName, string[] Prefix) SelfCommand()
    {
        var processPath = Environment.ProcessPath ?? throw new InvalidOperationException("The process path is unknown.");
        if (Path.GetFileNameWithoutExtension(processPath).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            return (processPath, [Path.Combine(AppContext.BaseDirectory, "arcforges-testload.dll")]);
        }

        return (processPath, []);
    }
}
