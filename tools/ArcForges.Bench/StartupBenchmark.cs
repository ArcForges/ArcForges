// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;

namespace ArcForges.Bench;

/// <summary>
/// <c>startup</c>: process start to exit of a command, measured <c>runs</c> times after
/// <c>warmup</c> unmeasured runs that warm the file cache (15 section 1). A run whose exit code
/// differs from <c>expect-exit</c>, or that does not exit within <c>timeout-ms</c>, fails the
/// benchmark (a hung run is killed with its process tree). Limits are optional: hosted runners
/// only report startup and compare it with the previous main run, the workstation checks the targets.
/// </summary>
internal static class StartupBenchmark
{
    public const int MaxRuns = 10_000;
    public const long DefaultTimeoutMs = 30_000;

    public static async Task<StartupResult> RunAsync(BenchOptions options)
    {
        var executable = Path.GetFullPath(options.GetRequired("exe"));
        var arguments = options.GetAll("arg");
        var runs = (int)(options.GetInt64("runs", 1, MaxRuns) ?? 50);
        var warmup = (int)(options.GetInt64("warmup", 0, MaxRuns) ?? 1);
        var expectExit = (int)(options.GetInt64("expect-exit", 0, 255) ?? 0);
        var timeout = TimeSpan.FromMilliseconds(options.GetInt64("timeout-ms", 1, 3_600_000) ?? DefaultTimeoutMs);
        var limitP50 = options.GetDouble("max-p50-ms", 0.001, 3_600_000);
        var limitP95 = options.GetDouble("max-p95-ms", 0.001, 3_600_000);
        var name = options.GetString("name") ?? Path.GetFileNameWithoutExtension(executable);
        options.GetString("output");
        options.EnsureAllUsed();

        if (!File.Exists(executable))
        {
            throw new FileNotFoundException($"'{executable}' is not a file.", executable);
        }

        for (var i = 0; i < warmup; i++)
        {
            await MeasureOnceAsync(executable, arguments, expectExit, timeout).ConfigureAwait(false);
        }

        var samples = new double[runs];
        for (var i = 0; i < runs; i++)
        {
            samples[i] = await MeasureOnceAsync(executable, arguments, expectExit, timeout).ConfigureAwait(false);
        }

        return Result(name, executable, arguments, warmup, samples, limitP50, limitP95);
    }

    /// <summary>
    /// Measures two executables with the same arguments on this machine, interleaved: the warm-up runs alternate, and each measured
    /// round runs both, the baseline first in even rounds and second in odd ones (<see cref="BaselineFirst"/>), so drift of the
    /// machine (cache, frequency, other load) during the measurement falls on both alike and neither always runs first.
    /// </summary>
    public static async Task<(StartupResult Baseline, StartupResult Current)> RunPairAsync(string name, string baselineExecutable, string currentExecutable,
        IReadOnlyList<string> arguments, int runs, int warmup, int expectExit, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        foreach (var executable in (string[])[baselineExecutable, currentExecutable])
        {
            if (!File.Exists(executable))
            {
                throw new FileNotFoundException($"'{executable}' is not a file.", executable);
            }
        }

        for (var i = 0; i < warmup; i++)
        {
            await MeasureOnceAsync(baselineExecutable, arguments, expectExit, timeout).ConfigureAwait(false);
            await MeasureOnceAsync(currentExecutable, arguments, expectExit, timeout).ConfigureAwait(false);
        }

        var baseline = new double[runs];
        var current = new double[runs];
        for (var i = 0; i < runs; i++)
        {
            if (BaselineFirst(i))
            {
                baseline[i] = await MeasureOnceAsync(baselineExecutable, arguments, expectExit, timeout).ConfigureAwait(false);
                current[i] = await MeasureOnceAsync(currentExecutable, arguments, expectExit, timeout).ConfigureAwait(false);
            }
            else
            {
                current[i] = await MeasureOnceAsync(currentExecutable, arguments, expectExit, timeout).ConfigureAwait(false);
                baseline[i] = await MeasureOnceAsync(baselineExecutable, arguments, expectExit, timeout).ConfigureAwait(false);
            }
        }

        return (Result(name, baselineExecutable, arguments, warmup, baseline, null, null), Result(name, currentExecutable, arguments, warmup, current, null, null));
    }

    /// <summary>Whether the baseline runs first in measured round <paramref name="round"/> (alternating, starting with the baseline).</summary>
    public static bool BaselineFirst(int round) => round % 2 == 0;

    private static StartupResult Result(string name, string executable, IReadOnlyList<string> arguments, int warmup, double[] samples, double? limitP50,
        double? limitP95)
    {
        var p50 = Percentile(samples, 50);
        var p95 = Percentile(samples, 95);
        return new StartupResult
        {
            Name = name,
            Command = [executable, .. arguments],
            Runs = samples.Length,
            Warmup = warmup,
            SamplesMs = samples.Select(Round).ToList(),
            P50Ms = Round(p50),
            P95Ms = Round(p95),
            MinMs = Round(samples.Min()),
            MaxMs = Round(samples.Max()),
            MeanMs = Round(samples.Average()),
            LimitP50Ms = limitP50,
            LimitP95Ms = limitP95,
            Pass = (limitP50 is null || p50 <= limitP50) && (limitP95 is null || p95 <= limitP95),
            Environment = BenchEnvironment.Current(),
        };
    }

    /// <summary>Nearest-rank percentile: the smallest sample with at least <paramref name="percent"/>% of samples at or below it.</summary>
    public static double Percentile(IReadOnlyCollection<double> samples, double percent)
    {
        ArgumentNullException.ThrowIfNull(samples);
        if (samples.Count == 0)
        {
            throw new ArgumentException("No samples.", nameof(samples));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(percent);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(percent, 100);
        var sorted = samples.Order().ToArray();
        var rank = (int)Math.Ceiling(percent / 100 * sorted.Length);
        return sorted[Math.Max(rank, 1) - 1];
    }

    private static async Task<double> MeasureOnceAsync(string executable, IReadOnlyList<string> arguments, int expectExit, TimeSpan timeout)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        var begin = Stopwatch.GetTimestamp();
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"'{executable}' did not start.");
        using var deadline = new CancellationTokenSource(timeout);
        try
        {
            process.StandardInput.Close();
            var output = process.StandardOutput.ReadToEndAsync(deadline.Token);
            var error = process.StandardError.ReadToEndAsync(deadline.Token);
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            var elapsed = Stopwatch.GetElapsedTime(begin);
            await output.ConfigureAwait(false);
            var errorText = await error.ConfigureAwait(false);
            if (process.ExitCode != expectExit)
            {
                throw new InvalidOperationException(
                    string.Create(CultureInfo.InvariantCulture, $"'{executable}' exited with {process.ExitCode}, expected {expectExit}: {errorText.Trim()}"));
            }

            return elapsed.TotalMilliseconds;
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            throw new InvalidOperationException(
                string.Create(CultureInfo.InvariantCulture, $"'{executable}' did not exit within {timeout.TotalMilliseconds} ms; the run was killed."));
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
    }

    private static double Round(double value) => Math.Round(value, 3, MidpointRounding.AwayFromZero);
}
