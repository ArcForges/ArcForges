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

        var p50 = Percentile(samples, 50);
        var p95 = Percentile(samples, 95);
        return new StartupResult
        {
            Name = name,
            Command = [executable, .. arguments],
            Runs = runs,
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
