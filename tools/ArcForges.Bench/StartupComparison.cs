// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;

namespace ArcForges.Bench;

/// <summary>
/// <c>compare-startup</c>: the startup regression gate of 15-performance-targets ("startup
/// regressions above 25% against the PR's base commit built on the same machine"). Hosted runners are noisy and the
/// current startup is a few milliseconds, so the rule uses the median (p50 of the runs) and a
/// regression must exceed both the relative limit (default 25%) and an absolute noise floor
/// (default 5 ms). Without a baseline the result is recorded as passing with the stated reason.
/// <list type="bullet">
/// <item>Same-runner mode (<c>--baseline-exe</c>, <c>--current-exe</c>; the gate): both executables are measured here, interleaved,
/// with the same arguments, warm-up and run count, so the comparison is free of the machine-to-machine variance of hosted runners.</item>
/// <item>Recorded mode (<c>--current</c>, <c>--baseline</c>): two saved startup results, meaningful only when both were measured on the
/// same machine; <c>--current</c> with <c>--reason</c> records a result without a baseline.</item>
/// </list>
/// </summary>
internal static class StartupComparison
{
    public const double DefaultMaxRegressionPercent = 25;
    public const double DefaultNoiseFloorMs = 5;

    public static async Task<StartupComparisonResult> RunAsync(BenchOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.GetString("current-exe") is { } currentExe)
        {
            return await RunPairAsync(options, currentExe).ConfigureAwait(false);
        }

        return Run(options);
    }

    /// <summary>Same-runner mode: measures both executables interleaved and compares their medians.</summary>
    private static async Task<StartupComparisonResult> RunPairAsync(BenchOptions options, string currentExe)
    {
        var baselineExe = options.GetString("baseline-exe") ?? throw new UsageException("--current-exe needs --baseline-exe (or --reason with --current for no baseline).");
        var arguments = options.GetAll("arg");
        var runs = (int)(options.GetInt64("runs", 1, StartupBenchmark.MaxRuns) ?? 50);
        var warmup = (int)(options.GetInt64("warmup", 0, StartupBenchmark.MaxRuns) ?? 1);
        var expectExit = (int)(options.GetInt64("expect-exit", 0, 255) ?? 0);
        var timeout = TimeSpan.FromMilliseconds(options.GetInt64("timeout-ms", 1, 3_600_000) ?? StartupBenchmark.DefaultTimeoutMs);
        var name = options.GetString("name") ?? Path.GetFileNameWithoutExtension(currentExe);
        var source = options.GetString("baseline-source");
        var maxPercent = options.GetDouble("max-regression-percent", 0, 1000) ?? DefaultMaxRegressionPercent;
        var floorMs = options.GetDouble("noise-floor-ms", 0, 60_000) ?? DefaultNoiseFloorMs;
        options.GetString("output");
        foreach (var recorded in (string[])["current", "baseline", "reason"])
        {
            if (options.GetString(recorded) is not null)
            {
                throw new UsageException($"--{recorded} belongs to the recorded mode; the same-runner mode measures --baseline-exe and --current-exe.");
            }
        }

        options.EnsureAllUsed();
        var (baseline, current) = await StartupBenchmark.RunPairAsync(name, Path.GetFullPath(baselineExe), Path.GetFullPath(currentExe), arguments, runs, warmup,
            expectExit, timeout).ConfigureAwait(false);
        return Compare(name, baseline.P50Ms, current.P50Ms, maxPercent, floorMs, source, null) with
        {
            Method = "interleaved-same-runner",
            BaselineP95Ms = baseline.P95Ms,
            CurrentP95Ms = current.P95Ms,
            Baseline = baseline,
            Current = current,
        };
    }

    /// <summary>Recorded mode: two saved startup results, or one with the reason there is no baseline.</summary>
    private static StartupComparisonResult Run(BenchOptions options)
    {
        var currentPath = options.GetRequired("current");
        var baselinePath = options.GetString("baseline");
        var reason = options.GetString("reason");
        var source = options.GetString("baseline-source");
        var maxPercent = options.GetDouble("max-regression-percent", 0, 1000) ?? DefaultMaxRegressionPercent;
        var floorMs = options.GetDouble("noise-floor-ms", 0, 60_000) ?? DefaultNoiseFloorMs;
        options.GetString("output");
        options.EnsureAllUsed();

        if (baselinePath is null && reason is null)
        {
            throw new UsageException("Give --baseline, or --reason when no baseline exists.");
        }

        var current = Read(currentPath);
        StartupResult? baseline = null;
        if (baselinePath is not null)
        {
            baseline = Read(baselinePath);
            if (baseline.Name != current.Name || baseline.Environment.RuntimeIdentifier != current.Environment.RuntimeIdentifier)
            {
                throw new InvalidOperationException(
                    $"The baseline ({baseline.Name}, {baseline.Environment.RuntimeIdentifier}) does not measure the same benchmark as the current result ({current.Name}, {current.Environment.RuntimeIdentifier}).");
            }
        }

        return Compare(current.Name, baseline?.P50Ms, current.P50Ms, maxPercent, floorMs, source, reason) with
        {
            BaselineP95Ms = baseline?.P95Ms,
            CurrentP95Ms = current.P95Ms,
            Baseline = baseline,
            Current = current,
        };
    }

    /// <summary>The comparison rule: a regression exceeds both the relative limit and the noise floor.</summary>
    public static StartupComparisonResult Compare(
        string name, double? baselineP50Ms, double currentP50Ms, double maxRegressionPercent, double noiseFloorMs, string? baselineSource, string? reason)
    {
        if (baselineP50Ms is not { } baseline)
        {
            return new StartupComparisonResult
            {
                Name = name,
                Status = "no-baseline",
                Reason = reason ?? "No baseline was given.",
                BaselineSource = baselineSource,
                CurrentP50Ms = currentP50Ms,
                MaxRegressionPercent = maxRegressionPercent,
                NoiseFloorMs = noiseFloorMs,
                Pass = true,
            };
        }

        var delta = currentP50Ms - baseline;
        var percent = baseline > 0 ? delta / baseline * 100 : double.PositiveInfinity;
        var regression = percent > maxRegressionPercent && delta > noiseFloorMs;
        return new StartupComparisonResult
        {
            Name = name,
            Status = regression ? "regression" : "pass",
            Reason = string.Create(
                CultureInfo.InvariantCulture,
                $"p50 {currentP50Ms:0.###} ms against {baseline:0.###} ms, a change of {delta:0.###} ms ({percent:0.#}%); a regression exceeds {maxRegressionPercent:0.#}% and {noiseFloorMs:0.###} ms."),
            BaselineSource = baselineSource,
            BaselineP50Ms = baseline,
            CurrentP50Ms = currentP50Ms,
            DeltaMs = Math.Round(delta, 3),
            DeltaPercent = Math.Round(percent, 1),
            MaxRegressionPercent = maxRegressionPercent,
            NoiseFloorMs = noiseFloorMs,
            Pass = !regression,
        };
    }

    private static StartupResult Read(string path)
    {
        var result = JsonSerializer.Deserialize(File.ReadAllBytes(path), BenchJsonContext.Default.StartupResult);
        return result is { Benchmark: "startup" }
            ? result
            : throw new InvalidOperationException($"'{path}' is not an arcforges-bench startup result.");
    }
}
