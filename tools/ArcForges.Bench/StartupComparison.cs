// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;

namespace ArcForges.Bench;

/// <summary>
/// <c>compare-startup</c>: the CI startup regression gate of 15-performance-targets ("startup
/// regressions above 25% against the previous main run"). Hosted runners are noisy and the
/// current startup is a few milliseconds, so the rule uses the median (p50 of the runs) and a
/// regression must exceed both the relative limit (default 25%) and an absolute noise floor
/// (default 5 ms). Without a baseline the result is recorded as passing with the stated reason.
/// </summary>
internal static class StartupComparison
{
    public const double DefaultMaxRegressionPercent = 25;
    public const double DefaultNoiseFloorMs = 5;

    public static StartupComparisonResult Run(BenchOptions options)
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

        return Compare(current.Name, baseline?.P50Ms, current.P50Ms, maxPercent, floorMs, source, reason);
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
                $"p50 {currentP50Ms:0.###} ms against {baseline:0.###} ms: {delta:+0.###;-0.###;0} ms ({percent:+0.#;-0.#;0}%); a regression exceeds {maxRegressionPercent:0.#}% and {noiseFloorMs:0.###} ms."),
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
