// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.TestLoad;

/// <summary>
/// <c>cpu</c>: a fixed amount of integer work on each of <c>threads</c> threads. The work per thread
/// is a dependent multiply-xorshift chain that cannot be skipped or vectorized, so the CPU time
/// is proportional to <c>iterations</c> and the result digest is identical on every run.
/// </summary>
internal static class CpuScenario
{
    public const long MaxThreads = 256;
    public const long MaxIterations = 20_000_000_000;

    public static ScenarioReport Run(ScenarioOptions options)
    {
        var threads = (int)options.GetInt64("threads", 1, 1, MaxThreads);
        var iterations = options.GetInt64("iterations", 100_000_000, 1, MaxIterations);
        var seed = options.GetSeed();
        options.GetUnrecorded("report");
        options.EnsureAllUsed();

        var stopwatch = Stopwatch.StartNew();
        var results = new ulong[threads];
        var workers = new Thread[threads];
        for (var i = 0; i < threads; i++)
        {
            var index = i;
            workers[i] = new Thread(() => results[index] = Spin(Deterministic.Mix(seed, (ulong)index), iterations))
            {
                IsBackground = true,
                Name = $"testload-cpu-{index}",
            };
            workers[i].Start();
        }

        foreach (var worker in workers)
        {
            worker.Join();
        }

        stopwatch.Stop();
        using var digest = Deterministic.StartDigest(options.Canonical("cpu"));
        foreach (var result in results)
        {
            Deterministic.AppendUInt64(digest, result);
        }

        return new ScenarioReport
        {
            Scenario = "cpu",
            Parameters = options.Parameters,
            Digest = Deterministic.Hex(digest.GetHashAndReset()),
            Results = new Dictionary<string, long>(StringComparer.Ordinal)
            {
                ["threads"] = threads,
                ["totalIterations"] = threads * iterations,
            },
            Measured = Measurements.Collect(stopwatch),
        };
    }

    /// <summary>
    /// The per-thread work chain, compiled fully optimized from its first call, so that under the JIT the probe's calibration and its
    /// periods run the same code.
    /// </summary>
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveOptimization)]
    public static ulong Spin(ulong state, long iterations)
    {
        for (var i = 0L; i < iterations; i++)
        {
            state = (state * 6364136223846793005UL) + 1442695040888963407UL;
            state ^= state >> 33;
        }

        return state;
    }
}
