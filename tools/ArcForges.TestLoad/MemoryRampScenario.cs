// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.TestLoad;

/// <summary>
/// <c>mem-ramp</c>: grows resident memory in steps of <c>step-mb</c> MiB up to <c>target-mb</c> MiB,
/// waiting <c>step-ms</c> after each step, then holds the memory for <c>hold-ms</c> and exits.
/// Every allocated byte is written with deterministic content, so the memory is committed and
/// resident (not merely reserved), and the content digest is reproducible.
/// </summary>
internal static class MemoryRampScenario
{
    public const long MaxTargetMiB = 64 * 1024;
    public const long MaxStepMs = 60_000;
    public const long MaxHoldMs = 3_600_000;
    private const long MiB = 1024 * 1024;

    public static ScenarioReport Run(ScenarioOptions options)
    {
        var targetMiB = options.GetInt64("target-mb", 256, 1, MaxTargetMiB);
        var stepMiB = options.GetInt64("step-mb", 64, 1, targetMiB);
        var stepMs = options.GetInt64("step-ms", 0, 0, MaxStepMs);
        var holdMs = options.GetInt64("hold-ms", 0, 0, MaxHoldMs);
        var seed = options.GetSeed();
        options.GetUnrecorded("report");
        options.EnsureAllUsed();

        var stopwatch = Stopwatch.StartNew();
        using var digest = Deterministic.StartDigest(options.Canonical("mem-ramp"));
        var chunks = new List<byte[]>();
        var allocated = 0L;
        var target = targetMiB * MiB;
        while (allocated < target)
        {
            var size = (int)Math.Min(stepMiB * MiB, target - allocated);
            var chunk = GC.AllocateUninitializedArray<byte>(size, pinned: false);
            Deterministic.FillBlocks(seed, allocated, chunk);
            digest.AppendData(chunk);
            chunks.Add(chunk);
            allocated += size;
            if (stepMs > 0)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(stepMs));
            }
        }

        if (holdMs > 0)
        {
            Thread.Sleep(TimeSpan.FromMilliseconds(holdMs));
        }

        stopwatch.Stop();
        var measured = Measurements.Collect(stopwatch);
        GC.KeepAlive(chunks);
        return new ScenarioReport
        {
            Scenario = "mem-ramp",
            Parameters = options.Parameters,
            Digest = Deterministic.Hex(digest.GetHashAndReset()),
            Results = new Dictionary<string, long>(StringComparer.Ordinal)
            {
                ["allocatedBytes"] = allocated,
                ["steps"] = chunks.Count,
            },
            Measured = measured,
        };
    }
}
