// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.TestLoad;

/// <summary>Run observations that vary between runs and are never part of a digest.</summary>
internal static class Measurements
{
    public static Dictionary<string, long> Collect(Stopwatch stopwatch)
    {
        using var process = Process.GetCurrentProcess();
        process.Refresh();
        return new Dictionary<string, long>(StringComparer.Ordinal)
        {
            ["elapsedMs"] = stopwatch.ElapsedMilliseconds,
            ["peakWorkingSetBytes"] = process.PeakWorkingSet64,
            ["processId"] = Environment.ProcessId,
        };
    }
}
