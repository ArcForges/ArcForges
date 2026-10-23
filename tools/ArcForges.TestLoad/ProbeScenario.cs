// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.TestLoad;

/// <summary>
/// <c>probe</c>: the unmanaged interactive probe of 15-performance-targets section 4 (headroom protection). Every <c>period-ms</c> it
/// wakes at the period's scheduled start and runs a fixed busy loop calibrated to take <c>work-us</c> on an idle processor; a period
/// misses its deadline when the loop completes later than <c>deadline-ms</c> after the scheduled start (the wake-up latency counts: an
/// interactive program that waits for its turn is late). A period skipped because the probe fell behind by a whole period counts as a
/// miss. It runs for <c>duration-ms</c> and reports the periods, the misses and the completion latencies (p50, p99, maximum, in
/// microseconds). The wait uses a high-resolution waitable timer on Windows and <c>nanosleep</c> on Linux, so the timer's own granularity
/// is not counted against the scheduler.
/// </summary>
internal static partial class ProbeScenario
{
    public static ScenarioReport Run(ScenarioOptions options)
    {
        var periodMs = options.GetInt64("period-ms", 100, 10, 10_000);
        var deadlineMs = options.GetInt64("deadline-ms", 10, 1, periodMs);
        var workUs = options.GetInt64("work-us", 2_000, 10, deadlineMs * 1000);
        var durationMs = options.GetInt64("duration-ms", 60_000, periodMs, 24L * 60 * 60 * 1000);
        options.GetUnrecorded("report");
        options.EnsureAllUsed();

        var iterations = Calibrate(workUs);
        var stopwatch = Stopwatch.StartNew();
        var frequency = Stopwatch.Frequency;
        var period = periodMs * frequency / 1000;
        var deadline = deadlineMs * frequency / 1000;
        var periods = durationMs / periodMs;
        var latencies = new List<long>((int)periods);
        long misses = 0, skipped = 0, state = 1;
        using var timer = OperatingSystem.IsWindows() ? WindowsTimer.Create() : null;
        var origin = Stopwatch.GetTimestamp() + period;
        for (var index = 0L; index < periods; index++)
        {
            var start = origin + (index * period);
            var now = Stopwatch.GetTimestamp();
            if (now - start >= period)
            {
                // Behind by a whole period or more: this period's work could not even begin in it.
                misses++;
                skipped++;
                continue;
            }

            if (start > now)
            {
                Wait(timer, start - now, frequency);
            }

            state = (long)CpuScenario.Spin((ulong)state, iterations);
            var latency = Stopwatch.GetTimestamp() - start;
            latencies.Add(latency * 1_000_000 / frequency);
            if (latency > deadline)
            {
                misses++;
            }
        }

        stopwatch.Stop();
        latencies.Sort();
        long Percentile(double fraction) => latencies.Count == 0 ? 0 : latencies[(int)Math.Min(latencies.Count - 1, Math.Floor(fraction * latencies.Count))];
        var measured = Measurements.Collect(stopwatch);
        measured["p50Us"] = Percentile(0.50);
        measured["p99Us"] = Percentile(0.99);
        measured["maxUs"] = latencies.Count == 0 ? 0 : latencies[^1];
        measured["calibratedIterations"] = iterations;
        measured["skipped"] = skipped;
        measured["state"] = state & 0xFF;
        using var digest = Deterministic.StartDigest(options.Canonical("probe"));
        return new ScenarioReport
        {
            Scenario = "probe",
            Parameters = options.Parameters,
            Digest = Deterministic.Hex(digest.GetHashAndReset()),
            Results = new Dictionary<string, long>(StringComparer.Ordinal) { ["periods"] = periods, ["misses"] = misses },
            Measured = measured,
        };
    }

    /// <summary>The loop iterations that take <paramref name="workUs"/>: the median of 15 timed runs before the measurement starts.</summary>
    private static long Calibrate(long workUs)
    {
        const long Trial = 200_000;
        var samples = new List<double>();
        for (var run = 0; run < 15; run++)
        {
            var started = Stopwatch.GetTimestamp();
            CpuScenario.Spin((ulong)run + 1, Trial);
            var elapsedUs = (Stopwatch.GetTimestamp() - started) * 1_000_000.0 / Stopwatch.Frequency;
            samples.Add(Trial / Math.Max(1, elapsedUs));
        }

        samples.Sort();
        return Math.Max(1, (long)(samples[samples.Count / 2] * workUs));
    }

    private static void Wait(WindowsTimer? timer, long ticks, long frequency)
    {
        if (timer is not null && OperatingSystem.IsWindows())
        {
            timer.Wait(ticks * 10_000_000 / frequency);
        }
        else
        {
            Thread.Sleep(TimeSpan.FromTicks(ticks * TimeSpan.TicksPerSecond / frequency));
        }
    }

    /// <summary>A high-resolution waitable timer (<c>CREATE_WAITABLE_TIMER_HIGH_RESOLUTION</c>, Windows 10 1803 and later).</summary>
    [SupportedOSPlatform("windows")]
    private sealed partial class WindowsTimer : IDisposable
    {
        private const uint HighResolution = 0x00000002;
        private const uint TimerAllAccess = 0x1F0003;
        private readonly nint _handle;

        private WindowsTimer(nint handle) => _handle = handle;

        public static WindowsTimer? Create()
        {
            var handle = CreateWaitableTimerExW(0, 0, HighResolution, TimerAllAccess);
            return handle == 0 ? null : new WindowsTimer(handle);
        }

        /// <summary>Waits for <paramref name="hundredNanoseconds"/> (a relative due time).</summary>
        public void Wait(long hundredNanoseconds)
        {
            var due = -Math.Max(1, hundredNanoseconds);
            if (SetWaitableTimer(_handle, ref due, 0, 0, 0, false))
            {
                WaitForSingleObject(_handle, 0xFFFFFFFF);
            }
        }

        public void Dispose() => CloseHandle(_handle);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        private static partial nint CreateWaitableTimerExW(nint attributes, nint name, uint flags, uint access);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool SetWaitableTimer(nint timer, ref long dueTime, int period, nint completion, nint argument, [MarshalAs(UnmanagedType.Bool)] bool resume);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        private static partial uint WaitForSingleObject(nint handle, uint milliseconds);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool CloseHandle(nint handle);
    }
}
