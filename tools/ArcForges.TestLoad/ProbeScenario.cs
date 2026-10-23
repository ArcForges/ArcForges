// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.TestLoad;

/// <summary>
/// <c>probe</c>: the unmanaged interactive probe of 15-performance-targets section 4 (headroom protection). Every <c>period-ms</c> it
/// wakes at the period's scheduled start and runs a fixed busy loop calibrated to take <c>work-us</c> on an idle processor; a period
/// misses its deadline when the loop completes later than <c>deadline-ms</c> after the scheduled start (the wake-up latency counts: an
/// interactive program that waits for its turn is late). A period skipped because the probe fell behind by a whole period counts as a
/// miss. It runs for <c>duration-ms</c> and reports the periods, the misses and the completion latencies (p50, p99, maximum, in
/// microseconds); to line them up with other events it also reports when period 0 was scheduled (<c>originMs</c>, from the process's
/// start), the longest period's index, and the index and latency of the first 8 missed periods (<c>missN*</c>; -1 for a skipped one).
/// The wait uses a high-resolution waitable timer on Windows and <c>Thread.Sleep</c> (whole milliseconds) on Linux, then
/// spins to the scheduled start, so the work never starts before it and an early wake never hides latency.
/// </summary>
internal static partial class ProbeScenario
{
    /// <summary>The missed periods whose index and latency the report lists.</summary>
    private const int MissesReported = 8;

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
        long misses = 0, skipped = 0, state = 1, longestIndex = -1, longest = -1;
        var missed = new List<(long Index, long LatencyUs)>(MissesReported);
        using var timer = OperatingSystem.IsWindows() ? WindowsTimer.Create() : null;
        var origin = Stopwatch.GetTimestamp() + period;
        using var self = Process.GetCurrentProcess();
        var originMs = (long)(DateTime.Now - self.StartTime).TotalMilliseconds + periodMs;
        for (var index = 0L; index < periods; index++)
        {
            var start = origin + (index * period);
            var now = Stopwatch.GetTimestamp();
            if (now - start >= period)
            {
                // Behind by a whole period or more: this period's work could not even begin in it.
                misses++;
                skipped++;
                if (missed.Count < MissesReported)
                {
                    missed.Add((index, -1));
                }

                continue;
            }

            if (start > now)
            {
                Wait(timer, start - now, frequency);

                // Thread.Sleep truncates to whole milliseconds (and a timer may fire a little early): the work starts at the period's
                // scheduled start, never before it, so an early wake never hides latency.
                while (Stopwatch.GetTimestamp() < start)
                {
                    Thread.SpinWait(20);
                }
            }

            state = (long)CpuScenario.Spin((ulong)state, iterations);
            var latency = Stopwatch.GetTimestamp() - start;
            var latencyUs = latency * 1_000_000 / frequency;
            latencies.Add(latencyUs);
            if (latencyUs > longest)
            {
                (longest, longestIndex) = (latencyUs, index);
            }

            if (latency > deadline)
            {
                misses++;
                if (missed.Count < MissesReported)
                {
                    missed.Add((index, latencyUs));
                }
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
        measured["originMs"] = originMs;
        measured["longestIndex"] = longestIndex;
        for (var number = 0; number < missed.Count; number++)
        {
            measured[string.Create(CultureInfo.InvariantCulture, $"miss{number + 1}Index")] = missed[number].Index;
            measured[string.Create(CultureInfo.InvariantCulture, $"miss{number + 1}Us")] = missed[number].LatencyUs;
        }
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

    /// <summary>
    /// The loop iterations that take <paramref name="workUs"/> on an uncontended processor: the fastest of 31 timed runs before the
    /// measurement starts (a run another thread interrupted is slower, so on a busy machine a median would shorten the work and make the
    /// probe easier to satisfy).
    /// </summary>
    private static long Calibrate(long workUs)
    {
        const long Trial = 200_000;

        // Warm up first (JIT, the processor's frequency ramp), so the calibration measures the speed the periods will see.
        var warm = Stopwatch.StartNew();
        while (warm.ElapsedMilliseconds < 100)
        {
            CpuScenario.Spin(7, Trial);
        }

        var samples = new List<double>();
        for (var run = 0; run < 31; run++)
        {
            var started = Stopwatch.GetTimestamp();
            CpuScenario.Spin((ulong)run + 1, Trial);
            var elapsedUs = (Stopwatch.GetTimestamp() - started) * 1_000_000.0 / Stopwatch.Frequency;
            samples.Add(Trial / Math.Max(1, elapsedUs));
        }

        return Math.Max(1, (long)(samples.Max() * workUs));
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
