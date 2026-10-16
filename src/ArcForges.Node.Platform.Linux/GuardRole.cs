// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Tmds.DBus.Protocol;

namespace ArcForges.Node.Platform.Linux;

/// <summary>How <c>arcforges node guard</c> runs.</summary>
public sealed class GuardOptions
{
    /// <summary>The node data root whose attempts it guards.</summary>
    public required string DataRoot { get; init; }

    /// <summary>The user manager's D-Bus address; null for its private socket.</summary>
    public string? ManagerAddress { get; init; }

    /// <summary>Stops the guard (tests); the unit runs it until systemd stops it.</summary>
    public CancellationToken Stop { get; init; }

    /// <summary>The clock.</summary>
    public TimeProvider Clock { get; init; } = TimeProvider.System;
}

/// <summary>
/// <c>arcforges node guard</c>, the process of <c>arcforges-guard.service</c> (13 section 3.4; 06 section 5): one guard for every attempt
/// unit of the data root while the node is down. It reads the node heartbeat (<c>run/node-heartbeat</c>) every 250 ms and judges it on its
/// own monotonic clock (<see cref="HeartbeatWatch"/>); while the heartbeat is fresh it does nothing else. Once an attempt's
/// <c>guard_takeover_ms</c> (from its <c>guard.json</c>) has passed without a renewal, it takes over that attempt and checks its captured
/// output every 100 ms against <c>max_attempt_output_bytes</c>: <c>TERMINATE</c> freezes the unit and kills it (<see cref="UnitControl"/>),
/// <c>NOTIFY</c> records the crossing. Every action, takeover and stand-down is appended to the attempt's <c>guard-events.jsonl</c>; the
/// guard never writes the node store. A node that restarts faster than the takeover time never renews the heartbeat, so the guard stays
/// in charge. The temporary-directory and low-space limits join with AF-STOR-01.
/// </summary>
[SupportedOSPlatform("linux")]
public static partial class GuardRole
{
    /// <summary>The output check interval while in charge.</summary>
    public static readonly TimeSpan CheckInterval = TimeSpan.FromMilliseconds(100);

    /// <summary>How often the heartbeat is read.</summary>
    public static readonly TimeSpan HeartbeatInterval = TimeSpan.FromMilliseconds(250);

    /// <summary>How often the attempt directories are scanned while in charge.</summary>
    public static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(1);

    /// <summary>Runs the guard until <see cref="GuardOptions.Stop"/>; returns its exit code.</summary>
    public static int Run(GuardOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var clock = options.Clock;
        var run = Path.Combine(options.DataRoot, "run");
        Directory.CreateDirectory(run);
        using var instance = AcquireLock(Path.Combine(run, "guard.lock"), options.Stop);
        if (instance is null)
        {
            return 0;
        }

        Console.Error.WriteLine($"arcforges guard: guarding {options.DataRoot}");
        var watch = new HeartbeatWatch(Path.Combine(run, "node-heartbeat"), TimeSpan.FromMilliseconds(2_000), clock);
        var attempts = new Dictionary<string, Guarded>(StringComparer.Ordinal);
        SystemdManager? manager = null;
        var lastPoll = long.MinValue;
        var lastScan = long.MinValue;
        try
        {
            while (!options.Stop.WaitHandle.WaitOne(CheckInterval))
            {
                if (lastPoll == long.MinValue || clock.GetElapsedTime(lastPoll) >= HeartbeatInterval)
                {
                    watch.Poll();
                    lastPoll = clock.GetTimestamp();
                }

                var age = watch.Age;
                if (age < TimeSpan.FromMilliseconds(2_000) && attempts.Values.All(attempt => !attempt.InCharge))
                {
                    // Fresh (below the smallest takeover time) and nothing to stand down: idle.
                    continue;
                }

                if (lastScan == long.MinValue || clock.GetElapsedTime(lastScan) >= ScanInterval)
                {
                    Scan(options.DataRoot, attempts);
                    lastScan = clock.GetTimestamp();
                }

                foreach (var attempt in attempts.Values)
                {
                    Check(attempt, watch, ref manager, options, clock);
                }
            }
        }
        finally
        {
            manager?.Dispose();
        }

        return 0;
    }

    private static void Scan(string dataRoot, Dictionary<string, Guarded> attempts)
    {
        var logs = Path.Combine(dataRoot, "logs");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        if (Directory.Exists(logs))
        {
            foreach (var directory in Directory.EnumerateDirectories(logs))
            {
                var name = Path.GetFileName(directory);
                if (name == "node" || File.Exists(Path.Combine(directory, AttemptFiles.Exit)))
                {
                    continue;
                }

                if (!attempts.ContainsKey(name))
                {
                    if (GuardSpec.TryRead(Path.Combine(directory, AttemptFiles.Guard)) is not { } spec)
                    {
                        continue;
                    }

                    attempts[name] = new Guarded(new AttemptFiles(dataRoot, name), spec);
                }

                seen.Add(name);
            }
        }

        foreach (var gone in attempts.Keys.Where(name => !seen.Contains(name)).ToList())
        {
            attempts.Remove(gone);
        }
    }

    private static void Check(Guarded attempt, HeartbeatWatch watch, ref SystemdManager? manager, GuardOptions options, TimeProvider clock)
    {
        var spec = attempt.Spec;
        var stale = watch.Age >= TimeSpan.FromMilliseconds(Math.Clamp(spec.TakeoverMs, 2_000, 60_000));
        if (!stale)
        {
            if (attempt.InCharge)
            {
                attempt.InCharge = false;
                Append(attempt, GuardEventKinds.StandDown, null, null, watch, clock);
            }

            return;
        }

        if (!attempt.InCharge)
        {
            attempt.InCharge = true;
            Append(attempt, GuardEventKinds.Takeover, null, null, watch, clock);
        }

        if (attempt.Stopped || spec.MaxOutputBytes <= 0 || (attempt.SkipUntil is { } skip && clock.GetTimestamp() < skip))
        {
            return;
        }

        long total = 0;
        foreach (var file in spec.OutputFiles)
        {
            try
            {
                total += new FileInfo(file).Length;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }

        if (total <= spec.MaxOutputBytes)
        {
            return;
        }

        if (string.Equals(spec.DiskLimitAction, "NOTIFY", StringComparison.OrdinalIgnoreCase))
        {
            if (!attempt.Notified)
            {
                attempt.Notified = true;
                Append(attempt, GuardEventKinds.Notify, "OUTPUT_LIMIT", total, watch, clock);
            }

            return;
        }

        try
        {
            if (manager is null || manager.Closed)
            {
                manager?.Dispose();
                manager = SystemdManager.Connect(options.ManagerAddress ?? SystemdManager.DefaultAddress()
                    ?? throw new InvalidOperationException("no systemd user manager runs for this user"), SystemdManager.CallTimeout);
            }

            var unit = LinuxExecutionPlatform.UnitName(attempt.Files.AttemptName);
            if (manager.State(unit) is not { } state || state.ActiveState is "inactive" or "failed")
            {
                // Not a running unit (finished, or never started under systemd): checked again later.
                attempt.SkipUntil = clock.GetTimestamp() + (long)(5 * TimeProvider.System.TimestampFrequency);
                return;
            }

            // TERMINATE: at once, without the graceful phase; frozen first (04 section 6 step 4).
            var stop = UnitControl.FreezeAndKill(manager, unit, state.ControlGroup.Length > 0 ? ProcFs.CgroupDirectory(state.ControlGroup) : null, (int)state.MainPid);
            attempt.Stopped = true;
            Append(attempt, GuardEventKinds.Terminate, "OUTPUT_LIMIT", total, watch, clock);
            Console.Error.WriteLine($"arcforges guard: stopped {unit} at {total.ToString(CultureInfo.InvariantCulture)} bytes of output (limit {spec.MaxOutputBytes.ToString(CultureInfo.InvariantCulture)}): {stop.Describe()}");
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException or IOException or InvalidOperationException
            or System.Net.Sockets.SocketException)
        {
            Console.Error.WriteLine("arcforges guard: the attempt unit could not be stopped: " + LinuxExecutionPlatform.OneLine(exception.Message));
            manager?.Dispose();
            manager = null;
        }
    }

    private static void Append(Guarded attempt, string kind, string? reason, long? output, HeartbeatWatch watch, TimeProvider clock)
    {
        try
        {
            new GuardEvent
            {
                AttemptId = attempt.Spec.AttemptId,
                At = HelperFiles.Now(clock),
                Event = kind,
                Reason = reason,
                OutputBytes = output,
                LimitBytes = reason is null ? null : attempt.Spec.MaxOutputBytes,
                HeartbeatAgeMs = (long)watch.Age.TotalMilliseconds,
                HeartbeatInstance = watch.Last?.Instance ?? string.Empty,
            }.Append(attempt.Files.GuardEventsPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The record is best effort; the stop itself already happened.
        }
    }

    /// <summary>The guard's lock (<c>run/guard.lock</c>, <c>flock</c>): one guard per data root; a second one waits.</summary>
    private static FileStream? AcquireLock(string path, CancellationToken stop)
    {
        while (!stop.IsCancellationRequested)
        {
            var stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
            if (Flock((int)stream.SafeFileHandle.DangerousGetHandle(), 6) == 0)
            {
                return stream;
            }

            stream.Dispose();
            stop.WaitHandle.WaitOne(TimeSpan.FromSeconds(1));
        }

        return null;
    }

    [LibraryImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static partial int Flock(int fd, int operation);

    private sealed class Guarded(AttemptFiles files, GuardSpec spec)
    {
        public AttemptFiles Files { get; } = files;

        public GuardSpec Spec { get; } = spec;

        public bool InCharge { get; set; }

        public bool Notified { get; set; }

        public bool Stopped { get; set; }

        public long? SkipUntil { get; set; }
    }
}
