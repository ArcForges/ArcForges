// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;

namespace ArcForges.LocalRpc;

/// <summary>The closed set of children a parent launches. There is no other kind and no discovery of children.</summary>
public enum LocalRpcChildKind
{
    /// <summary>No child; never a valid launch.</summary>
    None = 0,

    /// <summary>The first-party restricted content parser helper.</summary>
    ContentSandbox = 1,

    /// <summary>An admitted executable extension.</summary>
    ExecutableExtension = 2,

    /// <summary>An owned connector adapter child.</summary>
    Connector = 3,
}

/// <summary>
/// An OS process named by its id and its start time. An id alone is reused by the OS, so a stale record that names a
/// recycled id does not match the new process.
/// </summary>
/// <param name="ProcessId">The OS process id.</param>
/// <param name="StartTimeUtcTicks">
/// The process start value. On Windows and macOS it is the UTC start time in <see cref="DateTime.Ticks"/>. On Linux it is the
/// process start in clock ticks since boot (field 22 of <c>/proc/&lt;pid&gt;/stat</c>, USER_HZ taken as 100) in 100 ns units,
/// because the start time .NET reports on Linux is derived from the wall clock and moves when the clock is stepped.
/// </param>
public readonly record struct LocalRpcProcessIdentity(int ProcessId, long StartTimeUtcTicks)
{
    /// <summary>
    /// Two reads of one process start time can differ by the OS clock resolution (Linux derives it from boot time and
    /// clock ticks), so a start time within this distance names the same process.
    /// </summary>
    internal static readonly TimeSpan StartTimeTolerance = TimeSpan.FromSeconds(2);

    private static readonly Lazy<LocalRpcProcessIdentity> CurrentProcess = new(() => FromProcess(Process.GetCurrentProcess()));

    /// <summary>The identity of the running process.</summary>
    public static LocalRpcProcessIdentity Current => CurrentProcess.Value;

    /// <summary>Names a live process by id and start time. The process must not have exited.</summary>
    public static LocalRpcProcessIdentity FromProcess(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        return new LocalRpcProcessIdentity(process.Id, ProcessStart.Read(process));
    }

    internal bool Names(LocalRpcProcessIdentity other) =>
        ProcessId == other.ProcessId
        && ProcessId > 0
        && Math.Abs(StartTimeUtcTicks - other.StartTimeUtcTicks) <= StartTimeTolerance.Ticks;
}

/// <summary>What the OS reports about a named process.</summary>
internal enum ProcessLiveness
{
    /// <summary>No process with this id and start time exists.</summary>
    Dead = 0,

    /// <summary>The named process is running.</summary>
    Live = 1,

    /// <summary>The OS would not say (for example access denied); callers that authorize treat this as not live and callers that delete treat it as live.</summary>
    Unknown = 2,
}

/// <summary>Reads the start value of a process; see <see cref="LocalRpcProcessIdentity"/>.</summary>
internal static class ProcessStart
{
    /// <summary>100 ns units in one USER_HZ=100 clock tick of Linux.</summary>
    private const long LinuxTickUnits = 100_000;

    internal static long Read(Process process)
    {
        if (!OperatingSystem.IsLinux())
        {
            return process.StartTime.ToUniversalTime().Ticks;
        }

        return TryReadLinux(process.Id, out var start, out _)
            ? start
            : throw new InvalidOperationException("The process start time is not readable.");
    }

    /// <summary>Reads <c>/proc/&lt;pid&gt;/stat</c>: true with the start value, false when the file is not there or not readable.</summary>
    internal static bool TryReadLinux(int processId, out long start, out bool runnable)
    {
        start = 0;
        runnable = false;
        try
        {
            var stat = File.ReadAllText("/proc/" + processId.ToString(System.Globalization.CultureInfo.InvariantCulture) + "/stat");
            if (!TryParseLinuxStat(stat, out var state, out var ticks))
            {
                return false;
            }

            start = ticks * LinuxTickUnits;
            runnable = state is not ('Z' or 'X' or 'x');
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Parses a <c>/proc/&lt;pid&gt;/stat</c> line: the state is the first field after the command name, which can itself hold
    /// spaces and parentheses (so the last closing parenthesis ends it), and the start time is field 22.
    /// </summary>
    internal static bool TryParseLinuxStat(string stat, out char state, out long startTicks)
    {
        state = default;
        startTicks = 0;
        var close = stat.LastIndexOf(')');
        if (close < 0 || close + 2 >= stat.Length)
        {
            return false;
        }

        var fields = stat[(close + 2)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        // fields[0] is field 3 (the state), so field 22 is fields[19].
        if (fields.Length < 20 || fields[0].Length != 1
            || !long.TryParse(fields[19], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out startTicks)
            || startTicks > long.MaxValue / LinuxTickUnits)
        {
            return false;
        }

        state = fields[0][0];
        return true;
    }
}

internal static class ProcessProbe
{
    internal static ProcessLiveness Probe(LocalRpcProcessIdentity identity)
    {
        if (identity.ProcessId <= 0)
        {
            return ProcessLiveness.Dead;
        }

        return OperatingSystem.IsLinux() ? ProbeLinux(identity) : ProbePortable(identity);
    }

    private static ProcessLiveness ProbeLinux(LocalRpcProcessIdentity identity)
    {
        if (!Directory.Exists("/proc/" + identity.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)))
        {
            return ProcessLiveness.Dead;
        }

        if (!ProcessStart.TryReadLinux(identity.ProcessId, out var start, out var runnable))
        {
            // The directory is there but the file is not understood or not readable (or the process vanished meanwhile): not proof.
            return Directory.Exists("/proc/" + identity.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture))
                ? ProcessLiveness.Unknown : ProcessLiveness.Dead;
        }

        if (!runnable)
        {
            return ProcessLiveness.Dead;
        }

        return new LocalRpcProcessIdentity(identity.ProcessId, start).Names(identity) ? ProcessLiveness.Live : ProcessLiveness.Dead;
    }

    private static ProcessLiveness ProbePortable(LocalRpcProcessIdentity identity)
    {
        try
        {
            using var process = Process.GetProcessById(identity.ProcessId);
            if (process.HasExited)
            {
                return ProcessLiveness.Dead;
            }

            var observed = new LocalRpcProcessIdentity(identity.ProcessId, process.StartTime.ToUniversalTime().Ticks);
            return observed.Names(identity) ? ProcessLiveness.Live : ProcessLiveness.Dead;
        }
        catch (ArgumentException)
        {
            return ProcessLiveness.Dead;
        }
        catch (InvalidOperationException)
        {
            return ProcessLiveness.Dead;
        }
        catch (Win32Exception)
        {
            return ProcessLiveness.Unknown;
        }
        catch (NotSupportedException)
        {
            return ProcessLiveness.Unknown;
        }
    }
}
