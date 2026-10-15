// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;

namespace ArcForges.Tests;

/// <summary>
/// A process recorded by a test, identified by its ID and its creation, never by its ID alone (process IDs are reused: a descendant
/// that exited may hand its ID to an unrelated process of the runner). Linked into every test project from <c>tests/Directory.Build.props</c>.
/// <list type="bullet">
/// <item><see cref="Capture"/> records a running process exactly: its start key (Windows: the creation FILETIME; Linux: the
/// <c>starttime</c> field of <c>/proc/&lt;pid&gt;/stat</c>, in clock ticks since boot).</item>
/// <item><see cref="CreatedNoLaterThan"/> records a process known only by a moment it was alive at (a marker line it wrote, a
/// recorded start time): any process with that ID created after the moment is another one.</item>
/// </list>
/// <see cref="IsRunning"/> is true only while the recorded process itself runs; a different process with the same ID counts as exited.
/// </summary>
internal readonly record struct ProcessIdentity
{
    private static readonly TimeSpan Tolerance = TimeSpan.FromMilliseconds(100);

    private ProcessIdentity(int pid, long startKey, DateTimeOffset? aliveAt)
    {
        Pid = pid;
        StartKey = startKey;
        AliveAt = aliveAt;
    }

    /// <summary>The process ID.</summary>
    public int Pid { get; }

    /// <summary>The exact start key (0 when only <see cref="AliveAt"/> is known).</summary>
    public long StartKey { get; }

    /// <summary>A moment the process was alive at (when only that is known).</summary>
    public DateTimeOffset? AliveAt { get; }

    /// <summary>The identity of the running process <paramref name="pid"/>, or <see langword="null"/> when it is gone.</summary>
    public static ProcessIdentity? Capture(int pid) => StartKeyOf(pid) is { } key ? new ProcessIdentity(pid, key, null) : null;

    /// <summary>A process known to have been alive at <paramref name="aliveAt"/> (so created no later than that).</summary>
    public static ProcessIdentity CreatedNoLaterThan(int pid, DateTimeOffset aliveAt) => new(pid, 0, aliveAt);

    /// <summary>The same as <see cref="CreatedNoLaterThan"/> with a Unix time in milliseconds (the TestLoad marker lines).</summary>
    public static ProcessIdentity CreatedNoLaterThan(int pid, long aliveAtUnixMs) => new(pid, 0, DateTimeOffset.FromUnixTimeMilliseconds(aliveAtUnixMs));

    /// <summary>True while this process (not another one that reused its ID) runs.</summary>
    public bool IsRunning()
    {
        if (StartKey != 0)
        {
            return StartKeyOf(Pid) == StartKey;
        }

        return StartTimeOf(Pid) is { } started && started <= AliveAt!.Value + Tolerance;
    }

    /// <summary>
    /// Terminates this process (and its tree) when it is still the recorded one; a process that reused the ID is never touched.
    /// Returns true when it was terminated and exited within 10 s.
    /// </summary>
    public bool Kill()
    {
        try
        {
            // One handle for the check and the termination on Windows, so the ID cannot change hands in between.
            using var process = Process.GetProcessById(Pid);
            if (process.HasExited)
            {
                return false;
            }

            var matches = StartKey != 0
                ? (OperatingSystem.IsWindows() ? process.StartTime.ToUniversalTime().Ticks : StartKeyOf(Pid)) == StartKey
                : new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) <= AliveAt!.Value + Tolerance;
            if (!matches)
            {
                return false;
            }

            process.Kill(entireProcessTree: true);
            return process.WaitForExit(TimeSpan.FromSeconds(10));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>The start key of the running process <paramref name="pid"/>, or <see langword="null"/> when it is gone or exited.</summary>
    public static long? StartKeyOf(int pid)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                return process.HasExited ? null : process.StartTime.ToUniversalTime().Ticks;
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
            {
                return null;
            }
        }

        try
        {
            // Fields after the parenthesised command name: state (3), ppid (4), ..., starttime (22).
            var stat = File.ReadAllText($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/stat");
            var fields = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
            return fields[0] is "Z" or "X" ? null : long.Parse(fields[19], CultureInfo.InvariantCulture);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException or IndexOutOfRangeException)
        {
            return null;
        }
    }

    private static DateTimeOffset? StartTimeOf(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.HasExited ? null : new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            return null;
        }
    }

    /// <inheritdoc />
    public override string ToString() => StartKey != 0
        ? string.Create(CultureInfo.InvariantCulture, $"process {Pid} (start {StartKey})")
        : string.Create(CultureInfo.InvariantCulture, $"process {Pid} (alive at {AliveAt:O})");
}
