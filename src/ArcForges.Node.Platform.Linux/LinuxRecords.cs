// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Linux;

/// <summary>The exit records of Linux attempts (04 section 3, <c>exit.json</c> schema 1) from their three sources.</summary>
public static class LinuxRecords
{
    private static readonly string[] SignalNames =
    [
        "", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD",
        "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS",
    ];

    /// <summary>
    /// The number of a signal name as systemd writes it in <c>$EXIT_STATUS</c> (<c>KILL</c>), as a task's <c>stop_signal</c> gives it
    /// (<c>SIGKILL</c>), a real-time signal (<c>RTMIN</c>, <c>RTMIN+3</c>, <c>RTMAX</c>, <c>RTMAX-2</c>, with or without <c>SIG</c>, from the
    /// platform's <c>SIGRTMIN</c>/<c>SIGRTMAX</c>) or a number; 0 when unknown or out of range.
    /// </summary>
    public static int SignalNumber(string? name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return 0;
        }

        if (int.TryParse(name, NumberStyles.None, CultureInfo.InvariantCulture, out var number))
        {
            return number is > 0 and <= 64 ? number : 0;
        }

        var bare = name.StartsWith("SIG", StringComparison.Ordinal) ? name[3..] : name;
        if (RealTime(bare, "RTMIN", RtMin) is { } fromMinimum)
        {
            return fromMinimum;
        }

        if (RealTime(bare, "RTMAX", RtMax) is { } fromMaximum)
        {
            return fromMaximum;
        }

        var index = Array.IndexOf(SignalNames, bare);
        return index > 0 ? index : 0;
    }

    /// <summary>The name of a signal number (<c>TERM</c>, <c>RTMIN+3</c>), or the number as text.</summary>
    public static string SignalName(int number) => number > 0 && number < SignalNames.Length
        ? SignalNames[number]
        : number >= RtMin && number <= RtMax
            ? number == RtMin ? "RTMIN" : "RTMIN+" + (number - RtMin).ToString(CultureInfo.InvariantCulture)
            : number.ToString(CultureInfo.InvariantCulture);

    /// <summary>The platform's <c>SIGRTMIN</c> (34 with glibc; the same value elsewhere, where only tests parse Linux records).</summary>
    private static int RtMin => OperatingSystem.IsLinux() ? Libc.SigRtMin : 34;

    /// <summary>The platform's <c>SIGRTMAX</c>.</summary>
    private static int RtMax => OperatingSystem.IsLinux() ? Libc.SigRtMax : 64;

    private static int? RealTime(string bare, string prefix, int origin)
    {
        if (!bare.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }

        var rest = bare[prefix.Length..];
        int value;
        if (rest.Length == 0)
        {
            value = origin;
        }
        else if (rest[0] is '+' or '-' && int.TryParse(rest[1..], NumberStyles.None, CultureInfo.InvariantCulture, out var offset))
        {
            value = rest[0] == '+' ? origin + offset : origin - offset;
        }
        else
        {
            return 0;
        }

        return value >= RtMin && value <= RtMax ? value : 0;
    }

    /// <summary>
    /// The record <c>arcforges node exit-record</c> writes from systemd's <c>$EXIT_CODE</c>, <c>$EXIT_STATUS</c> and <c>$SERVICE_RESULT</c>
    /// (L-13) and the unit's cgroup accounting. The attempt's result is taken from <c>$EXIT_CODE</c> and <c>$EXIT_STATUS</c>: every exit
    /// status and signal is a success status of the unit (so its <c>ExecStop</c> end steps always run), which makes <c>$SERVICE_RESULT</c>
    /// <c>success</c> for ordinary exits; it is kept only when it says more (<c>oom-kill</c>, <c>timeout</c>, <c>watchdog</c>, ...).
    /// </summary>
    public static ExitRecord FromServiceEnvironment(string attemptId, string? exitCode, string? exitStatus, string? serviceResult, CgroupAccounting? accounting,
        StopRecord? stop, DateTimeOffset now)
    {
        var kind = exitCode is "exited" or "killed" or "dumped" ? exitCode : "exited";
        var status = kind == "exited"
            ? (int.TryParse(exitStatus, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var code) ? code : -1)
            : SignalNumber(exitStatus);
        var record = Base(attemptId, kind, status, serviceResult, now);
        record.RecordedBy = "exit-record";
        Apply(record, accounting);
        record.LeftoversTerminated = stop?.Leftovers ?? [];
        return record;
    }

    /// <summary>
    /// The record the node writes from a failed unit whose <c>ExecStopPost</c> systemd skipped (an OOM kill that races the unit's
    /// stop): the unit's <c>Result</c>, <c>ExecMainCode</c>, <c>ExecMainStatus</c> and its own
    /// accounting record (<c>MemoryPeak</c>, <c>MemorySwapPeak</c>, <c>CPUUsageNSec</c>).
    /// </summary>
    public static ExitRecord FromUnit(string attemptId, UnitState state, StopRecord? stop, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(state);
        var kind = state.ExecMainCode switch
        {
            2 => "killed",
            3 => "dumped",
            _ => "exited",
        };
        var record = Base(attemptId, kind, state.ExecMainCode == 0 ? -1 : state.ExecMainStatus, state.Result, now);
        record.RecordedBy = "unit";
        record.CpuUserMs = (long)(state.CpuUsageNs / 1_000_000);
        record.MemPeakBytes = state.MemoryPeak is > 0 and < long.MaxValue ? (long)state.MemoryPeak : 0;
        record.SwapPeakBytes = state.MemorySwapPeak is < long.MaxValue ? (long)state.MemorySwapPeak : null;
        if (state.Result == "oom-kill")
        {
            record.OomKills = 1;
            record.LimitViolations = ["oom_kill"];
        }

        record.LeftoversTerminated = stop?.Leftovers ?? [];
        return record;
    }

    /// <summary>The record of an attempt the node ran itself as a plain child process (degraded mode), from its wait status.</summary>
    public static ExitRecord FromWaitStatus(string attemptId, int waitStatus, List<string> leftovers, DateTimeOffset now)
    {
        string kind;
        int status;
        if (waitStatus < 0)
        {
            (kind, status) = ("exited", -1);
        }
        else if ((waitStatus & 0x7f) == 0)
        {
            (kind, status) = ("exited", (waitStatus >> 8) & 0xff);
        }
        else
        {
            (kind, status) = ((waitStatus & 0x80) != 0 ? "dumped" : "killed", waitStatus & 0x7f);
        }

        var record = Base(attemptId, kind, status, null, now);
        record.RecordedBy = "node";
        record.LeftoversTerminated = leftovers;
        return record;
    }

    private static ExitRecord Base(string attemptId, string kind, int status, string? serviceResult, DateTimeOffset now) => new()
    {
        AttemptId = attemptId,
        ExitCodeKind = kind,
        ExitStatus = status,
        ServiceResult = serviceResult is { Length: > 0 } result && result != "success"
            ? result
            : kind == "exited" ? (status == 0 ? "success" : "exit-code") : "signal",
        RecordedAt = now.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
    };

    private static void Apply(ExitRecord record, CgroupAccounting? accounting)
    {
        if (accounting is null)
        {
            return;
        }

        record.CpuUserMs = accounting.CpuUserMs;
        record.CpuKernelMs = accounting.CpuKernelMs;
        record.MemPeakBytes = accounting.MemPeakBytes;
        record.SwapPeakBytes = accounting.SwapPeakBytes;
        record.IoReadBytes = accounting.IoReadBytes;
        record.IoWriteBytes = accounting.IoWriteBytes;
        record.OomKills = accounting.OomKills;
        record.LimitViolations = accounting.Violations();
    }
}

/// <summary>What a launch or end step did.</summary>
/// <param name="Outcome"><c>exited</c>, <c>failed</c>, <c>timed_out</c> or <c>not_started</c>.</param>
/// <param name="ExitCode">Its exit code when it exited.</param>
/// <param name="Error">What went wrong, in words.</param>
/// <param name="OsError">The error number when it could not start.</param>
/// <param name="ElapsedMs">How long it ran.</param>
public sealed record StepResult(string Outcome, int? ExitCode, string? Error, int? OsError, long ElapsedMs)
{
    /// <summary>True when the step exited with 0.</summary>
    public bool Succeeded => Outcome == "exited" && ExitCode == 0;
}

/// <summary>Runs launch and end steps (04 section 3): each with <c>/dev/null</c> as its standard streams, the caller's environment and the step's (or the attempt's) working directory, bounded by its timeout.</summary>
[SupportedOSPlatform("linux")]
public static class StepRunner
{
    /// <summary>Runs one step, waiting at most <paramref name="timeout"/> (a step still running then is killed).</summary>
    public static StepResult Run(StepSpec step, IReadOnlyList<string> environment, string workingDirectory, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(step);
        var watch = Stopwatch.StartNew();
        List<string> argv = step.Argv.Count > 0 ? [.. step.Argv] : [step.Application];
        int pid;
        try
        {
            pid = Libc.Spawn(step.Application, argv, environment, (-1, -1, -1), step.WorkingDirectory.Length > 0 ? step.WorkingDirectory : workingDirectory, newProcessGroup: false);
        }
        catch (Win32Exception exception)
        {
            return new StepResult("not_started", null, $"step {step.Name} could not be started: {exception.Message}", exception.NativeErrorCode, watch.ElapsedMilliseconds);
        }

        var status = Libc.Wait(pid, timeout);
        if (status is null)
        {
            Libc.Kill(pid, Libc.SigKill);
            Libc.Wait(pid, TimeSpan.FromSeconds(5));
            return new StepResult("timed_out", null, string.Create(CultureInfo.InvariantCulture, $"step {step.Name} did not finish within {timeout.TotalSeconds:0.#} s"),
                null, watch.ElapsedMilliseconds);
        }

        var (exited, value, _) = Libc.Decode(status.Value);
        if (!exited)
        {
            return new StepResult("failed", null, $"step {step.Name} was killed by signal {LinuxRecords.SignalName(value)}", null, watch.ElapsedMilliseconds);
        }

        // posix_spawn reports an exec failure of the child as exit status 127.
        return value == 0
            ? new StepResult("exited", 0, null, null, watch.ElapsedMilliseconds)
            : new StepResult(value == 127 && !File.Exists(step.Application) ? "not_started" : "failed", value,
                value == 127 && !File.Exists(step.Application)
                    ? $"step {step.Name} could not be started: {step.Application} does not exist"
                    : string.Create(CultureInfo.InvariantCulture, $"step {step.Name} exited with code {value}"),
                null, watch.ElapsedMilliseconds);
    }
}
