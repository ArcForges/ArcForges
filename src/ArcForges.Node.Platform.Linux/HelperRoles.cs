// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Linux;

/// <summary>Parses the arguments of the Linux helper roles: <c>--name value</c> pairs, repeatable names, and everything after <c>--</c>.</summary>
internal sealed class RoleArguments
{
    private readonly Dictionary<string, List<string>> _values = new(StringComparer.Ordinal);

    private RoleArguments()
    {
    }

    public List<string> Rest { get; } = [];

    public static RoleArguments? Parse(IReadOnlyList<string> args)
    {
        var parsed = new RoleArguments();
        for (var index = 0; index < args.Count; index++)
        {
            if (args[index] == "--")
            {
                parsed.Rest.AddRange(args.Skip(index + 1));
                return parsed;
            }

            if (!args[index].StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Count)
            {
                return null;
            }

            if (!parsed._values.TryGetValue(args[index], out var list))
            {
                parsed._values[args[index]] = list = [];
            }

            list.Add(args[++index]);
        }

        return parsed;
    }

    public string? One(string name) => _values.TryGetValue(name, out var list) && list.Count == 1 ? list[0] : null;

    public List<string> All(string name) => _values.TryGetValue(name, out var list) ? list : [];
}

/// <summary>
/// <c>arcforges node exec-launch --attempt &lt;id&gt; --dir &lt;attempt directory&gt; --cwd &lt;dir&gt; --program &lt;path&gt;
/// [--nofile &lt;soft&gt;] [--unset &lt;name&gt;]... -- &lt;argv&gt;</c>: the <c>ExecStart</c> of an attempt unit (04 section 3; a stable
/// internal contract). It runs inside the unit's cgroup with the unit's exact environment: it enters the working directory, runs the
/// launch steps of <c>steps.json</c> in order (each with <c>/dev/null</c> as its streams, bounded by its timeout), then replaces itself
/// with the command (<c>execve</c>), so the command is the unit's main process with the PID systemd started. Before the <c>execve</c> it
/// restores what the .NET runtime changed in this process (the soft open-file limit it raised, <c>SIGPIPE</c> it ignores, the signal mask)
/// and removes the variables systemd adds to every service (<c>--unset</c>: those the resolved environment does not hold). A failing step,
/// a working directory it cannot enter, or a command it cannot start is written to <c>launch.json</c> and the role exits (126, or 127 when
/// the program does not exist); <c>exit-record</c> then records the attempt and the node records it as <c>SPAWN_FAILED</c>.
/// </summary>
[SupportedOSPlatform("linux")]
public static class ExecLaunchRole
{
    /// <summary>A launch step failed, or the command could not be started.</summary>
    public const int LaunchFailed = 126;

    /// <summary>The command does not exist.</summary>
    public const int NotFound = 127;

    /// <summary>Invalid arguments.</summary>
    public const int Usage = 2;

    /// <summary>The variable that carries the environment entries systemd refuses in <c>Environment=</c> (base64 of NUL-separated entries).</summary>
    public const string CarrierVariable = "ARCFORGES_EXEC_ENVIRONMENT";

    /// <summary>The variables systemd sets for every service process (the node's resolved environment decides which stay).</summary>
    public static readonly IReadOnlyList<string> ManagerAddedVariables =
        ["INVOCATION_ID", "MANAGERPID", "SYSTEMD_EXEC_PID", "MEMORY_PRESSURE_WATCH", "MEMORY_PRESSURE_WRITE", "JOURNAL_STREAM"];

    /// <summary>Runs the role; returns only when the command could not replace it.</summary>
    public static int Run(IReadOnlyList<string> args)
    {
        var parsed = RoleArguments.Parse(args);
        if (parsed?.One("--attempt") is not { } attempt || parsed.One("--dir") is not { } directory || parsed.One("--cwd") is not { } workingDirectory
            || parsed.One("--program") is not { } program || parsed.Rest.Count == 0)
        {
            return Usage;
        }

        var launchPath = Path.Combine(directory, AttemptFiles.Launch);
        if (Libc.ChangeDirectory(workingDirectory) != 0)
        {
            var error = Libc.LastError;
            return Fail(launchPath, attempt, "command", $"the working directory {workingDirectory} cannot be entered: {Marshal.GetPInvokeErrorMessage(error)}", null, error, LaunchFailed);
        }

        var unset = parsed.All("--unset").ToHashSet(StringComparer.Ordinal);
        var environment = CurrentEnvironment().Where(entry => !unset.Contains(entry[..Math.Max(0, entry.IndexOf('=', StringComparison.Ordinal))])).ToList();

        if (StepsFile.TryRead(Path.Combine(directory, AttemptFiles.Steps)) is { } steps)
        {
            foreach (var step in steps.LaunchSteps)
            {
                var result = StepRunner.Run(step, environment, workingDirectory, TimeSpan.FromMilliseconds(step.TimeoutMs));
                if (!result.Succeeded)
                {
                    return Fail(launchPath, attempt, step.Name, result.Error ?? $"step {step.Name} failed", result.ExitCode, result.OsError, LaunchFailed);
                }
            }
        }

        if (parsed.One("--nofile") is { } nofile && ulong.TryParse(nofile, NumberStyles.None, CultureInfo.InvariantCulture, out var soft)
            && Libc.GetRLimit(Libc.RlimitNofile, out var limit) == 0)
        {
            limit.Current = Math.Min(soft, limit.Maximum);
            Libc.SetRLimit(Libc.RlimitNofile, limit);
        }

        var failure = Libc.Exec(program, parsed.Rest, environment);
        return Fail(launchPath, attempt, "command", $"the command could not be started: {Marshal.GetPInvokeErrorMessage(failure)}", null, failure,
            failure == 2 ? NotFound : LaunchFailed);
    }

    /// <summary>This process's environment with the carried entries unpacked (and the carrier removed).</summary>
    internal static List<string> CurrentEnvironment()
    {
        var environment = new List<string>();
        string? carried = null;
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            var name = (string)entry.Key;
            if (name == CarrierVariable)
            {
                carried = (string?)entry.Value;
            }
            else
            {
                environment.Add(name + "=" + (string?)entry.Value);
            }
        }

        if (carried is { Length: > 0 })
        {
            try
            {
                environment.AddRange(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(carried)).Split('\0'));
            }
            catch (FormatException)
            {
                // Not ours: nothing to unpack.
            }
        }

        return environment;
    }

    private static int Fail(string path, string attempt, string step, string error, int? exitCode, int? osError, int code)
    {
        try
        {
            HelperFiles.WriteAtomically(path, new LaunchRecord
            {
                AttemptId = attempt,
                Step = step,
                Error = error,
                ExitCode = exitCode,
                OsError = osError,
                RecordedAt = HelperFiles.Now(),
            }.ToJson());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("arcforges: launch.json cannot be written: " + exception.Message);
        }

        Console.Error.WriteLine("arcforges: " + error);
        return code;
    }
}

/// <summary>
/// <c>arcforges node exec-stop --attempt &lt;id&gt; --dir &lt;attempt directory&gt;</c>: the <c>ExecStop=-</c> of an attempt unit (04
/// section 3). systemd runs it once the main process exited (every exit status and signal is a success status of the unit, so it always
/// runs), before it stops the remaining processes. It runs the end steps of <c>steps.json</c> within the end-step budget (10 s; a
/// failing or slow step is recorded and never changes the attempt's result), waits up to <c>leftover_grace</c> for the unit's other
/// processes to exit on their own, and writes what is still running to <c>stop.json</c>; systemd then stops those processes
/// (<c>KillMode=control-group</c>) and <c>exit-record</c> lists them as terminated leftovers. It always exits 0.
/// </summary>
[SupportedOSPlatform("linux")]
public static class ExecStopRole
{
    /// <summary>Runs the role.</summary>
    public static int Run(IReadOnlyList<string> args)
    {
        var parsed = RoleArguments.Parse(args);
        if (parsed?.One("--attempt") is not { } attempt || parsed.One("--dir") is not { } directory)
        {
            return 0;
        }

        var steps = StepsFile.TryRead(Path.Combine(directory, AttemptFiles.Steps)) ?? new StepsFile { AttemptId = attempt };
        var environment = ExecLaunchRole.CurrentEnvironment();
        var record = new StopRecord { AttemptId = attempt };
        var budget = Stopwatch.StartNew();
        var total = TimeSpan.FromMilliseconds(steps.EndStepBudgetMs);
        foreach (var step in steps.EndSteps)
        {
            var remaining = total - budget.Elapsed;
            if (remaining <= TimeSpan.Zero)
            {
                record.EndSteps.Add(new StepOutcome { Name = step.Name, Outcome = "skipped" });
                continue;
            }

            var timeout = TimeSpan.FromMilliseconds(Math.Min(step.TimeoutMs, remaining.TotalMilliseconds));
            var result = StepRunner.Run(step, environment, Environment.CurrentDirectory, timeout);
            record.EndSteps.Add(new StepOutcome { Name = step.Name, Outcome = result.Outcome, ExitCode = result.ExitCode, ElapsedMs = result.ElapsedMs });
        }

        // leftover_grace: the unit's other processes may still end on their own.
        var cgroup = ProcFs.OwnCgroup() is { } path ? ProcFs.CgroupDirectory(path) : null;
        var grace = Stopwatch.StartNew();
        var self = Environment.ProcessId;
        List<int> others = cgroup is null ? [] : [.. ProcFs.Procs(cgroup).Where(pid => pid != self)];
        while (others.Count > 0 && grace.ElapsedMilliseconds < steps.LeftoverGraceMs)
        {
            Thread.Sleep(50);
            others = [.. ProcFs.Procs(cgroup!).Where(pid => pid != self)];
        }

        record.Leftovers = [.. others.Select(ProcFs.Image)];
        record.RecordedAt = HelperFiles.Now();
        try
        {
            HelperFiles.WriteAtomically(Path.Combine(directory, AttemptFiles.Stop), record.ToJson());
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("arcforges: stop.json cannot be written: " + exception.Message);
        }

        return 0;
    }
}

/// <summary>
/// <c>arcforges node exit-record --attempt &lt;id&gt; --dir &lt;attempt directory&gt;</c>: the <c>ExecStopPost</c> of an attempt unit
/// (04 section 3; L-13). systemd runs it in the unit's cgroup after the unit's processes ended, with <c>$EXIT_CODE</c>,
/// <c>$EXIT_STATUS</c> and <c>$SERVICE_RESULT</c>, whether or not the node runs. It writes <c>exit.json</c> with the result and the
/// cgroup's accounting (<c>cpu.stat</c>, <c>memory.peak</c>, <c>memory.swap.peak</c>, <c>memory.events</c>, <c>io.stat</c>, <c>pids.events</c>)
/// and the leftovers <c>exec-stop</c> found, durably (written to a temporary file, flushed, renamed).
/// </summary>
[SupportedOSPlatform("linux")]
public static class ExitRecordRole
{
    /// <summary>Invalid arguments or the record could not be written.</summary>
    public const int Failed = 1;

    /// <summary>Runs the role.</summary>
    public static int Run(IReadOnlyList<string> args)
    {
        var parsed = RoleArguments.Parse(args);
        if (parsed?.One("--attempt") is not { } attempt || parsed.One("--dir") is not { } directory)
        {
            return Failed;
        }

        var cgroup = ProcFs.OwnCgroup() is { } path ? ProcFs.CgroupDirectory(path) : null;
        var record = LinuxRecords.FromServiceEnvironment(attempt, Environment.GetEnvironmentVariable("EXIT_CODE"), Environment.GetEnvironmentVariable("EXIT_STATUS"),
            Environment.GetEnvironmentVariable("SERVICE_RESULT"), cgroup is null ? null : ProcFs.Accounting(cgroup),
            StopRecord.TryRead(Path.Combine(directory, AttemptFiles.Stop)), DateTimeOffset.UtcNow);
        try
        {
            HelperFiles.WriteAtomically(Path.Combine(directory, AttemptFiles.Exit), record.ToJson());
            return 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("arcforges: exit.json cannot be written: " + exception.Message);
            return Failed;
        }
    }
}
