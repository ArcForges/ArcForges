// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// <c>arcforges node exec-wrap</c>, the attempt's holder (AD-0005 Windows section 3; 04 section 3). The node starts it outside the
/// attempt's jobs (detached, no console, no window) with inheritable handles to the child job, the root job, the attempt's stdin,
/// stdout and stderr, and the ack event, and sends the <see cref="HolderSpec"/> on its standard input. It runs the attempt
/// (<see cref="AttemptRunner"/>), is its disk guard while the node's heartbeat is stale, writes <c>exit.json</c>, and keeps both job
/// handles until the node sets the ack event, so a restarted node can re-open the jobs by name (L-14). Arguments (a stable internal
/// contract): <c>--attempt &lt;base32&gt; --job &lt;handle&gt; --root-job &lt;handle&gt; --stdin &lt;handle&gt; --stdout &lt;handle&gt;
/// --stderr &lt;handle&gt; --ack &lt;handle&gt;</c>, handles as decimal numbers.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ExecWrapRole
{
    /// <summary>Exit codes.</summary>
    public const int Success = 0;

    /// <summary>The arguments or the spec were invalid.</summary>
    public const int Usage = 2;

    /// <summary>Runs the holder; returns its exit code.</summary>
    public static int Run(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index + 1 < args.Count; index += 2)
        {
            values[args[index]] = args[index + 1];
        }

        if (!TryHandle(values, "--job", out var job) || !TryHandle(values, "--root-job", out var rootJob) || !TryHandle(values, "--stdin", out var stdin)
            || !TryHandle(values, "--stdout", out var stdout) || !TryHandle(values, "--stderr", out var stderr) || !TryHandle(values, "--ack", out var ack)
            || !values.TryGetValue("--attempt", out var attempt))
        {
            return Usage;
        }

        HolderSpec spec;
        try
        {
            using var input = Console.OpenStandardInput();
            using var reader = new StreamReader(input, new UTF8Encoding(false));
            spec = HolderSpec.Parse(reader.ReadToEnd());
        }
        catch (Exception exception) when (exception is IOException or System.Text.Json.JsonException)
        {
            return Usage;
        }

        if (!string.Equals(spec.AttemptId, attempt, StringComparison.Ordinal))
        {
            return Usage;
        }

        using var output = Console.OpenStandardOutput();
        var gate = new Lock();
        var reporting = true;
        void Report(HolderReport report)
        {
            lock (gate)
            {
                if (!reporting)
                {
                    return;
                }

                try
                {
                    output.Write(Encoding.UTF8.GetBytes(report.ToJson() + "\n"));
                    output.Flush();
                }
                catch (IOException)
                {
                    // The node is gone; the records on disk carry on.
                    reporting = false;
                }
            }
        }

        using var childJob = JobObject.FromHandle(job, null);
        using var root = JobObject.FromHandle(rootJob, null);
        using var stdinHandle = new SafeKernelHandle(stdin, ownsHandle: true);
        using var stdoutHandle = new SafeKernelHandle(stdout, ownsHandle: true);
        using var stderrHandle = new SafeKernelHandle(stderr, ownsHandle: true);
        using var ackEvent = new SafeKernelHandle(ack, ownsHandle: true);
        var runner = new AttemptRunner(spec, root, childJob, stdinHandle, stdoutHandle, stderrHandle, Report);
        runner.Run(guard: true);

        // Keep both job handles until the node acknowledges the record.
        Native.WaitForSingleObject(ackEvent, Native.Infinite);
        return Success;
    }

    private static bool TryHandle(Dictionary<string, string> values, string name, out nint handle)
    {
        handle = 0;
        return values.TryGetValue(name, out var text) && long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value)
            && (handle = (nint)value) != 0;
    }
}

/// <summary>
/// <c>arcforges node signal --pid &lt;root pid&gt;</c>: the graceful phase's console helper (04 section 6; L-18). The node starts it
/// detached (no console of its own, no window). It frees any console, attaches to the root process's windowless console, ignores
/// control events itself and generates <c>CTRL_BREAK_EVENT</c> for the root's process group (the root was created with
/// <c>CREATE_NEW_PROCESS_GROUP</c>, so its PID is the group ID). One helper serves one attempt: a process attaches to one console at a
/// time. Exit codes: 0 delivered; 2 the attach failed (the root exited, or it has no console); 3 the event failed; 4 usage.
/// </summary>
[SupportedOSPlatform("windows")]
public static unsafe class SignalRole
{
    /// <summary>Delivered.</summary>
    public const int Delivered = 0;

    /// <summary>The attach failed.</summary>
    public const int AttachFailed = 2;

    /// <summary>The event could not be generated.</summary>
    public const int EventFailed = 3;

    /// <summary>Invalid arguments.</summary>
    public const int Usage = 4;

    /// <summary>Runs the helper; returns its exit code.</summary>
    public static int Run(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Count != 2 || args[0] != "--pid" || !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid <= 0)
        {
            return Usage;
        }

        Native.FreeConsole();
        if (!Native.AttachConsole(pid))
        {
            return AttachFailed;
        }

        try
        {
            Native.SetConsoleCtrlHandler(null, add: true);
            Native.SetConsoleCtrlHandler(&Ignore, add: true);
            return Native.GenerateConsoleCtrlEvent(Native.CtrlBreakEvent, pid) ? Delivered : EventFailed;
        }
        finally
        {
            Native.FreeConsole();
        }
    }

    /// <summary>The meaning of an exit code, for the attempt's record.</summary>
    public static string Describe(int exitCode) => exitCode switch
    {
        Delivered => "CTRL_BREAK_EVENT delivered to the root's process group",
        AttachFailed => "the helper could not attach to the root's console (the root exited, or it is not a console program)",
        EventFailed => "GenerateConsoleCtrlEvent failed",
        Usage => "the helper was started with invalid arguments",
        _ => "the helper ended with exit code " + exitCode.ToString(CultureInfo.InvariantCulture),
    };

    [UnmanagedCallersOnly]
    private static int Ignore(uint controlType) => 1;
}

/// <summary>Sends <c>WM_CLOSE</c> to the top-level windows of processes (04 section 6: GUI processes in the tree).</summary>
[SupportedOSPlatform("windows")]
public static unsafe class GuiWindows
{
    [ThreadStatic]
    private static List<(nint Window, int ProcessId)>? t_windows;

    /// <summary>Posts <c>WM_CLOSE</c> to every top-level window (visible or hidden) owned by <paramref name="processIds"/>; returns the count.</summary>
    public static int Close(IReadOnlyCollection<int> processIds)
    {
        ArgumentNullException.ThrowIfNull(processIds);
        if (processIds.Count == 0)
        {
            return 0;
        }

        var closed = 0;
        foreach (var (window, processId) in TopLevelWindows())
        {
            if (processIds.Contains(processId) && Native.PostMessage(window, Native.WmClose, 0, 0))
            {
                closed++;
            }
        }

        return closed;
    }

    /// <summary>Every top-level window with its owning process.</summary>
    public static List<(nint Window, int ProcessId)> TopLevelWindows()
    {
        t_windows = [];
        try
        {
            Native.EnumWindows(&Collect, 0);
            return t_windows;
        }
        finally
        {
            t_windows = null;
        }
    }

    [UnmanagedCallersOnly]
    private static int Collect(nint window, nint parameter)
    {
        Native.GetWindowThreadProcessId(window, out var processId);
        t_windows?.Add((window, processId));
        return 1;
    }
}
