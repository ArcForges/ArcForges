// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ArcForges.Client;

/// <summary>Why an auto-start was not attempted, or how it failed.</summary>
public enum AutoStartOutcome
{
    /// <summary>The node (or its supervisor or unit) was started; readiness is awaited next.</summary>
    Started = 0,

    /// <summary>The caller runs in a CI job (CI markers present); auto-start is refused (experience/cli.md section 5).</summary>
    RefusedInCi = 1,

    /// <summary>The caller runs in a Windows job that does not allow breakaway (an AI-client sandbox or a CI job).</summary>
    RefusedInSandbox = 2,

    /// <summary>The start itself failed (the supervisor or unit is missing, or the OS refused).</summary>
    Failed = 3,
}

/// <summary>The result of <see cref="NodeAutoStart.Start"/>.</summary>
public sealed record AutoStartResult(AutoStartOutcome Outcome, string Detail);

/// <summary>
/// Starts the node detached when it is absent (architecture 02 section 3):
/// <list type="bullet">
/// <item>Windows: <c>CreateProcess</c> of <c>arcforges-supervisor.exe</c> beside this executable with <c>DETACHED_PROCESS |
/// CREATE_NEW_PROCESS_GROUP</c>, plus <c>CREATE_BREAKAWAY_FROM_JOB</c> only when the client runs inside a job that allows it. A job that
/// allows no breakaway (AI-client sandboxes, CI jobs) refuses the auto-start.</item>
/// <item>Linux: <c>systemctl --user start arcforges-node.service</c>, and a <c>setsid</c> launch of <c>arcforges node run</c> only
/// when the systemd user manager is absent.</item>
/// </list>
/// Inside CI jobs auto-start is refused on both platforms. No handle of the client (its redirected output included) is inherited.
/// </summary>
public static partial class NodeAutoStart
{
    private const uint DetachedProcess = 0x00000008;
    private const uint CreateNewProcessGroup = 0x00000200;
    private const uint CreateBreakawayFromJob = 0x01000000;
    private const uint JobObjectLimitBreakawayOk = 0x00000800;
    private const uint JobObjectLimitSilentBreakawayOk = 0x00001000;
    private const int JobObjectExtendedLimitInformation = 9;

    /// <summary>The supervisor's file name (13 section 3.1).</summary>
    public const string SupervisorFileName = "arcforges-supervisor.exe";

    /// <summary>Starts the node unless the environment refuses it.</summary>
    /// <param name="testMode">Pass <c>--test-mode</c> to what is started (the test hooks then reach the node).</param>
    public static AutoStartResult Start(bool testMode)
    {
        var markers = ClientProcess.CiMarkers();
        if (markers.Count > 0)
        {
            return new AutoStartResult(AutoStartOutcome.RefusedInCi, "CI job (" + string.Join(", ", markers) + ")");
        }

        return OperatingSystem.IsWindows() ? StartWindows(testMode) : StartLinux(testMode);
    }

    /// <summary>Starts the node in the background without the CI refusal (<c>arcforges node run --background</c>).</summary>
    public static AutoStartResult StartExplicitly(bool testMode) => OperatingSystem.IsWindows() ? StartWindows(testMode) : StartLinux(testMode);

    /// <summary>The executable the client runs from (the <c>arcforges</c> binary).</summary>
    public static string CurrentExecutable => Environment.ProcessPath ?? throw new InvalidOperationException("The executable path is unknown.");

    /// <summary>True when the systemd user manager of this user is running (its private socket exists).</summary>
    public static bool UserManagerAvailable()
    {
        var runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        return !string.IsNullOrEmpty(runtime) && Path.IsPathFullyQualified(runtime)
            && File.Exists(Path.Combine(runtime, "systemd", "private")) && FindOnPath("systemctl") is not null;
    }

    /// <summary>
    /// Windows: whether a process this client starts can leave the client's job. Null when it can (no job, or a job with silent
    /// breakaway or <c>JOB_OBJECT_LIMIT_BREAKAWAY_OK</c>, the latter needing <c>CREATE_BREAKAWAY_FROM_JOB</c>); otherwise why not.
    /// </summary>
    public static unsafe string? WindowsSandboxReason(out bool needsBreakawayFlag)
    {
        needsBreakawayFlag = false;
        if (!IsProcessInJob(GetCurrentProcess(), 0, out var inJob))
        {
            return $"IsProcessInJob failed ({Marshal.GetLastPInvokeError()})";
        }

        if (!inJob)
        {
            return null;
        }

        // JOBOBJECT_EXTENDED_LIMIT_INFORMATION is 144 bytes on 64-bit Windows (the query needs the exact size).
        var size = (uint)(IntPtr.Size == 8 ? 144 : 112);
        var info = stackalloc byte[144];
        if (!QueryInformationJobObject(0, JobObjectExtendedLimitInformation, info, size, out _))
        {
            return $"the job cannot be queried ({Marshal.GetLastPInvokeError()})";
        }

        // JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags follows two LARGE_INTEGER time limits.
        var limits = *(uint*)(info + 16);
        if ((limits & JobObjectLimitSilentBreakawayOk) != 0)
        {
            return null;
        }

        if ((limits & JobObjectLimitBreakawayOk) != 0)
        {
            needsBreakawayFlag = true;
            return null;
        }

        return "the client runs in a job that does not allow breakaway";
    }

    private static unsafe AutoStartResult StartWindows(bool testMode)
    {
        var supervisor = Path.Combine(Path.GetDirectoryName(CurrentExecutable)!, SupervisorFileName);
        if (!File.Exists(supervisor))
        {
            return new AutoStartResult(AutoStartOutcome.Failed, $"{SupervisorFileName} is missing beside {CurrentExecutable}");
        }

        var flags = DetachedProcess | CreateNewProcessGroup;
        if (WindowsSandboxReason(out var breakaway) is { } refused)
        {
            return new AutoStartResult(AutoStartOutcome.RefusedInSandbox, refused);
        }

        if (breakaway)
        {
            flags |= CreateBreakawayFromJob;
        }

        var commandLine = "\"" + supervisor + "\"" + (testMode ? " " + NodeLocations.TestModeOption : string.Empty);
        var buffer = (commandLine + "\0").ToCharArray();
        var startup = new StartupInfo { Size = (uint)sizeof(StartupInfo) };
        ProcessInformation process;
        bool created;
        fixed (char* line = buffer)
        {
            created = CreateProcessW(null, line, 0, 0, false, flags, 0, Path.GetDirectoryName(supervisor), &startup, &process);
        }

        if (!created)
        {
            var error = Marshal.GetLastPInvokeError();
            return (flags & CreateBreakawayFromJob) != 0 && error == 5
                ? new AutoStartResult(AutoStartOutcome.RefusedInSandbox, "breakaway from the client's job was denied")
                : new AutoStartResult(AutoStartOutcome.Failed, $"CreateProcess of {SupervisorFileName} failed ({error})");
        }

        CloseHandle(process.Thread);
        CloseHandle(process.Process);
        return new AutoStartResult(AutoStartOutcome.Started, $"{SupervisorFileName} (pid {process.ProcessId})");
    }

    private static AutoStartResult StartLinux(bool testMode)
    {
        var forced = NodeLocations.ForcedAutostart(testMode);
        var systemd = forced switch
        {
            "systemd" => true,
            "setsid" => false,
            _ => UserManagerAvailable(),
        };
        if (systemd)
        {
            var unit = NodeLocations.NodeUnit(testMode);
            var (exit, error) = Run(FindOnPath("systemctl") ?? "systemctl", ["--user", "start", "--no-block", unit]);
            return exit == 0
                ? new AutoStartResult(AutoStartOutcome.Started, $"systemctl --user start {unit}")
                : new AutoStartResult(AutoStartOutcome.Failed, $"systemctl --user start {unit} failed: {error.Trim()}");
        }

        var setsid = FindOnPath("setsid");
        if (setsid is null)
        {
            return new AutoStartResult(AutoStartOutcome.Failed, "the systemd user manager is absent and setsid is not on PATH");
        }

        // The node gets /dev/null as its standard streams and a new session, so it holds none of the client's.
        List<string> arguments = ["-c", "exec \"$0\" -f \"$@\" </dev/null >/dev/null 2>&1", setsid, CurrentExecutable, "node", "run"];
        if (testMode)
        {
            arguments.Add(NodeLocations.TestModeOption);
        }

        var (code, message) = Run("/bin/sh", arguments);
        return code == 0
            ? new AutoStartResult(AutoStartOutcome.Started, "setsid arcforges node run")
            : new AutoStartResult(AutoStartOutcome.Failed, $"setsid failed ({code}): {message.Trim()}");
    }

    /// <summary>Runs a short helper with its standard streams redirected (so the node never inherits the client's).</summary>
    private static (int ExitCode, string Error) Run(string program, IEnumerable<string> arguments)
    {
        var start = new ProcessStartInfo(program)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = "/",
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(start) ?? throw new InvalidOperationException($"{program} did not start.");
            process.StandardInput.Close();
            var error = process.StandardError.ReadToEndAsync();
            process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(TimeSpan.FromSeconds(15)))
            {
                process.Kill(entireProcessTree: true);
                return (-1, $"{program} did not finish within 15 s");
            }

            return (process.ExitCode, error.Wait(TimeSpan.FromSeconds(1)) ? error.Result : string.Empty);
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return (-1, exception.Message);
        }
    }

    /// <summary>The first executable named <paramref name="name"/> on PATH, or <see langword="null"/>.</summary>
    internal static string? FindOnPath(string name)
    {
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(directory, name);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsProcessInJob(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryInformationJobObject(nint job, int informationClass, void* information, uint length, out uint returned);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CreateProcessW(string? applicationName, char* commandLine, nint processAttributes, nint threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, nint environment, string? currentDirectory,
        StartupInfo* startupInfo, ProcessInformation* processInformation);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);

    /// <summary>STARTUPINFOW.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public uint Size;
        public nint Reserved;
        public nint Desktop;
        public nint Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort Reserved2Size;
        public nint Reserved2;
        public nint StandardInput;
        public nint StandardOutput;
        public nint StandardError;
    }

    /// <summary>PROCESS_INFORMATION.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public nint Process;
        public nint Thread;
        public uint ProcessId;
        public uint ThreadId;
    }
}
