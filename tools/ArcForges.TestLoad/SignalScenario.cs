// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace ArcForges.TestLoad;

/// <summary>
/// <c>signal</c> (Windows): a process tree with defined console-signal and window behaviour, the input of the termination tests of
/// architecture 04 section 6 (L-18, F-N03). The process records each event as a line <c>&lt;event&gt; &lt;pid&gt; &lt;unix ms&gt;</c> in the
/// <c>marker</c> file: <c>ready</c> once its handlers (and its child) are in place, <c>break</c> when CTRL_BREAK_EVENT (or CTRL_C)
/// arrives, <c>close</c> when its hidden window receives WM_CLOSE. Options:
/// <list type="bullet">
/// <item><c>--on-break exit|ignore</c>: exit with code 3 on the signal, or record it and keep running (a tree that ignores graceful
/// signals, R-EXE-006).</item>
/// <item><c>--window 1</c>: a hidden top-level window (never shown) whose WM_CLOSE ends the process with code 4.</item>
/// <item><c>--free-console 1</c>: the process detaches from its console, so a helper cannot attach to it.</item>
/// <item><c>--child none|same|group|console|window</c>: one child of this tool in the same process group, in its own group
/// (<c>CREATE_NEW_PROCESS_GROUP</c>), with its own windowless console (<c>CREATE_NO_WINDOW</c>), or in its own group with a hidden
/// window; <c>breakaway</c> asks for <c>CREATE_BREAKAWAY_FROM_JOB</c> and records <c>breakaway-refused</c> when the job refuses it, or
/// starts the child outside the job when it allows it.</item>
/// <item><c>--hold-ms</c>: how long to run before exiting 0; <c>--child-hold-ms</c> the child's (default the same).</item>
/// </list>
/// </summary>
[SupportedOSPlatform("windows")]
internal static unsafe partial class SignalScenario
{
    public const int BreakExitCode = 3;
    public const int CloseExitCode = 4;
    public const long MaxHoldMs = 3_600_000;
    private const uint CreateNewProcessGroup = 0x00000200;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateBreakawayFromJob = 0x01000000;
    private const uint WmClose = 0x0010;
    private const uint WmDestroy = 0x0002;
    private static string? s_marker;

    public static ScenarioReport Run(ScenarioOptions options)
    {
        var holdMs = options.GetInt64("hold-ms", 60_000, 0, MaxHoldMs);
        var onBreak = options.GetChoice("on-break", "exit", "exit", "ignore");
        var window = options.GetInt64("window", 0, 0, 1) == 1;
        var freeConsole = options.GetInt64("free-console", 0, 0, 1) == 1;
        var child = options.GetChoice("child", "none", "none", "same", "group", "console", "window", "breakaway");
        var childHoldMs = options.GetInt64("child-hold-ms", holdMs, 0, MaxHoldMs);
        s_marker = options.GetUnrecorded("marker") ?? throw new UsageException("Option '--marker' is required.");
        options.GetUnrecorded("report");
        options.EnsureAllUsed();

        var stopwatch = Stopwatch.StartNew();
        if (freeConsole)
        {
            FreeConsole();
        }

        using var registration = PosixSignalRegistration.Create(PosixSignal.SIGQUIT, context => OnSignal(context, onBreak));
        using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, context => OnSignal(context, onBreak));
        if (window)
        {
            var thread = new Thread(WindowLoop) { IsBackground = true, Name = "hidden-window" };
            thread.Start();
        }

        Process? started = null;
        if (child != "none")
        {
            started = StartChild(child, onBreak, childHoldMs);
        }

        Record("ready");
        Thread.Sleep(TimeSpan.FromMilliseconds(holdMs));
        stopwatch.Stop();
        started?.Dispose();
        return new ScenarioReport
        {
            Scenario = "signal",
            Parameters = options.Parameters,
            Digest = Deterministic.Hex(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(options.Canonical("signal")))),
            Results = new Dictionary<string, long>(StringComparer.Ordinal) { ["heldMs"] = holdMs },
            Measured = Measurements.Collect(stopwatch),
        };
    }

    private static void OnSignal(PosixSignalContext context, string onBreak)
    {
        Record("break");
        context.Cancel = true;
        if (onBreak == "exit")
        {
            Environment.Exit(BreakExitCode);
        }
    }

    private static Process? StartChild(string mode, string onBreak, long holdMs)
    {
        var self = Environment.ProcessPath ?? throw new InvalidOperationException("The tool's path is unknown.");
        var arguments = new StringBuilder();
        arguments.Append('"').Append(self).Append("\" signal --hold-ms ").Append(holdMs.ToString(CultureInfo.InvariantCulture))
            .Append(" --on-break ").Append(onBreak).Append(" --marker \"").Append(s_marker).Append('"');
        if (mode == "window")
        {
            arguments.Append(" --window 1");
        }

        var flags = mode switch
        {
            "group" or "window" => CreateNewProcessGroup,
            "console" => CreateNoWindow,
            "breakaway" => CreateBreakawayFromJob,
            _ => 0u,
        };
        var startup = default(StartupInfo);
        startup.Cb = sizeof(StartupInfo);
        var line = (arguments + "\0").ToCharArray();
        fixed (char* commandLine = line)
        {
            if (!CreateProcess(self, commandLine, 0, 0, false, flags, 0, null, &startup, out var info))
            {
                var error = Marshal.GetLastPInvokeError();
                if (mode == "breakaway")
                {
                    Record("breakaway-refused");
                    return null;
                }

                throw new InvalidOperationException($"The child could not be started (error {error}).");
            }

            if (mode == "breakaway")
            {
                Record("breakaway-allowed");
            }

            CloseHandle(info.Thread);
            CloseHandle(info.Process);
            return Process.GetProcessById(info.ProcessId);
        }
    }

    private static void WindowLoop()
    {
        var name = "ArcForgesTestLoadHidden" + Environment.ProcessId.ToString(CultureInfo.InvariantCulture);
        fixed (char* className = name)
        {
            var windowClass = new WindowClass
            {
                Size = (uint)sizeof(WindowClass),
                Procedure = &WindowProcedure,
                Instance = GetModuleHandle(null),
                ClassName = className,
            };
            if (RegisterClassEx(&windowClass) == 0)
            {
                return;
            }

            // Not WS_VISIBLE and never shown: a hidden top-level window that EnumWindows still lists.
            var handle = CreateWindowEx(0, className, className, 0, 0, 0, 0, 0, 0, 0, windowClass.Instance, 0);
            if (handle == 0)
            {
                return;
            }

            Message message;
            while (GetMessage(&message, 0, 0, 0) > 0)
            {
                TranslateMessage(&message);
                DispatchMessage(&message);
            }
        }

        Environment.Exit(CloseExitCode);
    }

    [UnmanagedCallersOnly]
    private static nint WindowProcedure(nint window, uint message, nint wParam, nint lParam)
    {
        switch (message)
        {
            case WmClose:
                Record("close");
                DestroyWindow(window);
                return 0;
            case WmDestroy:
                PostQuitMessage(0);
                return 0;
            default:
                return DefWindowProc(window, message, wParam, lParam);
        }
    }

    private static void Record(string what)
    {
        var line = what + " " + Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + " "
            + DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture) + "\n";
        for (var tries = 0; tries < 50; tries++)
        {
            try
            {
                // Writers share only reading, so two processes never append at the same offset (they retry instead).
                using var stream = new FileStream(s_marker!, FileMode.Append, FileAccess.Write, FileShare.Read | FileShare.Delete);
                stream.Write(Encoding.UTF8.GetBytes(line));
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(10);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public int Cb;
        public nint Reserved;
        public nint Desktop;
        public nint Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public int Flags;
        public short ShowWindow;
        public short Reserved2;
        public nint Reserved3;
        public nint StdInput;
        public nint StdOutput;
        public nint StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public nint Process;
        public nint Thread;
        public int ProcessId;
        public int ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowClass
    {
        public uint Size;
        public uint Style;
        public delegate* unmanaged<nint, uint, nint, nint, nint> Procedure;
        public int ClassExtra;
        public int WindowExtra;
        public nint Instance;
        public nint Icon;
        public nint Cursor;
        public nint Background;
        public char* MenuName;
        public char* ClassName;
        public nint SmallIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Message
    {
        public nint Window;
        public uint Value;
        public nint WParam;
        public nint LParam;
        public uint Time;
        public int X;
        public int Y;
        public uint Private;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FreeConsole();

    [LibraryImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateProcess(string application, char* commandLine, nint processAttributes, nint threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags, nint environment, string? directory, StartupInfo* startup, out ProcessInformation information);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);

    [LibraryImport("kernel32.dll", EntryPoint = "GetModuleHandleW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint GetModuleHandle(string? name);

    [LibraryImport("user32.dll", EntryPoint = "RegisterClassExW", SetLastError = true)]
    private static partial ushort RegisterClassEx(WindowClass* windowClass);

    [LibraryImport("user32.dll", EntryPoint = "CreateWindowExW", SetLastError = true)]
    private static partial nint CreateWindowEx(uint exStyle, char* className, char* windowName, uint style, int x, int y, int width, int height,
        nint parent, nint menu, nint instance, nint parameter);

    [LibraryImport("user32.dll", EntryPoint = "GetMessageW")]
    private static partial int GetMessage(Message* message, nint window, uint minimum, uint maximum);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TranslateMessage(Message* message);

    [LibraryImport("user32.dll", EntryPoint = "DispatchMessageW")]
    private static partial nint DispatchMessage(Message* message);

    [LibraryImport("user32.dll", EntryPoint = "DefWindowProcW")]
    private static partial nint DefWindowProc(nint window, uint message, nint wParam, nint lParam);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyWindow(nint window);

    [LibraryImport("user32.dll")]
    private static partial void PostQuitMessage(int exitCode);
}
