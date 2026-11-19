// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace ArcForges.TestLoad;

/// <summary>A bounded native terminal workload. Its private markers record observations, never input.</summary>
internal static partial class TerminalScenario
{
    private enum Mode { Tui, Signal, Quiet }

    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(90);
    private const string EnterScreen = "\u001b[?1049h\u001b[2J\u001b[HCORE03 星";
    private const string LeaveScreen = "\u001b[?1049l";

    public static async Task<int> RunAsync(string[] args)
    {
        if (args is ["slow-output", var marker, var prefixGate, var tailGate])
        {
            return await SlowOutputAsync(marker, prefixGate, tailGate).ConfigureAwait(false);
        }

        if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
        {
            throw new UsageException("The terminal probe requires a mode and a marker file.");
        }

        var mode = args[0] switch
        {
            "tui" when args.Length == 2 => Mode.Tui,
            "signal" when args.Length == 2 => Mode.Signal,
            "quiet" when args.Length is 3 or 4 => Mode.Quiet,
            _ => throw new UsageException("Invalid terminal probe arguments."),
        };
        int expected = mode == Mode.Quiet ? ReadBoundedInt(args[2], 1, 4 * 1024 * 1024) : 0;
        int linger = args.Length == 4 ? ReadBoundedInt(args[3], 0, 15_000) : 0;
        using var markers = new StreamWriter(new FileStream(args[1], FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        var probe = new Probe(mode, expected, TimeSpan.FromMilliseconds(linger), markers);
        try
        {
            if (OperatingSystem.IsWindows())
            {
                return await WindowsAsync(probe).ConfigureAwait(false);
            }

            if (OperatingSystem.IsLinux())
            {
                return await LinuxAsync(probe).ConfigureAwait(false);
            }

            markers.WriteLine("error unsupported-platform");
            return ExitCodes.Failure;
        }
        catch (TerminalFailure error)
        {
            markers.WriteLine(FormattableString.Invariant($"error {error.Operation} {error.NativeCode}"));
            return ExitCodes.Failure;
        }
    }

    private static async Task<int> SlowOutputAsync(string marker, string prefixGate, string tailGate)
    {
        using var milestones = new StreamWriter(new FileStream(marker, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        using var output = Console.OpenStandardOutput();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var cancellationToken = deadline.Token;
        await output.WriteAsync("CORE03 slow viewer \n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        milestones.WriteLine("started");
        await WaitForFileAsync(prefixGate, cancellationToken).ConfigureAwait(false);
        await WriteBurstAsync(512 * 1024, (byte)'P', cancellationToken).ConfigureAwait(false);
        milestones.WriteLine("prefix-complete");
        await WaitForFileAsync(tailGate, cancellationToken).ConfigureAwait(false);
        await WriteBurstAsync(3 * 1024 * 1024, (byte)'T', cancellationToken).ConfigureAwait(false);
        milestones.WriteLine("finished");
        return ExitCodes.Success;

        async Task WriteBurstAsync(int count, byte value, CancellationToken token)
        {
            var block = new byte[16 * 1024];
            Array.Fill(block, value);
            while (count > 0)
            {
                int length = Math.Min(count, block.Length);
                await output.WriteAsync(block.AsMemory(0, length), token).ConfigureAwait(false);
                count -= length;
            }

            await output.FlushAsync(token).ConfigureAwait(false);
        }
    }

    private static async Task WaitForFileAsync(string path, CancellationToken cancellationToken)
    {
        while (!File.Exists(path))
        {
            await Task.Delay(20, cancellationToken).ConfigureAwait(false);
        }
    }

    private static int ReadBoundedInt(string value, int minimum, int maximum) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int result) && result >= minimum && result <= maximum
            ? result : throw new UsageException("A terminal probe count or delay is outside its bounds.");

    private sealed class Probe(Mode mode, int expected, TimeSpan linger, TextWriter markers)
    {
        private int _consumed;
        private int _reported;
        private int _unicodePrefix;
        private bool _quit;

        public Mode Scenario { get; } = mode;

        public void Consume(ReadOnlySpan<byte> bytes)
        {
            if (Scenario == Mode.Quiet)
            {
                _consumed += bytes.Length;
                return;
            }

            if (Scenario != Mode.Tui)
            {
                return;
            }

            foreach (var value in bytes)
            {
                ReadOnlySpan<byte> unicode = "星"u8;
                _unicodePrefix = value == unicode[_unicodePrefix] ? _unicodePrefix + 1 : value == unicode[0] ? 1 : 0;
                if (_unicodePrefix == unicode.Length)
                {
                    markers.WriteLine("unicode");
                    _unicodePrefix = 0;
                }

                if (value == 3)
                {
                    markers.WriteLine("raw-etx");
                }
                else if (value == 'q')
                {
                    _quit = true;
                }
            }
        }

        public bool Restore(Action? leaveScreen, Action restoreMode)
        {
            bool screenRestored = leaveScreen is null || TryRestore(leaveScreen);
            bool modeRestored = TryRestore(restoreMode);
            if (modeRestored)
            {
                markers.WriteLine("restored");
            }

            return screenRestored && modeRestored;
        }

        private bool TryRestore(Action operation)
        {
            try
            {
                operation();
                return true;
            }
            catch (TerminalFailure error)
            {
                markers.WriteLine(FormattableString.Invariant($"error cleanup-{error.Operation} {error.NativeCode}"));
                return false;
            }
            catch (IOException)
            {
                markers.WriteLine("error cleanup-io");
                return false;
            }
        }

        public async Task<int> DriveAsync(Func<Geometry> size, Action<string> display, Action read, Func<bool> interrupted)
        {
            var previous = size();
            markers.WriteLine(FormattableString.Invariant($"ready {previous.Rows} {previous.Columns}"));
            var runtime = Stopwatch.StartNew();
            TimeSpan? firstComplete = null;
            while (runtime.Elapsed < Deadline)
            {
                if (Scenario == Mode.Signal && interrupted())
                {
                    markers.WriteLine("sigint");
                    return ExitCodes.Success;
                }

                read();
                if (Scenario == Mode.Tui)
                {
                    var current = size();
                    if (previous != current)
                    {
                        previous = current;
                        markers.WriteLine(FormattableString.Invariant($"resize {current.Rows} {current.Columns}"));
                        display(FormattableString.Invariant($"\u001b[2;1HCORE03 redraw 星 {current.Rows}x{current.Columns}\u001b[K"));
                    }

                    if (_quit)
                    {
                        return ExitCodes.Success;
                    }
                }

                if (Scenario == Mode.Quiet)
                {
                    if (_reported != _consumed)
                    {
                        _reported = _consumed;
                        markers.WriteLine(FormattableString.Invariant($"consumed {_reported}"));
                    }

                    if (_consumed > expected)
                    {
                        throw new TerminalFailure("unexpected-input-count", 0);
                    }

                    if (_consumed == expected)
                    {
                        firstComplete ??= runtime.Elapsed;
                        if (runtime.Elapsed - firstComplete.Value >= linger)
                        {
                            return ExitCodes.Success;
                        }
                    }
                }

                await Task.Delay(20).ConfigureAwait(false);
            }

            markers.WriteLine("error deadline");
            return ExitCodes.Failure;
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task<int> WindowsAsync(Probe probe)
    {
        const uint processedInput = 1;
        const uint lineInput = 2;
        const uint echoInput = 4;
        const uint processedOutput = 1;
        const uint virtualTerminalOutput = 4;
        nint input = GetStdHandle(-10);
        nint output = GetStdHandle(-11);
        Require(GetConsoleMode(input, out uint originalInput), "get-input-mode");
        Require(GetConsoleMode(output, out uint originalOutput), "get-output-mode");
        uint requested = originalInput & ~(processedInput | lineInput | echoInput);
        if (probe.Scenario == Mode.Signal)
        {
            requested |= processedInput;
        }

        int interrupted = 0;
        ConsoleCancelEventHandler handler = (_, args) =>
        {
            if (args.SpecialKey == ConsoleSpecialKey.ControlC)
            {
                args.Cancel = true;
                Interlocked.Exchange(ref interrupted, 1);
            }
        };
        bool signal = probe.Scenario == Mode.Signal;
        if (signal)
        {
            Console.CancelKeyPress += handler;
        }

        int result;
        bool restored;
        bool alternate = false;
        try
        {
            Require(SetConsoleMode(input, requested), "set-input-mode");
            Require(GetConsoleMode(input, out uint actualInput), "check-input-mode");
            if ((actualInput & (processedInput | lineInput | echoInput)) != (requested & (processedInput | lineInput | echoInput)))
            {
                throw new TerminalFailure("unexpected-input-mode", 0);
            }

            if (probe.Scenario == Mode.Tui)
            {
                Require(SetConsoleMode(output, originalOutput | processedOutput | virtualTerminalOutput), "set-output-mode");
                alternate = true;
                WindowsDisplay(output, EnterScreen);
            }

            var utf8 = new UTF8Encoding(false, true).GetEncoder();
            result = await probe.DriveAsync(() => WindowsSize(output), text => WindowsDisplay(output, text),
                () => WindowsRead(input, utf8, probe), () => Volatile.Read(ref interrupted) != 0).ConfigureAwait(false);
        }
        finally
        {
            restored = probe.Restore(alternate ? () => WindowsDisplay(output, LeaveScreen) : null,
                () => RestoreWindowsMode(input, output, originalInput, originalOutput));
            if (signal)
            {
                Console.CancelKeyPress -= handler;
            }
        }

        return restored ? result : ExitCodes.Failure;
    }

    [SupportedOSPlatform("windows")]
    private static void RestoreWindowsMode(nint input, nint output, uint originalInput, uint originalOutput)
    {
        bool inputRestored = SetConsoleMode(input, originalInput);
        int inputError = Marshal.GetLastPInvokeError();
        Require(SetConsoleMode(output, originalOutput), "restore-output-mode");
        if (!inputRestored)
        {
            throw new TerminalFailure("restore-input-mode", inputError);
        }

        Require(GetConsoleMode(input, out uint actualInput), "read-restored-input-mode");
        Require(GetConsoleMode(output, out uint actualOutput), "read-restored-output-mode");
        if (actualInput != originalInput || actualOutput != originalOutput)
        {
            throw new TerminalFailure("mode-not-restored", 0);
        }
    }

    [SupportedOSPlatform("windows")]
    private static Geometry WindowsSize(nint output)
    {
        Require(GetConsoleScreenBufferInfo(output, out var info), "get-screen-size");
        return new Geometry(info.Window.Bottom - info.Window.Top + 1, info.Window.Right - info.Window.Left + 1);
    }

    [SupportedOSPlatform("windows")]
    private static void WindowsDisplay(nint output, string text)
    {
        Require(WriteConsole(output, text, (uint)text.Length, out uint written, 0), "write-screen");
        if (written != (uint)text.Length)
        {
            throw new TerminalFailure("short-screen-write", 0);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void WindowsRead(nint input, Encoder utf8, Probe probe)
    {
        Require(GetNumberOfConsoleInputEvents(input, out uint count), "read-key-count");
        Span<char> character = stackalloc char[1];
        Span<byte> bytes = stackalloc byte[8];
        for (var index = 0U; index < Math.Min(count, 64U); index++)
        {
            Require(ReadConsoleInput(input, out var record, 1, out uint read), "read-key");
            if (read != 1 || record.EventType != 1 || record.KeyDown == 0 || record.Character == 0)
            {
                continue;
            }

            character[0] = (char)record.Character;
            for (int repeat = 0; repeat < record.RepeatCount; repeat++)
            {
                int length = utf8.GetBytes(character, bytes, flush: false);
                probe.Consume(bytes[..length]);
            }
        }
    }

    [SupportedOSPlatform("linux")]
    private static async Task<int> LinuxAsync(Probe probe)
    {
        const uint signals = 1;
        const uint canonical = 2;
        const uint echo = 8;
        Require(IsATty(0) == 1 && IsATty(1) == 1, "isatty");
        Require(TcGetAttr(0, out var original) == 0, "tcgetattr");
        var requested = original;
        MakeRaw(ref requested);
        int interrupted = 0;
        bool signal = probe.Scenario == Mode.Signal;
        using var interrupt = signal ? PosixSignalRegistration.Create(PosixSignal.SIGINT, context =>
        {
            context.Cancel = true;
            Interlocked.Exchange(ref interrupted, 1);
        }) : null;
        if (signal)
        {
            int group = GetProcessGroup();
            Require(group > 0 && TcGetPgrp(0) == group, "foreground-group");
            EnableInterrupt(ref requested);
        }

        int result;
        bool restored;
        bool alternate = false;
        try
        {
            Require(TcSetAttr(0, 0, in requested) == 0, "tcsetattr");
            Require(TcGetAttr(0, out var actual) == 0, "check-termios");
            if ((actual.Local & (signals | canonical | echo)) != (signal ? signals : 0))
            {
                throw new TerminalFailure("unexpected-termios", 0);
            }

            if (probe.Scenario == Mode.Tui)
            {
                alternate = true;
                LinuxDisplay(EnterScreen);
            }

            result = await probe.DriveAsync(LinuxSize, LinuxDisplay, () => LinuxRead(probe),
                () => Volatile.Read(ref interrupted) != 0).ConfigureAwait(false);
        }
        finally
        {
            restored = probe.Restore(alternate ? () => LinuxDisplay(LeaveScreen) : null, () => RestoreLinuxMode(original));
        }

        return restored ? result : ExitCodes.Failure;
    }

    [SupportedOSPlatform("linux")]
    private static void RestoreLinuxMode(Termios original)
    {
        Require(TcSetAttr(0, 0, in original) == 0, "restore-termios");
        Require(TcGetAttr(0, out var restored) == 0, "read-restored-termios");
        if (!SameTermios(restored, original))
        {
            throw new TerminalFailure("termios-not-restored", 0);
        }
    }

    [SupportedOSPlatform("linux")]
    private static Geometry LinuxSize()
    {
        Require(GetWindowSize(1, 0x5413, out var size) == 0, "tiocgwinsz");
        return new Geometry(size.Rows, size.Columns);
    }

    [SupportedOSPlatform("linux")]
    private static void LinuxDisplay(string text)
    {
        using var output = Console.OpenStandardOutput();
        output.Write(Encoding.UTF8.GetBytes(text));
        output.Flush();
    }

    [SupportedOSPlatform("linux")]
    private static unsafe void LinuxRead(Probe probe)
    {
        var polled = new PollDescriptor { Descriptor = 0, Events = 1 };
        int result = Poll(ref polled, 1, 0);
        const int interrupted = 4;
        if (result < 0)
        {
            if (Marshal.GetLastPInvokeError() == interrupted)
            {
                return;
            }

            throw new TerminalFailure("poll", Marshal.GetLastPInvokeError());
        }

        if (result == 0 || (polled.ReturnedEvents & (1 | 8 | 16)) == 0)
        {
            return;
        }

        Span<byte> bytes = stackalloc byte[512];
        fixed (byte* pointer = bytes)
        {
            nint count = ReadNative(0, (nint)pointer, (nuint)bytes.Length);
            if (count < 0 && Marshal.GetLastPInvokeError() == interrupted)
            {
                return;
            }

            Require(count > 0, "read-terminal");
            probe.Consume(bytes[..checked((int)count)]);
        }
    }

    private static unsafe void EnableInterrupt(ref Termios mode)
    {
        mode.Local |= 1;
        mode.Characters[0] = 3;
    }

    private static unsafe bool SameTermios(Termios left, Termios right) => left.Input == right.Input
        && left.Output == right.Output && left.Control == right.Control && left.Local == right.Local && left.Line == right.Line
        && left.InputSpeed == right.InputSpeed && left.OutputSpeed == right.OutputSpeed
        && new ReadOnlySpan<byte>(left.Characters, 32).SequenceEqual(new ReadOnlySpan<byte>(right.Characters, 32));

    private static void Require(bool success, string operation)
    {
        if (!success)
        {
            throw new TerminalFailure(operation, Marshal.GetLastPInvokeError());
        }
    }

    private sealed class TerminalFailure(string operation, int nativeCode) : IOException("A native terminal probe operation failed.")
    {
        public string Operation { get; } = operation;
        public int NativeCode { get; } = nativeCode;
    }

    private readonly record struct Geometry(int Rows, int Columns);

    [StructLayout(LayoutKind.Sequential)]
    private struct Coordinate { internal short X, Y; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Rectangle { internal short Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ScreenBufferInfo { internal Coordinate Size, Cursor; internal ushort Attributes; internal Rectangle Window; internal Coordinate Maximum; }
    [StructLayout(LayoutKind.Explicit, Size = 20)]
    private struct InputRecord
    {
        [FieldOffset(0)] internal ushort EventType;
        [FieldOffset(4)] internal int KeyDown;
        [FieldOffset(8)] internal ushort RepeatCount;
        [FieldOffset(14)] internal ushort Character;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct Termios
    {
        internal uint Input, Output, Control, Local;
        internal byte Line;
        internal fixed byte Characters[32];
        internal uint InputSpeed, OutputSpeed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowSize { internal ushort Rows, Columns, PixelWidth, PixelHeight; }
    [StructLayout(LayoutKind.Sequential)]
    private struct PollDescriptor { internal int Descriptor; internal short Events, ReturnedEvents; }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint GetStdHandle(int identifier);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetConsoleMode(nint handle, out uint mode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetConsoleMode(nint handle, uint mode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetConsoleScreenBufferInfo(nint handle, out ScreenBufferInfo info);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNumberOfConsoleInputEvents(nint handle, out uint count);

    [LibraryImport("kernel32.dll", EntryPoint = "ReadConsoleInputW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReadConsoleInput(nint handle, out InputRecord record, uint length, out uint read);

    [LibraryImport("kernel32.dll", EntryPoint = "WriteConsoleW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WriteConsole(nint handle, string text, uint length, out uint written, nint reserved);

    [LibraryImport("libc", EntryPoint = "isatty", SetLastError = true)]
    private static partial int IsATty(int descriptor);

    [LibraryImport("libc", EntryPoint = "tcgetattr", SetLastError = true)]
    private static partial int TcGetAttr(int descriptor, out Termios attributes);

    [LibraryImport("libc", EntryPoint = "tcsetattr", SetLastError = true)]
    private static partial int TcSetAttr(int descriptor, int action, in Termios attributes);

    [LibraryImport("libc", EntryPoint = "cfmakeraw")]
    private static partial void MakeRaw(ref Termios attributes);

    [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static partial int GetWindowSize(int descriptor, nuint request, out WindowSize size);

    [LibraryImport("libc", EntryPoint = "getpgrp")]
    private static partial int GetProcessGroup();

    [LibraryImport("libc", EntryPoint = "tcgetpgrp", SetLastError = true)]
    private static partial int TcGetPgrp(int descriptor);

    [LibraryImport("libc", EntryPoint = "poll", SetLastError = true)]
    private static partial int Poll(ref PollDescriptor descriptor, nuint count, int timeout);

    [LibraryImport("libc", EntryPoint = "read", SetLastError = true)]
    private static partial nint ReadNative(int descriptor, nint buffer, nuint count);
}
