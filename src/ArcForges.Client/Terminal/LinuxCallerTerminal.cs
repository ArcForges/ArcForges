// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Client;

[SupportedOSPlatform("linux")]
internal sealed partial class LinuxCallerTerminal(int descriptor, int processGroup, bool writer) : ICallerTerminal
{
    private const int StandardInput = 0;
    private const int StandardOutput = 1;
    private const int ReadOnly = 0;
    private const int WriteOnly = 1;
    private const int ReadWrite = 2;
    private const int NoControllingTerminal = 0x100;
    private const int NonBlocking = 0x800;
    private const int CloseOnExec = 0x80000;
    private const int Interrupted = 4;
    private const int WouldBlock = 11;
    private const int LockExclusive = 2;
    private const int LockNonBlocking = 4;
    private const int AtEmptyPath = 0x1000;
    private const uint DeviceIdentityFields = 0x101; // STATX_TYPE | STATX_INO
    private const uint DevPtsSlaveMajor = 136;
    private const int SetNow = 0;
    private const int SignalBlock = 0;
    private const int SignalRestore = 2;
    private const int TerminalOutputSignal = 22;
    private const short Readable = 0x01;
    private const short PollError = 0x08;
    private const short Hangup = 0x10;
    private const short InvalidDescriptor = 0x20;
    private const nuint GetWindowSizeRequest = 0x5413;
    private const nuint GetTerminalDeviceRequest = 0x80045432;
    private static readonly int NoFollow = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 0x8000 : 0x20000;
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(20);

    private readonly Lock _gate = new();
    private int _descriptor = descriptor;
    private Termios? _original;

    internal static ICallerTerminal Open(bool writer) => Open(writer, cookedInput: false);

    internal static ICallerTerminal OpenCookedInput() => Open(writer: true, cookedInput: true);

    private static LinuxCallerTerminal Open(bool writer, bool cookedInput)
    {
        int group = GetProcessGroup();
        if (group <= 0 || !cookedInput && GetForegroundGroup(StandardOutput) != group
            || writer && GetForegroundGroup(StandardInput) != group)
        {
            throw new IOException("Terminal attachment requires a foreground Linux terminal.");
        }

        int mode = (cookedInput ? ReadOnly : writer ? ReadWrite : WriteOnly) | NoControllingTerminal | NonBlocking | CloseOnExec;
        int fd = writer ? OpenInputTerminal(mode, group) : OpenDevice("/dev/tty", mode);
        var terminal = new LinuxCallerTerminal(fd, group, writer);
        try
        {
            terminal.RequireForeground();
            if (writer)
            {
                HoldInput(fd);
                if (!cookedInput) terminal.EnterRawMode();
            }

            return terminal;
        }
        catch (Exception initial)
        {
            try
            {
                terminal.RestoreAndClose();
            }
            catch (IOException restoration)
            {
                throw new IOException("Linux terminal setup and mode restoration failed.", new AggregateException(initial, restoration));
            }

            throw;
        }
    }

    private static int OpenInputTerminal(int mode, int group)
    {
        uint device = ReadTerminalDevice(StandardInput);
        uint major = (device >> 8) & 0xfff;
        uint minor = (device & 0xff) | ((device >> 12) & 0xfff00);
        var input = ReadDeviceNode(StandardInput);
        bool nativeInput = input.MatchesDevice(major, minor);
        DeviceNode? output = !nativeInput && GetForegroundGroup(StandardOutput) == group ? ReadDeviceNode(StandardOutput) : null;
        DeviceNode? expected = null;
        string path;
        if (nativeInput)
        {
            expected = input;
            path = "/proc/self/fd/0";
        }
        else if (output is { } outputNode && outputNode.MatchesDevice(major, minor))
        {
            expected = outputNode;
            path = "/proc/self/fd/1";
        }
        else
        {
            // A shell can redirect stdin from the generic /dev/tty alias. Resolve its actual native device.
            path = major switch
            {
                DevPtsSlaveMajor => FormattableString.Invariant($"/dev/pts/{minor}"),
                4 when minor is > 0 and < 64 => FormattableString.Invariant($"/dev/tty{minor}"),
                _ => throw new IOException("The actual Linux terminal device could not be resolved from standard input."),
            };
            mode |= NoFollow;
        }

        // Reopening gives each attachment a separate open file description on the actual tty inode.
        int fd = OpenDevice(path, mode);
        try
        {
            var actual = ReadDeviceNode(fd);
            if (!actual.MatchesDevice(major, minor) || expected is { } prior && !actual.SameNode(prior)
                || ReadTerminalDevice(fd) != device || GetForegroundGroup(fd) != group)
            {
                throw new IOException("The caller's controlling Linux terminal changed while it was being opened.");
            }

            return fd;
        }
        catch
        {
            _ = Close(fd);
            throw;
        }
    }

    private static int OpenDevice(string path, int mode)
    {
        int fd = OpenTerminal(path, mode);
        return fd >= 0 ? fd : throw Error("open the caller terminal", Marshal.GetLastPInvokeError());
    }

    private static uint ReadTerminalDevice(int fd)
    {
        if (GetTerminalDevice(fd, GetTerminalDeviceRequest, out uint device) != 0)
        {
            throw Error("identify the caller terminal", Marshal.GetLastPInvokeError());
        }

        return device;
    }

    private static DeviceNode ReadDeviceNode(int fd)
    {
        if (Statx(fd, string.Empty, AtEmptyPath, DeviceIdentityFields, out var result) != 0)
        {
            throw Error("read the caller terminal identity", Marshal.GetLastPInvokeError());
        }

        if ((result.Mask & DeviceIdentityFields) != DeviceIdentityFields)
        {
            throw new IOException("Linux did not return the caller terminal device identity.");
        }

        return result;
    }

    private static void HoldInput(int fd)
    {
        while (Flock(fd, LockExclusive | LockNonBlocking) != 0)
        {
            int error = Marshal.GetLastPInvokeError();
            if (error == WouldBlock) throw new CallerTerminalInUseException();
            if (error != Interrupted) throw Error("lock the caller terminal input", error);
        }
    }

    public CallerTerminalSize? GetSize()
    {
        lock (_gate)
        {
            RequireOpen();
            if (GetWindowSize(_descriptor, GetWindowSizeRequest, out var size) == 0)
            {
                return size.Rows > 0 && size.Columns > 0 ? new(size.Rows, size.Columns) : null;
            }

            int error = Marshal.GetLastPInvokeError();
            return error == Interrupted ? null : throw Error("read the caller terminal size", error);
        }
    }

    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!writer) throw new InvalidOperationException("An observing terminal cannot read terminal input.");
        if (buffer.IsEmpty) return 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (TryRead(buffer.Span) is { } count) return count;
            await Task.Delay(PollInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        while (!bytes.IsEmpty)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int count = TryWrite(bytes.Span);
            if (count == 0)
            {
                await Task.Delay(PollInterval, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                bytes = bytes[count..];
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate) RestoreAndClose();
        return ValueTask.CompletedTask;
    }

    private void EnterRawMode()
    {
        if (GetAttributes(_descriptor, out var original) != 0)
        {
            throw Error("save the caller terminal mode", Marshal.GetLastPInvokeError());
        }

        _original = original;
        var raw = original;
        MakeRaw(ref raw);
        SetMode(raw);
    }

    private void RestoreAndClose()
    {
        if (_descriptor < 0) return;
        try
        {
            if (_original is { } original) SetMode(original);
        }
        finally
        {
            // This close releases the input lock only after restoring the original mode.
            // Linux closes the descriptor even when close reports EINTR.
            _ = Close(_descriptor);
            _descriptor = -1;
            _original = null;
        }
    }

    private void SetMode(Termios mode)
    {
        // A foreground group change may happen after admission or during cleanup.
        if (EmptySignalSet(out var signals) != 0 || AddSignal(ref signals, TerminalOutputSignal) != 0)
        {
            throw Error("prepare the caller terminal mode change", Marshal.GetLastPInvokeError());
        }

        int error = ChangeSignalMask(SignalBlock, in signals, out var saved);
        if (error != 0) throw Error("protect the caller terminal mode change", error);
        int restoreError;
        try
        {
            while (SetAttributes(_descriptor, SetNow, in mode) != 0)
            {
                error = Marshal.GetLastPInvokeError();
                if (error != Interrupted) throw Error("set the caller terminal mode", error);
            }

            if (GetAttributes(_descriptor, out var actual) != 0)
            {
                throw Error("read back the caller terminal mode", Marshal.GetLastPInvokeError());
            }

            if (!SameMode(actual, mode)) throw new IOException("Linux did not apply the requested caller terminal mode.");
        }
        finally
        {
            restoreError = ChangeSignalMask(SignalRestore, in saved, out _);
        }

        if (restoreError != 0) throw Error("restore the caller signal mask", restoreError);
    }

    private unsafe int? TryRead(Span<byte> buffer)
    {
        lock (_gate)
        {
            RequireOpen();
            RequireForeground();
            var poll = new PollDescriptor { Descriptor = _descriptor, Events = Readable };
            int result = Poll(ref poll, 1, 0);
            if (result < 0)
            {
                int error = Marshal.GetLastPInvokeError();
                return error == Interrupted ? null : throw Error("poll the caller terminal", error);
            }

            if (result == 0) return null;
            if ((poll.ReturnedEvents & Readable) != 0)
            {
                fixed (byte* data = buffer)
                {
                    nint count = Read(_descriptor, data, (nuint)buffer.Length);
                    if (count >= 0) return checked((int)count);
                }

                int error = Marshal.GetLastPInvokeError();
                if ((poll.ReturnedEvents & Hangup) != 0) return 0;
                return error is Interrupted or WouldBlock ? null : throw Error("read the caller terminal", error);
            }

            if ((poll.ReturnedEvents & Hangup) != 0) return 0;
            if ((poll.ReturnedEvents & (PollError | InvalidDescriptor)) != 0)
            {
                throw new IOException("The caller terminal input is unavailable.");
            }

            return null;
        }
    }

    private unsafe int TryWrite(ReadOnlySpan<byte> bytes)
    {
        lock (_gate)
        {
            RequireOpen();
            RequireForeground();
            fixed (byte* data = bytes)
            {
                nint count = Write(_descriptor, data, (nuint)bytes.Length);
                if (count > 0) return checked((int)count);
                if (count == 0) throw new IOException("The caller terminal output closed during a write.");
            }

            int error = Marshal.GetLastPInvokeError();
            return error is Interrupted or WouldBlock ? 0 : throw Error("write to the caller terminal", error);
        }
    }

    private void RequireOpen() => ObjectDisposedException.ThrowIf(_descriptor < 0, this);

    private void RequireForeground()
    {
        if (GetForegroundGroup(_descriptor) != processGroup)
        {
            throw new IOException("The caller no longer owns the foreground Linux terminal.");
        }
    }

    private static IOException Error(string operation, int errno) =>
        new(FormattableString.Invariant($"Could not {operation} (Linux errno {errno})."));

    private static unsafe bool SameMode(Termios left, Termios right) => left.Input == right.Input && left.Output == right.Output
        && left.Control == right.Control && left.Local == right.Local && left.Line == right.Line
        && left.InputSpeed == right.InputSpeed && left.OutputSpeed == right.OutputSpeed
        && new ReadOnlySpan<byte>(left.Characters, 32).SequenceEqual(new ReadOnlySpan<byte>(right.Characters, 32));

    // glibc's Linux x64/arm64 layout, including all control characters and both speeds.
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

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct DeviceNode
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(128)] internal uint DeviceMajor;
        [FieldOffset(132)] internal uint DeviceMinor;
        [FieldOffset(136)] internal uint FilesystemMajor;
        [FieldOffset(140)] internal uint FilesystemMinor;

        internal readonly bool MatchesDevice(uint major, uint minor) => (Mode & 0xf000) == 0x2000
            && DeviceMajor == major && DeviceMinor == minor;

        internal readonly bool SameNode(DeviceNode other) => Inode == other.Inode && FilesystemMajor == other.FilesystemMajor
            && FilesystemMinor == other.FilesystemMinor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct SignalSet
    {
        internal fixed ulong Words[16];
    }

    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int OpenTerminal(string path, int flags);

    [LibraryImport("libc", EntryPoint = "close")]
    private static partial int Close(int fd);

    [LibraryImport("libc", EntryPoint = "getpgrp")]
    private static partial int GetProcessGroup();

    [LibraryImport("libc", EntryPoint = "tcgetpgrp")]
    private static partial int GetForegroundGroup(int fd);

    [LibraryImport("libc", EntryPoint = "tcgetattr", SetLastError = true)]
    private static partial int GetAttributes(int fd, out Termios mode);

    [LibraryImport("libc", EntryPoint = "tcsetattr", SetLastError = true)]
    private static partial int SetAttributes(int fd, int action, in Termios mode);

    [LibraryImport("libc", EntryPoint = "cfmakeraw")]
    private static partial void MakeRaw(ref Termios mode);

    [LibraryImport("libc", EntryPoint = "sigemptyset", SetLastError = true)]
    private static partial int EmptySignalSet(out SignalSet set);

    [LibraryImport("libc", EntryPoint = "sigaddset", SetLastError = true)]
    private static partial int AddSignal(ref SignalSet set, int signal);

    [LibraryImport("libc", EntryPoint = "pthread_sigmask")]
    private static partial int ChangeSignalMask(int operation, in SignalSet set, out SignalSet oldSet);

    [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static partial int GetWindowSize(int fd, nuint request, out WindowSize size);

    [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static partial int GetTerminalDevice(int fd, nuint request, out uint device);

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int Statx(int fd, string path, int flags, uint mask, out DeviceNode result);

    [LibraryImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static partial int Flock(int fd, int operation);

    [LibraryImport("libc", EntryPoint = "poll", SetLastError = true)]
    private static partial int Poll(ref PollDescriptor poll, nuint count, int timeout);

    [LibraryImport("libc", EntryPoint = "read", SetLastError = true)]
    private static unsafe partial nint Read(int fd, byte* buffer, nuint count);

    [LibraryImport("libc", EntryPoint = "write", SetLastError = true)]
    private static unsafe partial nint Write(int fd, byte* buffer, nuint count);
}
