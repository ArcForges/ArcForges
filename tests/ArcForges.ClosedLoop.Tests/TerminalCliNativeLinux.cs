// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.Client;
using ArcForges.Node.Platform.Linux;
using ArcForges.Security.Secrets;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>The exact fixture CLI child and its controlling Linux terminal. The test holds its matching slave for mode readback.</summary>
[SupportedOSPlatform("linux")]
internal sealed partial class TerminalCliNativeLinux : IAsyncDisposable
{
    private const string SessionLauncher = "/usr/bin/setsid";
    private const int ReadWrite = 2;
    private const int NoControllingTerminal = 0x100;
    private const int NonBlocking = 0x800;
    private const int OpenFlags = ReadWrite | NoControllingTerminal | Libc.OCloexec;
    private const int Interrupted = 4;
    private const int IoError = 5;
    private const int TryAgain = 11;
    private const int NoSuchProcess = 3;
    private const nuint PeerSlave = 0x5441;
    private const nuint GetWindowSize = 0x5413;
    private const nuint SetWindowSize = 0x5414;
    private static readonly TimeSpan IoPoll = TimeSpan.FromMilliseconds(15);
    private static readonly TimeSpan CleanupBound = TimeSpan.FromSeconds(5);

    private readonly SafeFileHandle _master;
    private readonly SafeFileHandle _slave;
    private readonly SafeFileHandle _process;
    private readonly Lock _exitGate = new();
    private int? _exitCode;
    private int _disposeStarted;
    private bool _ownsPeerController;

    internal sealed record TerminalMode(uint InputFlags, uint OutputFlags, uint ControlFlags, uint LocalFlags,
        byte Line, string ControlCharacters, uint InputSpeed, uint OutputSpeed);

    private TerminalCliNativeLinux(SafeFileHandle master, SafeFileHandle slave, SafeFileHandle process,
        int processId, DateTimeOffset processStartTimeUtc, TerminalMode originalMode)
    {
        _master = master;
        _slave = slave;
        _process = process;
        ProcessId = processId;
        ProcessStartTimeUtc = processStartTimeUtc;
        OriginalMode = originalMode;
        Input = new TerminalStream(this, writable: true);
        Output = new TerminalStream(this, writable: false);
    }

    public Stream Input { get; }
    public Stream Output { get; }
    public int ProcessId { get; }
    public DateTimeOffset ProcessStartTimeUtc { get; }
    public TerminalMode OriginalMode { get; }

    public static TerminalCliNativeLinux StartControlledPeers(string controller, string cli, string firstRun, string secondRun,
        string cwd, IReadOnlyDictionary<string, string?> environment, ushort rows, ushort columns)
    {
        var terminal = Start(controller, ["terminal", "share-linux-cli-console", cli, firstRun, secondRun, cwd,
            NodeLocations.TestModeOption], cwd, environment, rows, columns);
        terminal._ownsPeerController = true;
        return terminal;
    }

    public static TerminalCliNativeLinux Start(string executable, IReadOnlyList<string> args, string cwd,
        IReadOnlyDictionary<string, string?> environment, ushort rows, ushort columns)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(environment);
        if (!Path.IsPathFullyQualified(executable) || !File.Exists(executable) || !Path.IsPathFullyQualified(cwd)
            || !Directory.Exists(cwd) || !File.Exists(SessionLauncher))
        {
            throw new InvalidOperationException("The native CLI fixture requires the installed CLI, its private working directory and util-linux setsid.");
        }

        if (executable.Contains('\0') || cwd.Contains('\0') || args.Any(argument => argument.Contains('\0'))
            || !args.TakeWhile(argument => argument != "--").Contains(NodeLocations.TestModeOption, StringComparer.Ordinal)
            || !environment.TryGetValue(NodeLocations.ConfigDirectoryVariable, out var config) || !Path.IsPathFullyQualified(config ?? "")
            || !environment.TryGetValue(NodeLocations.EndpointVariable, out var endpoint) || !Path.IsPathFullyQualified(endpoint ?? ""))
        {
            throw new InvalidOperationException("The native CLI fixture requires isolated test mode, configuration and endpoint.");
        }

        var variables = ChildEnvironment(cwd, environment);
        SafeFileHandle? master = null;
        SafeFileHandle? slave = null;
        SafeFileHandle? process = null;
        int pid = 0;
        try
        {
            master = OwnTerminalDescriptor(OpenMaster(OpenFlags | NonBlocking), "open private PTY master");
            if (GrantTerminal(master) != 0) throw NativeError("grant private PTY slave");
            if (UnlockTerminal(master) != 0) throw NativeError("unlock private PTY slave");
            // The kernel returns this master's peer without resolving a potentially replaced /dev/pts path.
            slave = OwnTerminalDescriptor(OpenPeer(master, PeerSlave, OpenFlags), "open exact PTY slave peer");
            ResizeSlave(slave, rows, columns);
            var original = ReadMode(slave);
            int tty = slave.DangerousGetHandle().ToInt32();
            // Inherit the test process group initially. The spawned PID therefore is not its group leader,
            // so setsid can acquire a session and controlling terminal without forking before exec.
            pid = Libc.Spawn(SessionLauncher, [SessionLauncher, "--ctty", "--", executable, .. args], variables,
                (tty, tty, tty), cwd, newProcessGroup: false);
            int descriptor = Libc.PidfdOpen(pid);
            if (descriptor < 0) throw NativeError("hold exact fixture CLI pidfd");
            process = new SafeFileHandle(descriptor, ownsHandle: true);
            var birth = ProcFs.Stat(pid) ?? throw new InvalidOperationException("The spawned fixture CLI has no native process identity.");
            var terminal = new TerminalCliNativeLinux(master, slave, process, pid, ProcFs.StartInstant(birth.StartTicks), original);
            master = null;
            slave = null;
            process = null;
            return terminal;
        }
        catch (Exception launchFailure)
        {
            try
            {
                if (pid > 0 && Libc.Wait(pid, TimeSpan.Zero) is null)
                {
                    // A live direct child cannot be confused with a reused PID before it is reaped.
                    int signaled = process is null ? Libc.Kill(pid, Libc.SigKill)
                        : Libc.PidfdSendSignal(process.DangerousGetHandle().ToInt32(), Libc.SigKill);
                    if (signaled != 0 && Libc.LastError != NoSuchProcess) throw NativeError("clean up failed fixture CLI launch");
                    if (Libc.Wait(pid, CleanupBound) is null) throw new TimeoutException("The failed PTY launch did not release its exact CLI process.");
                }
            }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException("The PTY launch and its cleanup both failed.", launchFailure, cleanupFailure);
            }

            throw;
        }
        finally
        {
            process?.Dispose();
            slave?.Dispose();
            master?.Dispose();
        }
    }

    private static string[] ChildEnvironment(string cwd, IReadOnlyDictionary<string, string?> environment)
    {
        var variables = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["HOME"] = cwd,
            ["LANG"] = "C.UTF-8",
            ["PATH"] = "/usr/bin:/bin",
            ["TERM"] = "xterm-256color",
        };
        if (Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } dotnetRoot)
        {
            variables["DOTNET_ROOT"] = dotnetRoot;
        }

        foreach (var (name, value) in environment)
        {
            if (name.Length == 0 || name.Contains('=') || name.Contains('\0') || value?.Contains('\0') == true)
            {
                throw new ArgumentException("The native fixture received an invalid environment field.", nameof(environment));
            }

            if (value is null) variables.Remove(name);
            else variables[name] = value;
        }

        variables.Remove(OsSecretStoreGuard.OptInVariable);
        return variables.Select(pair => pair.Key + "=" + pair.Value).ToArray();
    }

    public void Resize(ushort rows, ushort columns) => ResizeSlave(_slave, rows, columns);

    public (ushort Rows, ushort Columns) ReadSize()
    {
        if (ReadWindow(_slave, GetWindowSize, out var size) != 0) throw NativeError("read matching PTY window size");
        return (size.Rows, size.Columns);
    }

    public TerminalMode ReadMode() => ReadMode(_slave);

    public void AssertModeRestored() => Assert.Equal(OriginalMode, ReadMode());

    private static void ResizeSlave(SafeFileHandle slave, ushort rows, ushort columns)
    {
        ArgumentOutOfRangeException.ThrowIfZero(rows);
        ArgumentOutOfRangeException.ThrowIfZero(columns);
        if (WriteWindow(slave, SetWindowSize, new Window { Rows = rows, Columns = columns }) != 0)
        {
            throw NativeError("resize matching PTY slave");
        }
    }

    private static unsafe TerminalMode ReadMode(SafeFileHandle slave)
    {
        if (ReadTerminal(slave, out var mode) != 0) throw NativeError("read matching PTY terminal mode");
        return new TerminalMode(mode.Input, mode.Output, mode.Control, mode.Local, mode.Line,
            Convert.ToHexString(new ReadOnlySpan<byte>(mode.Characters, 32)), mode.InputSpeed, mode.OutputSpeed);
    }

    public void Kill() => SignalIfLive(Libc.SigKill);

    private void SignalIfLive(int signal)
    {
        lock (_exitGate)
        {
            if (ObserveExit() is null && Libc.PidfdSendSignal(_process.DangerousGetHandle().ToInt32(), signal) != 0
                && Libc.LastError != NoSuchProcess)
            {
                throw NativeError("signal exact fixture CLI");
            }
        }
    }

    public async Task<int> WaitForExitAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_exitGate)
            {
                if (ObserveExit() is { } exit) return exit;
            }

            await Task.Delay(IoPoll, cancellationToken);
        }
    }

    private int? ObserveExit()
    {
        if (_exitCode.HasValue) return _exitCode;
        int result;
        int status;
        do
        {
            result = Libc.WaitPid(ProcessId, out status, Libc.WNoHang);
        }
        while (result < 0 && Libc.LastError == Interrupted);

        if (result < 0) throw NativeError("wait for exact fixture CLI");
        if (result == ProcessId)
        {
            var (exited, codeOrSignal, _) = Libc.Decode(status);
            _exitCode = exited ? codeOrSignal : 128 + codeOrSignal;
        }

        return _exitCode;
    }

    public async ValueTask<int> ReadAsync(Memory<byte> bytes, CancellationToken cancellationToken = default)
    {
        while (!bytes.IsEmpty)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (TryRead(bytes.Span) is { } read) return read;

            // The held slave keeps its termios readable after exit. End the stream only when the exact
            // child exited and a subsequent master read confirms its final bytes have been drained.
            lock (_exitGate)
            {
                if (ObserveExit().HasValue) return TryRead(bytes.Span) ?? 0;
            }

            await Task.Delay(IoPoll, cancellationToken);
        }

        return 0;
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
    {
        while (!bytes.IsEmpty)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (TryWrite(bytes.Span) is { } written)
            {
                bytes = bytes[written..];
                continue;
            }

            lock (_exitGate)
            {
                if (ObserveExit().HasValue) throw new IOException("The fixture CLI exited before the complete terminal write.");
            }

            await Task.Delay(IoPoll, cancellationToken);
        }
    }

    private unsafe int? TryRead(Span<byte> bytes)
    {
        fixed (byte* pointer = bytes)
        {
            nint read = ReadMaster(_master, pointer, (nuint)bytes.Length);
            if (read >= 0) return (int)read;
            int error = Marshal.GetLastPInvokeError();
            if (error is TryAgain or Interrupted) return null;
            if (error == IoError)
            {
                lock (_exitGate)
                {
                    if (ObserveExit().HasValue) return 0;
                }
            }

            throw new Win32Exception(error, "read fixture PTY master");
        }
    }

    private unsafe int? TryWrite(ReadOnlySpan<byte> bytes)
    {
        fixed (byte* pointer = bytes)
        {
            nint written = WriteMaster(_master, pointer, (nuint)bytes.Length);
            if (written > 0) return (int)written;
            if (written == 0) throw new IOException("The fixture PTY made no write progress.");
            int error = Marshal.GetLastPInvokeError();
            if (error is TryAgain or Interrupted) return null;
            throw new Win32Exception(error, "write fixture PTY master");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0) return;
        try
        {
            if (_ownsPeerController)
            {
                SignalIfLive(Libc.SigTerm); // The exact controller drains its two held CLI children on SIGTERM.
                using var peerDeadline = new CancellationTokenSource(CleanupBound);
                try
                {
                    await WaitForExitAsync(peerDeadline.Token);
                }
                catch (OperationCanceledException) when (peerDeadline.IsCancellationRequested)
                {
                    // Recover the separately held controller before closing the private terminal.
                }
            }

            Kill();
            using var deadline = new CancellationTokenSource(CleanupBound);
            await WaitForExitAsync(deadline.Token);
        }
        finally
        {
            lock (_exitGate) _process.Dispose();
            _slave.Dispose();
            _master.Dispose();
        }
    }

    private static SafeFileHandle OwnTerminalDescriptor(int fd, string operation)
    {
        if (fd < 0) throw NativeError(operation);
        var handle = new SafeFileHandle(fd, ownsHandle: true);
        if (fd >= 3) return handle;
        handle.Dispose();
        throw new InvalidOperationException("The fixture process must have its own standard streams before allocating a PTY.");
    }

    private static Win32Exception NativeError(string operation) => new(Marshal.GetLastPInvokeError(), operation);

    private sealed class TerminalStream(TerminalCliNativeLinux terminal, bool writable) : Stream
    {
        public override bool CanRead => !writable;
        public override bool CanWrite => writable;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            !writable ? terminal.ReadAsync(buffer, cancellationToken) : throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            writable ? terminal.WriteAsync(buffer, cancellationToken) : throw new NotSupportedException();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Window { internal ushort Rows, Columns, PixelWidth, PixelHeight; }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct Termios
    {
        internal uint Input, Output, Control, Local;
        internal byte Line;
        internal fixed byte Characters[32];
        internal uint InputSpeed, OutputSpeed;
    }

    [LibraryImport("libc", EntryPoint = "posix_openpt", SetLastError = true)]
    private static partial int OpenMaster(int flags);

    [LibraryImport("libc", EntryPoint = "grantpt", SetLastError = true)]
    private static partial int GrantTerminal(SafeFileHandle master);

    [LibraryImport("libc", EntryPoint = "unlockpt", SetLastError = true)]
    private static partial int UnlockTerminal(SafeFileHandle master);

    [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static partial int OpenPeer(SafeFileHandle master, nuint request, int flags);

    [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static partial int ReadWindow(SafeFileHandle slave, nuint request, out Window window);

    [LibraryImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static partial int WriteWindow(SafeFileHandle slave, nuint request, in Window window);

    [LibraryImport("libc", EntryPoint = "tcgetattr", SetLastError = true)]
    private static partial int ReadTerminal(SafeFileHandle slave, out Termios mode);

    [LibraryImport("libc", EntryPoint = "read", SetLastError = true)]
    private static unsafe partial nint ReadMaster(SafeFileHandle master, byte* buffer, nuint count);

    [LibraryImport("libc", EntryPoint = "write", SetLastError = true)]
    private static unsafe partial nint WriteMaster(SafeFileHandle master, byte* buffer, nuint count);
}
