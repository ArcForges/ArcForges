// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Client;

[SupportedOSPlatform("windows")]
internal sealed partial class WindowsCallerTerminal : ICallerTerminal
{
    private const int StandardInput = -10;
    private const int StandardOutput = -11;
    private const uint ProcessedInput = 0x0001;
    private const uint LineInput = 0x0002;
    private const uint EchoInput = 0x0004;
    private const uint VirtualTerminalInput = 0x0200;
    private const uint ProcessedOutput = 0x0001;
    private const uint VirtualTerminalOutput = 0x0004;
    private const uint DuplicateSameAccess = 0x0002;
    private const int InvalidHandle = 6;
    private const int OperationAborted = 995;
    private const int NoPendingIo = 1168;
    private static readonly TimeSpan InterruptBound = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan InterruptInterval = TimeSpan.FromMilliseconds(15);
    private static readonly TimeSpan GeometryBound = TimeSpan.FromMilliseconds(100);
    private static readonly TimeSpan RestorationBound = TimeSpan.FromSeconds(2);

    private readonly Mutex _console;
    private readonly SafeFileHandle? _output;
    private readonly SafeFileHandle? _input;
    private readonly uint? _originalOutput;
    private readonly uint? _originalInput;
    private readonly ConsoleIoWorker? _outputWorker;
    private readonly ConsoleIoWorker? _inputWorker;
    private readonly OutputEncoding? _outputEncoding;
    private readonly InputEncoding? _inputEncoding;
    private readonly SemaphoreSlim _outputLane = new(1, 1);
    private int _disposed;

    private WindowsCallerTerminal(Mutex console, SafeFileHandle? output, uint? originalOutput,
        SafeFileHandle? input, uint? originalInput)
    {
        _console = console;
        _output = output;
        _originalOutput = originalOutput;
        _input = input;
        _originalInput = originalInput;
        _outputEncoding = output is null ? null : new OutputEncoding(output);
        _inputEncoding = input is null ? null : new InputEncoding(input);
        _outputWorker = output is null ? null : new ConsoleIoWorker();
        try
        {
            _inputWorker = input is null ? null : new ConsoleIoWorker();
        }
        catch
        {
            // No output requests can exist before the attachment has been published.
            if (_outputWorker is { } worker)
            {
                worker.Stop();
                worker.Completion.GetAwaiter().GetResult();
                worker.Dispose();
            }

            throw;
        }
    }

    internal static ICallerTerminal Open(bool writer) => Open(read: writer, write: true, raw: writer);

    internal static ICallerTerminal OpenCookedInput() => Open(read: true, write: false, raw: false);

    private static WindowsCallerTerminal Open(bool read, bool write, bool raw)
    {
        var console = ClaimConsole();
        SafeFileHandle? output = null;
        SafeFileHandle? input = null;
        uint? restoreOutput = null;
        uint? restoreInput = null;
        try
        {
            if (write)
            {
                output = Duplicate(GetStdHandle(StandardOutput), "open console output");
                uint original = ReadMode(output, "read console output mode");
                uint rendering = original | ProcessedOutput | VirtualTerminalOutput;
                restoreOutput = original;
                if (rendering != original)
                {
                    ChangeMode(output, rendering, "enable console output VT processing");
                }
            }

            if (read)
            {
                input = Duplicate(GetStdHandle(StandardInput), "open console input");
                uint original = ReadMode(input, "read console input mode");
                if (raw)
                {
                    uint rawMode = (original & ~(ProcessedInput | LineInput | EchoInput)) | VirtualTerminalInput;
                    restoreInput = original;
                    if (rawMode != original)
                    {
                        ChangeMode(input, rawMode, "enable raw console input");
                    }
                }
            }

            return new WindowsCallerTerminal(console, output, restoreOutput, input, restoreInput);
        }
        catch (Exception initial)
        {
            try
            {
                RestoreModes(output, restoreOutput, input, restoreInput);
            }
            catch (IOException restoration)
            {
                throw new IOException("Windows terminal setup and mode restoration failed.", new AggregateException(initial, restoration));
            }
            finally
            {
                input?.Dispose();
                output?.Dispose();
                console.Dispose();
            }

            throw;
        }
    }

    private static Mutex ClaimConsole()
    {
        // ConPTY supplies its own message-only window. All local clients on that console see the same HWND.
        nint window = GetConsoleWindow();
        if (window == 0)
        {
            throw new IOException("Windows did not identify the caller's console.");
        }

        string name = "ArcForges.CallerConsole." + ((nuint)window).ToString("x", CultureInfo.InvariantCulture);
        var options = new NamedWaitHandleOptions { CurrentUserOnly = true, CurrentSessionOnly = true };
        Mutex claim;
        bool created;
        try
        {
            // The kernel object's lifetime claims the console across asynchronous continuations.
            claim = new Mutex(initiallyOwned: false, name, options, out created);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or WaitHandleCannotBeOpenedException)
        {
            throw new CallerTerminalInUseException();
        }

        if (!created)
        {
            claim.Dispose();
            throw new CallerTerminalInUseException();
        }

        return claim;
    }

    public CallerTerminalSize? GetSize()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (_output is not { } output || _outputWorker is not { } worker || !_outputLane.Wait(0))
        {
            return null;
        }

        using var deadline = new CancellationTokenSource(GeometryBound);
        try
        {
            return worker.RunAsync(token => ReadSize(output, token), deadline.Token).AsTask().GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            return null;
        }
        finally
        {
            _outputLane.Release();
        }
    }

    private static CallerTerminalSize? ReadSize(SafeFileHandle output, CancellationToken cancellationToken)
    {
        bool found = GetConsoleScreenBufferInfo(output, out var info);
        cancellationToken.ThrowIfCancellationRequested();
        if (!found)
        {
            return null;
        }

        int rows = info.Bottom - info.Top + 1;
        int columns = info.Right - info.Left + 1;
        return rows is > 0 and <= short.MaxValue && columns is > 0 and <= short.MaxValue
            ? new CallerTerminalSize(rows, columns) : null;
    }

    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        if (_inputWorker is not { } worker || _inputEncoding is not { } input)
        {
            throw new InvalidOperationException("An observing terminal cannot read console input.");
        }

        if (buffer.IsEmpty)
        {
            return 0;
        }

        byte[] bytes = await worker.RunAsync(token => input.Read(buffer.Length, token), cancellationToken).ConfigureAwait(false);
        bytes.AsSpan().CopyTo(buffer.Span);
        return bytes.Length;
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        if (_outputWorker is not { } worker || _outputEncoding is not { } output)
        {
            throw new InvalidOperationException("This terminal has no console output.");
        }

        if (bytes.IsEmpty)
        {
            return;
        }

        await _outputLane.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] pending = bytes.ToArray();
            await worker.RunAsync(token =>
            {
                output.Write(pending, token);
                return true;
            }, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _outputLane.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _inputWorker?.Stop();
        _outputWorker?.Stop();
        Task restored = FinishConsoleAsync();
        try
        {
            await restored.WaitAsync(RestorationBound).ConfigureAwait(false);
        }
        catch (TimeoutException failure)
        {
            // A backpressured host can block Win32 even during mode restoration.
            _ = ObserveRestoreAsync(restored);
            throw new IOException("Windows terminal mode restoration could not be confirmed.", failure);
        }
    }

    private async Task FinishConsoleAsync()
    {
        try
        {
            await Task.WhenAll(_inputWorker?.JoinAsync() ?? Task.CompletedTask,
                _outputWorker?.JoinAsync() ?? Task.CompletedTask).ConfigureAwait(false);
        }
        catch (IOException)
        {
            // Keep the modes and console claim together until both original operations have actually ended.
            await Task.WhenAll(_inputWorker?.Completion ?? Task.CompletedTask,
                _outputWorker?.Completion ?? Task.CompletedTask).ConfigureAwait(false);
        }

        await Task.Run(RestoreAndRelease, CancellationToken.None).ConfigureAwait(false);
    }

    private static async Task ObserveRestoreAsync(Task restored)
    {
        try
        {
            await restored.ConfigureAwait(false);
        }
        catch (IOException)
        {
            // The caller already received an unconfirmed restoration result.
        }
    }

    private void RestoreAndRelease()
    {
        try
        {
            RestoreModes(_output, _originalOutput, _input, _originalInput);
        }
        finally
        {
            _inputWorker?.Dispose();
            _outputWorker?.Dispose();
            _outputLane.Dispose();
            _input?.Dispose();
            _output?.Dispose();
            _console.Dispose();
        }
    }

    private sealed class ConsoleIoWorker : IDisposable
    {
        private readonly Channel<Action> _work = Channel.CreateBounded<Action>(
            new BoundedChannelOptions(1) { SingleReader = true });
        private readonly CancellationTokenSource _stop = new();
        private readonly SafeFileHandle _thread;
        private int _pending;

        internal ConsoleIoWorker()
        {
            var ready = new TaskCompletionSource<SafeFileHandle>(TaskCreationOptions.RunContinuationsAsynchronously);
            Completion = Task.Factory.StartNew(() => Work(ready), CancellationToken.None,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);
            try
            {
                _thread = ready.Task.GetAwaiter().GetResult();
            }
            catch
            {
                _stop.Dispose();
                throw;
            }
        }

        internal Task Completion { get; }

        internal async ValueTask<T> RunAsync<T>(Func<CancellationToken, T> operation, CancellationToken cancellationToken)
        {
            using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
            var token = lifetime.Token;
            token.ThrowIfCancellationRequested();
            if (Interlocked.Exchange(ref _pending, 1) != 0)
            {
                throw new InvalidOperationException("A Windows terminal I/O operation is already pending.");
            }

            try
            {
                var result = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
                ObjectDisposedException.ThrowIf(!_work.Writer.TryWrite(() => Perform(operation, result, token)), this);
                try
                {
                    var value = await result.Task.WaitAsync(token).ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    return value;
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    try
                    {
                        await InterruptAsync(result.Task).ConfigureAwait(false);
                    }
                    catch (IOException)
                    {
                        _work.Writer.TryComplete();
                        throw;
                    }

                    throw;
                }
            }
            finally
            {
                Volatile.Write(ref _pending, 0);
            }
        }

        internal void Stop()
        {
            _stop.Cancel();
            _work.Writer.TryComplete();
        }

        internal async Task JoinAsync()
        {
            await InterruptAsync(Completion).ConfigureAwait(false);
            await Completion.ConfigureAwait(false);
        }

        public void Dispose()
        {
            _thread.Dispose();
            _stop.Dispose();
        }

        private void Work(TaskCompletionSource<SafeFileHandle> ready)
        {
            try
            {
                ready.SetResult(Duplicate(GetCurrentThread(), "open console I/O thread"));
            }
            catch (IOException error)
            {
                ready.SetException(error);
                return;
            }

            // Work is requested by the attachment, with no input lookahead or concurrent output.
            while (_work.Reader.WaitToReadAsync().AsTask().GetAwaiter().GetResult() && _work.Reader.TryRead(out var work))
            {
                work();
            }
        }

        private static void Perform<T>(Func<CancellationToken, T> operation, TaskCompletionSource<T> result, CancellationToken token)
        {
            try
            {
                token.ThrowIfCancellationRequested();
                result.SetResult(operation(token));
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                result.SetCanceled(token);
            }
            catch (Exception failure)
            {
                result.SetException(failure);
            }
        }

        private async Task InterruptAsync(Task operation)
        {
            var clock = Stopwatch.StartNew();
            while (!operation.IsCompleted)
            {
                if (clock.Elapsed >= InterruptBound)
                {
                    throw new IOException("Windows terminal I/O cancellation could not be confirmed.");
                }

                try
                {
                    // Cancellation can win before the worker entered Windows. Retry until the I/O has settled.
                    if (!CancelSynchronousIo(_thread))
                    {
                        int error = Marshal.GetLastPInvokeError();
                        if (error != NoPendingIo && !operation.IsCompleted)
                        {
                            throw NativeFailure("cancel console I/O", error);
                        }
                    }
                }
                catch (ObjectDisposedException) when (operation.IsCompleted)
                {
                    return;
                }

                if (!operation.IsCompleted)
                {
                    await Task.Delay(InterruptInterval).ConfigureAwait(false);
                }
            }
        }
    }

    private sealed class InputEncoding(SafeFileHandle input)
    {
        private readonly Encoder _encoder = Encoding.UTF8.GetEncoder();
        private readonly char[] _characters = new char[256];
        private readonly byte[] _bytes = new byte[Encoding.UTF8.GetMaxByteCount(256)];
        private int _offset;
        private int _available;
        private bool _endOfInput;

        internal byte[] Read(int length, CancellationToken cancellationToken)
        {
            while (_offset == _available && !_endOfInput)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int count = ReadCharacters(input, _characters, cancellationToken);
                _endOfInput = count == 0;
                _available = _encoder.GetBytes(_characters.AsSpan(0, count), _bytes, flush: _endOfInput);
                _offset = 0;
            }

            cancellationToken.ThrowIfCancellationRequested();
            int copied = Math.Min(length, _available - _offset);
            var bytes = _bytes.AsSpan(_offset, copied).ToArray();
            _offset += copied;
            return bytes;
        }

        private static unsafe int ReadCharacters(SafeFileHandle handle, Span<char> characters, CancellationToken cancellationToken)
        {
            fixed (char* address = characters)
            {
                bool succeeded = ReadConsole(handle, address, (uint)characters.Length, out uint read, 0);
                int error = Marshal.GetLastPInvokeError();
                // A cooked Ctrl+C can abort a console read even when Win32 returns TRUE.
                if (error == OperationAborted)
                {
                    throw new OperationCanceledException("The caller console interrupted input.", cancellationToken);
                }

                if (!succeeded)
                {
                    throw NativeFailure("read console input", error);
                }

                return checked((int)read);
            }
        }
    }

    private sealed class OutputEncoding(SafeFileHandle output)
    {
        private readonly Decoder _decoder = Encoding.UTF8.GetDecoder();

        internal unsafe void Write(ReadOnlySpan<byte> bytes, CancellationToken cancellationToken)
        {
            Span<char> characters = stackalloc char[2048];
            while (!bytes.IsEmpty)
            {
                cancellationToken.ThrowIfCancellationRequested();
                _decoder.Convert(bytes, characters, flush: false, out int used, out int rendered, out _);
                var text = characters[..rendered];
                while (!text.IsEmpty)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    fixed (char* address = text)
                    {
                        if (!WriteConsole(output, address, (uint)text.Length, out uint written, 0))
                        {
                            int error = Marshal.GetLastPInvokeError();
                            if (error == OperationAborted)
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                            }

                            throw NativeFailure("write console output", error);
                        }

                        if (written == 0 || written > text.Length)
                        {
                            throw new IOException("Windows terminal returned an invalid console output length.");
                        }

                        text = text[(int)written..];
                    }
                }

                bytes = bytes[used..];
            }
        }
    }
    private static void RestoreModes(SafeFileHandle? output, uint? originalOutput, SafeFileHandle? input, uint? originalInput)
    {
        try
        {
            if (input is not null && originalInput is uint inputMode)
            {
                ChangeMode(input, inputMode, "restore console input mode");
            }
        }
        finally
        {
            if (output is not null && originalOutput is uint outputMode)
            {
                ChangeMode(output, outputMode, "restore console output mode");
            }
        }
    }

    private static SafeFileHandle Duplicate(nint handle, string operation)
    {
        nint process = GetCurrentProcess();
        if (handle is 0 or -1)
        {
            throw NativeFailure(operation, InvalidHandle);
        }

        if (!DuplicateHandle(process, handle, process, out nint copy, 0, false, DuplicateSameAccess))
        {
            throw NativeFailure(operation, Marshal.GetLastPInvokeError());
        }

        return new SafeFileHandle(copy, ownsHandle: true);
    }

    private static uint ReadMode(SafeFileHandle handle, string operation) =>
        GetConsoleMode(handle, out uint mode) ? mode : throw NativeFailure(operation, Marshal.GetLastPInvokeError());

    private static void ChangeMode(SafeFileHandle handle, uint mode, string operation)
    {
        if (!SetConsoleMode(handle, mode))
        {
            throw NativeFailure(operation, Marshal.GetLastPInvokeError());
        }

        if (ReadMode(handle, operation) != mode)
        {
            throw new IOException($"Windows terminal could not verify {operation}.");
        }
    }

    private static IOException NativeFailure(string operation, int error) =>
        new($"Windows terminal could not {operation}.", new Win32Exception(error));

    [StructLayout(LayoutKind.Sequential)]
    private struct ScreenBufferInfo
    {
        internal short Width;
        internal short Height;
        internal short CursorX;
        internal short CursorY;
        internal ushort Attributes;
        internal short Left;
        internal short Top;
        internal short Right;
        internal short Bottom;
        internal short MaximumWidth;
        internal short MaximumHeight;
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetStdHandle(int standardHandle);

    [LibraryImport("kernel32.dll")]
    private static partial nint GetConsoleWindow();

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentThread();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DuplicateHandle(nint sourceProcess, nint source, nint targetProcess, out nint target,
        uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetConsoleMode(SafeFileHandle handle, out uint mode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetConsoleMode(SafeFileHandle handle, uint mode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetConsoleScreenBufferInfo(SafeFileHandle output, out ScreenBufferInfo info);

    [LibraryImport("kernel32.dll", EntryPoint = "ReadConsoleW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool ReadConsole(SafeFileHandle input, char* characters, uint count, out uint read, nint control);

    [LibraryImport("kernel32.dll", EntryPoint = "WriteConsoleW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool WriteConsole(SafeFileHandle output, char* characters, uint count, out uint written, nint reserved);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CancelSynchronousIo(SafeFileHandle thread);
}
