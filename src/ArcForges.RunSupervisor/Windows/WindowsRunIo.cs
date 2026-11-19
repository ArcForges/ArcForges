// SPDX-License-Identifier: AGPL-3.0-only

using System.ComponentModel;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.RunSupervisor.Protocol;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("windows")]
internal sealed partial class WindowsRunIo : IDisposable
{
    private readonly PipePair _input;
    private readonly PipePair _output;
    private readonly PipePair? _error;
    private readonly SemaphoreSlim _inputGate = new(1, 1);
    private readonly object _consoleGate = new();
    private nint _console;
    private int _inputClosed;

    private WindowsRunIo(PipePair input, PipePair output, PipePair? error)
    {
        _input = input;
        _output = output;
        _error = error;
    }

    internal Stream Output => _output.Local;
    internal Stream? Error => _error?.Local;
    internal nint ConsoleHandle => _console;
    internal WindowsMxcStandardHandles? Standard => _error is null ? null :
        new(_input.Remote.SafePipeHandle, _output.Remote.SafePipeHandle, _error.Remote.SafePipeHandle);

    internal static WindowsRunIo Create(bool interactive, uint columns = 0, uint rows = 0)
    {
        PipePair? input = null;
        PipePair? output = null;
        PipePair? error = null;
        try
        {
            input = PipePair.Create(PipeDirection.Out);
            output = PipePair.Create(PipeDirection.In);
            if (!interactive)
            {
                error = PipePair.Create(PipeDirection.In);
                return new(input, output, error);
            }

            var result = new WindowsRunIo(input, output, null);
            var status = CreatePseudoConsole(Dimensions(rows, columns), input.Remote.SafePipeHandle,
                output.Remote.SafePipeHandle, 0, out result._console);
            if (status < 0 || result._console == 0)
            {
                if (result._console != 0) ClosePseudoConsole(result._console);
                throw new Win32Exception(status, "Create the official executor pseudoconsole failed.");
            }

            // ConPTY now owns its endpoints. The owner keeps only the opposite ends.
            result.ReleaseRemoteEnds();
            return result;
        }
        catch
        {
            error?.Dispose();
            output?.Dispose();
            input?.Dispose();
            throw;
        }
    }

    internal void ReleaseRemoteEnds()
    {
        _input.Remote.Dispose();
        _output.Remote.Dispose();
        _error?.Remote.Dispose();
    }

    internal void CloseInput()
    {
        if (Interlocked.Exchange(ref _inputClosed, 1) == 0)
        {
            _input.Local.Dispose();
        }
    }

    internal async ValueTask<int> WriteTerminalAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
    {
        await _inputGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _inputClosed) != 0)
            {
                throw new IOException("The Windows Run input is closed.");
            }

            await _input.Local.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            return bytes.Length;
        }
        finally
        {
            _inputGate.Release();
        }
    }

    internal async ValueTask CloseTerminalInputAsync(CancellationToken cancellationToken)
    {
        if (_error is null)
        {
            throw new InvalidOperationException("Explicit stdin EOF requires Windows pipe mode.");
        }

        await _inputGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            CloseInput();
        }
        finally
        {
            _inputGate.Release();
        }
    }

    internal ValueTask ResizeTerminalAsync(uint rows, uint columns, CancellationToken cancellationToken)
    {
        var dimensions = Dimensions(rows, columns);
        lock (_consoleGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_console == 0)
            {
                throw new InvalidOperationException("The Windows Run has no live pseudoconsole.");
            }

            var status = ResizePseudoConsole(_console, dimensions);
            if (status != 0)
            {
                throw new RunNativeException("windows_terminal_resize", "hresult:" + status.ToString("x8", CultureInfo.InvariantCulture));
            }
        }

        return ValueTask.CompletedTask;
    }

    internal async ValueTask InterruptAsync(TimeSpan remaining)
    {
        if (Volatile.Read(ref _console) == 0)
        {
            return;
        }

        var interruptBound = TimeSpan.FromMilliseconds(300);
        using var timeout = new CancellationTokenSource(remaining < interruptBound ? remaining : interruptBound);
        try
        {
            _ = await WriteTerminalAsync(new byte[] { 3 }, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception error) when (error is IOException or OperationCanceledException or ObjectDisposedException)
        {
            // Forced stop remains tied to the exact Job's deadline.
        }
    }

    internal Task CloseConsoleAsync()
    {
        // On Windows builds where ClosePseudoConsole blocks, the output reader stays active independently.
        return Volatile.Read(ref _console) == 0 ? Task.CompletedTask : Task.Run(() =>
        {
            var console = TakeConsole();
            if (console != 0) ClosePseudoConsole(console);
        });
    }

    public void Dispose()
    {
        var console = TakeConsole();
        CloseInput();
        _input.Dispose();
        _output.Dispose();
        _error?.Dispose();
        if (console != 0) ClosePseudoConsole(console);
    }

    private nint TakeConsole()
    {
        lock (_consoleGate)
        {
            var console = _console;
            _console = 0;
            return console;
        }
    }

    private static Coordinate Dimensions(uint rows, uint columns)
    {
        ArgumentOutOfRangeException.ThrowIfZero(rows);
        ArgumentOutOfRangeException.ThrowIfZero(columns);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(rows, (uint)short.MaxValue);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(columns, (uint)short.MaxValue);
        return new((short)columns, (short)rows);
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct Coordinate(short Columns, short Rows);

    [LibraryImport("kernel32.dll")]
    private static partial int CreatePseudoConsole(Coordinate size, SafePipeHandle input, SafePipeHandle output, uint flags, out nint console);

    [LibraryImport("kernel32.dll")]
    private static partial int ResizePseudoConsole(nint console, Coordinate size);

    [LibraryImport("kernel32.dll")]
    private static partial void ClosePseudoConsole(nint console);

    private sealed class PipePair(NamedPipeServerStream local, NamedPipeClientStream remote) : IDisposable
    {
        internal NamedPipeServerStream Local { get; } = local;
        internal NamedPipeClientStream Remote { get; } = remote;

        internal static PipePair Create(PipeDirection direction)
        {
            var name = "arcforges-run-io-" + Guid.NewGuid().ToString("N");
            var server = new NamedPipeServerStream(name, direction, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4096, 4096);
            NamedPipeClientStream? client = null;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                var connected = server.WaitForConnectionAsync(timeout.Token);
                client = new NamedPipeClientStream(".", name, direction == PipeDirection.Out ? PipeDirection.In : PipeDirection.Out,
                    PipeOptions.None, TokenImpersonationLevel.Anonymous);
                client.Connect(5000);
                connected.GetAwaiter().GetResult();
                return new(server, client);
            }
            catch
            {
                client?.Dispose();
                server.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            Remote.Dispose();
            Local.Dispose();
        }
    }
}
