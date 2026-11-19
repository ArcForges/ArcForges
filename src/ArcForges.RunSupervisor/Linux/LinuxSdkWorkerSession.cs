// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.RunSupervisor.Protocol;
using Microsoft.Mxc.Sdk.V1;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("linux")]
internal sealed class LinuxSdkWorkerSession : IRunWorkerSession
{
    // The pinned Bubblewrap SDK reports a signaled executor with no numeric exit status as -1.
    private const int SignalExitStatus = -1;
    private static readonly TimeSpan s_nativeDeadline = TimeSpan.FromSeconds(10);
    private readonly LinuxRunServiceState _owner;
    private readonly LinuxRunCgroup _scope;
    private readonly MxcProcess _process;
    private readonly Stream _input;
    private readonly RunOutputCapture _outputCapture;
    private readonly Task<WaitResult> _nativeWait;
    private readonly Task _outputDrains;
    private readonly Task _outputFinalization;
    private readonly Task _completion;
    private readonly Lock _gate = new();
    private readonly Lock _nativeGate = new();
    private readonly SemaphoreSlim _terminalIo = new(1, 1);
    private Task? _stop;
    private Task<bool>? _nativeKill;
    private Task? _nativeDisposal;
    private RunOwnerObservation _latest = new(RunOwnerState.Running, RunPayloadStart.Unknown, false);
    private InputState _inputState;
    private int _stopping;
    private string? _outputError;
    private bool _disposed;

    private LinuxSdkWorkerSession(LinuxRunServiceState owner, LinuxRunCgroup scope, MxcProcess process, RunOutputCapture outputCapture)
    {
        _owner = owner;
        _scope = scope;
        _process = process;
        _outputCapture = outputCapture;
        var terminal = process as MxcPtyProcess;
        _input = (terminal is null ? process.StandardInput : terminal.Input)
            ?? throw new IOException("The fixed MXC SDK did not return Run input.");
        var stdout = (terminal is null ? process.StandardOutput : terminal.Output)
            ?? throw new IOException("The fixed MXC SDK did not return Run output.");
        var stderr = process.StandardError;
        if (terminal is null && stderr is null)
        {
            throw new IOException("The fixed MXC SDK did not return the requested stderr pipe.");
        }

        var stdoutDrain = Task.Run(() => DrainAsync(stdout, terminal is null ? RunOutputStream.Stdout : RunOutputStream.Terminal), CancellationToken.None);
        // The official PTY combines the workload's output. Any separate SDK
        // diagnostics stream still needs drainage, but is not a second PTY cursor.
        var stderrDrain = Task.Run(() => DrainAsync(stderr, terminal is null ? RunOutputStream.Stderr : null), CancellationToken.None);
        _outputDrains = Task.WhenAll(stdoutDrain, stderrDrain);
        _outputFinalization = Task.Run(FinalizeOutputAsync, CancellationToken.None);
        // All owner streams have been taken before the independent native waiter
        // can claim an untaken stream for its internal discard drain.
        _nativeWait = _process.WaitAsync(CancellationToken.None);
        _completion = CompleteAsync();
    }

    internal static async ValueTask<LinuxSdkWorkerSession> StartAsync(RunLaunchSpec spec, ContainerRequest request,
        LinuxRunServiceState owner, LinuxRunCgroup scope, CancellationToken cancellationToken)
    {
        RunOutputCapture? outputCapture = null;
        MxcProcess? process = null;
        var invoked = false;
        var transferred = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            outputCapture = RunOutputCapture.Create(spec);
            cancellationToken.ThrowIfCancellationRequested();
            using var bindings = LinuxRunPathBindings.Open(spec);
            cancellationToken.ThrowIfCancellationRequested();
            invoked = true;
            process = spec.TerminalMode == RunTerminalMode.Interactive
                ? MxcContainer.SpawnWithPty(request, new SpawnWithPtyOptions
                {
                    Size = new(checked((ushort)spec.Rows), checked((ushort)spec.Columns)),
                    Telemetry = new() { Enabled = false },
                })
                : MxcContainer.Spawn(request, new SpawnOptions { Telemetry = new() { Enabled = false } });
            if (process.Id == 0)
            {
                throw new IOException("The fixed MXC SDK did not return a native process identity.");
            }

            var session = new LinuxSdkWorkerSession(owner, scope, process, outputCapture);
            transferred = true;
            return session;
        }
#pragma warning disable CA1031 // An official native spawn can fail after creation; this owner must attempt rollback on every failure.
        catch (Exception error)
        {
            if (process is not null)
            {
                try
                {
                    await Task.Run(() => process.Kill(), CancellationToken.None).WaitAsync(s_nativeDeadline, CancellationToken.None).ConfigureAwait(false);
                    await Task.Run(process.Dispose, CancellationToken.None).WaitAsync(s_nativeDeadline, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    throw new RunNativeException("linux_mxc_native_spawn", NativeCode(error));
                }
            }

            var empty = scope.TryContainsOnlyOwner(owner.OwnerPid, owner.OwnerStartTicks);
            if (error is RunNativeException native)
            {
                throw new RunNativeException(native.Phase, native.NativeCode, empty, payloadNotStarted: !invoked);
            }

            var code = error is OperationCanceledException ? "linux_worker_startup_cancelled" : NativeCode(error);
            throw new RunNativeException("linux_mxc_native_spawn", code, empty, payloadNotStarted: !invoked);
        }
#pragma warning restore CA1031
        finally
        {
            if (!transferred)
            {
                outputCapture?.Dispose();
            }
        }
    }

    public ValueTask<RunOwnerObservation> ObserveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var latest = Volatile.Read(ref _latest);
        return ValueTask.FromResult(Volatile.Read(ref _stopping) != 0 && latest.State == RunOwnerState.Running
            ? latest with { State = RunOwnerState.Stopping } : latest);
    }

    public ValueTask StopAsync(TimeSpan grace, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(grace, TimeSpan.Zero);
        lock (_gate)
        {
            _stop ??= StopCoreAsync(grace);
            return new(_stop.WaitAsync(cancellationToken));
        }
    }

    public async ValueTask<int> WriteTerminalAsync(ReadOnlyMemory<byte> input, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(input.Length, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(input.Length, 65_536);
        await EnterTerminalIoAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_inputState != InputState.Open)
            {
                throw new RunNativeException("linux_terminal_input",
                    _inputState == InputState.Closed ? "terminal_input_closed" : "terminal_ack_unavailable");
            }

            cancellationToken.ThrowIfCancellationRequested();
            var bytes = input.ToArray();
            try
            {
                // The SDK reports success for the whole write or throws without
                // an accepted prefix. Own the bytes and gate until it really ends.
                await Task.Run(() =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    _input.Write(bytes, 0, bytes.Length);
                }, cancellationToken).ConfigureAwait(false);
                return bytes.Length;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        finally
        {
            _terminalIo.Release();
        }
    }

    public async ValueTask CloseTerminalInputAsync(CancellationToken cancellationToken)
    {
        if (_process is MxcPtyProcess)
        {
            throw new RunNativeException("linux_terminal_input", "terminal_eof_pipe_only");
        }

        await EnterTerminalIoAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_inputState == InputState.Uncertain)
            {
                throw new RunNativeException("linux_terminal_input", "terminal_ack_unavailable");
            }

            await CloseInputCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _terminalIo.Release();
        }
    }

    public async ValueTask ResizeTerminalAsync(uint rows, uint columns, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(rows, 1u);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(rows, (uint)short.MaxValue);
        ArgumentOutOfRangeException.ThrowIfLessThan(columns, 1u);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(columns, (uint)short.MaxValue);
        if (_process is not MxcPtyProcess terminal)
        {
            throw new RunNativeException("linux_terminal_resize", "terminal_resize_requires_pty");
        }

        await EnterTerminalIoAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                terminal.Resize(new MxcPtySize((ushort)rows, (ushort)columns));
            }, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _terminalIo.Release();
        }
    }

    private async ValueTask EnterTerminalIoAsync(CancellationToken cancellationToken)
    {
        if (!await _terminalIo.WaitAsync(0, cancellationToken).ConfigureAwait(false))
        {
            throw new RunNativeException("linux_terminal_io", "terminal_native_io_busy");
        }

        if (_nativeWait.IsCompleted)
        {
            _terminalIo.Release();
            throw new RunNativeException("linux_terminal_io", "terminal_unavailable");
        }
    }

    private async Task CloseInputCoreAsync(CancellationToken cancellationToken)
    {
        if (_inputState != InputState.Open)
        {
            return;
        }

        await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            // An exception can follow the native close. Never repeat an ambiguous EOF.
            _inputState = InputState.Uncertain;
            _input.Dispose();
        }, cancellationToken).ConfigureAwait(false);
        _inputState = InputState.Closed;
    }

    private async Task CloseInputForExitAsync()
    {
        await _terminalIo.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            await CloseInputCoreAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _terminalIo.Release();
        }
    }

    private async Task StopCoreAsync(TimeSpan grace)
    {
        Interlocked.Exchange(ref _stopping, 1);
        if (!_nativeWait.IsCompleted && grace > TimeSpan.Zero)
        {
            try
            {
                _ = await _nativeWait.WaitAsync(grace).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                // The caller's grace elapsed. Native run ownership continues.
            }
        }

        if (_nativeWait.IsCompleted && _scope.TryContainsOnlyOwner(_owner.OwnerPid, _owner.OwnerStartTicks))
        {
            return;
        }

        Task? kill;
        lock (_nativeGate)
        {
            // Main-process exit says nothing about helpers or descendants. Keep using
            // the genuine SDK handle while disposal has not taken custody of it.
            if (_nativeDisposal is null)
            {
                _nativeKill ??= Task.Run(KillOfficial, CancellationToken.None);
            }

            kill = _nativeKill;
        }

        if (kill is not null)
        {
            try
            {
                await kill.WaitAsync(s_nativeDeadline).ConfigureAwait(false);
            }
            catch (MxcException error)
            {
                throw new RunNativeException("linux_mxc_native_stop", NativeCode(error));
            }
        }
    }

    private bool KillOfficial()
    {
        bool running = false;
        try
        {
            running = !_nativeWait.IsCompleted && !_process.TryGetExitCode(out _);
        }
        catch (MxcException)
        {
            // A refused status probe leaves attribution unknown but must not prevent the authorized Stop.
        }

        _process.Kill();
        return running;
    }

    private Task DisposeOfficialAsync()
    {
        lock (_nativeGate)
        {
            return _nativeDisposal ??= DisposeAfterStopAsync(_nativeKill);
        }
    }

    private async Task DisposeAfterStopAsync(Task? kill)
    {
        if (kill is not null)
        {
            try
            {
                await kill.ConfigureAwait(false);
            }
            catch (MxcException)
            {
                // A rejected native stop does not invalidate the independent disposal.
            }
        }

        await Task.Run(_process.Dispose, CancellationToken.None).ConfigureAwait(false);
    }

    private async Task CompleteAsync()
    {
        int? exitCode = null;
        string? reason = null;
        try
        {
            var exit = await _nativeWait.ConfigureAwait(false);
            exitCode = exit.ExitCode;
            reason = exit.TimedOut ? "timeout" : null;
            Volatile.Write(ref _latest, new(RunOwnerState.Draining, RunPayloadStart.Unknown, false,
                exitCode, RunExitSources.OfficialExecutor, reason));
            await WaitForOutputAsync().ConfigureAwait(false);
            await CloseInputForExitAsync().WaitAsync(s_nativeDeadline).ConfigureAwait(false);
            await DisposeOfficialAsync().WaitAsync(s_nativeDeadline).ConfigureAwait(false);
            var kill = Volatile.Read(ref _nativeKill);
            // Kill can return success after native reaping. Require a live native probe, accepted Kill and signaled wait result.
            reason ??= exit.ExitCode == SignalExitStatus && kill is { IsCompletedSuccessfully: true } && kill.Result
                ? "stopped" : "exited";
            using var clean = new CancellationTokenSource(s_nativeDeadline);
            while (!_scope.ContainsOnlyOwner(_owner.OwnerPid, _owner.OwnerStartTicks))
            {
                await Task.Delay(25, clean.Token).ConfigureAwait(false);
            }

            Volatile.Write(ref _latest, new(RunOwnerState.Exited, RunPayloadStart.Unknown, true,
                exitCode, RunExitSources.OfficialExecutor, reason, Volatile.Read(ref _outputError)));
        }
#pragma warning disable CA1031 // Both native wait and finalization failures must remain observable by the Node.
        catch (Exception error)
        {
            Volatile.Write(ref _latest, new(RunOwnerState.RecoveryRequired, RunPayloadStart.Unknown, false,
                exitCode, exitCode.HasValue ? RunExitSources.OfficialExecutor : RunExitSources.Unknown, reason, NativeCode(error)));
        }
#pragma warning restore CA1031
    }

    private async Task DrainAsync(Stream? input, RunOutputStream? selected)
    {
        if (input is null)
        {
            return;
        }

        await using var stream = input;
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, CancellationToken.None).ConfigureAwait(false);
            if (count == 0)
            {
                return;
            }

            if (selected is not { } streamKind || Volatile.Read(ref _outputError) is not null)
            {
                continue;
            }

            try
            {
                _outputCapture.Capture(streamKind, buffer.AsSpan(0, count));
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                // Output persistence failure must not stop native drainage.
                Interlocked.CompareExchange(ref _outputError, NativeCode(error), null);
            }
        }
    }

    private async Task WaitForOutputAsync()
    {
        try
        {
            await _outputDrains.WaitAsync(s_nativeDeadline).ConfigureAwait(false);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException or MxcException)
        {
            Interlocked.CompareExchange(ref _outputError, NativeCode(error), null);
        }

        try
        {
            await _outputFinalization.WaitAsync(s_nativeDeadline).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // Native streams have already stopped. An index write cannot undo
            // exact process exit or prevent independent native cleanup.
            AbortTimedOutOutput();
        }
    }

    private async Task FinalizeOutputAsync()
    {
        try
        {
            // WhenAll settles only after both drains stop, even when one faults.
            await _outputDrains.ConfigureAwait(false);
            if (Volatile.Read(ref _outputError) is null)
            {
                await _outputCapture.CompleteAsync().WaitAsync(s_nativeDeadline).ConfigureAwait(false);
            }
        }
        catch (TimeoutException)
        {
            AbortTimedOutOutput();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException or MxcException
            or OperationCanceledException)
        {
            Interlocked.CompareExchange(ref _outputError, NativeCode(error), null);
        }
        finally
        {
            _outputCapture.Dispose();
        }
    }

    private void AbortTimedOutOutput()
    {
        Interlocked.CompareExchange(ref _outputError, "linux_output_index_finalization_timeout", null);
        // Abort pending publication without waiting for a stalled storage call.
        _outputCapture.Dispose();
    }

    private enum InputState
    {
        Open,
        Uncertain,
        Closed,
    }

    private static string NativeCode(Exception error)
    {
        if (error is MxcException backend)
        {
            var code = backend.NativeCode;
            return code is { Length: > 0 and <= 80 } && code.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.' or ':')
                ? "linux_sdk_" + backend.Code + "_" + code : "linux_sdk_" + backend.Code;
        }

        return "linux_sdk_" + error.GetType().Name + "_" + error.HResult.ToString("X8", CultureInfo.InvariantCulture);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            await StopAsync(TimeSpan.Zero, CancellationToken.None).ConfigureAwait(false);
            await _completion.WaitAsync(s_nativeDeadline).ConfigureAwait(false);
        }
        finally
        {
            _disposed = true;
            _scope.Dispose();
        }
    }
}
