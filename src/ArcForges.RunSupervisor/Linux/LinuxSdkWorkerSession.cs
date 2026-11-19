// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.RunSupervisor.Protocol;
using Microsoft.Mxc.Sdk.V1;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("linux")]
internal sealed class LinuxSdkWorkerSession : IRunWorkerSession
{
    private static readonly TimeSpan s_nativeDeadline = TimeSpan.FromSeconds(10);
    private readonly LinuxRunServiceState _owner;
    private readonly LinuxRunCgroup _scope;
    private readonly MxcProcess _process;
    private readonly Stream _input;
    private readonly Task<WaitResult> _nativeWait;
    private readonly Task _stdout;
    private readonly Task _stderr;
    private readonly Task _completion;
    private readonly Lock _gate = new();
    private readonly Lock _nativeGate = new();
    private Task? _stop;
    private Task? _nativeKill;
    private Task? _nativeDisposal;
    private RunOwnerObservation _latest = new(RunOwnerState.Running, RunPayloadStart.Unknown, false);
    private long _outputRemaining;
    private int _stopping;
    private string? _outputError;
    private bool _disposed;

    private LinuxSdkWorkerSession(RunLaunchSpec spec, LinuxRunServiceState owner, LinuxRunCgroup scope, MxcProcess process,
        FileStream stdoutFile, FileStream stderrFile)
    {
        _owner = owner;
        _scope = scope;
        _process = process;
        _outputRemaining = checked((long)spec.OutputLimitBytes);
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

        _stdout = Task.Run(() => DrainAsync(stdout, stdoutFile), CancellationToken.None);
        _stderr = Task.Run(() => DrainAsync(stderr, stderrFile), CancellationToken.None);
        // All owner streams have been taken before the independent native waiter
        // can claim an untaken stream for its internal discard drain.
        _nativeWait = _process.WaitAsync(CancellationToken.None);
        _completion = CompleteAsync();
    }

    internal static async ValueTask<LinuxSdkWorkerSession> StartAsync(RunLaunchSpec spec, ContainerRequest request,
        LinuxRunServiceState owner, LinuxRunCgroup scope, CancellationToken cancellationToken)
    {
        FileStream? stdout = null;
        FileStream? stderr = null;
        MxcProcess? process = null;
        var invoked = false;
        var transferred = false;
        try
        {
            stdout = CreateOutput(spec, "stdout.bin");
            stderr = CreateOutput(spec, "stderr.bin");
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

            var session = new LinuxSdkWorkerSession(spec, owner, scope, process, stdout, stderr);
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
            // Once construction succeeds, the two independent drains own their output files.
            if (!transferred)
            {
                stdout?.Dispose();
                stderr?.Dispose();
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
                _nativeKill ??= Task.Run(() => _process.Kill(), CancellationToken.None);
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
            reason = exit.TimedOut ? "timeout" : Volatile.Read(ref _stopping) != 0 ? "stopped" : "exited";
            Volatile.Write(ref _latest, new(RunOwnerState.Draining, RunPayloadStart.Unknown, false,
                exitCode, RunExitSources.OfficialExecutor, reason));
            await Task.WhenAll(_stdout, _stderr).WaitAsync(s_nativeDeadline).ConfigureAwait(false);
            await Task.Run(_input.Dispose, CancellationToken.None).WaitAsync(s_nativeDeadline).ConfigureAwait(false);
            await DisposeOfficialAsync().WaitAsync(s_nativeDeadline).ConfigureAwait(false);
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

    private async Task DrainAsync(Stream? input, FileStream output)
    {
        await using var sink = output;
        if (input is null)
        {
            return;
        }

        await using var stream = input;
        var buffer = new byte[32 * 1024];
        var sinkAvailable = true;
        while (true)
        {
            var count = await stream.ReadAsync(buffer, CancellationToken.None).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }

            if (sinkAvailable)
            {
                var accepted = ReserveOutput(count);
                try
                {
                    await sink.WriteAsync(buffer.AsMemory(0, accepted), CancellationToken.None).ConfigureAwait(false);
                }
                catch (IOException error)
                {
                    sinkAvailable = false;
                    Interlocked.CompareExchange(ref _outputError, NativeCode(error), null);
                }
            }
        }

        await sink.FlushAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private int ReserveOutput(int bytes)
    {
        long available;
        int accepted;
        do
        {
            available = Volatile.Read(ref _outputRemaining);
            accepted = (int)Math.Min(available, bytes);
        }
        while (Interlocked.CompareExchange(ref _outputRemaining, available - accepted, available) != available);
        return accepted;
    }

    private static FileStream CreateOutput(RunLaunchSpec spec, string name) => new(Path.Combine(spec.ControlDirectory, name), new FileStreamOptions()
    {
        Mode = FileMode.CreateNew,
        Access = FileAccess.Write,
        Share = FileShare.Read,
        Options = FileOptions.Asynchronous,
        UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
    });

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
