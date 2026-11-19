// SPDX-License-Identifier: AGPL-3.0-only

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("windows")]
internal sealed class WindowsRunSession : IRunWorkerSession
{
    private static readonly TimeSpan DrainDeadline = TimeSpan.FromSeconds(10);
    private readonly WindowsMxcJob _aggregate;
    private readonly WindowsMxcJob _payload;
    private readonly LaunchedProcess _executor;
    private readonly WindowsRunIo _io;
    private readonly WindowsMxcStage _installed;
    private readonly WindowsMxcPathLease _control;
    private readonly WindowsMxcPathLease _policy;
    private readonly WindowsRunPathBindings _paths;
    private readonly WindowsRunEvidence _evidence;
    private readonly RunOutputCapture _capture;
    private readonly Task _monitor;
    private readonly object _stopGate = new();
    private RunOwnerObservation _observation = new(RunOwnerState.Running, RunPayloadStart.Unknown, false);
    private StopPlan? _stop;
    private bool _stopObserved;
    private bool _interruptAttempted;
    private long? _forcedAt;
    private uint? _forcedCode;
    private SafeKernelHandle? _forceWitness;

    internal WindowsRunSession(WindowsMxcJob aggregate, WindowsMxcJob payload, LaunchedProcess executor,
        WindowsRunIo io, WindowsMxcStage installed, WindowsMxcPathLease control, WindowsMxcPathLease policy,
        WindowsRunPathBindings paths, WindowsRunEvidence evidence, RunOutputCapture capture)
    {
        _aggregate = aggregate;
        _payload = payload;
        _executor = executor;
        _io = io;
        _installed = installed;
        _control = control;
        _policy = policy;
        _paths = paths;
        _evidence = evidence;
        _capture = capture;
        _monitor = MonitorAsync();
    }

    public ValueTask<RunOwnerObservation> ObserveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Volatile.Read(ref _observation));
    }

    public ValueTask<int> WriteTerminalAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken) =>
        _io.WriteTerminalAsync(bytes, cancellationToken);

    public ValueTask CloseTerminalInputAsync(CancellationToken cancellationToken) =>
        _io.CloseTerminalInputAsync(cancellationToken);

    public ValueTask ResizeTerminalAsync(uint rows, uint columns, CancellationToken cancellationToken) =>
        _io.ResizeTerminalAsync(rows, columns, cancellationToken);

    public ValueTask StopAsync(TimeSpan grace, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentOutOfRangeException.ThrowIfLessThan(grace, TimeSpan.Zero);
        lock (_stopGate)
        {
            var now = Stopwatch.GetTimestamp();
            if (_stop is null || _stop.Grace - Stopwatch.GetElapsedTime(_stop.RequestedAt, now) > grace)
            {
                _stop = new StopPlan(now, grace);
            }
        }

        return ValueTask.CompletedTask;
    }

    private async Task MonitorAsync()
    {
        var stderr = _io.Error;
        var output = Task.Run(() => DrainOutputAsync(_io.Output, stderr is null ? RunOutputStream.Terminal : RunOutputStream.Stdout));
        var error = stderr is null ? Task.CompletedTask : Task.Run(() => DrainOutputAsync(stderr, RunOutputStream.Stderr));
        int? rawExit = null;
        string? reason = null;
        try
        {
            uint? exit;
            while ((exit = WindowsMxcProcess.PollExit(_executor)) is null)
            {
                _ = await ApplyPendingStopAsync(executorRunning: true).ConfigureAwait(false);
                RequireForcedStopBound();
                await Task.Delay(20, CancellationToken.None).ConfigureAwait(false);
            }

            rawExit = unchecked((int)exit.Value);
            reason = ExitReason(rawExit.Value);
            Volatile.Write(ref _observation, new(RunOwnerState.Draining, RunPayloadStart.Unknown, false,
                rawExit, RunExitSources.OfficialExecutor, reason));

            // The pinned executor's own completion is independent of the outer Run drain proof.
            var payload = await DrainPayloadAsync().ConfigureAwait(false);
            reason = ExitReason(rawExit.Value);
            _io.CloseInput();
            await Task.WhenAll(_io.CloseConsoleAsync(), output, error).WaitAsync(DrainDeadline).ConfigureAwait(false);
            var aggregate = await _aggregate.WaitForDrainAsync(Environment.ProcessId, DrainDeadline, CancellationToken.None).ConfigureAwait(false);
            var retentionFailure = await CompleteOutputRetentionAsync().ConfigureAwait(false);
            _policy.DeletePrivateFile();
            _evidence.WriteDrained(rawExit.Value, reason, aggregate, payload);
            Volatile.Write(ref _observation, new(RunOwnerState.Exited, RunPayloadStart.Unknown, true,
                rawExit, RunExitSources.OfficialExecutor, reason, retentionFailure));
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or Win32Exception or TimeoutException or UnauthorizedAccessException or ObjectDisposedException)
        {
            _capture.Dispose();
            Volatile.Write(ref _observation, new(RunOwnerState.RecoveryRequired, RunPayloadStart.Unknown, false,
                rawExit, rawExit.HasValue ? RunExitSources.OfficialExecutor : RunExitSources.Unknown,
                reason ?? "owner_failure", WindowsRunLauncher.NativeCode(exception)));
        }
        finally
        {
            _forceWitness?.Dispose();
        }
    }

    private string ExitReason(int rawExit)
    {
        if (_forcedCode is uint forced && (unchecked((uint)rawExit) == forced
            || _forceWitness is { } process && Native.WaitForSingleObject(process, 0) == Native.WaitObject0
                && Native.GetExitCodeProcess(process, out var observed) && observed == forced))
        {
            return "user_stop";
        }

        // Terminal input can be accepted without the workload processing it or exiting because of it.
        return _interruptAttempted || _forcedAt.HasValue ? "stop_effect_unconfirmed" : "natural_exit";
    }

    private async Task DrainOutputAsync(Stream source, RunOutputStream kind)
    {
        var buffer = new byte[16 * 1024];
        while (await source.ReadAsync(buffer, CancellationToken.None).ConfigureAwait(false) is var count && count > 0)
        {
            _capture.Capture(kind, buffer.AsSpan(0, count));
        }
    }

    private async Task<string?> CompleteOutputRetentionAsync()
    {
        try
        {
            await _capture.CompleteAsync().WaitAsync(DrainDeadline).ConfigureAwait(false);
            return null;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or TimeoutException or OperationCanceledException)
        {
            return "windows_output_retention/" + WindowsRunLauncher.NativeCode(error);
        }
        finally
        {
            _capture.Dispose();
        }
    }

    private async Task<WindowsMxcJobObservation> DrainPayloadAsync()
    {
        var draining = Stopwatch.StartNew();
        while (true)
        {
            var observed = _payload.Observe();
            if (observed.Empty) return observed;
            var stopping = await ApplyPendingStopAsync(executorRunning: false).ConfigureAwait(false);
            RequireForcedStopBound();
            if (!stopping && draining.Elapsed >= DrainDeadline)
            {
                throw new TimeoutException("The official executor exited without independently verified payload drain.");
            }

            await Task.Delay(20, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async ValueTask<bool> ApplyPendingStopAsync(bool executorRunning)
    {
        StopPlan? plan;
        lock (_stopGate) plan = _stop;
        if (plan is null) return false;
        if (!_stopObserved)
        {
            _stopObserved = true;
            if (executorRunning)
            {
                Volatile.Write(ref _observation, new(RunOwnerState.Stopping, RunPayloadStart.Unknown, false,
                    TerminationReason: "stop_requested"));
            }

            var remaining = plan.Grace - Stopwatch.GetElapsedTime(plan.RequestedAt);
            if (remaining > TimeSpan.Zero && _io.ConsoleHandle != 0 && !_payload.Observe().Empty)
            {
                _interruptAttempted = true;
                await _io.InterruptAsync(remaining).ConfigureAwait(false);
            }
        }

        if (_forcedAt is null && Stopwatch.GetElapsedTime(plan.RequestedAt) >= plan.Grace)
        {
            ForceOwnedPayload();
        }

        return true;
    }

    private void ForceOwnedPayload()
    {
        var members = _payload.Observe();
        if (members.Empty) return;

        _forceWitness = HoldLiveDescendant(members);
        // A fresh application exit status distinguishes this action from an independent Ctrl+C or natural exit.
        uint? code = null;
        try
        {
            code = 0xe0000000u | (uint)RandomNumberGenerator.GetInt32(1 << 29);
        }
        catch (CryptographicException)
        {
            // Terminate the scope even when corroboration is unavailable.
        }

        if (code is null) _payload.Terminate();
        else if (!Native.TerminateJobObject(_payload.Handle, code.Value))
        {
            throw WindowsMxcJob.Error("Terminate the exact Windows payload Job");
        }

        _forcedCode = code;
        _forcedAt = Stopwatch.GetTimestamp();
    }

    private SafeKernelHandle? HoldLiveDescendant(WindowsMxcJobObservation members)
    {
        foreach (var pid in members.ProcessIds)
        {
            if (pid == _executor.ProcessId || ProcessInfo.Open(pid) is not { } process) continue;
            if (ProcessInfo.CreationFileTime(process) > 0
                && Native.IsProcessInJob(process, _payload.Handle.DangerousGetHandle(), out var member) && member
                && ProcessInfo.IsRunning(process))
            {
                return process;
            }

            process.Dispose();
        }

        return null;
    }

    private void RequireForcedStopBound()
    {
        if (_forcedAt is { } forced && Stopwatch.GetElapsedTime(forced) >= DrainDeadline)
        {
            throw new TimeoutException("Native termination of the held Windows payload Job did not prove drain.");
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (!_monitor.IsCompleted)
            {
                await StopAsync(TimeSpan.Zero, CancellationToken.None).ConfigureAwait(false);
                await _monitor.WaitAsync(DrainDeadline).ConfigureAwait(false);
            }
        }
        finally
        {
            _capture.Dispose();
            _io.Dispose();
            _executor.Dispose();
            _payload.Dispose();
            _aggregate.Dispose();
            _policy.Dispose();
            _control.Dispose();
            _paths.Dispose();
            _installed.Dispose();
        }
    }

    private sealed record StopPlan(long RequestedAt, TimeSpan Grace);
}
