// SPDX-License-Identifier: AGPL-3.0-only

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
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
    private readonly Task _monitor;
    private readonly object _stopGate = new();
    private RunOwnerObservation _observation = new(RunOwnerState.Running, RunPayloadStart.Unknown, false);
    private StopPlan? _stop;
    private bool _stopObserved;
    private long? _forcedAt;

    internal WindowsRunSession(WindowsMxcJob aggregate, WindowsMxcJob payload, LaunchedProcess executor,
        WindowsRunIo io, WindowsMxcStage installed, WindowsMxcPathLease control, WindowsMxcPathLease policy,
        WindowsRunPathBindings paths, WindowsRunEvidence evidence)
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
        _monitor = MonitorAsync();
    }

    public ValueTask<RunOwnerObservation> ObserveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Volatile.Read(ref _observation));
    }

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
        // Drain both selected pipe streams, or the ConPTY stream, even when no client is attached.
        // Terminal export and replay are implemented by the terminal broker.
        var output = _io.Output.CopyToAsync(Stream.Null, 16 * 1024, CancellationToken.None);
        var error = _io.Error?.CopyToAsync(Stream.Null, 16 * 1024, CancellationToken.None) ?? Task.CompletedTask;
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
            reason = _stopObserved ? "user_stop" : "natural_exit";
            Volatile.Write(ref _observation, new(RunOwnerState.Draining, RunPayloadStart.Unknown, false,
                rawExit, RunExitSources.OfficialExecutor, reason));

            // The pinned executor's own completion is independent of the outer Run drain proof.
            var payload = await DrainPayloadAsync().ConfigureAwait(false);
            reason = _stopObserved ? "user_stop" : reason;
            _io.CloseInput();
            await Task.WhenAll(_io.CloseConsoleAsync(), output, error).WaitAsync(DrainDeadline).ConfigureAwait(false);
            var aggregate = await _aggregate.WaitForDrainAsync(Environment.ProcessId, DrainDeadline, CancellationToken.None).ConfigureAwait(false);
            _policy.DeletePrivateFile();
            _evidence.WriteDrained(rawExit.Value, reason, aggregate, payload);
            Volatile.Write(ref _observation, new(RunOwnerState.Exited, RunPayloadStart.Unknown, true,
                rawExit, RunExitSources.OfficialExecutor, reason));
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or Win32Exception or TimeoutException or UnauthorizedAccessException or ObjectDisposedException)
        {
            Volatile.Write(ref _observation, new(RunOwnerState.RecoveryRequired, RunPayloadStart.Unknown, false,
                rawExit, rawExit.HasValue ? RunExitSources.OfficialExecutor : RunExitSources.Unknown,
                _stopObserved ? "user_stop" : reason ?? "owner_failure", WindowsRunLauncher.NativeCode(exception)));
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
                    TerminationReason: "user_stop"));
            }

            var remaining = plan.Grace - Stopwatch.GetElapsedTime(plan.RequestedAt);
            if (remaining > TimeSpan.Zero) await _io.InterruptAsync(remaining).ConfigureAwait(false);
        }

        if (_forcedAt is null && Stopwatch.GetElapsedTime(plan.RequestedAt) >= plan.Grace)
        {
            _payload.Terminate();
            _forcedAt = Stopwatch.GetTimestamp();
        }

        return true;
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
