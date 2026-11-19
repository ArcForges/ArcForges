// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    /// <summary>Closes Node observation only. An activated owner retains its independent platform handles.</summary>
    internal void StopRunObservations()
    {
        lock (OwnershipGate)
        {
            if (_runObservationStopped)
            {
                return;
            }

            _runObservationStopped = true;
            _runObserverStop.Cancel();
            _runObserverStop.Dispose();
        }
    }

    private async Task OwnRunAsync(LiveRun live)
    {
        var token = live.CancellationToken;
        using var operations = CancellationTokenSource.CreateLinkedTokenSource(token);
        IRunOwnerLease? lease = null;
        Task? stop = null;
        bool preparing = false;
        bool releaseAttempted = false;
        try
        {
            token.ThrowIfCancellationRequested();
            if (live.StopRequest.Task.IsCompletedSuccessfully)
            {
                ObserveRun(live, NoRunPayload("stopped_before_prepare") with { State = RunOwnerState.Exited });
                return;
            }

            PrepareRunControl(live.Spec);
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(token);
            startup.CancelAfter(TimeSpan.FromSeconds(30));
            preparing = true;
            lease = await live.Launcher.PrepareAsync(live.Spec, startup.Token).ConfigureAwait(false);
            BindRunOwner(live, lease.Identity);
            stop = ForwardRunStopAsync(live, lease, operations.Token);

            try
            {
                ValueTask activation = default;
                lock (OwnershipGate)
                {
                    token.ThrowIfCancellationRequested();
                    // Initiating release and admitting Stop are ordered by the same Owner gate.
                    if (!live.StopRequest.Task.IsCompletedSuccessfully)
                    {
                        releaseAttempted = true;
                        activation = lease.ActivateAsync(startup.Token);
                    }
                }

                await activation.ConfigureAwait(false);
            }
            catch (RunNativeException error) when (live.StopRequest.Task.IsCompletedSuccessfully && error.NativeCode == "activation_closed")
            {
                // The owner accepted Stop before the payload release. Observe its original boundary.
            }
            catch (Exception error) when (!token.IsCancellationRequested && IsRunOwnerFailure(error))
            {
                ReportRun(live.Spec.RunId, "release_response_unavailable", NativeFailure(error));
                ObserveRun(live, UncertainRun("native_release_requires_reconciliation"));
            }

            // Keep the checked Sandbox root held through the release handoff.
            live.Root.Dispose();
            while (!token.IsCancellationRequested)
            {
                RunOwnerObservation observed;
                try
                {
                    using var readback = CancellationTokenSource.CreateLinkedTokenSource(token);
                    readback.CancelAfter(TimeSpan.FromSeconds(5));
                    observed = await lease.ObserveAsync(readback.Token).ConfigureAwait(false);
                }
                catch (Exception error) when (!token.IsCancellationRequested && IsRunOwnerFailure(error))
                {
                    ReportRun(live.Spec.RunId, "observe_failed", NativeFailure(error));
                    ObserveRun(live, UncertainRun("native_observation_unavailable"));
                    await Task.Delay(TimeSpan.FromMilliseconds(500), token).ConfigureAwait(false);
                    continue;
                }

                ObserveRun(live, observed);
                if (observed.IsTerminal && observed.GroupEmptyVerified)
                {
                    return;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(150), token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception error) when (!token.IsCancellationRequested)
        {
            ReportRun(live.Spec.RunId, releaseAttempted ? "release_failed" : "prepare_failed", NativeFailure(error));
            var safeRefusal = !preparing || !releaseAttempted && error is RunNativeException { BoundaryEmptyVerified: true };
            try
            {
                ObserveRun(live, safeRefusal ? NoRunPayload("native_launch_refused") : UncertainRun("native_launch_unresolved"));
            }
            catch (Exception stateError)
            {
                ReportRun(live.Spec.RunId, "persist_observation_failed", NativeFailure(stateError));
            }
        }
        finally
        {
            await operations.CancelAsync().ConfigureAwait(false);
            if (stop is not null)
            {
                await stop.ConfigureAwait(false);
            }

            if (lease is not null)
            {
                try
                {
                    await lease.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception error)
                {
                    ReportRun(live.Spec.RunId, "owner_channel_close_failed", NativeFailure(error));
                }
            }

            live.Root.Dispose();
            CryptographicOperations.ZeroMemory(live.Spec.ControlKey);
            lock (OwnershipGate)
            {
                _liveRuns.Remove(live.Spec.RunId);
            }
        }
    }

    private void PrepareRunControl(RunLaunchSpec spec)
    {
        _roots.ValidateControlPaths();
        if (Directory.Exists(spec.ControlDirectory) || File.Exists(spec.ControlDirectory))
        {
            throw new IOException("run_control_path_exists");
        }

        if (OperatingSystem.IsLinux())
        {
            Directory.CreateDirectory(spec.ControlDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        else
        {
            Directory.CreateDirectory(spec.ControlDirectory);
        }

        using var created = WorkspacePath.OpenRoot(spec.ControlDirectory);
        _roots.ValidateControlPaths();
    }

    private void BindRunOwner(LiveRun live, RunOwnerIdentity identity)
    {
        lock (OwnershipGate)
        {
            live.CancellationToken.ThrowIfCancellationRequested();
            if (identity.ControlEpoch != live.Spec.Epoch || identity.ProcessId <= 0
                || string.IsNullOrWhiteSpace(identity.InstanceId) || string.IsNullOrWhiteSpace(identity.BootId)
                || string.IsNullOrWhiteSpace(identity.CreationIdentity) || string.IsNullOrWhiteSpace(identity.BoundaryIdentity)
                || string.IsNullOrWhiteSpace(identity.Endpoint) || string.IsNullOrWhiteSpace(identity.BackendId)
                || string.IsNullOrWhiteSpace(identity.Cohort))
            {
                throw new InvalidDataException("run_owner_identity_invalid");
            }

            var stored = new StoredSupervisorIdentity(live.Spec.RunId, identity.InstanceId, identity.BootId,
                identity.ProcessId, identity.CreationIdentity, identity.Endpoint, identity.BoundaryIdentity,
                identity.BackendId, identity.Cohort, identity.ControlEpoch, _clock.GetUtcNow());
            _store.Write(transaction => RequireChanged(RunRecords.InsertSupervisor(transaction, OwnerId, live.Spec.Epoch, stored)),
                CommitDurability.Full);
        }
    }

    private async Task ForwardRunStopAsync(LiveRun live, IRunOwnerLease lease, CancellationToken cancellationToken)
    {
        try
        {
            var grace = await live.StopRequest.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            stop.CancelAfter(grace + TimeSpan.FromSeconds(15));
            await lease.StopAsync(grace, stop.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception error)
        {
            ReportRun(live.Spec.RunId, "stop_handoff_failed", NativeFailure(error));
            try
            {
                ObserveRun(live, UncertainRun("stop_handoff_unresolved"));
            }
            catch (Exception stateError)
            {
                ReportRun(live.Spec.RunId, "persist_observation_failed", NativeFailure(stateError));
            }
        }
    }

    private void ObserveRun(LiveRun live, RunOwnerObservation observation)
    {
        lock (OwnershipGate)
        {
            if (_runObservationStopped || observation.State == RunOwnerState.Ready)
            {
                return;
            }

            var id = live.Spec.RunId;
            var run = _store.Read(reader => RunRecords.Get(reader, OwnerId, id));
            if (run is null || run.Epoch != live.Spec.Epoch || run.State is StoredRunState.Exited or StoredRunState.Failed)
            {
                return;
            }

            if (observation.NativeError is { } error)
            {
                ReportRun(id, "native_observation", error);
            }

            if (observation.State == RunOwnerState.Failed && observation.GroupEmptyVerified
                && observation.PayloadStarted == RunPayloadStart.NotStarted
                && live.StopRequest.Task.IsCompletedSuccessfully)
            {
                observation = observation with { State = RunOwnerState.Exited, TerminationReason = "stopped_before_payload" };
            }

            if (ConflictingRunEvidence(run, observation))
            {
                ReportRun(id, "native_evidence_conflict", null);
                observation = UncertainRun("conflicting_native_exit_evidence");
            }

            var target = RunStoreState(observation, run);
            if (target == StoredRunState.Exited && run.State != StoredRunState.Draining)
            {
                // A short foreground process can reach its exit before the first Running poll.
                var draining = BuildRunObservation(run, observation, StoredRunState.Draining, _clock.GetUtcNow());
                AdvanceRun(run, draining);
                run = _store.Read(reader => RunRecords.Get(reader, OwnerId, id))!;
            }

            var change = BuildRunObservation(run, observation, target, _clock.GetUtcNow());
            if (target is StoredRunState.Exited or StoredRunState.Failed)
            {
                CommitRunExit(live, run, change);
            }
            else if (target == StoredRunState.RecoveryRequired)
            {
                RecordRunUncertain(live, run, change);
            }
            else if (RunObservationChanged(run, change))
            {
                AdvanceRun(run, change);
            }
        }
    }

    private static StoredRunState RunStoreState(RunOwnerObservation observation, StoredRun run)
    {
        if (observation.IsTerminal && !observation.GroupEmptyVerified)
        {
            return observation is { State: RunOwnerState.Failed, PayloadStarted: RunPayloadStart.NotStarted }
                ? run.State : StoredRunState.Draining;
        }

        return observation.State switch
        {
            RunOwnerState.Starting => run.State,
            RunOwnerState.Running when run.State is StoredRunState.Stopping or StoredRunState.Draining => run.State,
            RunOwnerState.Running => StoredRunState.Running,
            RunOwnerState.Stopping when run.State is StoredRunState.RecoveryRequired or StoredRunState.Draining => run.State,
            RunOwnerState.Stopping => StoredRunState.Stopping,
            RunOwnerState.Draining => StoredRunState.Draining,
            RunOwnerState.Exited => StoredRunState.Exited,
            RunOwnerState.Failed when observation.PayloadStarted == RunPayloadStart.NotStarted => StoredRunState.Failed,
            _ => StoredRunState.RecoveryRequired,
        };
    }

    private static StoredRunObservation BuildRunObservation(StoredRun run, RunOwnerObservation observation, StoredRunState state,
        DateTimeOffset now)
    {
        var payload = observation.PayloadStarted == RunPayloadStart.Unknown
            ? run.PayloadStarted : (StoredPayloadStart)observation.PayloadStarted;
        var effect = payload switch
        {
            StoredPayloadStart.Confirmed => EffectCertainty.Happened,
            StoredPayloadStart.NotStarted => EffectCertainty.DidNotHappen,
            _ => EffectCertainty.Unknown,
        };
        var terminal = state is StoredRunState.Exited or StoredRunState.Failed;
        var reachedStart = observation.PayloadStarted != RunPayloadStart.NotStarted
            && (observation.State == RunOwnerState.Running || observation.PayloadStarted == RunPayloadStart.Confirmed
                || observation is { RawExitCode: not null, ExitSource: RunExitSources.Payload or RunExitSources.OfficialExecutor });
        var source = IsKnownExitSource(observation.ExitSource) ? observation.ExitSource : null;
        return new StoredRunObservation(state, payload, (int)effect,
            StartedAt: run.StartedAt ?? (reachedStart ? now : null),
            EndedAt: terminal ? now : null,
            RawExitCode: observation.RawExitCode,
            ExitSource: source ?? (terminal && run.ExitSource is null ? RunExitSources.Unknown : null),
            TerminationReason: terminal ? observation.TerminationReason ?? "native_owner_exited" : null,
            GroupEmptyVerified: terminal && observation.GroupEmptyVerified);
    }

    private static bool ConflictingRunEvidence(StoredRun run, RunOwnerObservation observed) =>
        run.RawExitCode is int raw && observed.RawExitCode is int seen && raw != seen
        || IsKnownExitSource(run.ExitSource) && IsKnownExitSource(observed.ExitSource) && run.ExitSource != observed.ExitSource
        || run.PayloadStarted != StoredPayloadStart.Unknown && observed.PayloadStarted != RunPayloadStart.Unknown
            && (int)run.PayloadStarted != (int)observed.PayloadStarted;

    private static bool IsKnownExitSource(string? source) =>
        source is RunExitSources.Payload or RunExitSources.OfficialExecutor or RunExitSources.Supervisor;

    private static bool RunObservationChanged(StoredRun run, StoredRunObservation change) =>
        run.State != change.State || run.PayloadStarted != change.PayloadStarted || run.EffectCertainty != change.EffectCertainty
        || run.StartedAt is null && change.StartedAt is not null
        || run.RawExitCode is null && change.RawExitCode is not null
        || !IsKnownExitSource(run.ExitSource) && IsKnownExitSource(change.ExitSource);

    private void AdvanceRun(StoredRun run, StoredRunObservation change) =>
        _store.Write(transaction => RequireChanged(RunRecords.TryAdvance(transaction, OwnerId, run.RunId, run.Epoch,
            run.Revision, run.State, change)), CommitDurability.Full);

    private void RecordRunUncertain(LiveRun live, StoredRun run, StoredRunObservation change)
    {
        var previous = Receipts.Inspect(live.StartCommand);
        if (previous?.State == "ACCEPTED")
        {
            Receipts.SetResult(live.StartCommand, "UNKNOWN", (int)EffectCertainty.Unknown,
                ResultBody(run.Revision + 1, null, ErrorCategory.Execution, "outcome_unknown", "run_boundary_requires_reconciliation"),
                transaction => RequireChanged(RunRecords.TryAdvance(transaction, OwnerId, run.RunId, run.Epoch, run.Revision, run.State, change)));
        }
        else if (RunObservationChanged(run, change))
        {
            AdvanceRun(run, change);
        }

        if (live.StopCommand is { } stop && Receipts.Inspect(stop)?.State == "ACCEPTED")
        {
            Receipts.SetResult(stop, "UNKNOWN", (int)EffectCertainty.Unknown,
                ResultBody(run.Revision + 1, null, ErrorCategory.Execution, "outcome_unknown", "run_boundary_requires_reconciliation"));
        }
    }

    private void CommitRunExit(LiveRun live, StoredRun run, StoredRunObservation change)
    {
        var notStarted = change.PayloadStarted == StoredPayloadStart.NotStarted;
        var startUnknown = !notStarted && run.StartedAt is null && change.StartedAt is null;
        var revision = checked(run.Revision + 1);
        var state = notStarted ? "FAILED" : startUnknown ? "UNKNOWN" : "SUCCEEDED";
        var effect = notStarted ? EffectCertainty.DidNotHappen : startUnknown ? EffectCertainty.Unknown : EffectCertainty.Happened;
        var result = state switch
        {
            "FAILED" => ResultBody(revision, null, change.State == StoredRunState.Failed ? ErrorCategory.Execution : ErrorCategory.State,
                change.State == StoredRunState.Failed ? "launch_failed" : "busy", change.TerminationReason),
            "UNKNOWN" => ResultBody(revision, null, ErrorCategory.Execution, "outcome_unknown", "payload_start_evidence_unavailable"),
            _ => ResultBody(revision, null),
        };

        if (startUnknown && live.StopCommand is null && Receipts.Inspect(live.StartCommand)?.State == "UNKNOWN")
        {
            AdvanceRun(run, change);
        }
        else
        {
            Receipts.SetResult(live.StartCommand, state, (int)effect, result,
                transaction => RequireChanged(RunRecords.TryAdvance(transaction, OwnerId, run.RunId, run.Epoch, run.Revision, run.State, change)),
                settledSafetyCommand: live.StopCommand, settledSafetyJson: live.StopCommand is null ? null : ResultBody(revision, null));
        }

        ReportRun(run.RunId, "native_boundary_empty", change.TerminationReason);
    }

    private void ReportRun(string runId, string phase, string? native)
    {
        if (native is { Length: > 160 } || native is not null
            && native.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('_' or '-' or '/' or ':' or '.')))
        {
            native = "native_error_redacted";
        }

        RunDiagnostic?.Invoke(runId, phase, native);
    }

    private static bool IsRunOwnerFailure(Exception error) => error is IOException or InvalidDataException
        or UnauthorizedAccessException or OperationCanceledException or System.Net.Sockets.SocketException;

    private static string NativeFailure(Exception error) => error is RunNativeException native
        ? $"{native.Phase}/{native.NativeCode}" : error.GetType().Name;

    private static RunOwnerObservation NoRunPayload(string reason) =>
        new(RunOwnerState.Failed, RunPayloadStart.NotStarted, true, ExitSource: RunExitSources.Supervisor, TerminationReason: reason);

    private static RunOwnerObservation UncertainRun(string reason) =>
        new(RunOwnerState.RecoveryRequired, RunPayloadStart.Unknown, false, TerminationReason: reason);
}
