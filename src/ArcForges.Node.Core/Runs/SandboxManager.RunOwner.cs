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

    private async Task OwnRunAsync(LiveRun live, RunLaunchSpec spec, IRunLauncher launcher, SandboxPrivateRootLease root)
    {
        var token = live.CancellationToken;
        using var operations = CancellationTokenSource.CreateLinkedTokenSource(token);
        IRunOwnerLease? lease = null;
        Task? stop = null;
        bool preparing = false;
        bool releaseAttempted = false;
        try
        {
            lock (OwnershipGate)
            {
                token.ThrowIfCancellationRequested();
                if (live.StopRequest.Task.IsCompletedSuccessfully)
                {
                    ObserveRun(live, NoRunPayload("stopped_before_prepare") with { State = RunOwnerState.Exited });
                    return;
                }

                Receipts.RecordRunPreparing(live.StartCommand, live.RunId, live.Epoch);
            }

            PrepareRunControl(spec);
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(token);
            startup.CancelAfter(TimeSpan.FromSeconds(30));
            preparing = true;
            lease = await launcher.PrepareAsync(spec, startup.Token).ConfigureAwait(false);
            bool verifiedLimits = BindRunOwner(live, spec, lease);
            stop = ForwardRunStopAsync(live, lease, operations.Token);

            try
            {
                if (!verifiedLimits)
                {
                    ReportRun(live.RunId, "prepared_resource_readback", "required_run_limit_unconfirmed");
                    await lease.StopAsync(TimeSpan.Zero, startup.Token).ConfigureAwait(false);
                }
                else
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
            }
            catch (RunNativeException error) when (live.StopRequest.Task.IsCompletedSuccessfully && error.NativeCode == "activation_closed")
            {
                // The owner accepted Stop before the payload release. Observe its original boundary.
            }
            catch (Exception error) when (!token.IsCancellationRequested && IsRunOwnerFailure(error))
            {
                ReportRun(live.RunId, "release_response_unavailable", NativeFailure(error));
                ObserveRun(live, UncertainRun("native_release_requires_reconciliation"));
            }
            finally
            {
                spec.ClearInputs();
            }

            // Keep the checked Sandbox root held through the release handoff.
            root.Dispose();
            await ObserveOwnerAsync(live, lease, refusedStartup: !verifiedLimits && !releaseAttempted).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception error) when (!token.IsCancellationRequested)
        {
            ReportRun(live.RunId, releaseAttempted ? "release_failed" : "prepare_failed", NativeFailure(error));
            var safeRefusal = !preparing || !releaseAttempted && error is RunNativeException { BoundaryEmptyVerified: true };
            try
            {
                ObserveRun(live, safeRefusal ? NoRunPayload("native_launch_refused") : UncertainRun("native_launch_unresolved"));
            }
            catch (Exception stateError)
            {
                ReportRun(live.RunId, "persist_observation_failed", NativeFailure(stateError));
            }
        }
        finally
        {
            lock (OwnershipGate)
            {
                live.OwnerLease = null;
            }

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
                    ReportRun(live.RunId, "owner_channel_close_failed", NativeFailure(error));
                }
            }

            root.Dispose();
            spec.ClearInputs();
            CryptographicOperations.ZeroMemory(spec.ControlKey);
            lock (OwnershipGate)
            {
                _liveRuns.Remove(live.RunId);
            }
        }
    }

    private async Task ObserveOwnerAsync(LiveRun live, IRunOwnerLease lease, bool refusedStartup = false)
    {
        var token = live.CancellationToken;
        bool refusedStartConflictsWithPayload = false;
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
                ReportRun(live.RunId, "observe_failed", NativeFailure(error));
                ObserveRun(live, UncertainRun("native_observation_unavailable"));
                await Task.Delay(TimeSpan.FromMilliseconds(500), token).ConfigureAwait(false);
                continue;
            }

            bool drained = observed.IsTerminal && observed.GroupEmptyVerified;
            if (refusedStartup)
            {
                if (!refusedStartConflictsWithPayload && (observed.PayloadStarted == RunPayloadStart.Confirmed
                    || observed.State == RunOwnerState.Running
                    || observed.ExitSource is RunExitSources.Payload or RunExitSources.OfficialExecutor))
                {
                    refusedStartConflictsWithPayload = true;
                    ReportRun(live.RunId, "prepared_resource_refusal_conflicts_with_payload", observed.NativeError);
                }

                if (refusedStartConflictsWithPayload)
                {
                    observed = UncertainRun("prepared_resource_refusal_conflicts_with_payload");
                }
                else if (drained)
                {
                    // No activation was issued, and the original held boundary is now empty.
                    observed = observed with
                    {
                        State = RunOwnerState.Failed,
                        PayloadStarted = RunPayloadStart.NotStarted,
                        TerminationReason = "required_run_limit_unconfirmed",
                    };
                }
                else if (observed.IsTerminal || observed.State is RunOwnerState.Stopping or RunOwnerState.Draining)
                {
                    // The safety Stop has not yet proved the outer boundary empty. Keep
                    // the stored state eligible to record a failed Start once it does.
                    observed = observed with { State = RunOwnerState.Starting };
                }
            }

            ObserveRun(live, observed);
            if (drained)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(150), token).ConfigureAwait(false);
        }
    }

    private void PrepareRunControl(RunLaunchSpec spec)
    {
        _roots.ValidateControlPaths();
        using var dataRoot = WorkspacePath.OpenRoot(_dataRoot);
        WorkspacePath.CheckSandboxDirectory(dataRoot.RootHandle, configuredRoot: true);
        using var parent = dataRoot.OpenSandboxDirectory("control", configuredRoot: true);
        var name = "run-" + spec.RunId;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!string.Equals(Path.Combine(parent.RootPath, name), spec.ControlDirectory, comparison))
        {
            throw new InvalidDataException("run_control_path_mismatch");
        }

        using var created = parent.CreateSandboxDirectory(name);
        _roots.ValidateControlPaths();
    }

    private bool BindRunOwner(LiveRun live, RunLaunchSpec spec, IRunOwnerLease lease)
    {
        lock (OwnershipGate)
        {
            live.CancellationToken.ThrowIfCancellationRequested();
            var identity = lease.Identity;
            if (identity.ControlEpoch != live.Epoch || identity.ProcessId <= 0
                || string.IsNullOrWhiteSpace(identity.InstanceId) || string.IsNullOrWhiteSpace(identity.BootId)
                || string.IsNullOrWhiteSpace(identity.CreationIdentity) || string.IsNullOrWhiteSpace(identity.BoundaryIdentity)
                || string.IsNullOrWhiteSpace(identity.Endpoint) || string.IsNullOrWhiteSpace(identity.BackendId)
                || string.IsNullOrWhiteSpace(identity.Cohort))
            {
                throw new InvalidDataException("run_owner_identity_invalid");
            }

            var stored = new StoredSupervisorIdentity(live.RunId, identity.InstanceId, identity.BootId,
                identity.ProcessId, identity.CreationIdentity, identity.Endpoint, identity.BoundaryIdentity,
                identity.BackendId, identity.Cohort, identity.ControlEpoch, _clock.GetUtcNow());
            var readback = PrepareRunGrantReadback(spec, lease, stored.LastSeenAt);
            bool releaseAllowed = live.StopRequest.Task.IsCompletedSuccessfully || readback.All(fact =>
                fact.Observation.Status == StoredRunLimitStatus.Effective);
            _store.Write(transaction =>
            {
                RequireChanged(RunRecords.InsertSupervisor(transaction, OwnerId, live.Epoch, stored));
                int bound = ResourceStateRecords.BindPendingLimits(transaction, OwnerId, live.RunId,
                    live.Epoch, identity.BoundaryIdentity);
                RequireChanged(bound == readback.Length);
                if (live.StopRequest.Task.IsCompletedSuccessfully)
                {
                    return;
                }

                foreach (var fact in readback)
                {
                    RequireChanged(ResourceStateRecords.TryObserveLimit(transaction, OwnerId, live.RunId,
                        live.Epoch, identity.BoundaryIdentity, fact.Dimension, 1, fact.Observation));
                }
            }, CommitDurability.Full);
            live.OwnerLease = lease;
            return releaseAllowed;
        }
    }

    private async Task ForwardRunStopAsync(LiveRun live, IRunOwnerLease lease, CancellationToken cancellationToken)
    {
        try
        {
            var intent = await live.StopRequest.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            var grace = intent.Remaining(_clock.GetUtcNow());
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            stop.CancelAfter(grace + TimeSpan.FromSeconds(15));
            await lease.StopAsync(grace, stop.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception error)
        {
            ReportRun(live.RunId, "stop_handoff_failed", NativeFailure(error));
            try
            {
                ObserveRun(live, UncertainRun("stop_handoff_unresolved"));
            }
            catch (Exception stateError)
            {
                ReportRun(live.RunId, "persist_observation_failed", NativeFailure(stateError));
            }
        }
    }

    private void ObserveRun(LiveRun live, RunOwnerObservation observation)
    {
        lock (OwnershipGate)
        {
            if (live.RecoveryLimitRefusal is { } refusal && observation is not { IsTerminal: true, GroupEmptyVerified: true })
            {
                observation = UncertainRun(refusal) with { NativeError = observation.NativeError };
            }

            if (_runObservationStopped || observation.State == RunOwnerState.Ready)
            {
                return;
            }

            var id = live.RunId;
            var run = _store.Read(reader => RunRecords.Get(reader, OwnerId, id));
            if (run is null || run.Epoch != live.Epoch || run.State is StoredRunState.Exited or StoredRunState.Failed)
            {
                return;
            }

            if (observation.NativeError is { } error)
            {
                ReportRun(id, "native_observation", error);
            }

            if (observation.State == RunOwnerState.Failed && observation.GroupEmptyVerified
                && observation.PayloadStarted == RunPayloadStart.NotStarted
                && (run.State is StoredRunState.Stopping or StoredRunState.Draining
                    || observation.TerminationReason == "stopped_before_payload"))
            {
                // STOPPING/DRAINING cannot transition straight to FAILED. Keep the owner's
                // actual reason so an unrelated failure cannot prove the Stop's effect.
                observation = observation with { State = RunOwnerState.Exited };
            }

            if (run.TerminationReason == "pressure_stop_requested" && observation is
                { State: RunOwnerState.Exited, GroupEmptyVerified: true, TerminationReason: "user_stop" or "stopped" })
            {
                observation = observation with { TerminationReason = "pressure_preempted" };
            }

            if (ConflictingRunEvidence(run, observation))
            {
                ReportRun(id, "native_evidence_conflict", null);
                observation = UncertainRun("conflicting_native_exit_evidence");
            }

            var target = RunStoreState(observation, run);
            if (run.State == StoredRunState.RecoveryRequired && target == StoredRunState.Running
                && live.StopRequest.Task.IsCompletedSuccessfully)
            {
                target = run.State;
            }
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
            else if (observation.State == RunOwnerState.Running && Receipts.Inspect(live.StartCommand)?.State is "ACCEPTED" or "UNKNOWN")
            {
                // Native executor acceptance establishes the business Start. PayloadStarted remains
                // the independent observation supplied by the official backend.
                bool changed = RunObservationChanged(run, change);
                Receipts.SetResult(live.StartCommand, "SUCCEEDED", (int)EffectCertainty.Happened,
                    ResultBody(changed ? checked(run.Revision + 1) : run.Revision, null), transaction =>
                    {
                        if (changed)
                        {
                            RequireChanged(RunRecords.TryAdvance(transaction, OwnerId, run.RunId, run.Epoch, run.Revision, run.State, change));
                        }
                    });
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
            "FAILED" => change.TerminationReason is "stopped_before_prepare" or "stopped_before_payload"
                ? ResultBody(revision, null, ErrorCategory.State, "busy", change.TerminationReason)
                : ResultBody(revision, null, ErrorCategory.Execution, "launch_failed", change.TerminationReason),
            "UNKNOWN" => ResultBody(revision, null, ErrorCategory.Execution, "outcome_unknown", "payload_start_evidence_unavailable"),
            _ => ResultBody(revision, null),
        };

        var start = Receipts.Inspect(live.StartCommand) ?? throw new InvalidDataException("run_start_receipt_missing");
        var stop = live.StopCommand;
        bool hasUnsettledStop = stop is not null && Receipts.Inspect(stop)?.State is "ACCEPTED" or "UNKNOWN";
        bool provedStop = hasUnsettledStop && change.State == StoredRunState.Exited && change.TerminationReason is
            "user_stop" or "stopped" or "stopped_before_prepare" or "stopped_before_payload" or "pressure_preempted";
        string stopUnknown = ResultBody(revision, null, ErrorCategory.Execution, "outcome_unknown", "run_stop_effect_unconfirmed");
        string stopSuccess = ResultBody(revision, null);
        void Advance(StoreTransaction transaction) => RequireChanged(RunRecords.TryAdvance(transaction, OwnerId, run.RunId,
            run.Epoch, run.Revision, run.State, change));

        if (start.State is "SUCCEEDED" or "FAILED" || startUnknown && start.State == "UNKNOWN")
        {
            if (hasUnsettledStop)
            {
                Receipts.SettleRunStop(live.StartCommand, stop!, provedStop ? "SUCCEEDED" : "UNKNOWN",
                    (int)(provedStop ? EffectCertainty.Happened : EffectCertainty.Unknown), provedStop ? stopSuccess : stopUnknown, Advance);
            }
            else
            {
                _store.Write(Advance, CommitDurability.Full);
            }
        }
        else
        {
            Receipts.SetResult(live.StartCommand, state, (int)effect, result, Advance,
                settledSafetyCommand: hasUnsettledStop ? stop : null,
                settledSafetyJson: hasUnsettledStop ? (provedStop ? stopSuccess : stopUnknown) : null,
                settledSafetyState: hasUnsettledStop && !provedStop ? "UNKNOWN" : "SUCCEEDED");
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
