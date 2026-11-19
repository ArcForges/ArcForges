// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using V1 = ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private readonly CriticalShedding _resourceShedding = new();
    private SandboxPressureFacts? _previousPressure;
    private string? _pressureVictim;
    private bool _pressureUnrelieved;
    private bool _resourceControlFailed;

    private void ControlResources(SandboxResourceFrame frame, NodeLog log)
    {
        lock (OwnershipGate)
        {
            if (_runObservationStopped || !frame.HasFreshBudget || frame.PressureFacts is not { } pressure
                || !ReferenceEquals(_resourceMonitor?.Latest, frame))
            {
                return;
            }

            try
            {
                // The sample's pressure thresholds and budget must still be from the active host policy.
                if (frame.Host.PolicyRevision?.Value != _store.Policies.Current().Revision)
                {
                    return;
                }

                var previous = _previousPressure;
                _previousPressure = pressure;
                if (previous?.Raw != pressure.Raw || previous?.Level != pressure.Level || pressure.NewOomKills > 0)
                {
                    log.Info("sandbox.resources.pressure", new LogField("raw", pressure.Raw.ToString().ToLowerInvariant()),
                        new LogField("effective", pressure.Level.ToString().ToLowerInvariant()),
                        new LogField("trigger", pressure.Trigger), new LogField("sampleSequence", (long)frame.Host.SampleSequence));
                }

                bool forceReduction = previous is not null && pressure.Level > previous.Level;
                RebalanceRunCpuLocked(frame, forceReduction);
                if (frame.HasFreshBudget)
                {
                    ShedCriticalPressureLocked(frame, pressure, log);
                }

                _resourceControlFailed = false;
            }
            catch (Exception error) when (IsStorageFailure(error) || IsNativeResourceFailure(error))
            {
                if (!_resourceControlFailed)
                {
                    log.Info("sandbox.resources.control_unavailable", new LogField("reason", error.GetType().Name));
                    _resourceControlFailed = true;
                }
            }
        }
    }

    private void ShedCriticalPressureLocked(SandboxResourceFrame frame, SandboxPressureFacts pressure, NodeLog log)
    {
        if (pressure.Raw != V1.PressureLevel.Critical)
        {
            _pressureUnrelieved = false;
        }

        // A terminal stored state requires verified native drain. Also require a frame
        // whose inventory no longer contains the victim before considering another.
        if (_pressureVictim is { } pending && !frame.Runs.ContainsKey(pending)
            && _store.Read(reader => RunRecords.Get(reader, OwnerId, pending)) is
            { State: StoredRunState.Exited or StoredRunState.Failed })
        {
            _pressureVictim = null;
        }

        if (!_resourceShedding.ShouldStop(pressure.Level, pressure.Raw, pressure.MemoryCritical,
                pressure.NewOomKills, _pressureVictim is not null))
        {
            return;
        }

        if (!TrySelectPressureVictim(frame, out var victim))
        {
            return;
        }

        if (victim is null)
        {
            ReportPressureUnrelieved(log, "no_eligible_run");
            return;
        }

        var request = new RunServiceStopRequest
        {
            Meta = new() { CommandId = CommandIds.New(), ExpectedRev = new() { Value = victim.Revision } },
            OwnerEpoch = new() { Value = ByteString.CopyFrom(Receipts.OwnerEpoch.Span) },
            RunId = FromHex(victim.RunId),
        };
        var result = StopRunLocked(request, pressureRequested: true);
        if (result.Operation?.State != OperationState.Accepted)
        {
            ReportPressureUnrelieved(log, result.Error?.Code ?? "stop_outcome_unconfirmed");
            return;
        }

        _pressureVictim = victim.RunId;
        _resourceShedding.Stopped();
        _pressureUnrelieved = false;
        log.Info("sandbox.resources.pressure_stop", new LogField("runId", victim.RunId),
            new LogField("sampleSequence", (long)frame.Host.SampleSequence), new LogField("trigger", pressure.Trigger));
    }

    private bool TrySelectPressureVictim(SandboxResourceFrame frame, out StoredRun? victim)
    {
        victim = null;
        var (catalogue, runs) = _store.Read(reader => (SandboxRecords.CatalogRevision(reader, OwnerId),
            RunRecords.ListNonterminal(reader, OwnerId)));
        if (frame.CatalogueRevision != catalogue || runs.Count != frame.Runs.Count
            || runs.Any(run => !frame.Runs.TryGetValue(run.RunId, out var measured) || measured.Target.Epoch != run.Epoch
                || !ReferenceEquals(measured.Target.Source, CurrentResourceSource(run.RunId, run.Epoch))))
        {
            return false;
        }

        var eligible = new List<(StoredRun Run, int Priority)>();
        foreach (var run in runs)
        {
            if (run.State != StoredRunState.Running
                || !_liveRuns.TryGetValue(run.RunId, out var live)
                || live.Epoch != run.Epoch
                || live.StopRequest.Task.IsCompleted
                || live.OwnerLease is not IRunResourceSource source
                || live.OwnerLease.Identity.ControlEpoch != run.Epoch
                || !frame.Runs.TryGetValue(run.RunId, out var measurement)
                || measurement.Target.Epoch != run.Epoch
                || !ReferenceEquals(measurement.Target.Source, source)
                || measurement.Reading is not { ProcessCount: > 1 } reading
                || OperatingSystem.IsLinux() && reading.OomKills != 0)
            {
                continue;
            }

            var committed = ReadRunSnapshot(run);
            if (!committed.Preemptible || committed.PressureAction != PressureAction.StopPreemptible
                || DecodeResourcePolicy(ReadResourcePolicy("sandbox", run.SandboxId)) is
                { PressureAction: not PressureAction.StopPreemptible }
                || DecodeResourcePolicy(ReadResourcePolicy("run", run.RunId)) is
                { PressureAction: not PressureAction.StopPreemptible })
            {
                continue;
            }

            eligible.Add((run, committed.Priority));
        }

        victim = eligible.OrderBy(candidate => candidate.Priority)
            .ThenByDescending(candidate => candidate.Run.StartedAt ?? candidate.Run.CreatedAt)
            .ThenBy(candidate => candidate.Run.RunId, StringComparer.Ordinal)
            .FirstOrDefault().Run;
        return true;
    }

    private void ReportPressureUnrelieved(NodeLog log, string reason)
    {
        if (!_pressureUnrelieved)
        {
            log.Info("sandbox.resources.pressure_unrelieved", new LogField("reason", reason));
            _pressureUnrelieved = true;
        }
    }

    private void AddResourcePressureWarning(ResponseMeta meta, SandboxResourceFrame? frame)
    {
        if (_pressureUnrelieved && frame is
            { HasFreshBudget: true, PressureFacts.Level: V1.PressureLevel.Critical })
        {
            meta.Warnings.Add("pressure_unrelieved");
        }
    }
}
