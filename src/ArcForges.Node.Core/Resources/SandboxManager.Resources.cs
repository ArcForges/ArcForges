// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private SandboxResourceMonitor? _resourceMonitor;

    internal IAsyncDisposable? StartResourceSampling(IHostResourceSource? source, NodeLog log)
    {
        if (source is null)
        {
            return null;
        }

        _resourceMonitor = new SandboxResourceMonitor(_clock, source, CaptureResourceTargets, _store.Policies.Current, log);
        return _resourceMonitor;
    }

    private RunResourceInventory? CaptureResourceTargets()
    {
        lock (OwnershipGate)
        {
            try
            {
                return _store.Read(reader =>
                {
                    long catalogue = SandboxRecords.CatalogRevision(reader, OwnerId);
                    using var command = reader.CreateCommand("""
                        SELECT r.run_id, r.sandbox_id, r.epoch FROM sandbox s
                        JOIN run r ON r.sandbox_id = s.sandbox_id
                        WHERE s.owner_id = $owner AND r.state IN (1, 2, 3, 4, 7);
                        """);
                    command.Parameters.AddWithValue("$owner", OwnerId);
                    using var rows = command.ExecuteReader();
                    var targets = new List<RunResourceTarget>();
                    while (rows.Read())
                    {
                        var id = rows.GetString(0);
                        var epoch = rows.GetString(2);
                        // Durable unsettled Runs may outlive the Node. A missing held scope
                        // must prevent subtracting or budgeting its unknown managed use.
                        targets.Add(new(id, rows.GetString(1), epoch, CurrentResourceSource(id, epoch)));
                    }

                    return new RunResourceInventory(catalogue, targets.ToArray());
                });
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return null;
            }
        }
    }

    internal ResourceServiceGetBudgetResponse GetResourceBudget(ResourceServiceGetBudgetRequest request,
        CancellationToken cancellationToken)
    {
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var meta = Response(request.Meta);
            try
            {
                var frame = _resourceMonitor?.Latest;
                if (request.ScopeKind == "node" && request.ScopeId is null)
                {
                    var host = frame?.Host.Clone() ?? ResourceScopeSnapshot("node", null, null);
                    host.Stale = frame?.Stale ?? true;
                    host.PolicyRevision = new Revision { Value = ResourcePolicyRevision("node", null) };
                    ApplyResourceBudgetPolicy(host, DecodeResourcePolicy(ReadResourcePolicy("node", null)));
                    return new() { Meta = meta, Value = new() { Snapshot = host } };
                }

                if (request.ScopeKind is not ("sandbox" or "run") || !ValidId(request.ScopeId))
                {
                    return new()
                    {
                        Meta = meta,
                        Error = Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "resource_scope_invalid")
                    };
                }

                string id = ToHex(request.ScopeId);
                var snapshot = ResourceScopeSnapshot(request.ScopeKind, request.ScopeId, frame);
                bool visible = request.ScopeKind == "run" ? ApplyRunResources(id, snapshot, frame) : ApplySandboxResources(id, snapshot, frame);
                return visible ? new() { Meta = meta, Value = new() { Snapshot = snapshot } }
                    : new() { Meta = meta, Error = NotFound(request.Meta) };
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return new() { Meta = meta, Error = StorageFailure(request.Meta) };
            }
        }
    }

    private ResourceSnapshot ResourceScopeSnapshot(string scope, Id? id, SandboxResourceFrame? frame)
    {
        var snapshot = new ResourceSnapshot
        {
            ScopeKind = scope,
            ScopeId = id?.Clone(),
            SampledAt = frame?.Host.SampledAt?.Clone() ?? ProtoTime.ToInstant(_clock.GetUtcNow()),
            SampleSequence = frame?.Host.SampleSequence ?? 0,
            SampleEpoch = _resourceMonitor?.Epoch ?? _nodeEpoch,
            Stale = frame?.Stale ?? true,
            Pressure = "unknown",
        };
        if (frame?.RunIntervalMs is uint interval)
        {
            snapshot.SampleIntervalMs = interval;
        }

        return snapshot;
    }

    private bool ApplyRunResources(string id, ResourceSnapshot snapshot, SandboxResourceFrame? frame)
    {
        var row = _store.Read(reader => RunRecords.Get(reader, OwnerId, id));
        if (row is null)
        {
            return false;
        }

        snapshot.PolicyRevision = new Revision { Value = ResourcePolicyRevision("run", id) };
        snapshot.Limits.AddRange(ReadProjectedRunLimits(row));
        if (frame is null || !frame.Runs.TryGetValue(id, out var measurement) || measurement.Target.Epoch != row.Epoch
            || !ReferenceEquals(CurrentResourceSource(id, row.Epoch), measurement.Target.Source)
            || measurement.Reading is not { } read)
        {
            snapshot.Stale = true;
            return true;
        }

        snapshot.MemoryKind = MemoryKind(read.Accounting);
        if (read.MemoryBytes is ulong memory) snapshot.ManagedMemoryBytes = memory;
        if (read.PeakMemoryBytes is ulong peak) snapshot.PeakMemoryBytes = peak;
        if (measurement.CpuMillicores is >= 0 and <= uint.MaxValue) snapshot.ManagedCpuMillicores = (uint)measurement.CpuMillicores.Value;
        if (read.CumulativeCpuUsec is ulong cumulativeCpu) snapshot.CumulativeCpuUsec = cumulativeCpu;
        if (read.ProcessCount is uint count) snapshot.ProcessCount = count;
        SandboxResourceMonitor.SetPressureFacts(snapshot, read.PsiCpuSome, read.PsiMemorySome, read.PsiMemoryFull);
        snapshot.Stale |= row.State is StoredRunState.Failed or StoredRunState.Exited or StoredRunState.RecoveryRequired;
        return true;
    }

    private bool ApplySandboxResources(string id, ResourceSnapshot snapshot, SandboxResourceFrame? frame)
    {
        RunResourceMeasurement[] runs = frame is null ? [] : [.. frame.Runs.Values.Where(run => run.Target.SandboxId == id)];
        var (row, coherent) = _store.Read(reader =>
        {
            var sandbox = SandboxRecords.Get(reader, OwnerId, id);
            bool sameSample = sandbox is not null && frame?.CatalogueRevision is long catalogue
                && catalogue == SandboxRecords.CatalogRevision(reader, OwnerId)
                && MatchesSampledRuns(reader, id, runs);
            return (sandbox, sameSample);
        });
        if (row is null)
        {
            return false;
        }

        snapshot.PolicyRevision = new Revision { Value = ResourcePolicyRevision("sandbox", id) };
        ApplySandboxGrantCeiling(snapshot, row, DecodeResourcePolicy(ReadResourcePolicy("sandbox", id)));
        if (!coherent)
        {
            snapshot.Stale = true;
            return true;
        }
        if (SandboxResourceMonitor.Sum(runs, run => run.CpuMillicores) is >= 0 and <= uint.MaxValue and var cpu)
            snapshot.ManagedCpuMillicores = (uint)cpu;
        if (SandboxResourceMonitor.Sum(runs, run => run.Reading?.ProcessCount) is >= 0 and <= uint.MaxValue and var count)
            snapshot.ProcessCount = (uint)count;

        var kinds = runs.Select(run => run.Reading?.Accounting).Distinct().ToArray();
        if (kinds is [{ } kind])
        {
            snapshot.MemoryKind = MemoryKind(kind);
            if (SandboxResourceMonitor.Sum(runs, run => SandboxResourceMonitor.AsLong(run.Reading?.MemoryBytes)) is >= 0 and var memory)
                snapshot.ManagedMemoryBytes = (ulong)memory;
        }

        snapshot.Stale |= runs.Any(run => run.Reading is null);
        return true;
    }

    private bool MatchesSampledRuns(StoreReader reader, string sandboxId, RunResourceMeasurement[] runs)
    {
        var current = SandboxRecords.ListNonterminalRunIds(reader, sandboxId).ToHashSet(StringComparer.Ordinal);
        return current.Count == runs.Length && runs.All(run => current.Contains(run.Target.RunId)
            && ReferenceEquals(CurrentResourceSource(run.Target.RunId, run.Target.Epoch), run.Target.Source));
    }

    private IRunResourceSource? CurrentResourceSource(string id, string epoch) =>
        _liveRuns.TryGetValue(id, out var run) && run.Spec.Epoch == epoch ? run.OwnerLease as IRunResourceSource : null;

    private static string MemoryKind(RunMemoryAccounting kind) => kind switch
    {
        RunMemoryAccounting.WindowsCommit => "windows_commit",
        RunMemoryAccounting.LinuxCgroupCurrent => "linux_cgroup_current",
        _ => throw new InvalidDataException("Unknown native Run memory accounting."),
    };
}
