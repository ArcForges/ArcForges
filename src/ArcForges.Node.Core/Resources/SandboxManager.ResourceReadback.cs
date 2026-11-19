// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private static (string Dimension, StoredRunLimitObservation Observation)[] PrepareRunGrantReadback(
        RunLaunchSpec spec, IRunOwnerLease lease, DateTimeOffset preparedAt)
    {
        var control = lease as IRunResourceControl;
        var reading = ReadOwnedLimits(lease);
        var facts = new List<(string, StoredRunLimitObservation)>();
        foreach (var (dimension, _, desired) in InitialRunGrant(spec))
        {
            var native = NativeLimitDimension(dimension);
            ulong? expected = native is RunResourceDimension.ProcessCount or RunResourceDimension.Swap
                ? desired : control?.NormalizeRunLimit(native, desired);
            ulong? actual = reading?.Value(native);
            StoredRunLimitObservation evidence = actual.HasValue && actual == expected
                ? new(StoredRunLimitStatus.Effective, "native_readback_confirmed", LimitText(expected!.Value),
                    LimitText(actual.Value), preparedAt, preparedAt)
                : new(control is null ? StoredRunLimitStatus.Unsupported : StoredRunLimitStatus.Degraded,
                    actual.HasValue ? "native_readback_mismatch" : "native_readback_unavailable",
                    ReadbackValue: actual is { } value ? LimitText(value) : null,
                    ReadbackAt: actual.HasValue ? preparedAt : null);
            facts.Add((dimension, evidence));
        }

        return facts.ToArray();
    }

    private static RunResourceLimitReading? ReadOwnedLimits(IRunOwnerLease? lease)
    {
        try
        {
            return lease is IRunResourceControl control
                && control.ReadRunLimits() is { } reading
                && reading.BoundaryIdentity == lease.Identity.BoundaryIdentity
                ? reading : null;
        }
        catch (Exception error) when (IsRunOwnerFailure(error) || error is ObjectDisposedException)
        {
            return null;
        }
    }

    private LimitState[] ReadProjectedRunLimits(StoredRun run)
    {
        var limits = _store.Read(reader => ResourceStateRecords.ReadLimits(reader, OwnerId, run.RunId));
        if (limits.Count == 0)
        {
            return [];
        }

        var owned = _liveRuns.TryGetValue(run.RunId, out var candidate) && candidate.Epoch == run.Epoch ? candidate : null;
        RunResourceLimitReading? live = run.State is StoredRunState.Starting or StoredRunState.Running or StoredRunState.Stopping
            ? ReadOwnedLimits(owned?.OwnerLease) : null;
        var now = _clock.GetUtcNow();
        var projected = new List<LimitState>(limits.Count);
        foreach (var limit in limits)
        {
            var value = ProjectStoredRunLimit(limit);
            if (live is not null && limit.BoundaryIdentity == live.BoundaryIdentity
                && live.Value(NativeLimitDimension(limit.Dimension)) is { } actual)
            {
                value.ReadbackValue = LimitText(actual);
                value.ReadbackAt = ProtoTime.ToInstant(now);
                if (value.Status == LimitStatus.Effective && value.AppliedValue != value.ReadbackValue)
                {
                    value.Status = LimitStatus.Degraded;
                    value.Reason = "native_readback_mismatch";
                }
            }
            else if (value.Status == LimitStatus.Effective)
            {
                value.Status = LimitStatus.Degraded;
                value.Reason = owned?.RecoveryLimitRefusal ?? "native_scope_unavailable";
            }

            projected.Add(value);
        }

        return projected.ToArray();
    }

    private void ApplyResourceBudgetPolicy(ResourceSnapshot snapshot, ResourcePolicy? policy)
    {
        if (policy is null)
        {
            return;
        }

        if (policy.HasHostReserveMillicores && snapshot.HasHostCpuMillicores)
        {
            snapshot.ReservedCpuMillicores = Math.Min(snapshot.HostCpuMillicores, policy.HostReserveMillicores);
            var retained = _store.Policies.Current().Document.Resources;
            uint minimum = retained?.HasMinManagedCpuMillicores == true ? retained.MinManagedCpuMillicores : 1000;
            long? budget = ResourceBudgetMath.CpuBudget(snapshot.HostCpuMillicores, snapshot.ReservedCpuMillicores,
                snapshot.HasUnmanagedCpuMillicores ? snapshot.UnmanagedCpuMillicores : null, minimum);
            if (budget is { } value)
            {
                snapshot.BudgetCpuMillicores = (uint)value;
            }
            else
            {
                snapshot.ClearBudgetCpuMillicores();
            }
        }

        if (policy.HasHostReserveBytes && snapshot.HasHostMemoryBytes)
        {
            snapshot.ReservedMemoryBytes = Math.Min(snapshot.HostMemoryBytes, policy.HostReserveBytes);
            long? budget = ResourceBudgetMath.MemoryBudget(SandboxResourceMonitor.AsLong(snapshot.HostMemoryBytes),
                SandboxResourceMonitor.AsLong(snapshot.ReservedMemoryBytes),
                snapshot.HasUnmanagedMemoryBytes ? SandboxResourceMonitor.AsLong(snapshot.UnmanagedMemoryBytes) : null);
            if (budget is { } value)
            {
                snapshot.BudgetMemoryBytes = (ulong)value;
            }
            else
            {
                snapshot.ClearBudgetMemoryBytes();
            }
        }

        if (policy.HasCpuMaxMillicores && snapshot.HasBudgetCpuMillicores)
        {
            snapshot.BudgetCpuMillicores = Math.Min(snapshot.BudgetCpuMillicores, policy.CpuMaxMillicores);
        }

        if (policy.HasMemoryMaxBytes && snapshot.HasBudgetMemoryBytes)
        {
            snapshot.BudgetMemoryBytes = Math.Min(snapshot.BudgetMemoryBytes, policy.MemoryMaxBytes);
        }
    }

    private void ApplySandboxGrantCeiling(ResourceSnapshot snapshot, StoredSandbox sandbox, ResourcePolicy? overlay,
        SandboxResourceFrame? frame)
    {
        var node = CurrentResourceAdmissionBudget(DecodeResourcePolicy(ReadResourcePolicy("node", null)), frame);
        if (node is { } bounded)
        {
            var ceiling = SandboxHardGrant(sandbox, overlay, bounded.Hard);
            snapshot.BudgetCpuMillicores = (uint)ceiling.Cpu;
            snapshot.BudgetMemoryBytes = Math.Min(bounded.Resident, ceiling.Memory);
        }
        else
        {
            snapshot.ClearBudgetCpuMillicores();
            snapshot.ClearBudgetMemoryBytes();
            snapshot.Stale = true;
        }
    }
}
