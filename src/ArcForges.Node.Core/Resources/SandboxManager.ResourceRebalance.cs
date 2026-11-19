// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private ulong? _cpuBudgetForRebalance;
    private long? _lastCpuRebalanceFrame;
    private long? _cpuRebalanceCohortObservedAt;
    private long? _lastCpuRebalanceAppliedAt;

    // The caller holds OwnershipGate. Admission, user edits, and the rebalance cannot interleave.
    private void RebalanceRunCpuLocked(SandboxResourceFrame frame, bool force)
    {
        if (!frame.HasFreshBudget || !frame.Host.HasHostCpuMillicores || _lastCpuRebalanceFrame >= frame.Timestamp
            || !ReferenceEquals(_resourceMonitor?.Latest, frame))
        {
            return;
        }

        var nodePolicy = DecodeResourcePolicy(ReadResourcePolicy("node", null));
        if (CurrentNodeGrantBudget(nodePolicy, frame) is not { } measured)
        {
            return;
        }

        var active = ReadActiveHardGrants();
        if (frame.CatalogueRevision != _store.Read(reader => SandboxRecords.CatalogRevision(reader, OwnerId))
            || active.Count != frame.Runs.Count || active.Any(entry => !frame.Runs.TryGetValue(entry.Run.RunId, out var sample)
                || sample.Target.Epoch != entry.Run.Epoch))
        {
            return;
        }

        _lastCpuRebalanceFrame = frame.Timestamp;
        if (active.Count == 0)
        {
            _cpuBudgetForRebalance = measured.Cpu;
            _cpuRebalanceCohortObservedAt = null;
            return;
        }

        // A coherent batch may redistribute shares after confirming its reductions. Only completed
        // native changes and the first observation of a new cohort anchor the next batch's delay.
        _cpuRebalanceCohortObservedAt ??= frame.Timestamp;
        long anchor = Math.Max(_cpuRebalanceCohortObservedAt.Value, _lastCpuRebalanceAppliedAt ?? 0);
        var sinceApply = Stopwatch.GetElapsedTime(anchor, frame.Timestamp);
        ulong planned = _cpuBudgetForRebalance is { } prior
            ? WeightedCpuAllocation.SelectBudget(prior, measured.Cpu, NodeHardGrant(nodePolicy).Cpu,
                frame.Host.HostCpuMillicores, sinceApply, force)
            : measured.Cpu;
        _cpuBudgetForRebalance = planned;

        var candidates = new Dictionary<string, CpuRebalanceCandidate>(StringComparer.Ordinal);
        var shares = new List<SandboxCpuShares>();
        var sandboxCeilings = new Dictionary<string, HardGrant>(StringComparer.Ordinal);
        var fixedGrants = new HardGrant();
        bool readyToIncrease = true;
        var planningBudget = measured with { Cpu = planned };
        var increaseBudget = measured.Limit(planningBudget);
        foreach (var group in active.GroupBy(entry => entry.Run.SandboxId, StringComparer.Ordinal))
        {
            var sandbox = _store.Read(reader => SandboxRecords.Get(reader, OwnerId, group.Key));
            if (sandbox is not { State: StoredSandboxState.Ready })
            {
                fixedGrants = fixedGrants.Add(SumGrants(group, null));
                readyToIncrease = false;
                continue;
            }

            var policy = DecodeResourcePolicy(ReadResourcePolicy("sandbox", sandbox.SandboxId));
            var ceiling = SandboxHardGrant(sandbox, policy, planningBudget);
            sandboxCeilings.Add(group.Key, ceiling.Limit(increaseBudget));
            var fixedSandbox = new HardGrant();
            var runShares = new List<CpuShare>();
            foreach (var entry in group)
            {
                var candidate = ReadCpuRebalanceCandidate(entry, frame.Runs[entry.Run.RunId]);
                if (candidate is null)
                {
                    fixedSandbox = fixedSandbox.Add(entry.Grant);
                    // A pending Start has an immutable, charged grant. A Running scope without matching
                    // evidence cannot be used as proof that it is safe to increase anything else.
                    readyToIncrease &= entry.Authoritative && entry.Run.State != StoredRunState.Running;
                    continue;
                }

                candidates.Add(candidate.Run.RunId, candidate);
                runShares.Add(new(candidate.Run.RunId, candidate.Weight, candidate.Ceiling));
            }

            fixedGrants = fixedGrants.Add(fixedSandbox);
            var configured = FromStored(sandbox.Config).Resources;
            uint weight = configured is { HasWeight: true, Weight: > 0 } ? configured.Weight : 1;
            shares.Add(new(group.Key, weight, ceiling.AvailableAfter(fixedSandbox).Cpu, runShares));
        }

        var grants = WeightedCpuAllocation.Allocate(planningBudget.AvailableAfter(fixedGrants).Cpu, shares);
        var increases = new List<CpuRebalanceEdit>();
        foreach (var (id, requested) in grants.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            if (!frame.HasFreshBudget || !ReferenceEquals(_resourceMonitor?.Latest, frame))
            {
                return;
            }

            var candidate = candidates[id];
            if (NormalizeCpuShare(candidate.Control, requested) is not { } target)
            {
                // The kernel's smallest finite cap may exceed the budget. Keep this cap and block all rises.
                readyToIncrease = false;
                continue;
            }

            if (target < candidate.Current)
            {
                readyToIncrease &= TryApplyCpuRebalance(new(candidate, requested, target));
            }
            else if (target > candidate.Current)
            {
                increases.Add(new(candidate, requested, target));
            }
        }

        if (readyToIncrease && increases.Count > 0 && WeightedCpuAllocation.CanIncreaseAfter(sinceApply))
        {
            ApplyCpuRebalanceIncreases(frame, increaseBudget, sandboxCeilings, increases);
        }
    }

    private CpuRebalanceCandidate? ReadCpuRebalanceCandidate(ActiveHardGrant entry, RunResourceMeasurement sample)
    {
        var run = entry.Run;
        if (!entry.Authoritative || run.State != StoredRunState.Running
            || entry.Actual is not { CpuMillicores: ulong current } reading || current == 0
            || !_liveRuns.TryGetValue(run.RunId, out var live) || live.Spec.Epoch != run.Epoch
            || live.OwnerLease is not IRunResourceControl control || !ReferenceEquals(live.OwnerLease, sample.Target.Source)
            || live.OwnerLease.Identity.ControlEpoch != run.Epoch)
        {
            return null;
        }

        var limit = _store.Read(reader => ResourceStateRecords.ReadLimits(reader, OwnerId, run.RunId))
            .FirstOrDefault(value => value.Dimension == "cpu");
        if (limit is not { Status: StoredRunLimitStatus.Effective, BoundaryIdentity: not null }
            || limit.BoundaryIdentity != reading.BoundaryIdentity || limit.AppliedValue != limit.ReadbackValue
            || limit.ReadbackValue != LimitText(current))
        {
            return null;
        }

        var snapshot = ReadRunSnapshot(run);
        ulong ceiling = LimitNumber(limit.DesiredValue);
        if (limit.DesiredRevision == 1)
        {
            ceiling = Math.Min(ceiling, snapshot.CpuCeilingMillicores);
        }

        return new(run, limit, control, current, ceiling, snapshot.LogicalWeight,
            snapshot.CpuWasExplicit || limit.DesiredRevision > 1);
    }

    // Compute the prospective grant before recording Start, with no native mutations. During admission
    // an incumbent's previously explicit cap remains reserved. Only default grants may be reduced.
    private ProspectiveCpuPlan? PlanProspectiveCpuLocked(SandboxResourceFrame frame, IReadOnlyList<ActiveHardGrant> active,
        StoredSandbox sandbox, string runId, uint requestedCeiling, uint logicalWeight, bool explicitCpu,
        HardGrant node, HardGrant ceiling)
    {
        var incumbentEpochs = active.ToDictionary(entry => entry.Run.RunId, entry => entry.Run.Epoch, StringComparer.Ordinal);
        ulong nodeFree = node.AvailableAfter(SumGrants(active, null)).Cpu;
        ulong sandboxFree = ceiling.AvailableAfter(SumGrants(active, sandbox.SandboxId)).Cpu;
        ulong direct = explicitCpu ? requestedCeiling
            : Math.Min(requestedCeiling, ceiling.Cpu / Math.Max(1UL, ceiling.Runs));
        var ceilings = new Dictionary<string, ulong>(StringComparer.Ordinal) { [sandbox.SandboxId] = ceiling.Cpu };
        if (explicitCpu && direct <= nodeFree && direct <= sandboxFree)
        {
            return MakePlan(direct, []);
        }

        if (requestedCeiling == 0 || requestedCeiling > Math.Min(node.Cpu, ceiling.Cpu) && explicitCpu)
        {
            return null;
        }

        var candidates = new Dictionary<string, CpuRebalanceCandidate>(StringComparer.Ordinal);
        var shares = new List<SandboxCpuShares>();
        ulong totalFixed = explicitCpu ? requestedCeiling : 0;
        var groups = active.ToLookup(entry => entry.Run.SandboxId, StringComparer.Ordinal);
        foreach (var sandboxId in groups.Select(group => group.Key).Append(sandbox.SandboxId).Distinct(StringComparer.Ordinal))
        {
            bool incoming = sandboxId == sandbox.SandboxId;
            var scope = incoming ? sandbox : _store.Read(reader => SandboxRecords.Get(reader, OwnerId, sandboxId));
            if (scope is not { State: StoredSandboxState.Ready })
            {
                return null;
            }

            ulong scopeCeiling = incoming ? ceiling.Cpu
                : SandboxHardGrant(scope, DecodeResourcePolicy(ReadResourcePolicy("sandbox", sandboxId)), node).Cpu;
            ceilings[sandboxId] = scopeCeiling;
            ulong fixedCpu = incoming && explicitCpu ? requestedCeiling : 0;
            var runShares = new List<CpuShare>();
            foreach (var entry in groups[sandboxId])
            {
                var candidate = frame.Runs.TryGetValue(entry.Run.RunId, out var sample) && sample.Target.Epoch == entry.Run.Epoch
                    ? ReadCpuRebalanceCandidate(entry, sample) : null;
                if (candidate is { FixedForAdmission: false })
                {
                    candidates.Add(entry.Run.RunId, candidate);
                    runShares.Add(new(entry.Run.RunId, candidate.Weight, Math.Min(candidate.Ceiling, candidate.Current)));
                }
                else
                {
                    if (entry.Grant.Cpu > node.Cpu - totalFixed || entry.Grant.Cpu > scopeCeiling - fixedCpu)
                    {
                        return null;
                    }

                    totalFixed += entry.Grant.Cpu;
                    fixedCpu += entry.Grant.Cpu;
                }
            }

            if (incoming && !explicitCpu)
            {
                runShares.Add(new(runId, logicalWeight, direct));
            }

            var configured = FromStored(scope.Config).Resources;
            uint weight = configured is { HasWeight: true, Weight: > 0 } ? configured.Weight : 1;
            shares.Add(new(sandboxId, weight, scopeCeiling - fixedCpu, runShares));
        }

        var grants = WeightedCpuAllocation.Allocate(node.Cpu - totalFixed, shares);
        ulong initial = explicitCpu ? requestedCeiling : grants[runId];
        var reductions = new List<CpuRebalanceEdit>();
        foreach (var (id, candidate) in candidates.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            ulong requested = grants[id];
            if (requested >= candidate.Current)
            {
                continue;
            }

            if (NormalizeCpuShare(candidate.Control, requested) is not { } target)
            {
                return null;
            }

            reductions.Add(new(candidate, requested, target));
        }

        return MakePlan(initial, reductions);

        ProspectiveCpuPlan? MakePlan(ulong initialCpu, IReadOnlyList<CpuRebalanceEdit> edits) =>
            IsLaunchCpuRepresentable(initialCpu, frame.Host.HostCpuMillicores)
                ? new(frame, runId, sandbox.SandboxId, (uint)initialCpu, requestedCeiling, node.Cpu, ceilings, incumbentEpochs, edits)
                : null;
    }

    private static bool IsLaunchCpuRepresentable(ulong millicores, uint hostCapacity)
    {
        if (millicores == 0 || millicores > hostCapacity)
        {
            return false;
        }

        if (OperatingSystem.IsWindows())
        {
            // Host capacity and the Job actuator both count all active Windows processors.
            // One Job rate unit represents 1/10,000 of that capacity.
            return millicores * 10_000 >= hostCapacity;
        }

        // The official Linux path uses a fixed 100ms cgroup period and a 1ms minimum quota.
        return OperatingSystem.IsLinux() && millicores >= 10;
    }

    // Called under OwnershipGate after the exact Start reservation commits, before dispatch or lease creation.
    private bool TryApplyProspectiveCpuLocked(ProspectiveCpuPlan plan, StoredRun started)
    {
        if (!plan.Frame.HasFreshBudget || !ReferenceEquals(_resourceMonitor?.Latest, plan.Frame)
            || started.RunId != plan.RunId || started.SandboxId != plan.SandboxId)
        {
            return false;
        }

        var active = ReadActiveHardGrants();
        if (!MatchesReservation(active))
        {
            return false;
        }

        foreach (var edit in plan.Reductions)
        {
            if (!plan.Frame.HasFreshBudget || !ReferenceEquals(_resourceMonitor?.Latest, plan.Frame)
                || !TryApplyCpuRebalance(edit))
            {
                return false;
            }
        }

        if (plan.Reductions.Count != 0)
        {
            active = ReadActiveHardGrants();
        }

        return plan.Frame.HasFreshBudget && ReferenceEquals(_resourceMonitor?.Latest, plan.Frame)
            && MatchesReservation(active) && SumGrants(active, null).Cpu <= plan.NodeCpuCeiling
            && active.GroupBy(entry => entry.Run.SandboxId, StringComparer.Ordinal).All(group =>
                !plan.SandboxCpuCeilings.TryGetValue(group.Key, out var limit) || SumGrants(group, null).Cpu <= limit);

        bool MatchesReservation(IReadOnlyList<ActiveHardGrant> grants) => grants.Count == plan.IncumbentEpochs.Count + 1
            && grants.All(entry => entry.Run.RunId == plan.RunId
                ? entry.Run.Epoch == started.Epoch && entry.Run.SandboxId == plan.SandboxId
                    && entry.Run.State == StoredRunState.Starting && entry.Grant.Cpu == plan.InitialCpuMillicores
                : entry.Authoritative && plan.IncumbentEpochs.TryGetValue(entry.Run.RunId, out var epoch) && epoch == entry.Run.Epoch);
    }

    private static ulong? NormalizeCpuShare(IRunResourceControl control, ulong requested)
    {
        try
        {
            var target = control.NormalizeRunLimit(RunResourceDimension.Cpu, requested);
            return target is > 0 && target <= requested ? target : null;
        }
        catch (Exception error) when (IsNativeResourceFailure(error) || error is ObjectDisposedException)
        {
            return null;
        }
    }

    private void ApplyCpuRebalanceIncreases(SandboxResourceFrame frame, HardGrant nodeCeiling,
        Dictionary<string, HardGrant> sandboxCeilings, List<CpuRebalanceEdit> increases)
    {
        var active = ReadActiveHardGrants();
        if (active.Any(entry => !entry.Authoritative))
        {
            return;
        }

        var byId = active.ToDictionary(entry => entry.Run.RunId, StringComparer.Ordinal);
        var sandboxUsed = active.GroupBy(entry => entry.Run.SandboxId, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => SumGrants(group, null), StringComparer.Ordinal);
        var nodeUsed = SumGrants(active, null);
        foreach (var edit in increases)
        {
            var candidate = edit.Candidate;
            var sandbox = candidate.Run.SandboxId;
            var delta = new HardGrant(edit.Target - candidate.Current, 0, 0);
            if (!frame.HasFreshBudget || !ReferenceEquals(_resourceMonitor?.Latest, frame)
                || !byId.TryGetValue(candidate.Run.RunId, out var actual) || actual.Run.Epoch != candidate.Run.Epoch
                || actual.Actual is not { } reading || reading.BoundaryIdentity != candidate.Limit.BoundaryIdentity
                || reading.CpuMillicores != candidate.Current
                || actual.Grant.Cpu != candidate.Current
                || nodeUsed.Add(delta).Exceeded(nodeCeiling) is not null || sandboxUsed[sandbox].Add(delta).Exceeded(sandboxCeilings[sandbox]) is not null
                || !TryApplyCpuRebalance(edit))
            {
                return;
            }

            sandboxUsed[sandbox] = sandboxUsed[sandbox].Add(delta);
            nodeUsed = nodeUsed.Add(delta);
        }
    }

    private bool TryApplyCpuRebalance(CpuRebalanceEdit edit)
    {
        var candidate = edit.Candidate;
        string id = candidate.Run.RunId;
        string epoch = candidate.Run.Epoch;
        string boundary = candidate.Limit.BoundaryIdentity!;
        if (!_store.Write(transaction => ResourceStateRecords.TryBeginCpuRebalance(transaction, OwnerId, id, epoch,
            boundary, candidate.Limit, edit.Target), CommitDurability.Full))
        {
            return false;
        }

        var result = ApplyRunLimitEdit(candidate.Control, boundary,
            new(RunResourceDimension.Cpu, "cpu", edit.Requested, edit.Target, candidate.Current, candidate.Limit));
        bool confirmed = result.Facts.Status == StoredRunLimitStatus.Effective;
        if (confirmed)
        {
            _lastCpuRebalanceAppliedAt = Stopwatch.GetTimestamp();
        }

        var facts = confirmed ? result.Facts with { Reason = "weighted_cpu_readback_confirmed" } : result.Facts;
        _store.Write(transaction => RequireChanged(ResourceStateRecords.TryObserveLimit(transaction, OwnerId, id, epoch,
            boundary, "cpu", candidate.Limit.DesiredRevision, facts)), CommitDurability.Full);
        ReportRun(id, "resource_cpu_rebalance", facts.Reason);
        return confirmed;
    }

    private sealed record CpuRebalanceCandidate(StoredRun Run, StoredRunLimit Limit, IRunResourceControl Control,
        ulong Current, ulong Ceiling, uint Weight, bool FixedForAdmission);

    private sealed record CpuRebalanceEdit(CpuRebalanceCandidate Candidate, ulong Requested, ulong Target);

    private sealed record ProspectiveCpuPlan(SandboxResourceFrame Frame, string RunId, string SandboxId, uint InitialCpuMillicores,
        uint ImmutableCpuCeilingMillicores, ulong NodeCpuCeiling, IReadOnlyDictionary<string, ulong> SandboxCpuCeilings,
        IReadOnlyDictionary<string, string> IncumbentEpochs, IReadOnlyList<CpuRebalanceEdit> Reductions);
}
