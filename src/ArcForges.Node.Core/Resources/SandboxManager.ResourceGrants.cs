// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.RunSupervisor.Protocol;
using PressureLevel = ArcForges.Contracts.Node.V1.PressureLevel;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    // Allocation charges the native hard bounds independently of the resident-memory
    // estimation and priority policy. Starting and unresolved Runs retain their grants.
    private readonly record struct HardGrant(ulong Cpu, ulong Memory, ulong Runs)
    {
        internal HardGrant Add(HardGrant other) =>
            new(Sum(Cpu, other.Cpu), Sum(Memory, other.Memory), Sum(Runs, other.Runs));

        internal HardGrant Limit(HardGrant other) =>
            new(Math.Min(Cpu, other.Cpu), Math.Min(Memory, other.Memory), Math.Min(Runs, other.Runs));

        internal HardGrant AvailableAfter(HardGrant used) =>
            new(Cpu - Math.Min(Cpu, used.Cpu), Memory - Math.Min(Memory, used.Memory), Runs - Math.Min(Runs, used.Runs));

        internal bool TighterThan(HardGrant other) => Cpu < other.Cpu || Memory < other.Memory || Runs < other.Runs;

        internal string? Exceeded(HardGrant ceiling) =>
            Cpu > ceiling.Cpu ? "cpu" : Memory > ceiling.Memory ? "memory" : Runs > ceiling.Runs ? "concurrency" : null;

        internal ulong Amount(string dimension) => dimension switch
        {
            "cpu" => Cpu,
            "memory" => Memory,
            "concurrency" => Runs,
            _ => throw new ArgumentOutOfRangeException(nameof(dimension)),
        };

        private static ulong Sum(ulong left, ulong right) =>
            left > ulong.MaxValue - right ? ulong.MaxValue : left + right;
    }

    private sealed record ActiveHardGrant(StoredRun Run, HardGrant Grant,
        RunResourceLimitReading? Actual, bool Authoritative);

    // V2 Sandbox policies created before resident admission may omit the inherited estimate.
    // Keep this policy default stable across sample, backend and Run hard-cap changes.
    private const ulong DefaultExpectedResidentBytes = 64UL * 1024 * 1024;

    private sealed record RunResourceCommitment(RunStartResourcePolicy Policy, ulong ExpectedResidentBytes,
        uint CpuCeilingMillicores, bool CpuWasExplicit, long NodePolicyRevision, long SandboxPolicyRevision,
        string SampleEpoch, ulong SampleSequence);

    private sealed record RunBudgetRefusal(string Scope, string Dimension, ulong Requested, ulong Available,
        long PolicyRevision, string SampleEpoch, ulong SampleSequence, DateTimeOffset? SampledAt);

    private (RunLaunchSpec? Spec, RunResourceCommitment? Commitment, ProspectiveCpuPlan? CpuPlan, ArcError? Error,
        bool AwaitingResidentFrame, RunBudgetRefusal? Refusal) AuthorizeRunResourceGrant(
        RunServiceStartRequest request, StoredSandbox sandbox, RunLaunchSpec spec, RunStartResourcePolicy resourcePolicy,
        SandboxResourceFrame? frame)
    {
        var nodePolicy = ReadResourcePolicy("node", null);
        var nodeLimits = DecodeResourcePolicy(nodePolicy);
        if (frame is not { HasFreshBudget: true } || !frame.Host.HasSampleEpoch || !frame.Host.HasSampleSequence
            || CurrentResourceAdmissionBudget(nodeLimits, frame) is not { } budget)
        {
            return Reject("resource_sample_unavailable");
        }

        if (frame.PressureFacts is not { } pressure
            || pressure.Level is not (PressureLevel.Normal or PressureLevel.Tight or PressureLevel.Pressure or PressureLevel.Critical))
        {
            return Reject("resource_pressure_unavailable");
        }

        if (pressure.Level == PressureLevel.Critical)
        {
            return Reject("resource_pressure_critical");
        }

        if ((pressure.Level is PressureLevel.Tight or PressureLevel.Pressure) && resourcePolicy.Priority < 10)
        {
            return Reject("resource_pressure_interactive_required");
        }

        HardGrant nodeCeiling = budget.Hard;
        var sandboxPolicy = ReadResourcePolicy("sandbox", sandbox.SandboxId);
        HardGrant sandboxCeiling = SandboxHardGrant(sandbox, DecodeResourcePolicy(sandboxPolicy), nodeCeiling);
        var active = ReadActiveHardGrants();
        if (active.Any(entry => !entry.Authoritative))
        {
            return Reject("existing_run_limit_unconfirmed");
        }

        HardGrant nodeFree = nodeCeiling.AvailableAfter(SumGrants(active, null));
        HardGrant sandboxFree = sandboxCeiling.AvailableAfter(SumGrants(active, sandbox.SandboxId));
        HardGrant commonFree = nodeFree.Limit(sandboxFree);
        var requested = request.RequestedResources;

        bool cpuWasExplicit = requested?.HasCpuMaxMillicores == true;
        ulong requestedMemory = requested?.HasMemoryMaxBytes == true ? spec.MemoryMaxBytes
            : Math.Min(spec.MemoryMaxBytes, Math.Min(commonFree.Memory, sandboxCeiling.Memory / Math.Max(1UL, sandboxCeiling.Runs)));
        if (requested?.HasMemoryMaxBytes != true && OperatingSystem.IsLinux())
        {
            ulong page = (ulong)Environment.SystemPageSize;
            requestedMemory -= requestedMemory % page;
        }

        var cpuPlan = PlanProspectiveCpuLocked(frame, active, sandbox, spec.RunId, spec.CpuMillicores,
            resourcePolicy.LogicalWeight, cpuWasExplicit, nodeCeiling, sandboxCeiling);
        var grant = new HardGrant(cpuPlan is null && cpuWasExplicit ? spec.CpuMillicores : 0U, requestedMemory, 1);
        string? nodeFailure = grant.Exceeded(nodeFree);
        string? sandboxFailure = grant.Exceeded(sandboxFree);
        if (nodeFailure is not null)
        {
            return Reject($"node_{nodeFailure}_grant_unavailable",
                refusal: Fact("node", nodeFailure, grant.Amount(nodeFailure), nodeFree.Amount(nodeFailure)));
        }

        if (sandboxFailure is not null)
        {
            return Reject($"sandbox_{sandboxFailure}_grant_unavailable",
                refusal: Fact("sandbox", sandboxFailure, grant.Amount(sandboxFailure), sandboxFree.Amount(sandboxFailure)));
        }

        if (cpuPlan is null || requestedMemory == 0)
        {
            return Reject(cpuPlan is null ? "cpu_grant_unavailable" : "memory_grant_unavailable");
        }

        ulong expectedResident = resourcePolicy.ExpectedResidentBytes ?? DefaultExpectedResidentBytes;
        if (expectedResident == 0 || expectedResident > requestedMemory)
        {
            return Reject("run_resident_estimate_outside_grant",
                refusal: Fact("run", "resident_memory", expectedResident, requestedMemory));
        }

        if (!TryReadResidentReservations(active.Select(entry => entry.Run), frame, sandbox.SandboxId,
                requireFreshReading: true, out var resident))
        {
            bool pending = active.Any(entry => HasNewResidentSource(entry.Run, frame));
            return Reject("existing_run_resident_reservation_unconfirmed", pending);
        }

        ulong nodeResidentFree = budget.Resident - Math.Min(budget.Resident, resident.Node);
        if (expectedResident > nodeResidentFree)
        {
            return Reject("node_resident_memory_unavailable",
                refusal: Fact("node", "resident_memory", expectedResident, nodeResidentFree));
        }

        ulong sandboxResident = Math.Min(budget.Resident, sandboxCeiling.Memory);
        ulong sandboxResidentFree = sandboxResident - Math.Min(sandboxResident, resident.Sandbox);
        if (expectedResident > sandboxResidentFree)
        {
            return Reject("sandbox_resident_memory_unavailable",
                refusal: Fact("sandbox", "resident_memory", expectedResident, sandboxResidentFree));
        }

        var commitment = new RunResourceCommitment(resourcePolicy, expectedResident, cpuPlan.ImmutableCpuCeilingMillicores,
            cpuWasExplicit, nodePolicy?.Revision ?? 1, sandboxPolicy?.Revision ?? 1, frame.Host.SampleEpoch, frame.Host.SampleSequence);
        return (spec with { CpuMillicores = cpuPlan.InitialCpuMillicores, MemoryMaxBytes = requestedMemory },
            commitment, cpuPlan, null, false, null);

        RunBudgetRefusal Fact(string scope, string dimension, ulong amount, ulong available) =>
            new(scope, dimension, amount, available, (scope == "node" ? nodePolicy : sandboxPolicy)?.Revision ?? 1,
                frame.Host.SampleEpoch, frame.Host.SampleSequence, ProtoTime.ToDateTimeOffset(frame.Host.SampledAt));

        (RunLaunchSpec?, RunResourceCommitment?, ProspectiveCpuPlan?, ArcError?, bool, RunBudgetRefusal?) Reject(
            string reason, bool awaitingResidentFrame = false, RunBudgetRefusal? refusal = null) =>
            (null, null, null, Error(request.Meta, ErrorCategory.Resource, "budget_unavailable", reason), awaitingResidentFrame, refusal);
    }

    private bool HasNewResidentSource(StoredRun run, SandboxResourceFrame frame)
    {
        if (run.State is not (StoredRunState.Starting or StoredRunState.Running)
            || CurrentResourceSource(run.RunId, run.Epoch) is null)
        {
            return false;
        }

        // The Run acquired its exact source after this frame captured its inventory.
        return !frame.Runs.TryGetValue(run.RunId, out var prior)
            || (prior.Target.Epoch == run.Epoch && prior.Target.SandboxId == run.SandboxId && prior.Target.Source is null);
    }

    private bool TryReadResidentReservations(IEnumerable<StoredRun> active, SandboxResourceFrame? frame,
        string? sandboxId, bool requireFreshReading, out (ulong Node, ulong Sandbox) reserved)
    {
        ulong node = 0;
        ulong sandbox = 0;
        foreach (var run in active)
        {
            if (ReadResidentReservation(run, frame, requireFreshReading) is not ulong reservation
                || ulong.MaxValue - node < reservation)
            {
                reserved = default;
                return false;
            }

            node += reservation;
            if (sandboxId is not null && run.SandboxId == sandboxId)
            {
                sandbox += reservation;
            }
        }

        reserved = (node, sandbox);
        return true;
    }

    private ulong? ReadResidentReservation(StoredRun run, SandboxResourceFrame? frame, bool requireFreshReading)
    {
        if (run.State is StoredRunState.Exited or StoredRunState.Failed)
        {
            return run.EndedAt.HasValue ? 0UL : null;
        }

        var launch = ReadRunSnapshot(run);
        if (launch.ExpectedResidentBytes is not ulong expected)
        {
            // A Run admitted before resident reservations has no authoritative expected estimate.
            return null;
        }


        var source = CurrentResourceSource(run.RunId, run.Epoch);
        if (source is null && run.State == StoredRunState.Starting
            && _liveRuns.TryGetValue(run.RunId, out var live) && live.Spec.Epoch == run.Epoch && live.OwnerLease is null)
        {
            return expected;
        }

        if (source is null || frame is null || (requireFreshReading && !frame.HasFreshBudget)
            || !frame.Runs.TryGetValue(run.RunId, out var measurement)
            || measurement.Target.Epoch != run.Epoch || measurement.Target.SandboxId != run.SandboxId
            || !ReferenceEquals(measurement.Target.Source, source)
            || (requireFreshReading && measurement.Reading?.ResidentBytes is null))
        {
            return null;
        }

        ulong? peak = measurement.ResidentPeakBytes ?? measurement.Reading?.ResidentBytes;
        return peak is ulong observed ? Math.Max(expected, observed) : null;
    }

    private ArcError? CheckResourcePolicyCeiling(string scopeKind, string? scopeId, ResourcePolicy policy, RequestMeta? meta,
        SandboxResourceFrame? frame)
    {
        var nodePolicy = DecodeResourcePolicy(ReadResourcePolicy("node", null));
        HardGrant node = NodeHardGrant(scopeKind == "node" ? policy : nodePolicy);
        var active = ReadActiveHardGrants();
        if (scopeKind == "node")
        {
            HardGrant used = SumGrants(active, null);
            string? dimension = used.Exceeded(node);
            if (dimension is null && CurrentNodeGrantBudget(nodePolicy, frame) is { } prior
                && CurrentNodeGrantBudget(policy, frame) is { } changed && changed.TighterThan(prior))
            {
                dimension = used.Exceeded(changed);
            }

            return dimension is not null ? ResourcePolicyBusy(meta, $"node_{dimension}_has_active_grants") : null;
        }

        var target = scopeKind == "run" ? active.SingleOrDefault(entry => entry.Run.RunId == scopeId) : null;
        string? sandboxId = scopeKind == "sandbox" ? scopeId : target?.Run.SandboxId;
        if (sandboxId is null || _store.Read(reader => SandboxRecords.Get(reader, OwnerId, sandboxId)) is not { } sandbox)
        {
            return NotFound(meta);
        }

        var ceiling = SandboxHardGrant(sandbox, scopeKind == "sandbox"
            ? policy : DecodeResourcePolicy(ReadResourcePolicy("sandbox", sandboxId)), node);
        if (target is null)
        {
            return SumGrants(active, sandboxId).Exceeded(ceiling) is { } dimension
                ? ResourcePolicyBusy(meta, $"sandbox_{dimension}_has_active_grants") : null;
        }

        var grant = new HardGrant(policy.HasCpuMaxMillicores ? Math.Max(target.Grant.Cpu, policy.CpuMaxMillicores) : target.Grant.Cpu,
            policy.HasMemoryMaxBytes ? Math.Max(target.Grant.Memory, policy.MemoryMaxBytes) : target.Grant.Memory, 1);
        bool increasing = (policy.HasCpuMaxMillicores && (target.Actual?.CpuMillicores is not { } actualCpu
                || policy.CpuMaxMillicores > actualCpu))
            || (policy.HasMemoryMaxBytes && (target.Actual?.MemoryBytes is not { } actualMemory
                || policy.MemoryMaxBytes > actualMemory));
        if (increasing)
        {
            if (active.Any(entry => !entry.Authoritative)
                || CurrentNodeGrantBudget(nodePolicy, frame) is not { } sampled)
            {
                return ResourcePolicyBusy(meta, "resource_sample_or_existing_limit_unconfirmed");
            }

            node = node.Limit(sampled);
            ceiling = ceiling.Limit(node);
        }

        var siblings = active.Where(entry => entry.Run.RunId != scopeId);
        var nodeFailure = SumGrants(siblings, null).Add(grant).Exceeded(node);
        var sandboxFailure = SumGrants(siblings, sandboxId).Add(grant).Exceeded(ceiling);
        return nodeFailure is not null ? ResourcePolicyBusy(meta, $"node_{nodeFailure}_grant_unavailable")
            : sandboxFailure is not null ? ResourcePolicyBusy(meta, $"sandbox_{sandboxFailure}_grant_unavailable") : null;
    }

    private static ArcError ResourcePolicyBusy(RequestMeta? meta, string reason) =>
        Error(meta, ErrorCategory.State, "busy", reason);

    private HardGrant? CurrentNodeGrantBudget(ResourcePolicy? policy, SandboxResourceFrame? frame) =>
        CurrentResourceAdmissionBudget(policy, frame)?.Hard;

    private (HardGrant Hard, ulong Resident)? CurrentResourceAdmissionBudget(ResourcePolicy? policy, SandboxResourceFrame? frame)
    {
        if (frame is not { HasFreshBudget: true })
        {
            return null;
        }

        var snapshot = frame.Host.Clone();
        ApplyResourceBudgetPolicy(snapshot, policy);
        if (!snapshot.HasBudgetCpuMillicores || !snapshot.HasBudgetMemoryBytes)
        {
            return null;
        }

        var bound = NodeHardGrant(policy);
        // Native memory uses the absolute configured hard envelope. Unmanaged resident load
        // constrains the independent resident reservations, not the Job/cgroup hard grant.
        return (bound with { Cpu = Math.Min(bound.Cpu, snapshot.BudgetCpuMillicores) }, snapshot.BudgetMemoryBytes);
    }

    private HardGrant NodeHardGrant(ResourcePolicy? policy)
    {
        var (cpu, memory) = RunGrantHostCeilings() ?? (0U, 0UL);
        if (policy is null)
        {
            return new(cpu, memory, 1024);
        }

        if (policy.HasHostReserveMillicores)
        {
            ulong raw = (ulong)Environment.ProcessorCount * 1000;
            cpu = (uint)Math.Min(uint.MaxValue, raw - Math.Min(raw, policy.HostReserveMillicores));
        }

        if (policy.HasHostReserveBytes)
        {
            ulong raw = (ulong)Math.Max(0, GC.GetGCMemoryInfo().TotalAvailableMemoryBytes);
            memory = raw - Math.Min(raw, policy.HostReserveBytes);
        }

        return new(policy.HasCpuMaxMillicores ? Math.Min(cpu, policy.CpuMaxMillicores) : cpu,
            policy.HasMemoryMaxBytes ? Math.Min(memory, policy.MemoryMaxBytes) : memory,
            policy.HasMaxConcurrentRuns ? policy.MaxConcurrentRuns : 1024);
    }

    private static HardGrant SandboxHardGrant(StoredSandbox sandbox, ResourcePolicy? overlay, HardGrant node)
    {
        var configured = FromStored(sandbox.Config).Resources;
        var ceiling = node.Limit(PolicyHardGrant(configured, defaultRuns: 1));
        return overlay is null ? ceiling : ceiling.Limit(PolicyHardGrant(overlay, defaultRuns: 1024));
    }

    private static HardGrant PolicyHardGrant(ResourcePolicy? policy, ulong defaultRuns) =>
        new(policy?.HasCpuMaxMillicores == true ? policy.CpuMaxMillicores : ulong.MaxValue,
            policy?.HasMemoryMaxBytes == true ? policy.MemoryMaxBytes : ulong.MaxValue,
            policy?.HasMaxConcurrentRuns == true ? policy.MaxConcurrentRuns : defaultRuns);

    private List<ActiveHardGrant> ReadActiveHardGrants() => _store.Read(reader =>
    {
        var result = new List<ActiveHardGrant>();
        foreach (var run in RunRecords.ListNonterminal(reader, OwnerId))
        {
            var launch = ReadRunSnapshot(run);
            var limits = ResourceStateRecords.ReadLimits(reader, OwnerId, run.RunId);
            // A STARTING Run still has its exact immutable launch assignment. Its policy
            // ceiling is an authority for future changes once the native readback is effective.
            var cpu = run.State == StoredRunState.Starting ? launch.CpuMillicores : Charge(limits, "cpu", launch.CpuMillicores);
            var memory = Charge(limits, "memory", launch.MemoryMaxBytes);
            var hasCurrentOwner = _liveRuns.TryGetValue(run.RunId, out var live) && live.Spec.Epoch == run.Epoch;
            var native = hasCurrentOwner ? ReadOwnedLimits(live!.OwnerLease) : null;
            bool planned = run.State == StoredRunState.Starting && hasCurrentOwner;
            bool confirmed = planned || (native?.CpuMillicores is { } observedCpu && observedCpu <= cpu
                && native.MemoryBytes is { } observedMemory && observedMemory <= memory
                && run.State != StoredRunState.RecoveryRequired);
            result.Add(new(run, new(Math.Max(cpu, native?.CpuMillicores ?? 0),
                Math.Max(memory, native?.MemoryBytes ?? 0), 1), native, confirmed));
        }

        return result;
    });

    private static ulong Charge(IReadOnlyList<StoredRunLimit> limits, string dimension, ulong fallback)
    {
        var limit = limits.FirstOrDefault(value => value.Dimension == dimension);
        if (limit is null)
        {
            return fallback;
        }

        ulong desired = LimitNumber(limit.DesiredValue);
        ulong? applied = limit.AppliedValue is { } accepted ? LimitNumber(accepted) : null;
        ulong? readback = limit.ReadbackValue is { } read ? LimitNumber(read) : null;
        if (limit.Status == StoredRunLimitStatus.Effective && applied.HasValue && applied == readback)
        {
            return readback!.Value;
        }

        return Math.Max(desired, Math.Max(applied ?? fallback, readback ?? fallback));
    }

    private static HardGrant SumGrants(IEnumerable<ActiveHardGrant> grants, string? sandboxId)
    {
        var result = new HardGrant();
        foreach (var active in grants)
        {
            if (sandboxId is null || active.Run.SandboxId == sandboxId)
            {
                result = result.Add(active.Grant);
            }
        }

        return result;
    }

    private void RecordRunResourceGrant(StoreTransaction transaction, StoredRun started, RunLaunchSpec spec, RunResourceCommitment commitment)
    {
        foreach (var (dimension, unit, value) in InitialRunGrant(spec))
        {
            RequireChanged(ResourceStateRecords.TryInsertPendingLimit(transaction, OwnerId,
                started.RunId, started.Epoch,
                new(dimension, unit, 1, LimitText(dimension == "cpu" ? commitment.CpuCeilingMillicores : value))));
        }
    }

    private static IEnumerable<(string Dimension, string Unit, ulong Value)> InitialRunGrant(RunLaunchSpec spec)
    {
        yield return ("cpu", "millicores", spec.CpuMillicores);
        yield return ("memory", OperatingSystem.IsWindows() ? "windows_commit_bytes" : "linux_cgroup_bytes", spec.MemoryMaxBytes);
        yield return ("pids", "count", spec.MaxProcesses);
        if (spec.CpuWeight is { } weight)
        {
            yield return ("cpu_weight", "weight", weight);
        }

        if (OperatingSystem.IsLinux())
        {
            yield return ("swap", "bytes", 0);
        }
    }

    private static RunResourceDimension NativeLimitDimension(string dimension) => dimension switch
    {
        "cpu" => RunResourceDimension.Cpu,
        "memory" => RunResourceDimension.Memory,
        "pids" => RunResourceDimension.ProcessCount,
        "cpu_weight" => RunResourceDimension.CpuWeight,
        "swap" => RunResourceDimension.Swap,
        _ => throw new InvalidDataException("A stored Run limit has an unknown dimension."),
    };

    private static string LimitText(ulong value) => value.ToString(CultureInfo.InvariantCulture);

    private static ulong LimitNumber(string value) => ulong.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);
}
