// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.RunSupervisor.Protocol;

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

        private static ulong Sum(ulong left, ulong right) =>
            left > ulong.MaxValue - right ? ulong.MaxValue : left + right;
    }

    private sealed record ActiveHardGrant(StoredRun Run, HardGrant Grant,
        RunResourceLimitReading? Actual, bool Authoritative);

    private (RunLaunchSpec? Spec, ArcError? Error) AuthorizeRunResourceGrant(RunServiceStartRequest request,
        StoredSandbox sandbox, RunLaunchSpec spec, SandboxResourceFrame? frame)
    {
        var nodePolicy = DecodeResourcePolicy(ReadResourcePolicy("node", null));
        if (CurrentNodeGrantBudget(nodePolicy, frame) is not { } nodeCeiling)
        {
            return (null, Error(request.Meta, ErrorCategory.Resource, "budget_unavailable", "resource_sample_unavailable"));
        }

        HardGrant sandboxCeiling = SandboxHardGrant(sandbox,
            DecodeResourcePolicy(ReadResourcePolicy("sandbox", sandbox.SandboxId)), nodeCeiling);
        var active = ReadActiveHardGrants();
        if (active.Any(entry => !entry.Authoritative))
        {
            return (null, Error(request.Meta, ErrorCategory.Resource, "budget_unavailable", "existing_run_limit_unconfirmed"));
        }
        HardGrant nodeFree = nodeCeiling.AvailableAfter(SumGrants(active, null));
        HardGrant sandboxFree = sandboxCeiling.AvailableAfter(SumGrants(active, sandbox.SandboxId));
        HardGrant commonFree = nodeFree.Limit(sandboxFree);
        var requested = request.RequestedResources;

        // An unspecified Run limit is a grant within the current shared ceiling. Share the
        // default over the configured concurrency allowance and reserve the result atomically.
        ulong requestedCpu = requested?.HasCpuMaxMillicores == true ? spec.CpuMillicores
            : Math.Min(spec.CpuMillicores, Math.Min(commonFree.Cpu, sandboxCeiling.Cpu / Math.Max(1UL, sandboxCeiling.Runs)));
        ulong requestedMemory = requested?.HasMemoryMaxBytes == true ? spec.MemoryMaxBytes
            : Math.Min(spec.MemoryMaxBytes, Math.Min(commonFree.Memory, sandboxCeiling.Memory / Math.Max(1UL, sandboxCeiling.Runs)));
        if (requested?.HasMemoryMaxBytes != true && OperatingSystem.IsLinux())
        {
            ulong page = (ulong)Environment.SystemPageSize;
            requestedMemory -= requestedMemory % page;
        }

        var grant = new HardGrant(requestedCpu, requestedMemory, 1);
        string? nodeFailure = grant.Exceeded(nodeFree);
        string? sandboxFailure = grant.Exceeded(sandboxFree);
        if (nodeFailure is not null || sandboxFailure is not null || requestedCpu == 0 || requestedMemory == 0)
        {
            string reason = nodeFailure is not null ? $"node_{nodeFailure}_grant_unavailable"
                : sandboxFailure is not null ? $"sandbox_{sandboxFailure}_grant_unavailable"
                : requestedCpu == 0 ? "cpu_grant_unavailable" : "memory_grant_unavailable";
            return (null, Error(request.Meta, ErrorCategory.Resource, "budget_unavailable", reason));
        }

        return (spec with { CpuMillicores = checked((uint)requestedCpu), MemoryMaxBytes = requestedMemory }, null);
    }

    private ArcError? CheckResourcePolicyCeiling(string scopeKind, string? scopeId, ResourcePolicy policy, RequestMeta? meta)
    {
        var nodePolicy = DecodeResourcePolicy(ReadResourcePolicy("node", null));
        HardGrant node = NodeHardGrant(scopeKind == "node" ? policy : nodePolicy);
        var active = ReadActiveHardGrants();
        if (scopeKind == "node")
        {
            HardGrant used = SumGrants(active, null);
            string? dimension = used.Exceeded(node);
            var frame = _resourceMonitor?.Latest;
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
                || CurrentNodeGrantBudget(nodePolicy) is not { } sampled)
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

    private HardGrant? CurrentNodeGrantBudget(ResourcePolicy? policy) =>
        CurrentNodeGrantBudget(policy, _resourceMonitor?.Latest);

    private HardGrant? CurrentNodeGrantBudget(ResourcePolicy? policy, SandboxResourceFrame? frame)
    {
        if (frame is not { HasFreshBudget: true })
        {
            return null;
        }

        var snapshot = frame.Host.Clone();
        ApplyResourceBudgetPolicy(snapshot, policy);
        return snapshot.HasBudgetCpuMillicores && snapshot.HasBudgetMemoryBytes
            ? NodeHardGrant(policy).Limit(new(snapshot.BudgetCpuMillicores, snapshot.BudgetMemoryBytes, 1024))
            : null;
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
            var cpu = Charge(limits, "cpu", launch.CpuMillicores);
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

    private void RecordRunResourceGrant(StoreTransaction transaction, StoredRun started, RunLaunchSpec spec)
    {
        foreach (var (dimension, unit, value) in InitialRunGrant(spec))
        {
            RequireChanged(ResourceStateRecords.TryInsertPendingLimit(transaction, OwnerId,
                started.RunId, started.Epoch, new(dimension, unit, 1, LimitText(value))));
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
