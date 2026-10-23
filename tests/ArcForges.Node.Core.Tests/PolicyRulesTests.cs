// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>The policy document's validation rules (policy.proto <c>validate:</c>) and the <c>retry_safety</c> rule match (pure rules).</summary>
public sealed class PolicyRulesTests
{
    private const long Capacity = 32L << 30;

    private static List<PolicyIssue> Validate(Action<PolicyDocument> change)
    {
        var document = DefaultPolicy.Create();
        change(document);
        return PolicyRules.Validate(document, Capacity, 16);
    }

    private static void Refused(string path, Action<PolicyDocument> change) =>
        Assert.Contains(Validate(change), issue => issue.Severity == Severity.Error && issue.Path.StartsWith(path, StringComparison.Ordinal));

    [Fact]
    public void TheDefaultDocumentIsValid() => Assert.DoesNotContain(Validate(_ => { }), issue => issue.Severity == Severity.Error);

    [Fact]
    public void ResourceRangesAndThePressureOrderAreChecked()
    {
        Refused("resources.overcommit_cpu", policy => policy.Resources.OvercommitCpu = 0.5);
        Refused("resources.overcommit_mem", policy => policy.Resources.OvercommitMem = 1.5);
        Refused("resources.starvation_bound_ms", policy => policy.Resources.StarvationBoundMs = 1_000);
        Refused("resources.large_task_bypass_ms", policy => policy.Resources.LargeTaskBypassMs = 9_999);
        Refused("resources.large_task_reservation_max_ms", policy => policy.Resources.LargeTaskReservationMaxMs = 59_999);
        Refused("resources.reserve_cpu_fraction", policy => policy.Resources.ReserveCpuFraction = 0.95);
        Refused("resources.pressure", policy => policy.Resources.Pressure = new PressureThresholds { TightAvailableFraction = 0.04, PressureAvailableFraction = 0.05 });

        // A max_task_memory above the managed share is allowed with a warning: larger requests stay exceeds_capacity.
        var issues = Validate(policy => policy.Resources.MaxTaskMemoryBytes = (ulong)Capacity);
        Assert.Contains(issues, issue => issue.Severity == Severity.Warning && issue.Path == "resources.max_task_memory_bytes");
        Assert.DoesNotContain(issues, issue => issue.Severity == Severity.Error);
    }

    [Fact]
    public void PoolsAreUniqueNamedWeightedAndKeepTheBuiltIns()
    {
        Refused("pools[", policy => policy.Pools.Add(new PoolPolicy { Name = "default" }));
        Refused("pools[", policy => policy.Pools.Add(new PoolPolicy { Name = "Has Space" }));
        Refused("pools[", policy => policy.Pools.Add(new PoolPolicy { Name = "heavy", Weight = 101 }));
        Refused("pools[", policy => policy.Pools.Add(new PoolPolicy { Name = "hot", DefaultPriority = Priority.Interactive }));
        Refused("pools", policy => policy.Pools.Remove(policy.Pools.Single(pool => pool.Name == "agents")));
        Assert.DoesNotContain(Validate(policy => policy.Pools.Add(new PoolPolicy { Name = "builds", Weight = 3, MaxParallelMode = ParallelismMode.Fixed, MaxParallelFixed = 2 })),
            issue => issue.Severity == Severity.Error);
    }

    [Fact]
    public void ReservedAndRoadmapFeaturesAreRefused()
    {
        Refused("agents.default_pool", policy => (policy.Agents ??= new AgentPolicy()).DefaultPool = "missing");
        Refused("agents.allowed_command_patterns", policy => (policy.Agents ??= new AgentPolicy()).AllowedCommandPatterns.Add("(unclosed"));
    }

    [Fact]
    public void ARetrySafetyRuleAssertsItsClassForMatchingCommandsInItsWorkspace()
    {
        var workspace = new byte[16];
        workspace[15] = 7;
        var other = new byte[16];
        var rules = new List<RetrySafetyRule>
        {
            new() { Pattern = "^dotnet test( |$)", SideEffect = SideEffectClass.Idempotent, WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) } },
            new() { Pattern = "^cargo check( |$)", SideEffect = SideEffectClass.Pure },
        };
        Assert.Equal(SideEffectClass.Idempotent, PolicyRules.RetrySafety(rules, "dotnet test --no-build", workspace));
        Assert.Null(PolicyRules.RetrySafety(rules, "dotnet test --no-build", other));
        Assert.Equal(SideEffectClass.Pure, PolicyRules.RetrySafety(rules, "cargo check", other));
        Assert.Null(PolicyRules.RetrySafety(rules, "cargo publish", workspace));
    }
}
