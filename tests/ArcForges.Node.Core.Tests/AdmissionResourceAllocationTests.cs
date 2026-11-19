// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Resources;

namespace ArcForges.Node.Core.Tests;

public sealed class AdmissionResourceAllocationTests
{
    [Fact]
    public void WeightedSandboxesAndRunsRedistributeCappedAndIdleShares()
    {
        var grants = WeightedCpuAllocation.Allocate(500,
        [
            new("idle", 100, 1000, []),
            new("small", 1, 100, [new("small-run", 1, 500)]),
            new("large", 3, 1000, [new("light-run", 1, 1000), new("capped-run", 3, 100)]),
        ]);

        Assert.Equal(3, grants.Count);
        Assert.Equal(100UL, grants["small-run"]);
        Assert.Equal(300UL, grants["light-run"]);
        Assert.Equal(100UL, grants["capped-run"]);
    }

    [Fact]
    public void BothLevelsResolveFractionalTiesByOrdinalIdentity()
    {
        SandboxCpuShares[] scopes =
        [
            new("z", 1, 10, [new("z-run", 1, 10)]),
            new("a", 1, 10, [new("c-run", 1, 10), new("b-run", 1, 10)]),
        ];
        var grants = WeightedCpuAllocation.Allocate(1, scopes);
        Assert.Equal(1UL, grants["b-run"]);
        Assert.Equal(0UL, grants["c-run"]);
        Assert.Equal(0UL, grants["z-run"]);
        Assert.Equal(grants.OrderBy(pair => pair.Key, StringComparer.Ordinal),
            WeightedCpuAllocation.Allocate(1, scopes.Reverse().ToArray()).OrderBy(pair => pair.Key, StringComparer.Ordinal));
    }

    [Fact]
    public void UnsaturatedDemandAndZeroBudgetDoNotCreateCpuGrants()
    {
        SandboxCpuShares[] scopes =
        [
            new("one", 1, 100, [new("limited", 4, 23), new("empty", 1, 0)]),
            new("two", 1, 80, [new("bounded", 1, 13)]),
        ];
        var grants = WeightedCpuAllocation.Allocate(200, scopes);
        Assert.Equal(23UL, grants["limited"]);
        Assert.Equal(0UL, grants["empty"]);
        Assert.Equal(13UL, grants["bounded"]);
        Assert.All(WeightedCpuAllocation.Allocate(0, scopes).Values, grant => Assert.Equal(0UL, grant));
    }

    [Fact]
    public void LargeWeightedProductsCannotOversubscribeTheBudget()
    {
        var grants = WeightedCpuAllocation.Allocate(ulong.MaxValue,
        [
            new("sandbox-one", 1, ulong.MaxValue, [new("run-one", 1, ulong.MaxValue)]),
            new("sandbox-two", 10_000, ulong.MaxValue, [new("run-two", 10_000, ulong.MaxValue)]),
        ]);

        Assert.Equal(ulong.MaxValue, checked(grants["run-one"] + grants["run-two"]));
        Assert.InRange(grants["run-one"], 1UL, ulong.MaxValue / 10_000);
    }

    [Fact]
    public void BudgetHysteresisRetainsTheHostReserveAndDelaysEscalation()
    {
        var next = TimeSpan.FromSeconds(1);
        var due = TimeSpan.FromSeconds(10);
        Assert.Equal(599UL, WeightedCpuAllocation.SelectBudget(700, 599, 900, 2000, next, false));
        Assert.Equal(700UL, WeightedCpuAllocation.SelectBudget(700, 600, 900, 2000, next, false));
        Assert.Equal(699UL, WeightedCpuAllocation.SelectBudget(700, 699, 900, 2000, next, true));
        Assert.Equal(700UL, WeightedCpuAllocation.SelectBudget(700, 801, 900, 2000, next, false));
        Assert.Equal(801UL, WeightedCpuAllocation.SelectBudget(700, 801, 900, 2000, due, false));
        Assert.Equal(650UL, WeightedCpuAllocation.SelectBudget(700, 800, 650, 2000, next, false));
        Assert.False(WeightedCpuAllocation.CanIncreaseAfter(due - TimeSpan.FromMilliseconds(1)));
        Assert.True(WeightedCpuAllocation.CanIncreaseAfter(due));
    }
}
