// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Resources;

namespace ArcForges.Node.Core.Tests;

public sealed class ResourceBudgetMathTests
{
    private const long GiB = 1024L * 1024 * 1024;

    [Fact]
    public void DefaultHeadroomMatchesTheHistoricalFormulaOnAnOrdinaryHost()
    {
        const long cpu = 16_000;
        const long memory = 32 * GiB;
        long cpuReserve = ResourceBudgetMath.ResolveReserve(cpu, 1_000, 0.10);
        long memoryReserve = ResourceBudgetMath.ResolveReserve(memory, 2 * GiB, 0.10);

        Assert.Equal(2_600L, cpuReserve);
        Assert.Equal((long)(2 * GiB + 0.10 * memory), memoryReserve);
        Assert.Equal(10_300L, ResourceBudgetMath.CpuBudget(cpu, cpuReserve, 3_100, 1_000));
        double budgetGiB = ResourceBudgetMath.MemoryBudget(memory, memoryReserve, (long)(9.7 * GiB))!.Value / (double)GiB;
        Assert.Equal(17.1, budgetGiB, 6);
    }

    [Fact]
    public void ManagedCpuFloorCannotSpendTheHostReserve()
    {
        Assert.Equal(900L, ResourceBudgetMath.NormalizeReserve(900, 1_000));
        Assert.Equal(0L, ResourceBudgetMath.CpuBudget(900, 1_000, 0, 1_000));
        Assert.Equal(100L, ResourceBudgetMath.CpuBudget(900, 800, 300, 1_000));
        Assert.Equal(0L, ResourceBudgetMath.MemoryBudget(900, 800, long.MaxValue));
    }

    [Fact]
    public void MissingOrInvalidObservationsCannotCreateSpareCapacity()
    {
        Assert.Null(ResourceBudgetMath.CpuBudget(16_000, 2_600, null, 1_000));
        Assert.Null(ResourceBudgetMath.MemoryBudget(null, 2 * GiB, 0));
        Assert.Null(ResourceBudgetMath.MemoryBudget(8 * GiB, null, 0));
        Assert.Null(ResourceBudgetMath.MemoryBudget(8 * GiB, 2 * GiB, -1));

        Assert.Null(ResourceBudgetMath.UnmanagedUsage(20, null, 3));
        Assert.Null(ResourceBudgetMath.UnmanagedUsage(20, 5, null));
        Assert.Equal(12L, ResourceBudgetMath.UnmanagedUsage(20, 5, 3));
        Assert.Equal(0L, ResourceBudgetMath.UnmanagedUsage(20, long.MaxValue, long.MaxValue));
    }

    [Fact]
    public void CpuIntervalRequiresAnOrderedCumulativeBaseline()
    {
        Assert.Equal(1_500L, ResourceBudgetMath.CpuRateMillicores(2_000_000, 3_500_000, TimeSpan.FromSeconds(1)));
        Assert.Equal(0L, ResourceBudgetMath.CpuRateMillicores(2_000_000, 2_000_000, TimeSpan.FromSeconds(1)));
        Assert.Null(ResourceBudgetMath.CpuRateMillicores(null, 2_000_000, TimeSpan.FromSeconds(1)));
        Assert.Null(ResourceBudgetMath.CpuRateMillicores(2_000_000, 1, TimeSpan.FromSeconds(1)));
        Assert.Null(ResourceBudgetMath.CpuRateMillicores(0, 1, TimeSpan.Zero));
        Assert.Null(ResourceBudgetMath.CpuRateMillicores(0, long.MaxValue, TimeSpan.FromTicks(1)));
    }

    [Fact]
    public void ResidentReservationStartsAtExpectedAndKeepsTheHigherObservedPeak()
    {
        Assert.Equal(64L, ResourceBudgetMath.ResidentReservation(64, null));
        Assert.Equal(64L, ResourceBudgetMath.ResidentReservation(64, 32));
        Assert.Equal(128L, ResourceBudgetMath.ResidentReservation(64, 128));
        Assert.Null(ResourceBudgetMath.ResidentReservation(null, 128));
        Assert.Null(ResourceBudgetMath.ResidentReservation(0, 128));
        Assert.Null(ResourceBudgetMath.ResidentReservation(64, -1));
    }
}
