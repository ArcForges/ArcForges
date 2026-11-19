// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core.Resources;

/// <summary>Budget and interval arithmetic independent of the owner, sampler and scheduler.</summary>
internal static class ResourceBudgetMath
{
    // Preserve the fixed-plus-fraction calculation and truncation of the retained policy.
    internal static long ResolveReserve(long capacity, long fixedAmount, double fraction) =>
        (long)(fixedAmount + (fraction * capacity));

    internal static long NormalizeReserve(long capacity, long reserve) =>
        Math.Clamp(reserve, 0, Math.Max(0, capacity));

    // Legacy callers keep their original CPU floor even where it exceeds capacity minus reserve.
    internal static (long Cpu, long Memory) LegacyBudgets(long capacityCpu, long capacityMemory,
        long reserveCpu, long reserveMemory, long minimumManagedCpu, long unmanagedCpu, long unmanagedMemory) =>
        (Math.Max(minimumManagedCpu, AfterUnmanaged(capacityCpu - reserveCpu, unmanagedCpu)),
            Math.Max(0, AfterUnmanaged(capacityMemory - reserveMemory, unmanagedMemory)));

    internal static long? CpuBudget(long? capacity, long? reserve, long? unmanaged, long minimumManagedCpu)
    {
        if (ManagedShare(capacity, reserve) is not { } share || unmanaged is not >= 0)
        {
            return null;
        }

        // The CPU floor is a lower bound on the budget within the managed share. It cannot consume
        // the normalized host reserve, including when the reserve accounts for the whole capacity.
        return Math.Max(Math.Clamp(minimumManagedCpu, 0, share), AfterUnmanaged(share, unmanaged.Value));
    }

    internal static long? MemoryBudget(long? capacity, long? reserve, long? unmanaged) =>
        ManagedShare(capacity, reserve) is { } share && unmanaged is >= 0
            ? Math.Max(0, AfterUnmanaged(share, unmanaged.Value)) : null;

    internal static long? UnmanagedUsage(long? total, long? managed, long? node)
    {
        if (total is not >= 0 || managed is not >= 0 || node is not >= 0)
        {
            return null;
        }

        // Subtract each disjoint measurement without overflowing their sum.
        long remaining = total.Value - Math.Min(total.Value, managed.Value);
        return remaining - Math.Min(remaining, node.Value);
    }

    internal static long? CumulativeDelta(long? previous, long? current) =>
        previous is >= 0 && current is >= 0 && current >= previous ? current.Value - previous.Value : null;

    internal static long? CpuRateMillicores(long? previousUsec, long? currentUsec, TimeSpan interval)
    {
        if (interval <= TimeSpan.Zero || CumulativeDelta(previousUsec, currentUsec) is not { } delta)
        {
            return null;
        }

        // A microsecond of CPU per millisecond of elapsed time is one millicore.
        var rate = (Int128)delta * TimeSpan.TicksPerMillisecond / interval.Ticks;
        return rate <= long.MaxValue ? (long)rate : null;
    }

    // The expected estimate is required. A new Run has no peak yet, so its estimate is its initial reservation.
    internal static long? ResidentReservation(long? expectedBytes, long? observedPeakBytes) =>
        expectedBytes is > 0 && observedPeakBytes is null or >= 0
            ? Math.Max(expectedBytes.Value, observedPeakBytes ?? expectedBytes.Value) : null;

    private static long? ManagedShare(long? capacity, long? reserve) =>
        capacity is >= 0 && reserve is >= 0 ? capacity.Value - NormalizeReserve(capacity.Value, reserve.Value) : null;

    private static long AfterUnmanaged(long managedShare, long unmanaged) =>
        managedShare - Math.Max(0, unmanaged);
}
