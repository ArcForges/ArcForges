// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core.Resources;

internal readonly record struct CpuShare(string Id, uint Weight, ulong Ceiling);

internal sealed record SandboxCpuShares(string Id, uint Weight, ulong Ceiling, IReadOnlyList<CpuShare> Runs);

/// <summary>Divides the current CPU budget among runnable scopes, independently of native setters and durable policy.</summary>
internal static class WeightedCpuAllocation
{
    internal static ulong SelectBudget(ulong prior, ulong measured, ulong ceiling, ulong capacity,
        TimeSpan sinceChange, bool forceReduction)
    {
        prior = Math.Min(prior, ceiling);
        measured = Math.Min(measured, ceiling);
        if (measured < prior)
        {
            return forceReduction || prior - measured > capacity / 20 ? measured : prior;
        }

        return measured - prior > capacity / 20 && CanIncreaseAfter(sinceChange) ? measured : prior;
    }

    internal static bool CanIncreaseAfter(TimeSpan elapsed) => elapsed >= TimeSpan.FromSeconds(10);

    internal static Dictionary<string, ulong> Allocate(ulong budget, IReadOnlyList<SandboxCpuShares> sandboxes)
    {
        var shares = new List<CpuShare>(sandboxes.Count);
        foreach (var sandbox in sandboxes)
        {
            if (sandbox.Runs.Count == 0)
            {
                continue;
            }

            UInt128 demand = 0;
            foreach (var run in sandbox.Runs)
            {
                demand += run.Ceiling;
            }

            shares.Add(new(sandbox.Id, sandbox.Weight, demand < sandbox.Ceiling ? (ulong)demand : sandbox.Ceiling));
        }

        var bySandbox = Split(budget, shares);
        var grants = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (var sandbox in sandboxes)
        {
            if (bySandbox.TryGetValue(sandbox.Id, out var available) && sandbox.Runs.Count > 0)
            {
                foreach (var (id, grant) in Split(available, sandbox.Runs))
                {
                    grants.Add(id, grant);
                }
            }
        }

        return grants;
    }

    private static Dictionary<string, ulong> Split(ulong budget, IReadOnlyList<CpuShare> shares)
    {
        var grants = new Dictionary<string, ulong>(shares.Count, StringComparer.Ordinal);
        var ordered = shares.ToArray();
        ulong weight = 0;
        foreach (var share in ordered)
        {
            ArgumentOutOfRangeException.ThrowIfZero(share.Weight);
            grants.Add(share.Id, 0);
            weight += share.Weight;
        }

        // Satisfy all capped scopes, redistributing their unused share before rounding any others.
        Array.Sort(ordered, static (a, b) => ((UInt128)a.Ceiling * b.Weight).CompareTo((UInt128)b.Ceiling * a.Weight));
        int firstUncapped = 0;
        while (firstUncapped < ordered.Length)
        {
            var share = ordered[firstUncapped];
            if ((UInt128)share.Ceiling * weight > (UInt128)budget * share.Weight)
            {
                break;
            }

            grants[share.Id] = share.Ceiling;
            budget -= share.Ceiling;
            weight -= share.Weight;
            firstUncapped++;
        }

        if (firstUncapped == ordered.Length)
        {
            return grants;
        }

        var remainders = new List<(string Id, ulong Fraction)>(ordered.Length - firstUncapped);
        var remaining = budget;
        for (int index = firstUncapped; index < ordered.Length; index++)
        {
            var share = ordered[index];
            UInt128 proportional = (UInt128)budget * share.Weight;
            var whole = (ulong)(proportional / weight);
            grants[share.Id] = whole;
            remaining -= whole;
            remainders.Add((share.Id, (ulong)(proportional % weight)));
        }

        // The undistributed remainder is smaller than the number of uncapped scopes.
        foreach (var remainder in remainders.OrderByDescending(item => item.Fraction)
            .ThenBy(item => item.Id, StringComparer.Ordinal).Take((int)remaining))
        {
            grants[remainder.Id]++;
        }

        return grants;
    }
}
