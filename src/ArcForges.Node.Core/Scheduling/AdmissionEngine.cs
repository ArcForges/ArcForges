// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core.Scheduling;

/// <summary>The memory feasibility classes of 03 section 4.</summary>
public enum Feasibility
{
    /// <summary><c>mem_expected &lt;= idle_budget_mem</c>.</summary>
    Feasible,

    /// <summary><c>idle_budget_mem &lt; mem_expected &lt;= max_share_mem</c>.</summary>
    ExceedsBudget,

    /// <summary><c>mem_expected &gt; max_share_mem</c> or <c>&gt; max_task_memory</c>.</summary>
    ExceedsCapacity,
}

/// <summary>Classifies the stored memory demand of a retained task for its explanation.</summary>
public static class AdmissionEngine
{
    /// <summary>The memory feasibility class of a request (03 section 4).</summary>
    public static Feasibility Classify(long memExpected, long maxShareMemory, long idleBudgetMemory, long maxTaskMemory) =>
        memExpected > Math.Min(maxShareMemory, maxTaskMemory) ? Scheduling.Feasibility.ExceedsCapacity
        : memExpected > idleBudgetMemory ? Scheduling.Feasibility.ExceedsBudget
        : Scheduling.Feasibility.Feasible;
}
