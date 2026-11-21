// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core.Scheduling;

/// <summary>The tool-level parallelism of 03 section 5.3.</summary>
public static class ToolParallelism
{
    /// <summary><c>clamp(ceil(cpu_grant / 1000), 1, adapter_max)</c>.</summary>
    public static int For(long cpuGrantMillicores, int adapterMax) =>
        (int)Math.Clamp((cpuGrantMillicores + 999) / 1000, 1, Math.Max(1, adapterMax));
}
