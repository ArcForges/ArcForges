// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Scheduling;

/// <summary>
/// How an adapter runs a classified command with the tool-level setting it chose (03 section 5.3): the tool and operation names, the
/// argument vector to run, the parallelism it set, and whether the caller had already passed its own flag (then respected and recorded,
/// never overridden). Records show this setting beside the OS enforcement and never call the tool flag a limit (R-TOOL-003).
/// </summary>
/// <param name="Tool">The adapter tool, e.g. <c>dotnet</c>.</param>
/// <param name="Operation">The operation, e.g. <c>dotnet.build</c>.</param>
/// <param name="Argv">The argument vector to run.</param>
/// <param name="Parallelism">The tool-level parallelism applied (or found in the caller's flag).</param>
/// <param name="CallerFlag">The caller passed an explicit flag, which was kept.</param>
public sealed record ToolInvocation(string Tool, string Operation, IReadOnlyList<string> Argv, int Parallelism, bool CallerFlag);

/// <summary>
/// The tool-level concurrency hook for adapters (03 section 5.3; AF-TOOL-01 and AF-TOOL-02 implement it per tool): at launch the
/// supervisor offers each argv command with its CPU grant; an adapter that classifies the command returns the invocation with the tool's
/// parallelism set to <see cref="ToolParallelism.For"/>, unless the caller already passed a flag.
/// </summary>
public interface IToolConcurrency
{
    /// <summary>The invocation of <paramref name="spec"/> with the tool-level setting for <paramref name="cpuGrantMillicores"/>, or <see langword="null"/>.</summary>
    ToolInvocation? Apply(TaskSpec spec, long cpuGrantMillicores);
}

/// <summary>The tool-level parallelism of 03 section 5.3.</summary>
public static class ToolParallelism
{
    /// <summary><c>clamp(ceil(cpu_grant / 1000), 1, adapter_max)</c>.</summary>
    public static int For(long cpuGrantMillicores, int adapterMax) =>
        (int)Math.Clamp((cpuGrantMillicores + 999) / 1000, 1, Math.Max(1, adapterMax));
}
