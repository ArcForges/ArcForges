// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;

namespace ArcForges.Node.Core.Resources;

/// <summary>The attempt a process belongs to or escaped from.</summary>
/// <param name="AttemptId">The attempt ID.</param>
/// <param name="TaskId">The task ID.</param>
/// <param name="CrossesVmBoundary">The attempt ran a launcher into a virtual machine (03 section 9).</param>
public sealed record ProcessOwner(byte[] AttemptId, byte[] TaskId, bool CrossesVmBoundary);

/// <summary>What the classification knows besides the process table.</summary>
public sealed class ProcessContext
{
    /// <summary>The node's own process ID.</summary>
    public required int NodePid { get; init; }

    /// <summary>The node's image name (its helper processes, the Windows holders, run the same executable).</summary>
    public string? NodeImage { get; init; }

    /// <summary>The members of every attempt container now (container membership).</summary>
    public required IReadOnlyDictionary<int, ProcessOwner> Managed { get; init; }

    /// <summary>The escaped processes the ancestry scan recorded, by ID and creation time.</summary>
    public IReadOnlyList<(int Pid, DateTimeOffset Start, ProcessOwner Owner)> Escaped { get; init; } = [];

    /// <summary>True for a virtual machine's worker process (Windows: the WSL VM).</summary>
    public Func<string, bool> IsVmWorker { get; init; } = _ => false;
}

/// <summary>
/// The process labels of 03 section 9 (R-RES-002), observed versus controlled: <c>MANAGED</c> by container membership (only these, and
/// <c>ADOPTED</c> processes, are ever controlled); the node's own process and helpers <c>NODE_SELF</c>; <c>ESCAPED</c> when the ancestry
/// scan found the process outside its attempt's container; a VM worker <c>GUEST_VM</c>, one unmanaged consumer that is never summed from
/// the processes inside the VM (AD-0018 section 2); everything else <c>UNMANAGED</c>. <c>ADOPTED</c> needs adoption records
/// (<c>AdoptProcess</c>) and <c>BYPASSED</c> registered agent roots (sessions); release 1 has neither yet, so neither label is produced.
/// </summary>
public static class ProcessClassifier
{
    /// <summary>The label of <paramref name="process"/> and the attempt it belongs to, if any.</summary>
    public static (ProcessLabel Label, ProcessOwner? Owner) Classify(ProcessSample process, ProcessContext context)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(context);
        if (context.Managed.TryGetValue(process.Pid, out var owner))
        {
            return (ProcessLabel.Managed, owner);
        }

        if (process.Pid == context.NodePid)
        {
            return (ProcessLabel.NodeSelf, null);
        }

        foreach (var escaped in context.Escaped)
        {
            if (escaped.Pid == process.Pid && Math.Abs((escaped.Start - process.StartTime).TotalMilliseconds) <= 10)
            {
                return (ProcessLabel.Escaped, escaped.Owner);
            }
        }

        if (process.ParentPid == context.NodePid && context.NodeImage is { } image && string.Equals(process.Image, image, StringComparison.OrdinalIgnoreCase))
        {
            return (ProcessLabel.NodeSelf, null);
        }

        return context.IsVmWorker(process.Image) ? (ProcessLabel.GuestVm, null) : (ProcessLabel.Unmanaged, null);
    }

    /// <summary>True when a process with <paramref name="label"/> is controlled by the node (03 section 9: only MANAGED and ADOPTED).</summary>
    public static bool Controlled(ProcessLabel label) => label is ProcessLabel.Managed or ProcessLabel.Adopted;
}
