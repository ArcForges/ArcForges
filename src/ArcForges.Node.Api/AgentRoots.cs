// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;

namespace ArcForges.Node.Api;

/// <summary>
/// The registered agent process roots (08 section 3: the nearest client-executable ancestor of a hook or the MCP adapter, registered by the
/// session that found it; sessions arrive with AF-AI-01, so the set is empty until then). A CLI whose ancestry reaches a root is AGENT
/// (11 section 1). Each root is a process ID with its start time, and the walk up the parent chain stops at a parent that started after its
/// child (its ID was reused), so a reused ID never makes a process an agent's descendant. Leaving the ancestry (a detached launcher, a
/// scheduled task) is a documented bypass (11 section 1).
/// </summary>
public sealed class AgentRoots
{
    /// <summary>How far two reads of one process's start time may differ (Linux reads them in clock ticks of 10 ms).</summary>
    private static readonly TimeSpan Tolerance = TimeSpan.FromMilliseconds(20);

    private readonly ConcurrentDictionary<int, DateTimeOffset> _roots = new();

    /// <summary>The number of registered roots.</summary>
    public int Count => _roots.Count;

    /// <summary>Registers a root (its process ID and start time).</summary>
    public void Register(int pid, DateTimeOffset start) => _roots[pid] = start;

    /// <summary>Removes a root.</summary>
    public void Remove(int pid) => _roots.TryRemove(pid, out _);

    /// <summary>True when <paramref name="pid"/> is a root or descends from one.</summary>
    public bool Contains(int pid)
    {
        if (_roots.IsEmpty || Lookup(pid) is not { } current)
        {
            return false;
        }

        for (var depth = 0; depth < 64; depth++)
        {
            if (_roots.TryGetValue(current.Pid, out var start) && (start - current.Start).Duration() <= Tolerance)
            {
                return true;
            }

            if (current.Parent <= 0 || current.Parent == current.Pid || Lookup(current.Parent) is not { } parent || parent.Start > current.Start + Tolerance)
            {
                return false;
            }

            current = parent;
        }

        return false;
    }

    /// <summary>A process's parent and start time, or <see langword="null"/> when it is gone or unreadable.</summary>
    private static (int Pid, int Parent, DateTimeOffset Start)? Lookup(int pid)
    {
        if (OperatingSystem.IsLinux())
        {
            return Node.Platform.Linux.ProcFs.Stat(pid) is { } stat ? (pid, stat.ParentPid, Node.Platform.Linux.ProcFs.StartInstant(stat.StartTicks)) : null;
        }

        if (OperatingSystem.IsWindows())
        {
            var entry = Node.Platform.Windows.ProcessInfo.Snapshot().FirstOrDefault(candidate => candidate.Pid == pid);
            using var handle = entry.Pid == pid ? Node.Platform.Windows.ProcessInfo.Open(pid) : null;
            var created = handle is null ? 0 : Node.Platform.Windows.ProcessInfo.CreationFileTime(handle);
            return created > 0 ? (pid, entry.ParentPid, Node.Platform.Windows.ProcessInfo.FromFileTime(created)) : null;
        }

        return null;
    }
}
