// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Principal;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// The ancestry scan of 04 section 3 and 03 section 9 (R-RES-012): processes that descend from a process seen in an attempt's job but
/// run outside it (created through WMI, a service broker, or under another parent before the job assignment) are <c>ESCAPED</c>. The
/// scan walks a Toolhelp snapshot from every member the node has seen, running or exited. A child counts only when it was created after
/// its parent, and when a parent ID now belongs to a different live process, the children younger than that process are its own, so a
/// reused ID never makes a stranger a descendant. Only same-user escaped processes are ever terminated.
/// </summary>
[SupportedOSPlatform("windows")]
public static class EscapedProcesses
{
    /// <summary>The escaped descendants of <paramref name="members"/> (process ID to creation FILETIME of every process seen in the job).</summary>
    public static List<EscapedProcess> Scan(JobObject job, IReadOnlyDictionary<int, long> members)
    {
        ArgumentNullException.ThrowIfNull(job);
        ArgumentNullException.ThrowIfNull(members);
        var result = new List<EscapedProcess>();
        if (members.Count == 0)
        {
            return result;
        }

        var children = ProcessInfo.Snapshot().ToLookup(entry => entry.ParentPid);
        var frontier = new Queue<(int Pid, long Created)>(members.Select(member => (member.Key, member.Value)));
        var visited = new HashSet<int>(members.Keys);
        while (frontier.TryDequeue(out var parent))
        {
            long liveCreated = 0;
            using (var live = ProcessInfo.Open(parent.Pid))
            {
                if (live is not null)
                {
                    liveCreated = ProcessInfo.CreationFileTime(live);
                }
            }

            var reused = liveCreated != 0 && parent.Created != 0 && Math.Abs(liveCreated - parent.Created) >= 10;
            foreach (var child in children[parent.Pid])
            {
                if (visited.Contains(child.Pid))
                {
                    continue;
                }

                using var process = ProcessInfo.Open(child.Pid);
                if (process is null)
                {
                    continue;
                }

                var created = ProcessInfo.CreationFileTime(process);
                if ((parent.Created != 0 && created < parent.Created) || (reused && created >= liveCreated))
                {
                    continue;
                }

                visited.Add(child.Pid);
                frontier.Enqueue((child.Pid, created));
                if (job.Contains(process))
                {
                    continue;
                }

                result.Add(new EscapedProcess(child.Pid, parent.Pid, ProcessInfo.FromFileTime(created), child.Image, IsSameUser(process)));
            }
        }

        return result;
    }

    /// <summary>Terminates the same-user processes of <paramref name="escaped"/> that are still the ones found; returns them as <c>image (pid)</c>.</summary>
    public static List<string> Terminate(IEnumerable<EscapedProcess> escaped, uint exitCode)
    {
        ArgumentNullException.ThrowIfNull(escaped);
        var terminated = new List<string>();
        foreach (var process in escaped.Where(process => process.SameUser))
        {
            using var handle = ProcessInfo.OpenIdentified(process.Pid, process.StartTime.ToFileTime(), terminate: true);
            if (handle is not null && Native.TerminateProcess(handle, exitCode))
            {
                terminated.Add($"{process.Image} ({process.Pid})");
            }
        }

        return terminated;
    }

    /// <summary>True when the process runs as the current user.</summary>
    public static bool IsSameUser(SafeKernelHandle process)
    {
        ArgumentNullException.ThrowIfNull(process);
        if (!Native.OpenProcessToken(process, Native.TokenQuery, out var token))
        {
            token.Dispose();
            return false;
        }

        using (token)
        {
            using var identity = new WindowsIdentity(token.DangerousGetHandle());
            using var current = WindowsIdentity.GetCurrent();
            return identity.User is { } user && current.User is { } me && user.Equals(me);
        }
    }
}
