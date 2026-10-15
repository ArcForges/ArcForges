// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace ArcForges.Node.Platform.Windows;

/// <summary>The lifetime of a process as FILETIMEs: its creation and, once it exited, its exit (0 while it runs).</summary>
/// <param name="Created">The creation time.</param>
/// <param name="Exited">The exit time, or 0 while the process runs.</param>
public readonly record struct ProcessLifetime(long Created, long Exited);

/// <summary>
/// The members of an attempt's job the node has seen, each with its exact lifetime. A member's process handle is held while it runs, so
/// its process ID cannot be reused meanwhile, and its exit time is read from that handle (<c>GetProcessTimes</c>) when it exits; only
/// then is the handle closed. A member whose creation time could not be read (it exited before the node opened it) is not recorded:
/// with an unknown lifetime its process ID is ambiguous, and the scan never treats a process as its child. A process is recorded only
/// when, once opened, it is in the job (<c>IsProcessInJob</c>): an ID freed and reused between a job message (or the process list)
/// and the open, or a dropped job message (V-W03), never makes an unrelated process a member.
/// </summary>
/// <param name="job">The attempt's job.</param>
[SupportedOSPlatform("windows")]
public sealed class JobMembers(JobObject job) : IDisposable
{
    private readonly ConcurrentDictionary<int, Member> _members = new();
    private readonly List<(int Pid, ProcessLifetime Life)> _retired = [];
    private readonly Lock _gate = new();
    private bool _disposed;

    /// <summary>Records a running member (from JOB_OBJECT_MSG_NEW_PROCESS or the job's process list).</summary>
    public void Remember(int pid)
    {
        lock (_gate)
        {
            if (_disposed || (_members.TryGetValue(pid, out var known) && known.Handle is not null))
            {
                return;
            }

            var handle = ProcessInfo.Open(pid);
            if (handle is null)
            {
                return;
            }

            if (!job.Contains(handle))
            {
                // Not (or no longer) this job's process: the ID was reused, or the message was not about this process.
                handle.Dispose();
                return;
            }

            var created = ProcessInfo.CreationFileTime(handle);
            if (created == 0 || (known is not null && known.Exited != 0 && created <= known.Exited))
            {
                handle.Dispose();
                return;
            }

            // A new member with a reused process ID: the exited one keeps its closed window among the retired members.
            if (known is not null && known.Exited > 0)
            {
                _retired.Add((pid, new ProcessLifetime(known.Created, known.Exited)));
            }

            _members[pid] = new Member(created) { Handle = handle };
            if (!ProcessInfo.IsRunning(handle))
            {
                Close(_members[pid]);
            }
        }
    }

    /// <summary>Records a member's exit (JOB_OBJECT_MSG_EXIT_PROCESS): its exact exit time is read, then its handle closed.</summary>
    public void Exited(int pid)
    {
        lock (_gate)
        {
            if (_members.TryGetValue(pid, out var member) && member.Handle is not null)
            {
                Close(member);
            }
        }
    }

    /// <summary>
    /// The members with a known lifetime (running ones with exit 0); members whose exit message was missed are closed with their exact
    /// exit time first, and a member whose exit time could not be read is left out.
    /// </summary>
    public List<(int Pid, ProcessLifetime Life)> Snapshot()
    {
        lock (_gate)
        {
            foreach (var member in _members.Values.Where(member => member.Handle is { } handle && !ProcessInfo.IsRunning(handle)))
            {
                Close(member);
            }

            return [.. _retired, .. _members.Where(pair => pair.Value.Exited >= 0).Select(pair => (pair.Key, new ProcessLifetime(pair.Value.Created, pair.Value.Exited)))];
        }
    }

    /// <summary>Closes the held handles.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            foreach (var member in _members.Values)
            {
                member.Handle?.Dispose();
                member.Handle = null;
            }
        }
    }

    private static void Close(Member member)
    {
        if (member.Handle is { } handle)
        {
            // An unreadable exit time leaves the lifetime unknown (-1): the member is then ambiguous and never a parent.
            member.Exited = Native.GetProcessTimes(handle, out _, out var exit, out _, out _) && exit != 0 ? exit : -1;
            handle.Dispose();
            member.Handle = null;
        }
    }

    private sealed class Member(long created)
    {
        public long Created { get; } = created;

        public long Exited { get; set; }

        public SafeKernelHandle? Handle { get; set; }
    }
}

/// <summary>
/// The ancestry scan of 04 section 3 and 03 section 9 (R-RES-012): processes that descend from a process seen in an attempt's job but
/// run outside it (created through WMI, a service broker, or under another parent before the job assignment) are <c>ESCAPED</c>.
/// A child counts only when it was created within its parent's lifetime: at or after the parent's creation and, when the parent has
/// exited, before its exit. Members have exact lifetimes (<see cref="JobMembers"/>); every process the walk passes through stays open
/// until the scan ends, so its ID cannot be reused during the scan and its exit time is exact. A process ID whose owner is ambiguous
/// is never followed, so a process that reused the ID of an exited member, and its children, are never reported or terminated
/// (the scan fails toward "not escaped"). Only same-user escaped processes are ever terminated.
/// </summary>
[SupportedOSPlatform("windows")]
public static class EscapedProcesses
{
    /// <summary>The escaped descendants of <paramref name="members"/> (every member seen, with its exact lifetime).</summary>
    public static List<EscapedProcess> Scan(JobObject job, IReadOnlyList<(int Pid, ProcessLifetime Life)> members)
    {
        ArgumentNullException.ThrowIfNull(job);
        ArgumentNullException.ThrowIfNull(members);
        var result = new List<EscapedProcess>();
        if (members.Count == 0)
        {
            return result;
        }

        var children = ProcessInfo.Snapshot().ToLookup(entry => entry.ParentPid);
        var frontier = new Queue<(int Pid, ProcessLifetime Life)>(members.Where(member => member.Life.Created > 0 && member.Life.Exited >= 0));
        var visited = new HashSet<int>(members.Select(member => member.Pid));
        var held = new List<SafeKernelHandle>();
        try
        {
            while (frontier.TryDequeue(out var parent))
            {
                foreach (var child in children[parent.Pid])
                {
                    if (visited.Contains(child.Pid))
                    {
                        continue;
                    }

                    var process = ProcessInfo.Open(child.Pid);
                    if (process is null)
                    {
                        continue;
                    }

                    var life = Lifetime(process);
                    if (!WithinLifetime(life.Created, parent.Life))
                    {
                        // Created outside the parent's lifetime: the parent ID belonged to another process then.
                        process.Dispose();
                        continue;
                    }

                    held.Add(process);
                    visited.Add(child.Pid);
                    frontier.Enqueue((child.Pid, life));
                    if (!job.Contains(process))
                    {
                        result.Add(new EscapedProcess(child.Pid, parent.Pid, ProcessInfo.FromFileTime(life.Created), child.Image, IsSameUser(process)));
                    }
                }
            }
        }
        finally
        {
            foreach (var handle in held)
            {
                handle.Dispose();
            }
        }

        return result;
    }

    /// <summary>True when a child created at <paramref name="created"/> can be a child of a process with <paramref name="parent"/>'s lifetime.</summary>
    public static bool WithinLifetime(long created, ProcessLifetime parent) =>
        created > 0 && parent.Created > 0 && parent.Exited >= 0 && created >= parent.Created && (parent.Exited == 0 || created <= parent.Exited);

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

    private static ProcessLifetime Lifetime(SafeKernelHandle process)
    {
        if (!Native.GetProcessTimes(process, out var created, out var exited, out _, out _))
        {
            return default;
        }

        if (ProcessInfo.IsRunning(process))
        {
            return new ProcessLifetime(created, 0);
        }

        // An exited process without a readable exit time has an unknown lifetime: neither it nor its children are followed.
        return exited == 0 ? default : new ProcessLifetime(created, exited);
    }
}
