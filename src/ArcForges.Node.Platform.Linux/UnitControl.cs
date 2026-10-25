// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using Tmds.DBus.Protocol;

namespace ArcForges.Node.Platform.Linux;

/// <summary>The stop of an attempt unit shared by the node and the guard (04 section 6 steps 3 and 4; 06 section 5).</summary>
[SupportedOSPlatform("linux")]
public static class UnitControl
{
    /// <summary>
    /// Freezes the unit (<c>FreezeUnit</c>), sends SIGKILL to every process of its cgroup (the main process last), and thaws the cgroup
    /// directly through its <c>cgroup.freeze</c> file before asking the user manager to thaw it: once the main process is gone the manager
    /// spawns the unit's <c>ExecStop</c> into the cgroup, and a spawn into a frozen cgroup blocks the manager until the cgroup is thawed, so
    /// the thaw must not depend on the manager. After the main command exits, a late forced phase kills remaining workload members
    /// without freezing or killing systemd's bounded control helpers and their descendants.
    /// If the freeze fails, known workload members are killed in bounded passes, and a timed-out freeze is still thawed directly.
    /// <c>ExecStop</c> and <c>ExecStopPost</c> then run as after any exit, so <c>exit.json</c> is written.
    /// </summary>
    public static LimitStop FreezeAndKill(SystemdManager manager, string unit, string? cgroupDirectory, int mainPid)
    {
        ArgumentNullException.ThrowIfNull(manager);
        // Once the main command has exited, systemd owns the bounded end steps and exit-record. Killing the unit's
        // remaining processes then kills those helpers, loses exit.json and can strand the manager's spawn in a frozen cgroup.
        var state = manager.State(unit);
        if (state is null || (mainPid != 0 && state.MainPid != 0 && state.MainPid != mainPid))
        {
            return new LimitStop(false, 0, null, DateTimeOffset.UtcNow);
        }

        if (state.MainPid == 0 || state.ControlPid != 0)
        {
            return KillOutsideControls(manager, unit, cgroupDirectory, mainPid);
        }

        mainPid = (int)state.MainPid;
        if (ProcFs.Stat(mainPid) is not { State: not ('Z' or 'X') } root)
        {
            return KillOutsideControls(manager, unit, cgroupDirectory, mainPid);
        }

        var members = Members();
        if (ProcFs.Stat(mainPid) is not { State: not ('Z' or 'X') } captured || captured.StartTicks != root.StartTicks)
        {
            return KillOutsideControls(manager, unit, cgroupDirectory, mainPid);
        }

        DateTimeOffset? frozenAt = null;
        var killed = 0;
        var killedAt = DateTimeOffset.UtcNow;
        var thawed = false;
        try
        {
            try
            {
                manager.FreezeUnit(unit);
                frozenAt = DateTimeOffset.UtcNow;
            }
            catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException)
            {
                // The root may have exited while FreezeUnit was in flight. Only the known members may be killed then.
            }

            for (var pass = 0; pass < 5; pass++)
            {
                var currentMembers = Members();
                if (ProcFs.Stat(mainPid) is { State: not ('Z' or 'X') } current && current.StartTicks == root.StartTicks)
                {
                    // Validate after the scan too: if the root exited during it, later helper PIDs must not enter the kill set.
                    foreach (var member in currentMembers)
                    {
                        members.TryAdd(member.Key, member.Value);
                    }
                }

                foreach (var (pid, start) in members.OrderBy(member => member.Key == mainPid))
                {
                    if (ProcFs.Stat(pid) is { State: not ('Z' or 'X') } live && live.StartTicks == start && Libc.Kill(pid, Libc.SigKill) == 0)
                    {
                        killed++;
                    }
                }

                if (frozenAt is not null)
                {
                    break;
                }

                Thread.Sleep(10);
            }

            killedAt = DateTimeOffset.UtcNow;
        }
        finally
        {
            // A timed-out FreezeUnit can already have frozen the cgroup and blocked a control-process spawn. Thaw directly
            // even when that call never returned success; the manager must not be needed to release its own blocked spawn.
            thawed = cgroupDirectory is not null && ProcFs.WriteControl(Path.Combine(cgroupDirectory, "cgroup.freeze"), "0");
            try
            {
                manager.ThawUnit(unit);
            }
            catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException)
            {
                // Already stopping or collected: the direct thaw above is what matters.
            }
        }

        if (frozenAt is null)
        {
            // A failed freeze can race the root's exit and later forks. Recheck workload membership while leaving new controls alone.
            var remaining = KillOutsideControls(manager, unit, cgroupDirectory, mainPid);
            killed += remaining.Killed;
            if (remaining.Killed > 0)
            {
                killedAt = remaining.KilledAt;
            }
        }

        return new LimitStop(frozenAt is not null, killed, frozenAt, killedAt) { DirectThaw = thawed, ThawedAt = DateTimeOffset.UtcNow };

        Dictionary<int, long> Members() => cgroupDirectory is null
            ? []
            : ProcFs.Procs(cgroupDirectory).Select(pid => (Pid: pid, Stat: ProcFs.Stat(pid)))
                .Where(member => member.Stat is { State: not ('Z' or 'X') })
                .ToDictionary(member => member.Pid, member => member.Stat!.Value.StartTicks);
    }

    /// <summary>Kills remaining workload members after the root exits, without freezing or killing systemd's bounded control tree.</summary>
    private static LimitStop KillOutsideControls(SystemdManager manager, string unit, string? directory, int mainPid)
    {
        var killed = 0;
        for (var pass = 0; directory is not null && pass < 5; pass++)
        {
            var before = manager.State(unit);
            if (before is null)
            {
                break;
            }

            var members = ProcFs.Procs(directory).Select(pid => (Pid: pid, Stat: ProcFs.Stat(pid)))
                .Where(member => member.Stat is { State: not ('Z' or 'X') })
                .ToDictionary(member => member.Pid, member => (Parent: member.Stat!.Value.ParentPid, Start: member.Stat!.Value.StartTicks));
            var after = manager.State(unit);
            if (after is null)
            {
                break;
            }

            // A control can change from exec-stop to exit-record during the scan. Both snapshots' control trees are protected;
            // a control started after the scan has no PID in it and cannot be a kill candidate.
            var controls = new HashSet<int> { (int)before.ControlPid, (int)after.ControlPid };
            bool IsControl(int pid)
            {
                for (var depth = 0; depth < 64 && pid > 1; depth++)
                {
                    if (controls.Contains(pid))
                    {
                        return true;
                    }

                    if (!members.TryGetValue(pid, out var member))
                    {
                        break;
                    }

                    pid = member.Parent;
                }

                return false;
            }

            var workload = members.Where(member => !IsControl(member.Key)).OrderBy(member => member.Key == mainPid).ToArray();
            if (workload.Length == 0)
            {
                break;
            }

            foreach (var (pid, identity) in workload)
            {
                if (ProcFs.Stat(pid) is { State: not ('Z' or 'X') } live && live.StartTicks == identity.Start && Libc.Kill(pid, Libc.SigKill) == 0)
                {
                    killed++;
                }
            }

            Thread.Sleep(10);
        }

        return new LimitStop(false, killed, null, DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Thaws attempt cgroups left frozen with nothing but the user manager's own spawn in them, without the user manager (it may be blocked
    /// in that state): a node or guard that died between killing the processes of a frozen unit and thawing it leaves the manager spawning
    /// <c>ExecStop</c>/<c>ExecStopPost</c> into the frozen cgroup, where the spawn cannot run (systemd 257 blocks the whole manager until the
    /// cgroup is thawed; otherwise the unit waits for its stop timeout and its exit record is lost). A frozen cgroup with any process of the
    /// attempt's own (a paused attempt) is left alone; an empty frozen one is thawed. Every <c>arcforges-a-*.service</c> cgroup under the
    /// user's manager is checked (<paramref name="managerCgroup"/>: <c>user@&lt;uid&gt;.service</c>); returns the directories thawed.
    /// </summary>
    public static List<string> ReleaseStuckFreezes(string? managerCgroup = null)
    {
        var released = new List<string>();
        var root = managerCgroup ?? ManagerCgroup();
        if (!Directory.Exists(root))
        {
            return released;
        }

        var manager = ManagerPid(root);
        IEnumerable<string> units;
        try
        {
            units = [.. Directory.EnumerateDirectories(root, LinuxExecutionPlatform.UnitPrefix + "*.service", SearchOption.AllDirectories)];
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return released;
        }

        foreach (var directory in units)
        {
            var freeze = Path.Combine(directory, "cgroup.freeze");

            // The thaw decision. An attempt's own processes are excluded only while the unit has its own user namespace (hardening
            // applied and read back). Without it, an attempt process that made itself non-dumpable and took the name "systemd", "(...)" or
            // digits counts as the manager's spawn (see IsManagerSpawn), and a frozen unit whose processes all match is thawed here. That
            // is the only effect, and same-user code can thaw its own cgroup anyway (T-22).
            if (ProcFs.Text(freeze) == "1" && OnlyManagerSpawns(directory, manager) && ProcFs.WriteControl(freeze, "0"))
            {
                released.Add(directory);
            }
        }

        return released;
    }

    /// <summary>The user manager's cgroup directory (<c>user@&lt;uid&gt;.service</c>).</summary>
    internal static string ManagerCgroup() =>
        Path.Combine("/sys/fs/cgroup/user.slice", $"user-{ProcFs.UserId}.slice", $"user@{ProcFs.UserId}.service");

    /// <summary>The user manager's PID (the process of its <c>init.scope</c>), or 0.</summary>
    internal static int ManagerPid(string managerCgroup) => ProcFs.Procs(Path.Combine(managerCgroup, "init.scope")).FirstOrDefault();

    /// <summary>True when every process of <paramref name="directory"/> is the manager's spawn (or there is none).</summary>
    internal static bool OnlyManagerSpawns(string directory, int manager) => ProcFs.Procs(directory).All(pid => IsManagerSpawn(pid, manager));

    /// <summary>Whether <paramref name="pid"/> is the user manager's spawn (<see cref="IsManagerSpawn(int, int, string, string?)"/>).</summary>
    internal static bool IsManagerSpawn(int pid, int manager) =>
        ProcFs.Stat(pid) is { } stat && IsManagerSpawn(stat.ParentPid, manager, ProcFs.Image(pid), Executable(pid));

    /// <summary>
    /// Whether a process is one the user manager started for a unit's command that has not become that command. The check uses the
    /// process's parent, name and executable (null when <c>/proc/&lt;pid&gt;/exe</c> cannot be read). The parent must be the user
    /// manager (known). L-24 records three shapes (ArcForges-Design#23):
    /// <list type="bullet">
    /// <item>The executable is <c>systemd-executor</c>, whatever name the executor gives itself (systemd 255 and later; on 255.4 the
    /// name was <c>9</c>).</item>
    /// <item>A fork of the manager whose executable cannot be read (the manager is not dumpable), named <c>systemd</c> (257, frozen
    /// right after the fork) or with systemd's parenthesized pre-exec name (<c>(arcforges)</c>, <c>(sd-...)</c>).</item>
    /// <item>The executor's own name, made only of digits, with an executable that cannot be read (257.9: <c>9</c>).</item>
    /// </list>
    /// Limit: an attempt's own processes are excluded only while the unit has its own user namespace (hardening applied and read back).
    /// Its main process, and any orphan the manager (a subreaper) adopts, are children of the manager too. Inside that namespace the node
    /// owns the namespace and can read their executable even if they made themselves non-dumpable. Without it, an attempt process that
    /// makes itself non-dumpable (<c>prctl(PR_SET_DUMPABLE, 0)</c>, no privilege needed) and takes the name <c>systemd</c>, <c>(...)</c>
    /// or digits is treated as the manager's spawn. This was already true for the first two names. The only effect is that the start-up
    /// release and the guard may thaw a frozen unit whose processes all match (<see cref="ReleaseStuckFreezes"/>). Same-user code can thaw
    /// its own cgroup anyway (T-22), so this adds no new class of exposure.
    /// Probe (AF-SEC-01, systemd 257.9): in a plain user service an orphan named <c>9</c> that made itself non-dumpable had the manager as
    /// parent and an unreadable executable. In a <c>PrivateUsers=yes</c> service the same orphan's executable was readable.
    /// </summary>
    internal static bool IsManagerSpawn(int parentPid, int manager, string name, string? executable)
    {
        if (manager == 0 || parentPid != manager)
        {
            return false;
        }

        if (executable is not null)
        {
            const string Deleted = " (deleted)";
            var path = executable.EndsWith(Deleted, StringComparison.Ordinal) ? executable[..^Deleted.Length] : executable;
            return Path.GetFileName(path) == "systemd-executor";
        }

        return name == "systemd" || (name.Length > 2 && name[0] == '(' && name[^1] == ')') || (name.Length > 0 && name.All(char.IsAsciiDigit));
    }

    /// <summary>The target of <c>/proc/&lt;pid&gt;/exe</c>, or null when it cannot be read.</summary>
    internal static string? Executable(int pid)
    {
        try
        {
            return new FileInfo("/proc/" + pid.ToString(System.Globalization.CultureInfo.InvariantCulture) + "/exe").LinkTarget;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
