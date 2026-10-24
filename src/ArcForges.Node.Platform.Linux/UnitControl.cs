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
    /// the thaw must not depend on the manager. A unit that cannot be frozen (already stopping) has its processes killed as they are, in
    /// up to five passes. <c>ExecStop</c> and <c>ExecStopPost</c> then run as after any exit, so <c>exit.json</c> is written.
    /// </summary>
    public static LimitStop FreezeAndKill(SystemdManager manager, string unit, string? cgroupDirectory, int mainPid)
    {
        ArgumentNullException.ThrowIfNull(manager);
        DateTimeOffset? frozenAt = null;
        try
        {
            manager.FreezeUnit(unit);
            frozenAt = DateTimeOffset.UtcNow;
        }
        catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException)
        {
            // Not active (stopping, or gone): the processes are killed as they are.
        }

        var killed = 0;
        if (cgroupDirectory is not null)
        {
            for (var pass = 0; pass < 5; pass++)
            {
                var pids = ProcFs.Procs(cgroupDirectory);
                if (pids.Count == 0)
                {
                    break;
                }

                foreach (var pid in pids.Where(pid => pid != mainPid).Append(mainPid).Where(pid => pid != 0 && pids.Contains(pid)))
                {
                    if (Libc.Kill(pid, Libc.SigKill) == 0)
                    {
                        killed++;
                    }
                }

                if (frozenAt is not null)
                {
                    // Frozen: nothing forked in between, every process got its signal.
                    break;
                }

                Thread.Sleep(10);
            }
        }

        var killedAt = DateTimeOffset.UtcNow;
        var thawed = frozenAt is null || (cgroupDirectory is not null && ProcFs.WriteControl(Path.Combine(cgroupDirectory, "cgroup.freeze"), "0"));
        if (frozenAt is not null)
        {
            try
            {
                manager.ThawUnit(unit);
            }
            catch (Exception exception) when (exception is DBusExceptionBase or TimeoutException)
            {
                // Already stopping: the direct thaw above is what matters.
            }
        }

        return new LimitStop(frozenAt is not null, killed, frozenAt, killedAt) { DirectThaw = thawed, ThawedAt = DateTimeOffset.UtcNow };
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
