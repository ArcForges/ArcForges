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
    /// Thaws attempt cgroups left frozen with nothing but the user manager's own spawn in them, without the user manager (it is blocked in
    /// that state): a node or guard that died between killing the processes of a frozen unit and thawing it leaves the manager spawning
    /// <c>ExecStop</c> into the frozen cgroup, which blocks the whole manager until the cgroup is thawed. A frozen cgroup whose processes
    /// are the attempt's own (a paused attempt) is left alone. Every <c>arcforges-a-*.service</c> cgroup under the user's manager is
    /// checked (<paramref name="managerCgroup"/>: <c>user@&lt;uid&gt;.service</c>); returns the directories thawed.
    /// </summary>
    public static List<string> ReleaseStuckFreezes(string? managerCgroup = null)
    {
        var released = new List<string>();
        var root = managerCgroup ?? Path.Combine("/sys/fs/cgroup/user.slice", $"user-{ProcFs.UserId}.slice", $"user@{ProcFs.UserId}.service");
        if (!Directory.Exists(root))
        {
            return released;
        }

        var manager = ProcFs.Procs(Path.Combine(root, "init.scope")).FirstOrDefault();
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
            if (ProcFs.Text(freeze) != "1")
            {
                continue;
            }

            // The manager's spawn is its child still named after it ("systemd", or "(sd-...)" before it renames itself).
            var stuck = ProcFs.Procs(directory).All(pid => ProcFs.Stat(pid) is { } stat && (manager == 0 || stat.ParentPid == manager)
                && ProcFs.Image(pid) is var image && (image == "systemd" || image.StartsWith("(sd-", StringComparison.Ordinal)));
            if (stuck && ProcFs.WriteControl(freeze, "0"))
            {
                released.Add(directory);
            }
        }

        return released;
    }
}
