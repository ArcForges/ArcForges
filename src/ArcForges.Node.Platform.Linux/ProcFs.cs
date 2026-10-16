// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Linux;

/// <summary>The accounting of one cgroup (04 section 3: <c>cpu.stat</c>, <c>memory.peak</c>, <c>memory.events</c>, <c>io.stat</c>).</summary>
/// <param name="CpuUserMs">User CPU time.</param>
/// <param name="CpuKernelMs">System CPU time.</param>
/// <param name="MemPeakBytes">Peak memory (<c>memory.peak</c>).</param>
/// <param name="MemCurrentBytes">Current memory (<c>memory.current</c>).</param>
/// <param name="SwapPeakBytes">Peak swap (<c>memory.swap.peak</c>), or null when the kernel has none.</param>
/// <param name="IoReadBytes">Bytes read (<c>io.stat</c> rbytes, all devices).</param>
/// <param name="IoWriteBytes">Bytes written (<c>io.stat</c> wbytes).</param>
/// <param name="Processes">Processes in the cgroup.</param>
/// <param name="MemoryHighEvents"><c>memory.events</c> high.</param>
/// <param name="MemoryMaxEvents"><c>memory.events</c> max.</param>
/// <param name="OomKills"><c>memory.events</c> oom_kill.</param>
/// <param name="TasksMaxEvents"><c>pids.events</c> max.</param>
public sealed record CgroupAccounting(long CpuUserMs, long CpuKernelMs, long MemPeakBytes, long MemCurrentBytes, long? SwapPeakBytes, long IoReadBytes,
    long IoWriteBytes, int Processes, long MemoryHighEvents, long MemoryMaxEvents, long OomKills, long TasksMaxEvents)
{
    /// <summary>The limit violations in the vocabulary of <c>exit.json</c>: <c>memory_high</c>, <c>memory_max</c>, <c>oom_kill</c>, <c>tasks_max</c>.</summary>
    public List<string> Violations()
    {
        var list = new List<string>();
        if (MemoryHighEvents > 0)
        {
            list.Add("memory_high");
        }

        if (MemoryMaxEvents > 0)
        {
            list.Add("memory_max");
        }

        if (OomKills > 0)
        {
            list.Add("oom_kill");
        }

        if (TasksMaxEvents > 0)
        {
            list.Add("tasks_max");
        }

        return list;
    }
}

/// <summary>Reads <c>/proc</c> and the cgroup v2 hierarchy (<c>/sys/fs/cgroup</c>).</summary>
[SupportedOSPlatform("linux")]
public static partial class ProcFs
{
    /// <summary>The cgroup v2 mount.</summary>
    public const string CgroupRoot = "/sys/fs/cgroup";

    private static readonly Lazy<long> s_bootTime = new(ReadBootTime);
    private static readonly Lazy<long> s_ticks = new(() => Math.Max(1, SysConf(2)));

    /// <summary>The user ID of this process.</summary>
    public static uint UserId => GetUid();

    /// <summary>The cgroup path of a process (the unified hierarchy's <c>0::</c> line), or null.</summary>
    public static string? CgroupOf(int pid)
    {
        try
        {
            foreach (var line in File.ReadAllLines(Path.Combine("/proc", pid.ToString(CultureInfo.InvariantCulture), "cgroup")))
            {
                if (line.StartsWith("0::", StringComparison.Ordinal))
                {
                    return line[3..];
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        return null;
    }

    /// <summary>This process's cgroup path.</summary>
    public static string? OwnCgroup() => CgroupOf(Environment.ProcessId);

    /// <summary>The directory of a cgroup path.</summary>
    public static string CgroupDirectory(string cgroupPath)
    {
        ArgumentNullException.ThrowIfNull(cgroupPath);
        return CgroupRoot + (cgroupPath.StartsWith('/') ? cgroupPath : "/" + cgroupPath);
    }

    /// <summary>The process IDs in a cgroup directory (its <c>cgroup.procs</c>); empty when it is gone.</summary>
    public static List<int> Procs(string directory)
    {
        var pids = new List<int>();
        try
        {
            foreach (var line in File.ReadAllLines(Path.Combine(directory, "cgroup.procs")))
            {
                if (int.TryParse(line, NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
                {
                    pids.Add(pid);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        return pids;
    }

    /// <summary>The accounting of a cgroup directory now, or null when it is gone.</summary>
    public static CgroupAccounting? Accounting(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return null;
        }

        var cpu = KeyValues(Path.Combine(directory, "cpu.stat"));
        var memory = KeyValues(Path.Combine(directory, "memory.events"));
        var pids = KeyValues(Path.Combine(directory, "pids.events"));
        long read = 0, written = 0;
        foreach (var line in Lines(Path.Combine(directory, "io.stat")))
        {
            foreach (var field in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var equals = field.IndexOf('=', StringComparison.Ordinal);
                if (equals > 0 && long.TryParse(field.AsSpan(equals + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var value))
                {
                    if (field.StartsWith("rbytes=", StringComparison.Ordinal))
                    {
                        read += value;
                    }
                    else if (field.StartsWith("wbytes=", StringComparison.Ordinal))
                    {
                        written += value;
                    }
                }
            }
        }

        return new CgroupAccounting(
            Get(cpu, "user_usec") / 1000, Get(cpu, "system_usec") / 1000,
            Number(Path.Combine(directory, "memory.peak")) ?? 0,
            Number(Path.Combine(directory, "memory.current")) ?? 0,
            Number(Path.Combine(directory, "memory.swap.peak")),
            read, written, Procs(directory).Count,
            Get(memory, "high"), Get(memory, "max"), Get(memory, "oom_kill"), Get(pids, "max"));
    }

    /// <summary>A single number file (<c>memory.max</c> reads <c>max</c> as <see cref="long.MaxValue"/>), or null.</summary>
    public static long? Number(string path)
    {
        var text = Text(path);
        if (text is null)
        {
            return null;
        }

        return text == "max" ? long.MaxValue : long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : null;
    }

    /// <summary>A file's text without the trailing line break, or null when it cannot be read.</summary>
    public static string? Text(string path)
    {
        try
        {
            return File.ReadAllText(path).TrimEnd('\n');
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Writes a cgroup control file (<c>cgroup.freeze</c>) in place: opened for writing without truncation, creation or locks, as the
    /// kernel expects. Returns false when the write failed (the cgroup is gone).
    /// </summary>
    public static bool WriteControl(string path, string text)
    {
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            RandomAccess.Write(handle, System.Text.Encoding.ASCII.GetBytes(text), 0);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary><c>key value</c> lines (<c>cpu.stat</c>, <c>memory.events</c>, <c>cgroup.events</c>).</summary>
    public static Dictionary<string, long> KeyValues(string path)
    {
        var values = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var line in Lines(path))
        {
            var space = line.IndexOf(' ', StringComparison.Ordinal);
            if (space > 0 && long.TryParse(line.AsSpan(space + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var value))
            {
                values[line[..space]] = value;
            }
        }

        return values;
    }

    /// <summary>A process's start (clock ticks since boot, and the instant), or null when it is gone or a zombie.</summary>
    public static (long Ticks, DateTimeOffset Start)? StartOf(int pid)
    {
        var stat = Stat(pid);
        if (stat is null || stat.Value.State is 'Z' or 'X')
        {
            return null;
        }

        var ticks = stat.Value.StartTicks;
        return (ticks, DateTimeOffset.FromUnixTimeMilliseconds((s_bootTime.Value * 1000) + (ticks * 1000 / s_ticks.Value)));
    }

    /// <summary>The instant of a start-tick value.</summary>
    public static DateTimeOffset StartInstant(long ticks) => DateTimeOffset.FromUnixTimeMilliseconds((s_bootTime.Value * 1000) + (ticks * 1000 / s_ticks.Value));

    /// <summary>A process's state, parent and start ticks from <c>/proc/&lt;pid&gt;/stat</c>, or null.</summary>
    public static (char State, int ParentPid, int ProcessGroup, long StartTicks)? Stat(int pid)
    {
        var text = Text(Path.Combine("/proc", pid.ToString(CultureInfo.InvariantCulture), "stat"));
        if (text is null)
        {
            return null;
        }

        var close = text.LastIndexOf(')');
        if (close < 0 || close + 2 >= text.Length)
        {
            return null;
        }

        // Fields after the parenthesised command name: state (3), ppid (4), pgrp (5), ..., starttime (22).
        var fields = text[(close + 2)..].Split(' ');
        return fields.Length > 19
            && int.TryParse(fields[1], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var parent)
            && int.TryParse(fields[2], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var group)
            && long.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out var start)
            ? (fields[0][0], parent, group, start)
            : null;
    }

    /// <summary>A process's command name (<c>/proc/&lt;pid&gt;/comm</c>), or <c>?</c>.</summary>
    public static string Image(int pid) => Text(Path.Combine("/proc", pid.ToString(CultureInfo.InvariantCulture), "comm")) ?? "?";

    /// <summary>The owner of a process (the real user ID of <c>/proc/&lt;pid&gt;/status</c>), or null.</summary>
    public static uint? OwnerOf(int pid)
    {
        foreach (var line in Lines(Path.Combine("/proc", pid.ToString(CultureInfo.InvariantCulture), "status")))
        {
            if (line.StartsWith("Uid:", StringComparison.Ordinal))
            {
                var fields = line[4..].Split('\t', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                return fields.Length > 0 && uint.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ? uid : null;
            }
        }

        return null;
    }

    /// <summary>Every process ID in <c>/proc</c>.</summary>
    public static IEnumerable<int> AllProcesses()
    {
        IEnumerable<string> entries;
        try
        {
            entries = Directory.EnumerateDirectories("/proc");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var entry in entries)
        {
            if (int.TryParse(Path.GetFileName(entry), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
            {
                yield return pid;
            }
        }
    }

    /// <summary>The machine's memory (<c>MemTotal</c> of <c>/proc/meminfo</c>) in bytes.</summary>
    public static long PhysicalMemory()
    {
        foreach (var line in Lines("/proc/meminfo"))
        {
            if (line.StartsWith("MemTotal:", StringComparison.Ordinal))
            {
                var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length >= 2 && long.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var kib))
                {
                    return kib * 1024;
                }
            }
        }

        return GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
    }

    private static long Get(Dictionary<string, long> values, string key) => values.TryGetValue(key, out var value) ? value : 0;

    private static string[] Lines(string path)
    {
        try
        {
            return File.ReadAllLines(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static long ReadBootTime()
    {
        foreach (var line in Lines("/proc/stat"))
        {
            if (line.StartsWith("btime ", StringComparison.Ordinal) && long.TryParse(line.AsSpan(6), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
            {
                return seconds;
            }
        }

        return 0;
    }

    [LibraryImport("libc", EntryPoint = "sysconf")]
    private static partial long SysConf(int name);

    [LibraryImport("libc", EntryPoint = "getuid")]
    private static partial uint GetUid();
}
