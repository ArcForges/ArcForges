// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Text;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;

namespace ArcForges.Node.Platform.Linux;

/// <summary>
/// The Linux observation sources (03 section 1): machine CPU from <c>/proc/stat</c>, memory, commit and swap from <c>/proc/meminfo</c>
/// and OOM kills from <c>/proc/vmstat</c> on every call; pressure from <c>/proc/pressure/{cpu,memory,io}</c> and block I/O from
/// <c>/proc/diskstats</c> (physical disks only, so stacked devices are not counted twice) at most every 5 s; and the process table from
/// <c>/proc/&lt;pid&gt;/stat</c>, with <c>status</c>, <c>io</c> and the <c>exe</c> link as the detail of selected processes. The files
/// are read into a reused buffer and parsed as bytes: the node samples every second (15 section 1 idle CPU target), so a sample
/// allocates almost nothing.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxResourceSampler : IResourceSampler
{
    /// <summary>How long pressure and disk counters are reused (03 section 1: pressure every 5 s).</summary>
    public static readonly TimeSpan SlowInterval = TimeSpan.FromSeconds(5);

    private static readonly long PageSize = Environment.SystemPageSize;
    private readonly List<byte[]> _disks = [];
    private readonly Lock _gate = new();
    private readonly byte[] _machine = new byte[16 * 1024];
    private long _slowAt = long.MinValue;
    private PressureStall? _pressure;
    private (long Read, long Written) _io;

    /// <summary>Creates the sampler; the physical disks are those of <c>/sys/block</c> with a <c>device</c> link.</summary>
    public LinuxResourceSampler()
    {
        try
        {
            foreach (var block in Directory.EnumerateDirectories("/sys/block"))
            {
                if (Path.Exists(Path.Combine(block, "device")))
                {
                    _disks.Add(Encoding.ASCII.GetBytes(Path.GetFileName(block)));
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    /// <inheritdoc />
    public string Name => "linux";

    /// <inheritdoc />
    public MachineSample Machine()
    {
        lock (_gate)
        {
            var buffer = _machine.AsSpan();

            // The first line of /proc/stat: cpu user nice system idle iowait irq softirq steal (guest time is already part of user).
            long busy = 0, total = 0;
            ReadOnlySpan<byte> stat = buffer[..Math.Max(0, ReadFile("/proc/stat", buffer[..512]))];
            if (stat.StartsWith("cpu "u8))
            {
                var line = stat[4..];
                for (var index = 0; index < 8 && NextNumber(ref line, out var value); index++)
                {
                    total += value;
                    if (index is not 3 and not 4)
                    {
                        busy += value;
                    }
                }
            }

            var meminfo = buffer[..Math.Max(0, ReadFile("/proc/meminfo", buffer))];
            var memTotal = Kib(meminfo, "MemTotal:"u8);
            var available = Kib(meminfo, "MemAvailable:"u8);
            var committed = Kib(meminfo, "Committed_AS:"u8);
            var limit = Kib(meminfo, "CommitLimit:"u8);
            var swap = Math.Max(0, Kib(meminfo, "SwapTotal:"u8) - Kib(meminfo, "SwapFree:"u8));
            var oom = Value(buffer[..Math.Max(0, ReadFile("/proc/vmstat", buffer))], "oom_kill "u8);
            var now = Environment.TickCount64;
            if (_slowAt == long.MinValue || now - _slowAt >= (long)SlowInterval.TotalMilliseconds)
            {
                _slowAt = now;
                _pressure = ReadPressure(buffer);
                _io = DiskBytes(buffer);
            }

            return new MachineSample
            {
                CpuBusyMs = busy * 1000 / ProcFs.TicksPerSecond,
                CpuTotalMs = total * 1000 / ProcFs.TicksPerSecond,
                TotalMemoryBytes = memTotal,
                AvailableMemoryBytes = available,
                CommitBytes = committed,
                CommitLimitBytes = limit,
                SwapUsedBytes = swap,
                IoReadBytes = _io.Read,
                IoWriteBytes = _io.Written,
                Pressure = _pressure,
                OomKills = oom,
            };
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<ProcessSample> Processes()
    {
        var processes = new List<ProcessSample>(512);
        Span<byte> buffer = stackalloc byte[1024];
        foreach (var pid in ProcFs.AllProcesses())
        {
            if (Read(pid, buffer) is { } process)
            {
                processes.Add(process);
            }
        }

        return processes;
    }

    /// <inheritdoc />
    public ProcessSample Detail(ProcessSample process)
    {
        ArgumentNullException.ThrowIfNull(process);
        var directory = "/proc/" + process.Pid.ToString(CultureInfo.InvariantCulture);
        Span<byte> buffer = stackalloc byte[4096];
        var status = buffer[..Math.Max(0, ReadFile(directory + "/status", buffer))];
        long? resident = status.IsEmpty ? null : Kib(status, "RssAnon:"u8) + Kib(status, "RssShmem:"u8);

        // /proc/<pid>/io and the exe link are readable only for the node's own processes (ptrace access); others stay unobserved, never zero.
        var length = ReadFile(directory + "/io", buffer);
        long? read = null, written = null;
        if (length > 0)
        {
            read = Value(buffer[..length], "read_bytes: "u8);
            written = Value(buffer[..length], "write_bytes: "u8);
        }

        string? executable = null;
        try
        {
            if (new FileInfo(directory + "/exe").LinkTarget is { Length: > 0 } target)
            {
                executable = Path.GetFileName(target.EndsWith(" (deleted)", StringComparison.Ordinal) ? target[..^10] : target);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        return process with
        {
            Executable = executable,
            MemoryBytes = resident ?? process.MemoryBytes,
            IoReadBytes = read,
            IoWriteBytes = written,
        };
    }

    /// <summary>One process from <c>/proc/&lt;pid&gt;/stat</c> (processor times, start and RSS), or null when it is gone.</summary>
    internal static ProcessSample? Read(int pid, Span<byte> buffer)
    {
        var length = ReadFile("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/stat", buffer);
        if (length <= 0)
        {
            return null;
        }

        ReadOnlySpan<byte> text = buffer[..length];
        var open = text.IndexOf((byte)'(');
        var close = text.LastIndexOf((byte)')');
        if (open < 0 || close < open || close + 2 >= text.Length)
        {
            return null;
        }

        // Fields after the command name: state (3), ppid (4), ..., utime (14), stime (15), ..., starttime (22), vsize (23), rss (24).
        var rest = text[(close + 2)..];
        long parent = 0, user = 0, system = 0, start = 0, rss = 0;
        for (var field = 3; field <= 24; field++)
        {
            var space = rest.IndexOf((byte)' ');
            var token = space < 0 ? rest : rest[..space];
            switch (field)
            {
                case 4:
                    parent = Number(token);
                    break;
                case 14:
                    user = Number(token);
                    break;
                case 15:
                    system = Number(token);
                    break;
                case 22:
                    start = Number(token);
                    break;
                case 24:
                    rss = Number(token);
                    break;
            }

            if (space < 0)
            {
                if (field < 24)
                {
                    return null;
                }

                break;
            }

            rest = rest[(space + 1)..];
        }

        return new ProcessSample(pid, (int)parent, ProcFs.StartInstant(start), Encoding.UTF8.GetString(text[(open + 1)..close]))
        {
            CpuTimeMs = (user + system) * 1000 / ProcFs.TicksPerSecond,
            MemoryBytes = Math.Max(0, rss) * PageSize,
        };
    }

    /// <summary>Pressure stall information, or null when the kernel has none (<c>CONFIG_PSI</c> off or <c>psi=0</c>).</summary>
    private static PressureStall? ReadPressure(Span<byte> buffer)
    {
        var cpu = Psi("/proc/pressure/cpu", buffer);
        var memory = Psi("/proc/pressure/memory", buffer);
        var io = Psi("/proc/pressure/io", buffer);
        return cpu is null || memory is null || io is null ? null : new PressureStall(cpu.Value.Some, memory.Value.Some, memory.Value.Full, io.Value.Some);
    }

    private static (double Some, double Full)? Psi(string path, Span<byte> buffer)
    {
        var length = ReadFile(path, buffer);
        if (length <= 0)
        {
            return null;
        }

        // some avg10=0.00 avg60=0.00 avg300=0.00 total=0
        // full avg10=0.00 avg60=0.00 avg300=0.00 total=0
        ReadOnlySpan<byte> text = buffer[..length];
        return (Average(text, "some avg10="u8), Average(text, "full avg10="u8));
    }

    private static double Average(ReadOnlySpan<byte> text, ReadOnlySpan<byte> key)
    {
        var at = text.IndexOf(key);
        return at >= 0 && Utf8Parser.TryParse(text[(at + key.Length)..], out double value, out _) ? value : 0;
    }

    private (long Read, long Written) DiskBytes(Span<byte> buffer)
    {
        long read = 0, written = 0;
        ReadOnlySpan<byte> text = buffer[..Math.Max(0, ReadFile("/proc/diskstats", buffer))];
        Span<long> numbers = stackalloc long[10];
        while (!text.IsEmpty)
        {
            var end = text.IndexOf((byte)'\n');
            var line = end < 0 ? text : text[..end];
            text = end < 0 ? [] : text[(end + 1)..];

            // major minor name reads merged sectors-read ms writes merged sectors-written ...; sectors are 512 bytes.
            numbers.Clear();
            var name = ReadOnlySpan<byte>.Empty;
            var index = 0;
            foreach (var range in line.Split((byte)' '))
            {
                var token = line[range];
                if (token.IsEmpty)
                {
                    continue;
                }

                if (index == 2)
                {
                    name = token;
                }
                else if (index < numbers.Length)
                {
                    numbers[index] = Number(token);
                }

                if (++index >= numbers.Length)
                {
                    break;
                }
            }

            foreach (var disk in _disks)
            {
                if (index >= numbers.Length && name.SequenceEqual(disk))
                {
                    read += numbers[5] * 512;
                    written += numbers[9] * 512;
                }
            }
        }

        return (read, written);
    }

    /// <summary>Reads a file into <paramref name="buffer"/>; returns the bytes read, or -1 when it cannot be read.</summary>
    private static int ReadFile(string path, Span<byte> buffer)
    {
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var total = 0;
            while (total < buffer.Length)
            {
                var read = RandomAccess.Read(handle, buffer[total..], total);
                if (read <= 0)
                {
                    break;
                }

                total += read;
            }

            return total;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return -1;
        }
    }

    /// <summary>A <c>key value kB</c> line of <c>meminfo</c> or <c>status</c> in bytes, or 0.</summary>
    private static long Kib(ReadOnlySpan<byte> text, ReadOnlySpan<byte> key) => Value(text, key) * 1024;

    /// <summary>The number after <paramref name="key"/> at the start of a line, or 0.</summary>
    private static long Value(ReadOnlySpan<byte> text, ReadOnlySpan<byte> key)
    {
        var at = 0;
        while (true)
        {
            var found = text[at..].IndexOf(key);
            if (found < 0)
            {
                return 0;
            }

            found += at;
            if (found == 0 || text[found - 1] == (byte)'\n')
            {
                var rest = text[(found + key.Length)..];
                return NextNumber(ref rest, out var value) ? value : 0;
            }

            at = found + key.Length;
        }
    }

    /// <summary>A decimal token, or 0 when it is not one (a field the kernel left out reads as none).</summary>
    private static long Number(ReadOnlySpan<byte> token) => Utf8Parser.TryParse(token, out long value, out _) ? value : 0;

    /// <summary>Skips spaces and parses the next unsigned number of <paramref name="text"/>, advancing it.</summary>
    private static bool NextNumber(ref ReadOnlySpan<byte> text, out long value)
    {
        var start = 0;
        while (start < text.Length && text[start] is (byte)' ' or (byte)'\t')
        {
            start++;
        }

        text = text[start..];
        if (!Utf8Parser.TryParse(text, out value, out var consumed) || consumed == 0)
        {
            return false;
        }

        text = text[consumed..];
        return true;
    }
}
