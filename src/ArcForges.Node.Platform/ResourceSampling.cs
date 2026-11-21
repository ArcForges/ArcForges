// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Platform;

/// <summary>Pressure stall information (Linux <c>/proc/pressure/{cpu,memory,io}</c>, the 10 s averages in percent).</summary>
/// <param name="CpuSome">cpu some avg10.</param>
/// <param name="MemorySome">memory some avg10.</param>
/// <param name="MemoryFull">memory full avg10.</param>
/// <param name="IoSome">io some avg10.</param>
public sealed record PressureStall(double CpuSome, double MemorySome, double MemoryFull, double IoSome);

/// <summary>
/// One machine sample (03 section 1: machine CPU and memory every 1 s; pressure every 5 s). CPU times are cumulative milliseconds of
/// processor time over every logical processor, so a delta over a wall interval in milliseconds, times 1,000, is millicores.
/// </summary>
public sealed record MachineSample
{
    /// <summary>Busy processor time so far (Windows <c>GetSystemTimes</c> kernel + user - idle; Linux <c>/proc/stat</c> without idle and iowait).</summary>
    public required long CpuBusyMs { get; init; }

    /// <summary>Total processor time so far (busy and idle).</summary>
    public required long CpuTotalMs { get; init; }

    /// <summary>Physical memory (<c>GlobalMemoryStatusEx</c> total; <c>MemTotal</c>).</summary>
    public required long TotalMemoryBytes { get; init; }

    /// <summary>Available memory (<c>GlobalMemoryStatusEx</c> available; <c>MemAvailable</c>).</summary>
    public required long AvailableMemoryBytes { get; init; }

    /// <summary>Committed memory (Windows commit total; Linux <c>Committed_AS</c>).</summary>
    public long CommitBytes { get; init; }

    /// <summary>The commit limit (Windows commit limit; Linux <c>CommitLimit</c>).</summary>
    public long CommitLimitBytes { get; init; }

    /// <summary>Swap in use (Linux <c>SwapTotal - SwapFree</c>; Windows 0).</summary>
    public long SwapUsedBytes { get; init; }

    /// <summary>
    /// Bytes read from block devices so far (Linux <c>/proc/diskstats</c>); 0 on Windows, whose machine I/O is the sum of the process
    /// table's transfer counts (<see cref="IResourceSampler.MachineIoFromProcesses"/>).
    /// </summary>
    public long IoReadBytes { get; init; }

    /// <summary>Bytes written to block devices so far.</summary>
    public long IoWriteBytes { get; init; }

    /// <summary>Pressure stall information, or <see langword="null"/> where the platform has none (Windows) or the kernel does not expose it.</summary>
    public PressureStall? Pressure { get; init; }

    /// <summary>OOM kills machine-wide so far (Linux <c>/proc/vmstat</c> <c>oom_kill</c>); 0 on Windows.</summary>
    public long OomKills { get; init; }
}

/// <summary>
/// One process of the process table (03 section 1: the process list and its detail). Identity is <c>(pid, start time)</c>, never the
/// ID alone. Memory is the process's private resident memory: the private working set on Windows, <c>RssAnon + RssShmem</c> on Linux
/// (the RSS of <c>/proc/&lt;pid&gt;/stat</c> until the detail is read).
/// </summary>
/// <param name="Pid">The process ID.</param>
/// <param name="ParentPid">The parent process ID.</param>
/// <param name="StartTime">Its creation time.</param>
/// <param name="Image">Its image name (Windows) or command name (Linux).</param>
public sealed record ProcessSample(int Pid, int ParentPid, DateTimeOffset StartTime, string Image)
{
    /// <summary>User and kernel processor time so far.</summary>
    public long CpuTimeMs { get; init; }

    /// <summary>Private resident memory.</summary>
    public long MemoryBytes { get; init; }

    /// <summary>The executable's file name when the detail read it (Linux truncates the command name to 15 characters), else null.</summary>
    public string? Executable { get; init; }

    /// <summary>Bytes read so far, or <see langword="null"/> when unobserved (never read as zero, 03 section 1).</summary>
    public long? IoReadBytes { get; init; }

    /// <summary>Bytes written so far, or <see langword="null"/> when unobserved.</summary>
    public long? IoWriteBytes { get; init; }
}

/// <summary>
/// The platform's observation sources (03 section 1; R-RES-001). Every call reads the operating system now; the node's resource monitor
/// decides how often. Implementations: <c>WindowsResourceSampler</c> and <c>LinuxResourceSampler</c>.
/// </summary>
public interface IResourceSampler
{
    /// <summary>The sampler's name for logs.</summary>
    string Name { get; }

    /// <summary>The machine's CPU times, memory, I/O and pressure now.</summary>
    MachineSample Machine();

    /// <summary>
    /// Every visible process with its processor time and memory. Windows reads the whole table in one system call
    /// (<c>NtQuerySystemInformation(SystemProcessInformation)</c>), without opening any process; Linux reads <c>/proc/&lt;pid&gt;/stat</c>.
    /// </summary>
    IReadOnlyList<ProcessSample> Processes();

    /// <summary>
    /// The detail of selected processes (03 section 1: managed trees and the top 20): private resident memory and I/O where the table
    /// does not carry them (Linux <c>/proc/&lt;pid&gt;/status</c> and <c>io</c>; Windows returns the table's own values).
    /// </summary>
    ProcessSample Detail(ProcessSample process) => process;

    /// <summary>
    /// True when the machine's I/O is the sum of the processes' I/O transfer counts of the process table (Windows), rather than the block
    /// device counters of <see cref="Machine"/> (Linux). Unobserved I/O is never stored as no I/O (03 section 1).
    /// </summary>
    bool MachineIoFromProcesses => false;

    /// <summary>True when <paramref name="image"/> names a virtual machine's worker process (03 section 9 <c>GUEST_VM</c>; A-L01).</summary>
    bool IsVmWorker(string image) => false;

    /// <summary>True when <paramref name="image"/> names a launcher into a virtual machine (<c>wsl.exe</c>; 03 section 9 <c>crosses_vm_boundary</c>).</summary>
    bool IsVmLauncher(string image) => false;
}

/// <summary>Native host observations used by the Sandbox resource monitor.</summary>
public sealed record HostResourceObservation
{
    /// <summary>Monotonic time of the underlying host counters in Stopwatch ticks.</summary>
    public long? MonotonicTimestamp { get; init; }
    public uint? CpuCapacityMillicores { get; init; }
    public ulong? CpuBusyUsec { get; init; }
    public ulong? PhysicalTotalBytes { get; init; }
    public ulong? PhysicalAvailableBytes { get; init; }
    public ulong? CommitBytes { get; init; }
    public ulong? CommitLimitBytes { get; init; }
    public ulong? NodeCpuUsec { get; init; }
    public ulong? NodeResidentBytes { get; init; }
    public ulong? OomKills { get; init; }
    public double? PsiCpuSome { get; init; }
    public double? PsiMemorySome { get; init; }
    public double? PsiMemoryFull { get; init; }
}

/// <summary>An observation source whose absent measurements have no numeric value.</summary>
public interface IHostResourceSource
{
    HostResourceObservation ObserveHostResources();
}

/// <summary>The native memory accounting used by an owned Run scope.</summary>
public enum RunMemoryAccounting
{
    WindowsCommit,
    LinuxCgroupCurrent,
}

/// <summary>
/// Readback from the original owned resource scope. Native controller bytes and resident estimates
/// have separate meanings. Null fields represent unavailable measurements.
/// </summary>
public sealed record RunResourceObservation(RunMemoryAccounting Accounting)
{
    public ulong? CumulativeCpuUsec { get; init; }
    public ulong? MemoryBytes { get; init; }
    public ulong? PeakMemoryBytes { get; init; }
    public ulong? ResidentBytes { get; init; }
    public ulong? OomKills { get; init; }
    public uint? ProcessCount { get; init; }
    public double? PsiCpuSome { get; init; }
    public double? PsiMemorySome { get; init; }
    public double? PsiMemoryFull { get; init; }
}

/// <summary>Reads a Run through its already verified platform resource handle.</summary>
public interface IRunResourceSource
{
    RunResourceObservation? ObserveRunResources();
}

/// <summary>The independently readable dimensions of a platform-owned Run scope.</summary>
public enum RunResourceDimension
{
    Cpu,
    Memory,
    ProcessCount,
    CpuWeight,
    Swap,
}

/// <summary>Current finite limits queried from the original owned scope.</summary>
public sealed record RunResourceLimitReading(string BoundaryIdentity, ulong? CpuMillicores, ulong? MemoryBytes,
    ulong? MaxProcesses, ulong? CpuWeight, ulong? SwapMaxBytes)
{
    public ulong? Value(RunResourceDimension dimension) => dimension switch
    {
        RunResourceDimension.Cpu => CpuMillicores,
        RunResourceDimension.Memory => MemoryBytes,
        RunResourceDimension.ProcessCount => MaxProcesses,
        RunResourceDimension.CpuWeight => CpuWeight,
        RunResourceDimension.Swap => SwapMaxBytes,
        _ => null,
    };
}

/// <summary>The outcome of a native setter, independent of its subsequent readback.</summary>
public enum RunResourceWriteStatus
{
    Applied,
    Unsupported,
    Failed,
    ScopeLost,
}

public readonly record struct RunResourceWriteResult(RunResourceWriteStatus Status, ulong? AppliedValue = null,
    string? Reason = null);

/// <summary>Controls only the original ArcForges-owned resource scope of a Run.</summary>
public interface IRunResourceControl
{
    /// <summary>Queries the actual limits. An unavailable scope has no readback.</summary>
    RunResourceLimitReading? ReadRunLimits();

    /// <summary>Normalizes a requested bound to the platform's conservative representable value.</summary>
    ulong? NormalizeRunLimit(RunResourceDimension dimension, ulong value);

    /// <summary>Applies one limit. Query the same scope separately to confirm enforcement.</summary>
    RunResourceWriteResult ApplyRunLimit(RunResourceDimension dimension, ulong value);
}
