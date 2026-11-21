// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Platform;

/// <summary>The limits of an attempt's container (03 section 5.2).</summary>
public sealed class ContainerLimits
{
    /// <summary>The CPU weight 1-9 (INTERACTIVE 9, HIGH 7, NORMAL 5, LOW 3, BACKGROUND 1), unless <see cref="CpuRateCap"/> is set.</summary>
    public int CpuWeight { get; init; } = 5;

    /// <summary>A hard CPU cap in 1/100 percent of the parent's allocation (replaces the weight; Windows cannot combine both).</summary>
    public int? CpuRateCap { get; init; }

    /// <summary>The commit limit (<c>commit_factor x mem_ceiling</c>), or 0 for none.</summary>
    public long CommitLimitBytes { get; init; }

    /// <summary>
    /// The commit notification limit (<c>mem_ceiling</c>): crossing it is reported (and recorded as the <c>job_memory</c> violation), never
    /// enforced. A crossing and nonzero exit are <c>MEMORY_LIMIT</c> evidence (04 section 7), not proof that a hard cap refused an
    /// allocation. Zero uses the commit limit.
    /// </summary>
    public long CommitNotificationBytes { get; init; }

    /// <summary>The active process limit when policy sets one.</summary>
    public int? ActiveProcessLimit { get; init; }

    /// <summary>Linux <c>MemoryHigh</c> (<c>1.25 x mem_expected</c>, 03 section 5.2), or 0 for none.</summary>
    public long MemoryHighBytes { get; init; }

    /// <summary>Linux <c>MemoryMax</c> (<c>mem_ceiling</c>, 03 section 5.2), or 0 for none.</summary>
    public long MemoryMaxBytes { get; init; }

    /// <summary>Linux <c>MemorySwapMax</c> (<c>swap_allowance</c>, default 0), or <see langword="null"/> to leave it unset.</summary>
    public long? SwapMaxBytes { get; init; }

    /// <summary>Linux <c>TasksMax</c> (03 section 5.2: default 4096; the active process limit when policy sets one).</summary>
    public int TasksMax { get; init; } = 4096;
}

/// <summary>The limits of the node's root container (03 section 5.1).</summary>
/// <param name="CpuRate">The hard CPU cap in 1/100 percent of the machine (<c>round(B_cpu / C_cpu x 10000)</c>, at least 100).</param>
/// <param name="CommitLimitBytes"><c>commit_factor x (C_mem - R_mem)</c>.</param>
/// <param name="NotificationBytes">The soft-pressure notification limit (<c>B_mem</c>; Linux <c>MemoryHigh</c>).</param>
public sealed record RootLimits(int CpuRate, long CommitLimitBytes, long NotificationBytes)
{
    /// <summary>Linux <c>MemoryMax</c> of the slice: the hard bound <c>C_mem - R_mem</c> (03 section 5.4); 0 leaves it unset.</summary>
    public long HardMemoryBytes { get; init; }

    /// <summary>Linux <c>MemorySwapMax</c> of the slice: <c>swap_allowance</c> (default 0).</summary>
    public long SwapAllowanceBytes { get; init; }

    /// <summary>Linux <c>TasksMax</c> of the slice (03 section 5.1: 32768).</summary>
    public int TasksMax { get; init; } = 32_768;
}

/// <summary>The root process of an attempt.</summary>
/// <param name="Pid">Its process ID.</param>
/// <param name="StartTime">Its creation time.</param>
public sealed record RootProcess(int Pid, DateTimeOffset StartTime);

/// <summary>A container's accounting (04 section 3).</summary>
public sealed record ContainerAccounting(long CpuUserMs, long CpuKernelMs, long MemPeakBytes, long IoReadBytes, long IoWriteBytes, int ActiveProcesses,
    IReadOnlyList<string> LimitViolations);

/// <summary>What the graceful phase did (04 section 6 step 1).</summary>
/// <param name="ConsoleSignalled">CTRL_BREAK_EVENT reached the root's process group.</param>
/// <param name="WindowsClosed">Top-level windows of processes in the container that received <c>WM_CLOSE</c>.</param>
/// <param name="Reason">Why the console signal failed (the root exited, it is not a console program, or the attach failed).</param>
public sealed record GracefulOutcome(bool ConsoleSignalled, int WindowsClosed, string? Reason);

/// <summary>A process of an attempt's container.</summary>
/// <param name="Pid">The process ID.</param>
/// <param name="Image">Its image name.</param>
public sealed record ContainerProcess(int Pid, string Image);

/// <summary>A process outside an attempt's container that descends from one of its processes (03 section 9: <c>ESCAPED</c>).</summary>
/// <param name="Pid">The process ID.</param>
/// <param name="ParentPid">The parent process ID (a member of the container or another escaped process).</param>
/// <param name="StartTime">Its creation time.</param>
/// <param name="Image">Its image name.</param>
/// <param name="SameUser">It runs as the node's user (only such processes are ever terminated).</param>
public sealed record EscapedProcess(int Pid, int ParentPid, DateTimeOffset StartTime, string Image, bool SameUser);

/// <summary>A running (or recovered) attempt's container, as the node controls it.</summary>
public interface IAttemptHandle : IDisposable
{
    /// <summary>The container's name (Windows job name).</summary>
    string ContainerName { get; }

    /// <summary>The root process once known.</summary>
    RootProcess? Root { get; }

    /// <summary>
    /// Completes once the root process runs (its identity), or with <see langword="null"/> when the launch failed. A handle re-opened after a
    /// node restart completes it at once with the recorded root, unless it was re-opened for a stop while the launch may still go on (no root
    /// recorded, no launch or exit record; <see cref="IExecutionPlatform.Reopen"/>). It then completes when the platform sees the launch
    /// continue, which may be a launch step rather than the root (Windows: the first process that enters the job; Linux: the unit's queued
    /// start job completing, with its main process), or when the handle is disposed.
    /// </summary>
    Task<RootProcess?> Started { get; }

    /// <summary>The known root start in UTC; a recovered Windows holder supplies its durable resume time.</summary>
    DateTimeOffset? StartedAt => Root?.StartTime;

    /// <summary>
    /// Raised (on a platform thread, with the process ID) when a launch the node no longer controls goes on, in a handle re-opened while the
    /// launch may still go on (no root recorded, no launch or exit record), until a launch or exit record exists. Windows: each process that
    /// enters the job, the only sign that the launch went on, since <see cref="Started"/> completes on the first such process only (a stop) or
    /// at once (any other re-open). The adapter's end steps (04 section 3) enter the job before the exit record too, so a forced phase that
    /// watches the launch ends a stopped attempt's end steps as well, as for a stop's re-open; that includes a recovered attempt whose command
    /// started while the node was down, which Windows re-opens without a root. Linux: the unit's main process, once the queued start job that
    /// <see cref="WatchLaunch"/> found completed. Other handles never raise it.
    /// </summary>
    event Action<int>? LaunchProcessEntered
    {
        add
        {
        }

        remove
        {
        }
    }

    /// <summary>
    /// Called by every forced phase before its termination, once it subscribed to <see cref="LaunchProcessEntered"/>. True when the handle was
    /// re-opened after a node restart for an attempt the node was not stopping (its <see cref="Started"/> completed at once), while its launch
    /// may still go on (no root recorded, no launch or exit record), and now reports that launch through <see cref="LaunchProcessEntered"/>:
    /// Windows, every process that enters the job, the end steps included (each is then terminated, as for a stop's re-open); Linux, the unit's
    /// queued start job read now (<c>PendingStartJob</c>), once, false when none waits. Every other handle returns false, a handle re-opened for
    /// a stop included (its <see cref="Started"/> awaits the launch). Never throws.
    /// </summary>
    bool WatchLaunch() => false;

    /// <summary>The write end of a STREAM stdin pipe.</summary>
    Stream? StdinWriter { get; }

    /// <summary>True while the root process (or, without one yet, the launch) has not finished.</summary>
    bool RootRunning { get; }

    /// <summary>Memory-limit evidence reported by the platform; Windows confirms its own job, never a nested job packet alone.</summary>
    bool MemoryLimitHit { get; }

    /// <summary>Raised on a platform thread when the attempt changed (started, root exited, record written, a limit event).</summary>
    event Action? Changed;

    /// <summary>The durable exit record, once written.</summary>
    ExitRecord? TryReadExit();

    /// <summary>The failed launch step, if any.</summary>
    LaunchRecord? TryReadLaunchFailure();

    /// <summary>The processes in the container now.</summary>
    IReadOnlyList<ContainerProcess> Processes();

    /// <summary>The container's accounting now.</summary>
    ContainerAccounting Accounting();

    /// <summary>Terminates every process in the container at once (the forced phase, and limit stops).</summary>
    void Terminate();

    /// <summary>The graceful phase: CTRL_BREAK_EVENT to the root's process group through the helper, and WM_CLOSE to GUI windows.</summary>
    GracefulOutcome RequestGracefulStop();

    /// <summary>
    /// The ancestry scan (04 section 3): descendants of the attempt's processes, running or exited, that run outside the container. The node
    /// records them and terminates the same-user ones by identity in the stop sequence (04 section 6 step 4; <see cref="IExecutionPlatform.TerminateProcess"/>).
    /// </summary>
    IReadOnlyList<EscapedProcess> ScanEscaped();

    /// <summary>The node recorded the attempt: the holder may release the container and exit.</summary>
    void Acknowledge();

    /// <summary>
    /// A limit stop (04 section 6 step 4: <c>OUTPUT_LIMIT</c>, <c>DISK_LIMIT</c>, critical pressure): no graceful phase. Linux freezes the
    /// unit and then kills it; Windows terminates the job at once. Returns what was done, for the record and the log.
    /// </summary>
    string StopAtLimit()
    {
        Terminate();
        return "terminated at once";
    }

    /// <summary>The graceful phase with the task's <c>stop_signal</c> (Linux only; Windows ignores it).</summary>
    GracefulOutcome RequestGracefulStop(string? stopSignal) => RequestGracefulStop();

    /// <summary>Called on every enforcement cycle: a platform that observes its containers by polling does it here.</summary>
    void Refresh()
    {
    }

    /// <summary>
    /// What the container uses now (03 sections 1 and 3), sampled every second while the attempt runs. The default sums the members of
    /// <see cref="Processes"/> in <paramref name="processes"/> (the process table, when the caller read one) for processor time and memory,
    /// and takes I/O from <see cref="Accounting"/>; the Windows and Linux unit handles read their containers instead.
    /// </summary>
    AttemptUsage Usage(IReadOnlyDictionary<int, ProcessSample>? processes)
    {
        var accounting = Accounting();
        var pids = Processes().Select(process => process.Pid).ToList();
        long cpu = 0, memory = 0;
        foreach (var pid in pids)
        {
            if (processes is not null && processes.TryGetValue(pid, out var process))
            {
                cpu += process.CpuTimeMs;
                memory += process.MemoryBytes;
            }
        }

        return new AttemptUsage(Math.Max(cpu, accounting.CpuUserMs + accounting.CpuKernelMs), memory, accounting.IoReadBytes, accounting.IoWriteBytes, pids);
    }

    /// <summary>True when <see cref="Usage"/> sums the container's memory from the process table (the caller then reads one every second).</summary>
    bool UsageNeedsProcessTable => true;

    /// <summary>True when the container can be paused as a whole (03 section 5.2: Linux <c>FreezeUnit</c>; Windows reports pause unsupported).</summary>
    bool CanPause => false;

    /// <summary>Pauses every process of the container (R-EXE-011: <c>FreezeUnit</c>, which returns once <c>cgroup.freeze</c> holds).</summary>
    void Freeze() => throw new NotSupportedException("Pause is not supported on this platform.");

    /// <summary>Resumes a paused container (<c>ThawUnit</c>).</summary>
    void Thaw() => throw new NotSupportedException("Pause is not supported on this platform.");

    /// <summary>
    /// Sets the container's soft memory limit (Linux <c>MemoryHigh</c>, through the user manager); the Pressure level lowers it to current
    /// usage to force reclaim and restores it at thaw (03 section 7). A platform without a soft limit ignores it.
    /// </summary>
    void SetMemoryHigh(long bytes)
    {
    }

    /// <summary>
    /// Changes the container's CPU weight to a priority weight (1-9; 03 section 5.2: Windows job weight, Linux <c>CPUWeight</c>) for
    /// <c>SetTaskPriority</c> on a running attempt. A container with a hard CPU cap keeps its cap. A platform without weights ignores it.
    /// </summary>
    void SetCpuWeight(int weight)
    {
    }
    /// <summary>
    /// True once a process of the container was seen running a launcher into a virtual machine (<c>wsl.exe</c>; 03 section 9,
    /// R-RES-002): the processes it starts in the VM are outside the container and are never presented as controlled.
    /// </summary>
    bool CrossesVmBoundary => false;
}

/// <summary>The machine's capacity as the platform sees it (03 section 2).</summary>
/// <param name="LogicalProcessors">Logical processors.</param>
/// <param name="PhysicalMemoryBytes">Physical memory.</param>
public sealed record MachineCapacity(int LogicalProcessors, long PhysicalMemoryBytes);

/// <summary>The original legacy process scope could not be observed reliably.</summary>
public sealed class LegacyCustodyUnavailableException : IOException
{
    /// <summary>Creates a custody failure.</summary>
    public LegacyCustodyUnavailableException() : base("Legacy process custody could not be confirmed.") { }

    /// <summary>Creates a custody failure with the platform reason.</summary>
    public LegacyCustodyUnavailableException(string message) : base(message) { }

    /// <summary>Creates a custody failure with the underlying observation error.</summary>
    public LegacyCustodyUnavailableException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// The legacy root container and the controls needed to recover existing attempt containers and holders by name.
/// </summary>
public interface IExecutionPlatform : IDisposable
{
    /// <summary>The platform's name for logs.</summary>
    string Name { get; }

    /// <summary>The machine's capacity.</summary>
    MachineCapacity Capacity { get; }

    /// <summary>The capability report (03 section 8) without its evaluation time, after <see cref="Start"/> verified the root container.</summary>
    CapabilityReport Evaluate();

    /// <summary>Creates or re-opens the root container and verifies enforcement with a probe container (02 section 2 step 6).</summary>
    void Start(string nodeName, RootLimits limits, string helperExecutable);

    /// <summary>Applies new root limits.</summary>
    void UpdateRootLimits(RootLimits limits);

    /// <summary>
    /// Re-opens a recovered attempt's container by name, or returns <see langword="null"/> when it is gone. With <paramref name="stopping"/>
    /// (the node continues the attempt's stop) a launch that may still go on (no root recorded, no launch or exit record) is awaited:
    /// <see cref="IAttemptHandle.Started"/> completes when it continues. Otherwise the start completes at once with <paramref name="root"/>, and
    /// a forced phase that stops the attempt later still sees such a launch go on (<see cref="IAttemptHandle.WatchLaunch"/>).
    /// </summary>
    /// <exception cref="LegacyCustodyUnavailableException">The original container's existence could not be determined.</exception>
    IAttemptHandle? Reopen(string nodeName, AttemptFiles files, RootProcess? root, bool stopping = false);

    /// <summary>
    /// Acknowledges the exit record of an attempt the store already records as finished, when its holder still waits (the node stopped
    /// between the record's commit and the acknowledgement). Returns true when a waiting holder was released.
    /// </summary>
    bool AcknowledgeRecorded(string nodeName, string attemptName);

    /// <summary>
    /// True when one of <paramref name="processIds"/> listens on TCP <paramref name="port"/> on a loopback or wildcard address (the
    /// <c>tcp_listen_port</c> readiness condition of 04 section 8; only the service's own processes count).
    /// </summary>
    bool Listens(int port, IReadOnlyCollection<int> processIds) => false;
    /// <summary>Re-opens a recorded adoption container by name after a node restart, or returns <see langword="null"/> when it is gone.</summary>
    /// <exception cref="LegacyCustodyUnavailableException">The original container's existence could not be determined.</exception>
    IAdoptedContainer? ReopenAdopted(string containerName) => throw new LegacyCustodyUnavailableException();

    /// <summary>
    /// Terminates the process identified by <paramref name="pid"/> and its start time when it still is that process and runs as the node's
    /// user (a process ID alone is never trusted: it may have been reused).
    /// </summary>
    ProcessTermination TerminateProcess(int pid, DateTimeOffset start) => ProcessTermination.Failed;
}

/// <summary>What <see cref="IExecutionPlatform.TerminateProcess"/> did.</summary>
public enum ProcessTermination
{
    /// <summary>The process was terminated.</summary>
    Terminated = 0,

    /// <summary>The process had already exited (its ID is free, or names a process that started later).</summary>
    Gone = 1,

    /// <summary>The process runs as another user: it is never terminated.</summary>
    OtherUser = 2,

    /// <summary>The OS refused or the platform cannot terminate processes.</summary>
    Failed = 3,
}

/// <summary>An adoption container: the adopted process and every process that joined it since (later children follow the container).</summary>
public interface IAdoptedContainer : IDisposable
{
    /// <summary>The container's name (the Windows adoption job's name; the Linux scope unit).</summary>
    string ContainerName { get; }

    /// <summary>The processes in the container now.</summary>
    IReadOnlyList<int> Processes();

    /// <summary>Terminates every process in the container.</summary>
    void Terminate();

    /// <summary>
    /// Gives up an adoption the node could not record, without terminating anything, and says what became of its processes (review round 2).
    /// </summary>
    string Abandon() => "the container was released; its processes keep running, not adopted";
}
