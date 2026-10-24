// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Platform;

/// <summary>
/// A command could not be prepared for execution: a catalogued <c>VALIDATION</c> code (errors.md) with the detail the error carries in
/// <c>details.state.reason</c>: <c>program_not_found</c> (the program), <c>unsafe_batch_argument</c> (the argument index),
/// <c>unsupported_shell</c> (the shell kind) or <c>invalid_argument</c> (the field and rule).
/// </summary>
public sealed class CommandRefusedException : Exception
{
    /// <summary>Creates the exception.</summary>
    public CommandRefusedException(string code, string reason)
        : base($"{code}: {reason}")
    {
        Code = code;
        Reason = reason;
    }

    /// <summary>Creates the exception.</summary>
    public CommandRefusedException()
        : this("invalid_argument", string.Empty)
    {
    }

    /// <summary>Creates the exception.</summary>
    public CommandRefusedException(string message)
        : this("invalid_argument", message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public CommandRefusedException(string message, Exception innerException)
        : base(message, innerException)
    {
        Code = "invalid_argument";
        Reason = message;
    }

    /// <summary>The catalogued VALIDATION code.</summary>
    public string Code { get; } = "invalid_argument";

    /// <summary><c>details.state.reason</c>.</summary>
    public string Reason { get; } = string.Empty;
}

/// <summary>What to run: an argument vector or a shell script, in a working directory, with the resolved environment.</summary>
public sealed class CommandRequest
{
    /// <summary>The argument vector (argv mode), or <see langword="null"/> in shell mode.</summary>
    public IReadOnlyList<string>? Argv { get; init; }

    /// <summary>The shell kind (shell mode).</summary>
    public ShellKind Shell { get; init; }

    /// <summary>The script (shell mode).</summary>
    public string? Script { get; init; }

    /// <summary>An absolute shell executable overriding the detected one (shell mode).</summary>
    public string? ShellPath { get; init; }

    /// <summary>The absolute working directory.</summary>
    public required string WorkingDirectory { get; init; }

    /// <summary>The resolved environment (its <c>PATH</c> and <c>PATHEXT</c> drive the program lookup).</summary>
    public required IReadOnlyDictionary<string, string> Environment { get; init; }

    /// <summary>The attempt's temporary directory, where long scripts are written; <see langword="null"/> while validating.</summary>
    public string? TempDirectory { get; init; }
}

/// <summary>A prepared command: what the platform starts.</summary>
public sealed class PreparedCommand
{
    /// <summary>The resolved executable (absolute path).</summary>
    public required string Application { get; init; }

    /// <summary>The complete command line (Windows), built with the quoting inverse to <c>CommandLineToArgvW</c>.</summary>
    public required string CommandLine { get; init; }

    /// <summary>The argument vector as the program receives it (Linux; informational on Windows).</summary>
    public required IReadOnlyList<string> Argv { get; init; }

    /// <summary>The program as the user named it, for summaries.</summary>
    public required string Program { get; init; }

    /// <summary>A script file the launch writes into the temporary directory first (long shell scripts, 04 section 2).</summary>
    public string? ScriptFile { get; init; }

    /// <summary>The script file's content.</summary>
    public string? ScriptContent { get; init; }

    /// <summary>The command runs a batch file through <c>cmd.exe /d /s /c</c>.</summary>
    public bool ViaBatch { get; init; }
}

/// <summary>The stdin of an attempt (04 section 3: NUL, a temporary file, a file, or a pipe).</summary>
public enum StdinKind
{
    /// <summary>The null device.</summary>
    None = 0,

    /// <summary>A file (FILE, or BYTES written to the temporary directory).</summary>
    File = 1,

    /// <summary>A pipe the node writes (STREAM).</summary>
    Stream = 2,
}

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
    /// enforced; an attempt that crossed it and exits non-zero ended at its memory limit (04 section 7 <c>MEMORY_LIMIT</c>). 0 uses the
    /// commit limit.
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

/// <summary>How to start one attempt.</summary>
public sealed class AttemptLaunch
{
    /// <summary>The node ID's text (job names).</summary>
    public required string NodeName { get; init; }

    /// <summary>The attempt's files.</summary>
    public required AttemptFiles Files { get; init; }

    /// <summary>The prepared command.</summary>
    public required PreparedCommand Command { get; init; }

    /// <summary>The exact environment as <c>NAME=value</c> entries.</summary>
    public required IReadOnlyList<string> Environment { get; init; }

    /// <summary>The working directory.</summary>
    public required string WorkingDirectory { get; init; }

    /// <summary>The stdin kind.</summary>
    public StdinKind Stdin { get; init; }

    /// <summary>The stdin file (FILE, or the BYTES file).</summary>
    public string? StdinPath { get; init; }

    /// <summary>The container limits.</summary>
    public required ContainerLimits Limits { get; init; }

    /// <summary>Launched by the node itself without a holder, in a container that dies with the node (AD-0005 Windows section 5).</summary>
    public bool KillWithNode { get; init; }

    /// <summary>Output capture <c>DISCARD</c>: stdout and stderr go to the null device.</summary>
    public bool DiscardOutput { get; init; }

    /// <summary>Launch steps (04 section 3).</summary>
    public IReadOnlyList<StepSpec> LaunchSteps { get; init; } = [];

    /// <summary>End steps (04 section 3).</summary>
    public IReadOnlyList<StepSpec> EndSteps { get; init; } = [];

    /// <summary><c>leftover_grace</c>.</summary>
    public int LeftoverGraceMs { get; init; } = 5_000;
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

    /// <summary>
    /// Raised (on a platform thread, with the process ID) for each process that enters the container of a handle re-opened for a stop while
    /// the launch may still go on, until a launch or exit record exists: on Windows the only sign that a launch the node no longer controls went
    /// on, since <see cref="Started"/> completes on the first such process only. Other handles never raise it.
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

    /// <summary>The write end of a STREAM stdin pipe.</summary>
    Stream? StdinWriter { get; }

    /// <summary>True while the root process (or, without one yet, the launch) has not finished.</summary>
    bool RootRunning { get; }

    /// <summary>True once the container reported a commit-limit (memory) event.</summary>
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

/// <summary>
/// An execution platform (architecture 02 section 1 "Platform layer"; AD-0005): the root container, attempt containers with their
/// holders, command preparation and recovery by name. The Windows platform is <c>WindowsExecutionPlatform</c>.
/// </summary>
public interface IExecutionPlatform : IDisposable
{
    /// <summary>The platform's name for logs.</summary>
    string Name { get; }

    /// <summary>How environment variable names compare (case-insensitive on Windows).</summary>
    StringComparer EnvironmentNames { get; }

    /// <summary>The machine's capacity.</summary>
    MachineCapacity Capacity { get; }

    /// <summary>The capability report (03 section 8) without its evaluation time, after <see cref="Start"/> verified the root container.</summary>
    CapabilityReport Evaluate();

    /// <summary>Creates or re-opens the root container and verifies enforcement with a probe container (02 section 2 step 6).</summary>
    void Start(string nodeName, RootLimits limits, string helperExecutable);

    /// <summary>Applies new root limits.</summary>
    void UpdateRootLimits(RootLimits limits);

    /// <summary>Resolves and builds the command (04 section 2).</summary>
    /// <exception cref="CommandRefusedException">The program, shell or an argument is refused.</exception>
    PreparedCommand Prepare(CommandRequest request);

    /// <summary>Creates the attempt's container and starts it (through its holder, or directly for <c>kill_with_node</c>).</summary>
    IAttemptHandle Launch(AttemptLaunch launch);

    /// <summary>
    /// Re-opens a recovered attempt's container by name, or returns <see langword="null"/> when it is gone. With <paramref name="stopping"/>
    /// (the node continues the attempt's stop) a launch that may still go on (no root recorded, no launch or exit record) is awaited:
    /// <see cref="IAttemptHandle.Started"/> completes when it continues. Otherwise the start completes at once with <paramref name="root"/>.
    /// </summary>
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
    /// <summary>The container name of an attempt (the Windows job name; the Linux unit name), recorded with the attempt.</summary>
    string ContainerName(string nodeName, string attemptName) => @"Local\ArcForges." + nodeName + "." + attemptName;

    /// <summary>
    /// Places an existing same-user process, and its children that exist now, under management in a new adoption container (04 section 10;
    /// R-RES-013): on Windows the root job and then a new adoption job nested under it; on Linux a transient scope in the node's slice.
    /// </summary>
    /// <exception cref="AdoptionRefusedException">The process is not the one named, not the node's user's, or the OS refused to place it.</exception>
    AdoptionResult Adopt(AdoptionRequest request) => throw new AdoptionRefusedException("process adoption is not supported on this platform");

    /// <summary>Re-opens a recorded adoption container by name after a node restart, or returns <see langword="null"/> when it is gone.</summary>
    IAdoptedContainer? ReopenAdopted(string containerName) => null;

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

/// <summary>A process to adopt (04 section 10).</summary>
/// <param name="NodeName">The node ID's text (container names).</param>
/// <param name="AttemptName">The adoption attempt's ID text (the container's own name).</param>
/// <param name="Pid">The process ID.</param>
/// <param name="Start">Its start time, which must match (a process ID alone may have been reused).</param>
public sealed record AdoptionRequest(string NodeName, string AttemptName, int Pid, DateTimeOffset Start);

/// <summary>The adoption container with how the children that existed at adoption time fared (04 section 10 step 3, best effort).</summary>
/// <param name="Container">The adoption container.</param>
/// <param name="Image">The adopted process's image.</param>
/// <param name="AdoptedChildren">Children placed in the container individually.</param>
/// <param name="FailedChildren">Children that could not be placed (each recorded in <paramref name="ChildResults"/>).</param>
/// <param name="ChildResults">One line per child: its image, ID and result.</param>
public sealed record AdoptionResult(IAdoptedContainer Container, string Image, int AdoptedChildren, int FailedChildren, IReadOnlyList<string> ChildResults);

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

/// <summary>The OS refused to place a process under management, or it is not the node's user's (<c>EXECUTION/adopt_not_permitted</c>).</summary>
public sealed class AdoptionRefusedException : Exception
{
    /// <summary>Creates the exception.</summary>
    public AdoptionRefusedException()
        : base("adoption refused")
    {
    }

    /// <summary>Creates the exception with the reason (<c>details.state.reason</c>).</summary>
    public AdoptionRefusedException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public AdoptionRefusedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>True when the process named does not exist (it exited, or its ID names a process that started later): <c>STATE/not_found</c>.</summary>
    public bool NotFound { get; init; }

    /// <summary>True when the process is already in one of this node's containers: <c>CONFLICT/already_exists</c>.</summary>
    public bool AlreadyManaged { get; init; }
}
