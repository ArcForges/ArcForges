// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.Contracts.Node.V1;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// The Windows execution platform (AD-0005 Windows; architecture 04 sections 3, 6 and 9):
/// <list type="bullet">
/// <item>The root job <c>Local\ArcForges.&lt;node&gt;.root</c> with a hard CPU cap, a commit limit and a soft-pressure notification limit,
/// created or re-opened at startup and verified with a probe job (02 section 2 step 6).</item>
/// <item>Each attempt's child job <c>Local\ArcForges.&lt;node&gt;.&lt;attempt&gt;</c> (weight or cap, commit limit, optional active-process
/// limit, never breakaway), started by its holder <c>arcforges node exec-wrap</c> outside the job; <c>kill_with_node</c> attempts are
/// started by the node itself in a job with <c>KILL_ON_JOB_CLOSE</c>.</item>
/// <item>One completion port for every child job; recovered jobs are re-associated by clearing the previous run's port first (L-15).</item>
/// </list>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsExecutionPlatform : IExecutionPlatform
{
    /// <summary>The ending of every resource guarantee's reason (03 sections 5 and 8; 11 section 1: T-22, T-23).</summary>
    public const string SameUserQualifier = "; same-user code can change or end ArcForges' containers (T-22), and work launched outside the recorded ancestry never joins them (T-23)";

    /// <summary>The exit code of a process <see cref="TerminateProcess"/> ends.</summary>
    public const uint TerminatedExitCode = 0xC000013A;

    /// <summary>How far a process's creation time may differ from the one named (FILETIME, 100 ns): 20 ms.</summary>
    private const long IdentityToleranceFileTime = 200_000;

    private const uint SignalTimeoutMs = 5_000;
    private readonly ConcurrentDictionary<nuint, WindowsAttemptHandle> _attempts = new();
    private readonly SafeKernelHandle _port;
    private readonly Thread _portThread;
    private JobObject? _root;
    private RootLimits? _rootLimits;
    private JobCount? _jobMembership;
    private string _nodeName = string.Empty;
    private string _helper = string.Empty;
    private string? _selfTest;
    private long _nextKey;
    private bool _disposed;

    /// <summary>Creates the platform and its completion port.</summary>
    public WindowsExecutionPlatform()
    {
        _port = Native.CreateIoCompletionPort(-1, 0, 0, 1);
        if (_port.IsInvalid)
        {
            throw new Win32Exception(Native.LastError, "CreateIoCompletionPort failed.");
        }

        Capacity = new MachineCapacity(Environment.ProcessorCount, ProcessInfo.PhysicalMemory());
        _portThread = new Thread(PortLoop) { IsBackground = true, Name = "arcforges-job-port" };
        _portThread.Start();
    }

    /// <inheritdoc />
    public string Name => "windows-jobs";

    /// <inheritdoc />
    public StringComparer EnvironmentNames => StringComparer.OrdinalIgnoreCase;

    /// <inheritdoc />
    public MachineCapacity Capacity { get; }

    /// <summary>The root job's name.</summary>
    public string RootJobName => JobName(_nodeName, "root");

    /// <summary>The root job (after <see cref="Start"/>).</summary>
    public JobObject? RootJob => _root;

    /// <summary>The priority class every attempt's job enforces on its processes: <c>BELOW_NORMAL_PRIORITY_CLASS</c> (03 section 5.2, amended).</summary>
    public const uint AttemptPriorityClass = Native.BelowNormalPriorityClass;

    /// <summary>The name of an attempt's child job.</summary>
    public static string JobName(string nodeName, string attemptName) => @"Local\ArcForges." + nodeName + "." + attemptName;

    /// <summary>The name of an attempt's ack event.</summary>
    public static string AckName(string nodeName, string attemptName) => JobName(nodeName, attemptName) + ".ack";

    /// <inheritdoc />
    public void Start(string nodeName, RootLimits limits, string helperExecutable)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeName);
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentException.ThrowIfNullOrWhiteSpace(helperExecutable);
        _nodeName = nodeName;
        _helper = helperExecutable;
        _root = JobObject.Create(RootJobName, openExisting: true);
        UpdateRootLimits(limits);
        _selfTest = SelfTest();
    }

    /// <inheritdoc />
    public void UpdateRootLimits(RootLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        var root = _root ?? throw new InvalidOperationException("The platform has not started.");
        root.SetCpuHardCap(Math.Clamp(limits.CpuRate, 100, 10_000));
        root.SetLimits(limits.CommitLimitBytes, activeProcessLimit: null, killOnClose: false);
        if (limits.NotificationBytes > 0)
        {
            root.SetMemoryNotification(limits.NotificationBytes);
        }

        _rootLimits = limits;
    }

    /// <inheritdoc />
    public CapabilityReport Evaluate()
    {
        var enforced = _root is not null && _selfTest is null;
        var why = enforced ? string.Empty : _selfTest ?? "the root job has not been created";
        var report = new CapabilityReport
        {
            Cpu = enforced ? CpuControl.EnforcedShareAndCap : CpuControl.ObserveOnly,
            CpuReason = enforced ? "job CPU rate control: weighted attempt jobs under a hard-capped root job (V-W04)" : why,
            Memory = enforced ? MemoryControl.EnforcedCommit : MemoryControl.ObserveOnly,
            MemoryReason = enforced ? "job commit limits bound committed memory, not physical memory (V-W05; 03 section 5.4)" : why,
            // No policy field sets a process-count limit in this build, so no attempt gets one: counted (job accounting), not enforced.
            Pids = ProcessCountControl.ObserveOnly,
            PidsReason = enforced
                ? "processes are counted by job accounting; no policy field sets a job active-process limit in this build"
                : why,
            Io = IoControl.ObserveOnly,
            IoReason = "Windows jobs account I/O but do not limit it without privileges",
            Pause = PauseSupport.Unsupported,
            PauseReason = "Windows has no supported job-wide freeze (AD-0005 Windows section 8)",
            KillTree = enforced ? KillTreeGuarantee.Guaranteed : KillTreeGuarantee.BestEffort,
            KillTreeReason = (enforced ? "TerminateJobObject ends every process of the attempt's job; jobs allow no breakaway" : why) + SameUserQualifier,
            Adopt = enforced ? AdoptSupport.Limited : AdoptSupport.Unsupported,
            AdoptReason = enforced ? AdoptReasonNow() : why,
            RestartSurvival = enforced,
            RestartSurvivalReason = enforced ? "each attempt's holder keeps its jobs openable by name across node restarts (L-14)" : why,
        };
        report.PlatformFacts.Add(new KeyValue { Name = "os", Value = RuntimeInformation.OSDescription });
        report.PlatformFacts.Add(new KeyValue { Name = "arch", Value = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant() });
        report.PlatformFacts.Add(new KeyValue { Name = "runtime", Value = RuntimeInformation.FrameworkDescription });
        report.PlatformFacts.Add(new KeyValue { Name = "job_nesting", Value = "root job then attempt job (V-W01)" });
        report.PlatformFacts.Add(new KeyValue { Name = "logical_processors", Value = Capacity.LogicalProcessors.ToString(CultureInfo.InvariantCulture) });
        report.PlatformFacts.Add(new KeyValue { Name = "physical_memory_bytes", Value = Capacity.PhysicalMemoryBytes.ToString(CultureInfo.InvariantCulture) });
        if (_rootLimits is { } limits)
        {
            report.PlatformFacts.Add(new KeyValue { Name = "root_job", Value = RootJobName });
            report.PlatformFacts.Add(new KeyValue { Name = "root_cpu_rate", Value = limits.CpuRate.ToString(CultureInfo.InvariantCulture) });
            report.PlatformFacts.Add(new KeyValue { Name = "root_commit_limit_bytes", Value = limits.CommitLimitBytes.ToString(CultureInfo.InvariantCulture) });
        }

        Native.IsProcessInJob(new SafeKernelHandle(Native.GetCurrentProcess(), ownsHandle: false), 0, out var nodeInJob);
        report.PlatformFacts.Add(new KeyValue { Name = "node_in_job", Value = nodeInJob ? "true" : "false" });
        return report;
    }

    /// <summary>
    /// The adopt capability's reason (04 section 10): a process already in a job is refused, so how many of the user's processes are in a job
    /// now is stated with it (counted at most once a minute; a few milliseconds over the process table).
    /// </summary>
    private string AdoptReasonNow()
    {
        var now = Environment.TickCount64;
        var membership = Volatile.Read(ref _jobMembership);
        if (membership is null || now - membership.At > 60_000)
        {
            var (inJob, total) = JobMembership();
            membership = new JobCount(now, inJob, total);
            Volatile.Write(ref _jobMembership, membership);
        }

        return string.Create(CultureInfo.InvariantCulture,
            $"a process already in a job is refused (04 section 10); {membership.InJob} of the user's {membership.Total} processes are in a job now. ")
            + "A same-user process outside every job joins the root job and then its own adoption job (V-W01); its exit status is not captured, "
            + "and its adoption job is not re-opened after a node restart";
    }

    private sealed record JobCount(long At, int InJob, int Total);

    /// <summary>How many of the processes of this user (that the node can query) are in a job, and how many there are.</summary>
    internal static (int InJob, int Total) JobMembership()
    {
        var (inJob, total) = (0, 0);
        foreach (var (pid, _, _) in ProcessInfo.Snapshot())
        {
            using var process = ProcessInfo.Open(pid);
            if (process is null || !EscapedProcesses.IsSameUser(process))
            {
                continue;
            }

            total++;
            if (Native.IsProcessInJob(process, 0, out var member) && member)
            {
                inJob++;
            }
        }

        return (inJob, total);
    }

    /// <inheritdoc />
    public PreparedCommand Prepare(CommandRequest request) => WindowsCommands.Prepare(request);

    /// <inheritdoc />
    public AdoptionResult Adopt(AdoptionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var root = _root is not null && _selfTest is null ? _root : throw new AdoptionRefusedException(_selfTest ?? "the root job has not been created");
        using var process = OpenForAdoption(request.Pid, request.Start.ToFileTime())
            ?? throw new AdoptionRefusedException($"no process {request.Pid.ToString(CultureInfo.InvariantCulture)} started at that time") { NotFound = true };
        if (!EscapedProcesses.IsSameUser(process))
        {
            throw new AdoptionRefusedException("the process runs as another user (adoption is same-user only, R-RES-013)");
        }

        if (root.Contains(process))
        {
            throw new AdoptionRefusedException("the process is already in a job of this node") { AlreadyManaged = true };
        }

        // 04 section 10: joining a foreign job would attach the ArcForges hierarchy to it.
        if (Native.IsProcessInJob(process, 0, out var inJob) && inJob)
        {
            throw new AdoptionRefusedException("the process is already in a job (IsProcessInJob); joining it would attach the ArcForges jobs to a foreign job");
        }

        var name = JobName(request.NodeName, request.AttemptName);
        var job = JobObject.Create(name);
        try
        {
            var inRoot = false;
            try
            {
                // V-W01: root first, then the adoption job, which nests it under the root.
                root.Assign(process);
                inRoot = true;
                job.Assign(process);
            }
            catch (Win32Exception exception)
            {
                // Windows offers no way to take a process out of a job: a process the root job accepted but the adoption job refused stays in
                // the root job, under its limits, without being adopted. That outcome is reported as it is, and the API audits it (review
                // round 1). It cannot happen where every process is already in a job (L-30): such a process is refused above.
                throw new AdoptionRefusedException(inRoot
                    ? $"the process is now in this node's root job, which it cannot leave, but the adoption job refused it ({exception.Message}): it is not adopted"
                    : $"the operating system refused to place the process in a job ({exception.Message})", exception);
            }

            var image = ProcessInfo.ImageName(process) ?? request.Pid.ToString(CultureInfo.InvariantCulture);
            var (adopted, failed, results) = AdoptChildren(root, job, request.Pid, ProcessInfo.CreationFileTime(process));
            return new AdoptionResult(new WindowsAdoptedJob(job), image, adopted, failed, results);
        }
        catch
        {
            job.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public IAdoptedContainer? ReopenAdopted(string containerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerName);
        return JobObject.Open(containerName) is { } job ? new WindowsAdoptedJob(job) : null;
    }

    /// <inheritdoc />
    public ProcessTermination TerminateProcess(int pid, DateTimeOffset start)
    {
        using var process = ProcessInfo.Open(pid, terminate: true);
        if (process is null)
        {
            return ProcessInfo.Open(pid) is { } readable && Matches(readable, start.ToFileTime()) ? Disposed(readable, ProcessTermination.Failed) : ProcessTermination.Gone;
        }

        if (!Matches(process, start.ToFileTime()) || !ProcessInfo.IsRunning(process))
        {
            return ProcessTermination.Gone;
        }

        if (!EscapedProcesses.IsSameUser(process))
        {
            return ProcessTermination.OtherUser;
        }

        return Native.TerminateProcess(process, TerminatedExitCode) ? ProcessTermination.Terminated
            : ProcessInfo.IsRunning(process) ? ProcessTermination.Failed : ProcessTermination.Gone;
    }

    private static ProcessTermination Disposed(SafeKernelHandle handle, ProcessTermination result)
    {
        handle.Dispose();
        return result;
    }

    private static bool Matches(SafeKernelHandle process, long creationFileTime) =>
        ProcessInfo.CreationFileTime(process) is var created and > 0 && Math.Abs(created - creationFileTime) <= IdentityToleranceFileTime;

    /// <summary>Opens a process with the rights a job assignment needs, when it is still the one created at <paramref name="creationFileTime"/>.</summary>
    private static SafeKernelHandle? OpenForAdoption(int pid, long creationFileTime)
    {
        var handle = Native.OpenProcess(Native.ProcessQueryLimitedInformation | Native.Synchronize | Native.ProcessTerminate | Native.ProcessSetQuota, inherit: false, pid);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            return null;
        }

        if (!Matches(handle, creationFileTime) || !ProcessInfo.IsRunning(handle))
        {
            handle.Dispose();
            return null;
        }

        return handle;
    }

    /// <summary>
    /// 04 section 10 step 3: the children of the adopted process that exist now (descendants by parent ID, each created within its parent's
    /// lifetime) join the root job and the adoption job one by one, best effort, each result recorded. Later children follow the job.
    /// </summary>
    private static (int Adopted, int Failed, List<string> Results) AdoptChildren(JobObject root, JobObject job, int pid, long created)
    {
        var table = ProcessInfo.Snapshot();
        var results = new List<string>();
        var adopted = 0;
        var failed = 0;
        var frontier = new Queue<(int Pid, long Created)>([(pid, created)]);
        var seen = new HashSet<int> { pid };
        while (frontier.TryDequeue(out var parent) && seen.Count < 4096)
        {
            foreach (var child in table.Where(entry => entry.ParentPid == parent.Pid && !seen.Contains(entry.Pid)))
            {
                using var process = Native.OpenProcess(Native.ProcessQueryLimitedInformation | Native.Synchronize | Native.ProcessTerminate | Native.ProcessSetQuota,
                    inherit: false, child.Pid);
                var childCreated = process.IsInvalid ? 0 : ProcessInfo.CreationFileTime(process);
                if (process.IsInvalid || childCreated < parent.Created)
                {
                    // Gone, or created before its parent: its parent ID belongs to another process.
                    continue;
                }

                seen.Add(child.Pid);
                frontier.Enqueue((child.Pid, childCreated));
                if (job.Contains(process))
                {
                    adopted++;
                    results.Add($"{child.Image} ({child.Pid.ToString(CultureInfo.InvariantCulture)}): adopted (it followed its parent)");
                    continue;
                }

                try
                {
                    if (Native.IsProcessInJob(process, 0, out var inJob) && inJob)
                    {
                        throw new Win32Exception(5, "the process is already in a job");
                    }

                    root.Assign(process);
                    job.Assign(process);
                    adopted++;
                    results.Add($"{child.Image} ({child.Pid.ToString(CultureInfo.InvariantCulture)}): adopted");
                }
                catch (Win32Exception exception)
                {
                    failed++;
                    results.Add($"{child.Image} ({child.Pid.ToString(CultureInfo.InvariantCulture)}): not adopted ({exception.Message})");
                }
            }
        }

        return (adopted, failed, results);
    }

    /// <inheritdoc />
    public bool Listens(int port, IReadOnlyCollection<int> processIds) => ListeningSockets.Listens(port, processIds);

    /// <inheritdoc />
    public IAttemptHandle Launch(AttemptLaunch launch)
    {
        ArgumentNullException.ThrowIfNull(launch);
        var root = _root ?? throw new InvalidOperationException("The platform has not started.");
        var files = launch.Files;
        Directory.CreateDirectory(files.Directory);
        Directory.CreateDirectory(files.TempDirectory);
        if (launch.Command.ScriptFile is { } scriptFile)
        {
            File.WriteAllText(scriptFile, launch.Command.ScriptContent ?? string.Empty, new UTF8Encoding(false));
        }

        var job = JobObject.Create(JobName(launch.NodeName, files.AttemptName));
        var key = (nuint)Interlocked.Increment(ref _nextKey);
        WindowsAttemptHandle? handle = null;
        SafeFileHandle? stdout = null, stderr = null;
        SafeHandle? stdin = null;
        Stream? stdinWriter = null;
        try
        {
            // Every attempt runs below normal priority, enforced by its job (03 section 5.2 as amended for AF-SCHED-01): the root's hard cap
            // bounds managed CPU over each rate-control interval, but within one, normal-priority managed threads would contend with the
            // user's own interactive work for the reserved headroom; below normal they always yield to it. The order among managed tasks
            // stays the jobs' CPU weights.
            job.SetLimits(launch.Limits.CommitLimitBytes, launch.Limits.ActiveProcessLimit, killOnClose: launch.KillWithNode, priorityClass: AttemptPriorityClass);
            if (launch.Limits.CommitLimitBytes > 0)
            {
                job.SetMemoryNotification(launch.Limits.CommitNotificationBytes > 0 ? launch.Limits.CommitNotificationBytes : launch.Limits.CommitLimitBytes);
            }

            if (launch.Limits.CpuRateCap is { } cap)
            {
                job.SetCpuHardCap(cap);
            }
            else
            {
                job.SetCpuWeight(launch.Limits.CpuWeight);
            }

            if (launch.DiscardOutput)
            {
                stdout = ProcessLauncher.OpenNull(write: true);
                stderr = ProcessLauncher.OpenNull(write: true);
            }
            else
            {
                stdout = File.OpenHandle(files.StdoutPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                stderr = File.OpenHandle(files.StderrPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            }

            (stdin, stdinWriter) = OpenStdin(launch);
            handle = new WindowsAttemptHandle(this, key, job, files, stdinWriter, root: null);
            _attempts[key] = handle;
            job.AssociateCompletionPort(_port, key, clearFirst: false);
            var spec = new HolderSpec
            {
                AttemptId = files.AttemptName,
                Application = launch.Command.Application,
                CommandLine = launch.Command.CommandLine,
                WorkingDirectory = launch.WorkingDirectory,
                Environment = [.. launch.Environment],
                LaunchSteps = [.. launch.LaunchSteps],
                EndSteps = [.. launch.EndSteps],
                LeftoverGraceMs = launch.LeftoverGraceMs,
                AttemptDirectory = files.Directory,
            };
            if (launch.KillWithNode)
            {
                StartDirect(handle, spec, root, job, stdin, stdout, stderr);
            }
            else
            {
                StartHolder(handle, spec, root, job, stdin, stdout, stderr);
            }

            return handle;
        }
        catch
        {
            _attempts.TryRemove(key, out _);
            job.Terminate(AttemptRunner.TerminatedExitCode);
            handle?.Dispose();
            job.Dispose();
            stdinWriter?.Dispose();
            throw;
        }
        finally
        {
            stdin?.Dispose();
            if (!launch.KillWithNode)
            {
                stdout?.Dispose();
                stderr?.Dispose();
            }
        }
    }

    /// <inheritdoc />
    public IAttemptHandle? Reopen(string nodeName, AttemptFiles files, RootProcess? root)
    {
        ArgumentNullException.ThrowIfNull(files);
        var job = JobObject.Open(JobName(nodeName, files.AttemptName));
        if (job is null)
        {
            return null;
        }

        var key = (nuint)Interlocked.Increment(ref _nextKey);
        var handle = new WindowsAttemptHandle(this, key, job, files, stdinWriter: null, root);
        _attempts[key] = handle;
        job.AssociateCompletionPort(_port, key, clearFirst: true);
        var ack = Native.OpenEvent(Native.EventModifyState | Native.Synchronize, inherit: false, AckName(nodeName, files.AttemptName));
        if (ack.IsInvalid)
        {
            ack.Dispose();
        }
        else
        {
            handle.Ack = ack;
        }

        handle.MarkReopened();
        return handle;
    }

    /// <inheritdoc />
    public bool AcknowledgeRecorded(string nodeName, string attemptName)
    {
        using var ack = Native.OpenEvent(Native.EventModifyState, inherit: false, AckName(nodeName, attemptName));
        return !ack.IsInvalid && Native.SetEvent(ack);
    }

    /// <summary>Stops the completion port thread. Attempt jobs are left to their holders.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Native.PostQueuedCompletionStatus(_port, 0, nuint.MaxValue, 0);
        _portThread.Join(TimeSpan.FromSeconds(2));
        _port.Dispose();
        _root?.Dispose();
    }

    /// <summary>Runs the console helper for one attempt (04 section 6 step 1) and returns its exit code.</summary>
    internal int RunSignalHelper(int rootPid)
    {
        var commandLine = WindowsCommandLine.Build([_helper, "node", "signal", "--pid", rootPid.ToString(CultureInfo.InvariantCulture)]);
        try
        {
            using var helper = ProcessLauncher.Start(new LaunchOptions
            {
                Application = _helper,
                CommandLine = commandLine,
                Flags = Native.DetachedProcess,
            });
            helper.Resume();
            if (!helper.WaitForExit(TimeSpan.FromMilliseconds(SignalTimeoutMs)))
            {
                helper.Kill(1);
                return -1;
            }

            return unchecked((int)helper.ExitCode);
        }
        catch (Win32Exception)
        {
            return -2;
        }
    }

    internal void Forget(nuint key) => _attempts.TryRemove(key, out _);

    private static (SafeHandle Handle, Stream? Writer) OpenStdin(AttemptLaunch launch)
    {
        switch (launch.Stdin)
        {
            case StdinKind.File:
                return (File.OpenHandle(launch.StdinPath ?? throw new ArgumentException("A stdin file is required.", nameof(launch)),
                    FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete), null);
            case StdinKind.Stream:
                var attributes = new Native.SecurityAttributes { Length = Marshal.SizeOf<Native.SecurityAttributes>() };
                if (!Native.CreatePipe(out var read, out var write, ref attributes, 64 * 1024))
                {
                    throw new Win32Exception(Native.LastError, "CreatePipe failed.");
                }

                var writer = new FileStream(new SafeFileHandle(write, ownsHandle: true), FileAccess.Write, 1, isAsync: false);
                return (new SafeKernelHandle(read, ownsHandle: true), writer);
            default:
                return (ProcessLauncher.OpenNull(write: false), null);
        }
    }

    private void StartHolder(WindowsAttemptHandle handle, HolderSpec spec, JobObject root, JobObject job, SafeHandle stdin, SafeHandle stdout, SafeHandle stderr)
    {
        var ack = Native.CreateEvent(0, manualReset: true, initialState: false, AckName(_nodeName, handle.Files.AttemptName));
        if (ack.IsInvalid)
        {
            var error = Native.LastError;
            ack.Dispose();
            throw new Win32Exception(error, "CreateEvent(ack) failed.");
        }

        handle.Ack = ack;
        var attributes = new Native.SecurityAttributes { Length = Marshal.SizeOf<Native.SecurityAttributes>() };
        if (!Native.CreatePipe(out var specRead, out var specWrite, ref attributes, 64 * 1024))
        {
            throw new Win32Exception(Native.LastError, "CreatePipe(spec) failed.");
        }

        if (!Native.CreatePipe(out var reportRead, out var reportWrite, ref attributes, 16 * 1024))
        {
            var error = Native.LastError;
            Native.CloseHandle(specRead);
            Native.CloseHandle(specWrite);
            throw new Win32Exception(error, "CreatePipe(report) failed.");
        }

        using var specReadHandle = new SafeKernelHandle(specRead, ownsHandle: true);
        using var reportWriteHandle = new SafeKernelHandle(reportWrite, ownsHandle: true);
        var reportStream = new FileStream(new SafeFileHandle(reportRead, ownsHandle: true), FileAccess.Read, 1, isAsync: false);
        var specStream = new FileStream(new SafeFileHandle(specWrite, ownsHandle: true), FileAccess.Write, 1, isAsync: false);
        var inheritable = new List<nint>();
        try
        {
            using var nulError = ProcessLauncher.OpenNull(write: true);
            nint Copy(SafeHandle source)
            {
                var copy = ProcessLauncher.InheritableCopy(source);
                inheritable.Add(copy);
                return copy;
            }

            var arguments = new List<string>
            {
                _helper, "node", "exec-wrap", "--attempt", handle.Files.AttemptName,
                "--job", Text(Copy(job.Handle)), "--root-job", Text(Copy(root.Handle)),
                "--stdin", Text(Copy(stdin)), "--stdout", Text(Copy(stdout)), "--stderr", Text(Copy(stderr)),
                "--ack", Text(Copy(ack)),
            };
            var holder = ProcessLauncher.Start(new LaunchOptions
            {
                Application = _helper,
                CommandLine = WindowsCommandLine.Build(arguments),
                WorkingDirectory = Path.GetDirectoryName(_helper),
                Flags = Native.DetachedProcess,
                StdInput = specReadHandle,
                StdOutput = reportWriteHandle,
                StdError = nulError,
                InheritableHandles = inheritable,
            });
            holder.Resume();
            handle.Holder = holder;
        }
        catch
        {
            reportStream.Dispose();
            specStream.Dispose();
            throw;
        }
        finally
        {
            foreach (var copy in inheritable)
            {
                Native.CloseHandle(copy);
            }
        }

        handle.ReadReports(reportStream);
        try
        {
            specStream.Write(Encoding.UTF8.GetBytes(spec.ToJson()));
        }
        finally
        {
            specStream.Dispose();
        }
    }

    private static void StartDirect(WindowsAttemptHandle handle, HolderSpec spec, JobObject root, JobObject job, SafeHandle stdin, SafeFileHandle stdout,
        SafeFileHandle stderr)
    {
        // The node is the holder: the runner keeps its own copies of the stdio handles; the job dies with the node (KILL_ON_JOB_CLOSE).
        var stdinCopy = new SafeKernelHandle(ProcessLauncher.InheritableCopy(stdin), ownsHandle: true);
        var thread = new Thread(() =>
        {
            try
            {
                var runner = new AttemptRunner(spec, root, job, stdinCopy, stdout, stderr, handle.OnReport);
                runner.Run(guard: false);
            }
            catch (ObjectDisposedException)
            {
                // The node closed the job (kill-on-close ended the attempt): nothing is left to record.
            }
            catch (Exception exception) when (exception is Win32Exception or IOException or UnauthorizedAccessException)
            {
                handle.OnReport(new HolderReport { Event = "spawn_failed", Error = exception.Message });
            }
            finally
            {
                stdinCopy.Dispose();
                stdout.Dispose();
                stderr.Dispose();
            }
        })
        {
            IsBackground = true,
            Name = "arcforges-attempt-" + spec.AttemptId,
        };
        thread.Start();
    }

    private static string? SelfTest()
    {
        try
        {
            using var probe = JobObject.Create(null);
            probe.SetLimits(256L * 1024 * 1024, activeProcessLimit: 64, killOnClose: true);
            probe.SetCpuWeight(5);
            var (flags, limit, processes) = probe.Limits();
            var (rateFlags, weight) = probe.CpuRateControl();
            return (flags & Native.JobObjectLimitJobMemory) != 0 && limit == 256L * 1024 * 1024 && processes == 64
                && (rateFlags & Native.CpuRateControlWeightBased) != 0 && weight == 5
                ? null
                : "the probe job did not keep its limits";
        }
        catch (Win32Exception exception)
        {
            return "the probe job failed: " + exception.Message;
        }
    }

    private void PortLoop()
    {
        while (true)
        {
            if (!Native.GetQueuedCompletionStatus(_port, out var message, out var key, out var data, Native.Infinite))
            {
                if (_disposed)
                {
                    return;
                }

                continue;
            }

            if (key == nuint.MaxValue)
            {
                return;
            }

            if (_attempts.TryGetValue(key, out var handle))
            {
                handle.OnJobMessage(message, (int)data);
            }
        }
    }

    private static string Text(nint handle) => ((long)handle).ToString(CultureInfo.InvariantCulture);
}
