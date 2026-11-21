// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// The Windows execution platform (AD-0005 Windows; architecture 04 sections 3, 6 and 9):
/// <list type="bullet">
/// <item>The root job <c>Local\ArcForges.&lt;node&gt;.root</c> with a hard CPU cap, a commit limit and a soft-pressure notification limit,
/// created or re-opened at startup and verified with a probe job (02 section 2 step 6).</item>
/// <item>Reopens a recorded child job <c>Local\ArcForges.&lt;node&gt;.&lt;attempt&gt;</c> and its holder acknowledgement
/// event to observe and control the surviving attempt.</item>
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
    public MachineCapacity Capacity { get; }

    /// <summary>The root job's name.</summary>
    public string RootJobName => JobName(_nodeName, "root");

    /// <summary>The root job (after <see cref="Start"/>).</summary>
    public JobObject? RootJob => _root;

    /// <summary>Read-only observation of real completion packets after routing, used to prove a test's event provenance.</summary>
    internal Action<uint, nuint, int>? JobMessageObserved { get; set; }

    /// <summary>The real port for a native job-composition test; tests associate jobs, never post simulated packets.</summary>
    internal SafeHandle JobCompletionPort => _port;

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
            Adopt = AdoptSupport.Unsupported,
            AdoptReason = "New legacy process adoption has been retired. Cleanup of recorded adoptions requires confirmed custody.",
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

    /// <inheritdoc />
    public IAdoptedContainer? ReopenAdopted(string containerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerName);
        return JobObject.Open(containerName) is { } job
            ? new WindowsAdoptedJob(job)
            : throw new LegacyCustodyUnavailableException("The recorded adoption job was not found in this Windows session.");
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

    /// <inheritdoc />
    public bool Listens(int port, IReadOnlyCollection<int> processIds) => ListeningSockets.Listens(port, processIds);

    /// <inheritdoc />
    public IAttemptHandle? Reopen(string nodeName, AttemptFiles files, RootProcess? root, bool stopping = false)
    {
        ArgumentNullException.ThrowIfNull(files);
        var job = JobObject.Open(JobName(nodeName, files.AttemptName));
        if (job is null)
        {
            // Legacy attempts did not record their Windows session. A Local job can exist in another session.
            throw new LegacyCustodyUnavailableException("The recorded attempt job was not found in this Windows session.");
        }

        WindowsAttemptHandle? handle = null;
        try
        {
            handle = CreateAttemptHandle(job, files, root);
            if (root is null && !File.Exists(files.ExitPath) && !File.Exists(files.LaunchPath))
            {
                // The node stopped in the middle of the attempt's launch: the holder may still start a launch step or the command. A stop awaits
                // it; any other attempt may be stopped later, and that forced phase must see it too (WatchLaunch). Before the port is associated:
                // the association posts a new-process message for every process in the job then (observed on the workstation), so the ones present
                // now are told apart, and none that enters later is missed.
                handle.AwaitLaunch(stopping);
            }

            ObserveAttemptJob(handle, clearFirst: true);
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
        catch
        {
            // The caller has not received this handle. Release only our reference, without signalling the holder or its Job.
            if (handle is null)
            {
                job.Dispose();
            }
            else
            {
                handle.Dispose();
            }

            throw;
        }
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

    internal WindowsAttemptHandle CreateAttemptHandle(JobObject job, AttemptFiles files, RootProcess? root) =>
        new(this, (nuint)Interlocked.Increment(ref _nextKey), job, files, stdinWriter: null, root);

    internal void ObserveAttemptJob(WindowsAttemptHandle handle, bool clearFirst)
    {
        _attempts[handle.CompletionKey] = handle;
        handle.Job.AssociateCompletionPort(_port, handle.CompletionKey, clearFirst);
    }

    internal void Forget(nuint key) => _attempts.TryRemove(key, out _);

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

            JobMessageObserved?.Invoke(message, key, (int)data);
        }
    }
}
