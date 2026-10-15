// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Text;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// One attempt's child job as the node controls it: the job handle (on the node's completion port), the holder process and its
/// report pipe while the node launched it, the ack event, and the attempt's files. A recovered attempt has only the re-opened job,
/// the ack event and its recorded root process.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsAttemptHandle : IAttemptHandle
{
    private readonly WindowsExecutionPlatform _platform;
    private readonly nuint _key;
    private readonly JobObject _job;
    private readonly TaskCompletionSource<RootProcess?> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentDictionary<int, long> _seen = new();
    private volatile bool _launchFinished;
    private volatile bool _rootExited;
    private volatile bool _memoryLimit;
    private RootProcess? _root;
    private SafeKernelHandle? _rootHandle;
    private Thread? _reportThread;
    private bool _disposed;

    internal WindowsAttemptHandle(WindowsExecutionPlatform platform, nuint key, JobObject job, AttemptFiles files, Stream? stdinWriter, RootProcess? root)
    {
        _platform = platform;
        _key = key;
        _job = job;
        Files = files;
        StdinWriter = stdinWriter;
        _root = root;
    }

    /// <summary>Raised (on a platform thread) when the attempt changed: started, the root exited, the record was written, a limit event.</summary>
    public event Action? Changed;

    /// <summary>The attempt's files.</summary>
    public AttemptFiles Files { get; }

    /// <summary>The child job.</summary>
    public JobObject Job => _job;

    /// <inheritdoc />
    public string ContainerName => _job.Name ?? string.Empty;

    /// <inheritdoc />
    public RootProcess? Root => Volatile.Read(ref _root);

    /// <inheritdoc />
    public Task<RootProcess?> Started => _started.Task;

    /// <inheritdoc />
    public Stream? StdinWriter { get; }

    /// <summary>True when the node re-opened the job after a restart.</summary>
    public bool Reopened { get; private set; }

    /// <inheritdoc />
    public bool RootRunning
    {
        get
        {
            if (_rootExited || File.Exists(Files.ExitPath))
            {
                return false;
            }

            if (Root is not { } root)
            {
                return !_launchFinished;
            }

            var handle = RootHandle(root);
            return handle is not null && ProcessInfo.IsRunning(handle);
        }
    }

    /// <inheritdoc />
    public bool MemoryLimitHit => _memoryLimit;

    /// <summary>The holder process, while the node launched it.</summary>
    internal LaunchedProcess? Holder { get; set; }

    /// <summary>The ack event.</summary>
    internal SafeKernelHandle? Ack { get; set; }

    /// <inheritdoc />
    public ExitRecord? TryReadExit() => ExitRecord.TryRead(Files.ExitPath);

    /// <inheritdoc />
    public LaunchRecord? TryReadLaunchFailure() => LaunchRecord.TryRead(Files.LaunchPath);

    /// <inheritdoc />
    public IReadOnlyList<ContainerProcess> Processes()
    {
        var result = new List<ContainerProcess>();
        int[] pids;
        try
        {
            pids = _job.ProcessIds();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return result;
        }

        foreach (var pid in pids)
        {
            using (var process = ProcessInfo.Open(pid))
            {
                if (process is not null)
                {
                    _seen.TryAdd(pid, ProcessInfo.CreationFileTime(process));
                }
            }

            result.Add(new ContainerProcess(pid, ProcessInfo.ImageName(pid)));
        }

        return result;
    }

    /// <inheritdoc />
    public ContainerAccounting Accounting()
    {
        var accounting = _job.Accounting();
        return new ContainerAccounting((long)accounting.UserTime.TotalMilliseconds, (long)accounting.KernelTime.TotalMilliseconds, accounting.PeakJobMemory,
            accounting.ReadBytes, accounting.WriteBytes, accounting.ActiveProcesses, _job.LimitViolations());
    }

    /// <inheritdoc />
    public void Terminate() => _job.Terminate(AttemptRunner.TerminatedExitCode);

    /// <inheritdoc />
    public GracefulOutcome RequestGracefulStop()
    {
        var processes = Processes();
        var windows = GuiWindows.Close([.. processes.Select(process => process.Pid)]);
        if (Root is not { } root)
        {
            return new GracefulOutcome(false, windows, "the root process is not known (the node restarted before the holder reported it)");
        }

        var handle = RootHandle(root);
        if (handle is null || !ProcessInfo.IsRunning(handle))
        {
            return new GracefulOutcome(false, windows, "the root process exited");
        }

        var exit = _platform.RunSignalHelper(root.Pid);
        return exit == SignalRole.Delivered
            ? new GracefulOutcome(true, windows, null)
            : new GracefulOutcome(false, windows, SignalRole.Describe(exit));
    }

    /// <inheritdoc />
    public IReadOnlyList<string> TerminateEscaped()
    {
        // Same-user descendants by ancestry of processes seen in the job that run outside it (WMI- or broker-created; 03 section 9).
        Processes();
        var known = new Dictionary<int, long>(_seen);
        var terminated = new List<string>();
        if (known.Count == 0)
        {
            return terminated;
        }

        var snapshot = ProcessInfo.Snapshot();
        var frontier = new Queue<int>(known.Keys);
        var visited = new HashSet<int>(known.Keys);
        while (frontier.Count > 0)
        {
            var parent = frontier.Dequeue();
            known.TryGetValue(parent, out var parentCreated);
            foreach (var (pid, parentPid, image) in snapshot)
            {
                if (parentPid != parent || !visited.Add(pid))
                {
                    continue;
                }

                using var process = ProcessInfo.Open(pid, terminate: true);
                if (process is null)
                {
                    continue;
                }

                var created = ProcessInfo.CreationFileTime(process);
                if (parentCreated != 0 && created < parentCreated)
                {
                    // The parent ID was reused: not a descendant.
                    continue;
                }

                known[pid] = created;
                frontier.Enqueue(pid);
                if (!_job.Contains(process) && Native.TerminateProcess(process, AttemptRunner.TerminatedExitCode))
                {
                    terminated.Add(image);
                }
            }
        }

        return terminated;
    }

    /// <inheritdoc />
    public void Acknowledge()
    {
        if (Ack is { } ack)
        {
            Native.SetEvent(ack);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _platform.Forget(_key);
        StdinWriter?.Dispose();
        _rootHandle?.Dispose();
        Holder?.Dispose();
        Ack?.Dispose();
        _job.Dispose();
        _started.TrySetResult(Root);
    }

    internal void MarkReopened()
    {
        Reopened = true;
        _launchFinished = true;
        _started.TrySetResult(Root);
    }

    internal void ReadReports(Stream stream)
    {
        _reportThread = new Thread(() =>
        {
            using (stream)
            {
                using var reader = new StreamReader(stream, new UTF8Encoding(false));
                try
                {
                    while (reader.ReadLine() is { } line)
                    {
                        if (HolderReport.TryParse(line) is { } report)
                        {
                            OnReport(report);
                        }
                    }
                }
                catch (IOException)
                {
                    // The holder ended.
                }
            }

            _launchFinished = true;
            _started.TrySetResult(Root);
            Changed?.Invoke();
        })
        {
            IsBackground = true,
            Name = "arcforges-holder-" + Files.AttemptName,
        };
        _reportThread.Start();
    }

    internal void OnReport(HolderReport report)
    {
        switch (report.Event)
        {
            case "started":
                Volatile.Write(ref _root, new RootProcess(report.Pid, ProcessInfo.FromFileTime(report.StartFileTime)));
                _seen.TryAdd(report.Pid, report.StartFileTime);
                _launchFinished = true;
                _started.TrySetResult(Root);
                break;
            case "spawn_failed":
                _launchFinished = true;
                _started.TrySetResult(null);
                break;
            case "exited":
                _rootExited = true;
                break;
            case "recorded":
                _rootExited = true;
                _launchFinished = true;
                _started.TrySetResult(Root);
                break;
        }

        Changed?.Invoke();
    }

    internal void OnJobMessage(uint message, int data)
    {
        switch (message)
        {
            case Native.JobMsgJobMemoryLimit:
            case Native.JobMsgProcessMemoryLimit:
                _memoryLimit = true;
                break;
            case Native.JobMsgNotificationLimit:
                if (_job.LimitViolations().Contains("job_memory"))
                {
                    _memoryLimit = true;
                }

                break;
            case Native.JobMsgExitProcess:
            case Native.JobMsgAbnormalExitProcess:
                if (Root is { } root && root.Pid == data)
                {
                    _rootExited = true;
                }

                break;
        }

        Changed?.Invoke();
    }

    private SafeKernelHandle? RootHandle(RootProcess root)
    {
        if (_rootHandle is { IsInvalid: false, IsClosed: false } existing)
        {
            return existing;
        }

        var fileTime = root.StartTime.ToFileTime();
        _rootHandle = ProcessInfo.OpenIdentified(root.Pid, fileTime);
        return _rootHandle;
    }
}
