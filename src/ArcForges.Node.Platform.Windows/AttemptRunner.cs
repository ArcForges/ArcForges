// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Windows;

/// <summary>
/// The life of one attempt inside its jobs (architecture 04 section 3, AD-0005 Windows section 3), run by the holder
/// <c>arcforges node exec-wrap</c> outside the jobs, or by the node itself for <c>kill_with_node</c> attempts:
/// <list type="number">
/// <item>Launch steps: each step is created suspended, assigned to the root job and then to the child job (which nests the child
/// under the root, V-W01), resumed and awaited (<see cref="WaitForProcess"/>); a failing step terminates the child job and records
/// <c>launch.json</c>.</item>
/// <item>The root process: <c>CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT
/// | CREATE_NO_WINDOW</c> (a windowless console a helper can attach to, L-18), root job then child job, resumed; its PID and start
/// time are reported.</item>
/// <item>After the root exits: the end steps (bounded to 10 s), then <c>leftover_grace</c>, then the remaining processes are
/// terminated and listed.</item>
/// <item><c>exit.json</c> with the exit code and the job accounting (basic and I/O, peak job commit, limit violations).</item>
/// </list>
/// While it waits for the root, a holder is also the attempt's disk guard (<see cref="OutputGuard"/>).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AttemptRunner
{
    /// <summary>The exit code TerminateJobObject gives the processes ArcForges stops.</summary>
    public const uint TerminatedExitCode = 1;

    private const uint RootFlags = Native.CreateSuspended | Native.CreateNewProcessGroup | Native.CreateNoWindow;

    /// <summary>How often a step's wait also checks for a stopped process.</summary>
    private static readonly TimeSpan StepCheckInterval = TimeSpan.FromMilliseconds(50);

    /// <summary>
    /// A root may run for days: four wakeups per second, querying the job only after a final nonzero exit code. The node owns the job's
    /// sole completion port (also after recovery), and the holder must observe a limit stop even while the node is down.
    /// </summary>
    private static readonly TimeSpan RootCheckInterval = TimeSpan.FromMilliseconds(250);

    private readonly HolderSpec _spec;
    private readonly JobObject _root;
    private readonly JobObject _child;
    private readonly SafeHandle _stdin;
    private readonly SafeHandle _stdout;
    private readonly SafeHandle _stderr;
    private readonly Action<HolderReport> _report;
    private readonly TimeProvider _clock;
    private readonly AttemptFiles _files;

    /// <summary>Creates the runner over the attempt's jobs and standard handles.</summary>
    public AttemptRunner(HolderSpec spec, JobObject root, JobObject child, SafeHandle stdin, SafeHandle stdout, SafeHandle stderr,
        Action<HolderReport> report, TimeProvider? clock = null)
    {
        _spec = spec ?? throw new ArgumentNullException(nameof(spec));
        _root = root ?? throw new ArgumentNullException(nameof(root));
        _child = child ?? throw new ArgumentNullException(nameof(child));
        _stdin = stdin ?? throw new ArgumentNullException(nameof(stdin));
        _stdout = stdout ?? throw new ArgumentNullException(nameof(stdout));
        _stderr = stderr ?? throw new ArgumentNullException(nameof(stderr));
        _report = report ?? throw new ArgumentNullException(nameof(report));
        _clock = clock ?? TimeProvider.System;
        _files = new AttemptFiles(Path.GetDirectoryName(Path.GetDirectoryName(spec.AttemptDirectory)!)!, Path.GetFileName(spec.AttemptDirectory));
    }

    /// <summary>The root process once started.</summary>
    public RootProcess? Root { get; private set; }

    /// <summary>
    /// Runs the attempt to its exit record. With <paramref name="guard"/> the holder enforces the attempt's output limit while the
    /// node's heartbeat is stale. Returns the exit record written.
    /// </summary>
    public ExitRecord Run(bool guard)
    {
        OutputGuard? outputGuard = null;
        try
        {
            if (guard && GuardSpec.TryRead(_files.GuardPath) is { } guardSpec)
            {
                outputGuard = new OutputGuard(guardSpec, _files.GuardEventsPath, _child, [_stdout, _stderr], _clock);
                outputGuard.Start();
            }

            foreach (var step in _spec.LaunchSteps)
            {
                var outcome = RunStep(step, TimeSpan.FromMilliseconds(step.TimeoutMs));
                if (outcome is not null)
                {
                    return LaunchFailed(step.Name, outcome.Value.Error, outcome.Value.ExitCode, outcome.Value.OsError);
                }
            }

            LaunchedProcess process;
            try
            {
                process = StartInJobs(_spec.Application, _spec.CommandLine, _spec.WorkingDirectory, _stdin, _stdout, _stderr, RootFlags);
            }
            catch (Win32Exception exception)
            {
                return LaunchFailed("command", $"the command could not be started: {exception.Message}", null, exception.NativeErrorCode);
            }

            using (process)
            {
                var creation = process.CreationFileTime;
                process.Resume();
                Root = new RootProcess(process.ProcessId, ProcessInfo.FromFileTime(creation));
                string? startRecordError = null;
                try
                {
                    HelperFiles.WriteAtomically(_files.StartedPath, new StartedRecord
                    {
                        AttemptId = _files.AttemptName,
                        RootPid = process.ProcessId,
                        RootStartFileTime = creation,
                        StartedAt = HelperFiles.Now(_clock),
                    }.ToJson());
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    // A metadata-write failure must not abandon a root that was already resumed. The live start report still reaches the node.
                    startRecordError = "started.json unavailable: " + exception.GetType().Name;
                }

                _report(new HolderReport { Event = "started", Pid = process.ProcessId, StartFileTime = creation, Error = startRecordError });
                var exitCode = WaitForProcess(process, Timeout.InfiniteTimeSpan, RootCheckInterval)!.Value;
                _report(new HolderReport { Event = "exited", ExitCode = unchecked((int)exitCode) });
                RunEndSteps();
                var leftovers = TerminateLeftovers(TimeSpan.FromMilliseconds(_spec.LeftoverGraceMs));
                return WriteExit(unchecked((int)exitCode), leftovers);
            }
        }
        finally
        {
            outputGuard?.Dispose();
        }
    }

    private (string Error, int? ExitCode, int? OsError)? RunStep(StepSpec step, TimeSpan timeout)
    {
        LaunchedProcess process;
        try
        {
            using var nul = ProcessLauncher.OpenNull(write: false);
            using var nulOut = ProcessLauncher.OpenNull(write: true);
            process = StartInJobs(step.Application, step.CommandLine, step.WorkingDirectory.Length > 0 ? step.WorkingDirectory : _spec.WorkingDirectory,
                nul, nulOut, nulOut, Native.CreateSuspended | Native.CreateNoWindow);
        }
        catch (Win32Exception exception)
        {
            return ($"step {step.Name} could not be started: {exception.Message}", null, exception.NativeErrorCode);
        }

        using (process)
        {
            process.Resume();
            if (WaitForProcess(process, timeout, StepCheckInterval) is not { } exitCode)
            {
                process.Kill(TerminatedExitCode);
                return ($"step {step.Name} did not finish within {timeout.TotalSeconds:0.#} s", null, null);
            }

            var code = unchecked((int)exitCode);
            return code == 0 ? null : ($"step {step.Name} exited with code {code}", code, null);
        }
    }

    /// <summary>
    /// Waits up to <paramref name="timeout"/> (<see cref="Timeout.InfiniteTimeSpan"/>: without a bound) for a step or root to end and returns
    /// its exit code, or <see langword="null"/> at the timeout. The process ends when its handle is signaled, or as soon as it was stopped
    /// (<see cref="StoppedCode"/>), checked every <paramref name="checkInterval"/>. A forced phase terminates the job
    /// (<c>TerminateJobObject</c>): the job then reports no process and the process its termination code at once, but the process's handle
    /// is signaled only once its own threads have run down, at the job's
    /// below-normal priority. Under CPU load that took seconds (MR-101: up to 12 s after the node found the job empty; about 4.8 s, the
    /// scheduler's starvation boost, for a terminated process on a saturated machine), and the stop's records waited for it, so the end
    /// of the stopped attempt did too.
    /// </summary>
    private uint? WaitForProcess(LaunchedProcess process, TimeSpan timeout, TimeSpan checkInterval)
    {
        var infinite = timeout == Timeout.InfiniteTimeSpan;
        var waited = Stopwatch.StartNew();
        while (true)
        {
            var remaining = infinite ? checkInterval : timeout - waited.Elapsed;
            var slice = remaining <= TimeSpan.Zero ? TimeSpan.Zero : remaining < checkInterval ? remaining : checkInterval;
            if (process.WaitForExit(slice))
            {
                return process.ExitCode;
            }

            if (StoppedCode(process) is { } code)
            {
                return code;
            }

            if (!infinite && waited.Elapsed >= timeout)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// The exit code of a step or root that was stopped before its handle is signaled: the child job holds no process and its exit status
    /// is final and not 0 (a terminated job gives <see cref="TerminatedExitCode"/>), or <see langword="null"/>. A process that exits 0 is
    /// awaited through its handle only, as before: in a normal exit a process can leave the job's active count before its handles are
    /// closed, and the next step, the command or the end of the attempt would then start while it still holds files, locks or pipes. A
    /// job query that fails reads as not empty.
    /// </summary>
    private uint? StoppedCode(LaunchedProcess process)
    {
        // ExitCode reads uint.MaxValue when it cannot be read: only a status that is known, final and nonzero counts.
        var code = process.ExitCode;
        if (code is 0 or Native.StillActive or uint.MaxValue)
        {
            return null;
        }

        try
        {
            if (_child.Accounting().ActiveProcesses != 0)
            {
                return null;
            }
        }
        catch (Win32Exception)
        {
            return null;
        }

        return code;
    }

    private void RunEndSteps()
    {
        var budget = Stopwatch.StartNew();
        var total = TimeSpan.FromMilliseconds(_spec.EndStepBudgetMs);
        foreach (var step in _spec.EndSteps)
        {
            var remaining = total - budget.Elapsed;
            if (remaining <= TimeSpan.Zero)
            {
                break;
            }

            // A failing or slow end step never changes the attempt's result (04 section 3).
            var timeout = step.TimeoutMs <= 0 ? remaining : TimeSpan.FromMilliseconds(step.TimeoutMs);
            RunStep(step, remaining < timeout ? remaining : timeout);
        }
    }

    /// <summary>Waits <paramref name="grace"/> for the job to empty, then terminates and lists what is left (04 section 3).</summary>
    private List<string> TerminateLeftovers(TimeSpan grace)
    {
        var waited = Stopwatch.StartNew();
        while (_child.Accounting().ActiveProcesses > 0 && waited.Elapsed < grace)
        {
            Thread.Sleep(50);
        }

        var images = new List<string>();
        if (_child.Accounting().ActiveProcesses == 0)
        {
            return images;
        }

        foreach (var pid in _child.ProcessIds())
        {
            images.Add(ProcessInfo.ImageName(pid));
        }

        _child.Terminate(TerminatedExitCode);
        var verify = Stopwatch.StartNew();
        while (_child.Accounting().ActiveProcesses > 0 && verify.Elapsed < TimeSpan.FromSeconds(5))
        {
            Thread.Sleep(20);
        }

        return images;
    }

    private LaunchedProcess StartInJobs(string application, string commandLine, string workingDirectory, SafeHandle stdin, SafeHandle stdout, SafeHandle stderr,
        uint flags)
    {
        var process = ProcessLauncher.Start(new LaunchOptions
        {
            Application = application,
            CommandLine = commandLine,
            WorkingDirectory = workingDirectory,
            Environment = _spec.Environment,
            Flags = flags,
            StdInput = stdin,
            StdOutput = stdout,
            StdError = stderr,
        });
        try
        {
            // Root job first, then the child job: the second assignment nests the child under the root (V-W01).
            _root.Assign(process.Process);
            _child.Assign(process.Process);
            return process;
        }
        catch
        {
            process.Kill(TerminatedExitCode);
            process.Dispose();
            throw;
        }
    }

    private ExitRecord LaunchFailed(string step, string error, int? exitCode, int? osError)
    {
        _child.Terminate(TerminatedExitCode);
        HelperFiles.WriteAtomically(_files.LaunchPath, new LaunchRecord
        {
            AttemptId = _spec.AttemptId,
            Step = step,
            Error = error,
            ExitCode = exitCode,
            OsError = osError,
            RecordedAt = HelperFiles.Now(_clock),
        }.ToJson());
        _report(new HolderReport { Event = "spawn_failed", Error = error });
        return WriteExit(exitCode ?? 1, []);
    }

    private ExitRecord WriteExit(int exitCode, List<string> leftovers)
    {
        var accounting = _child.Accounting();
        var violations = _child.LimitViolations();
        if (accounting.JobMemoryLimit > 0 && accounting.PeakJobMemory >= accounting.JobMemoryLimit - (64 * 1024) && !violations.Contains("job_memory"))
        {
            // The commit limit was reached (allocations at the limit fail); the violation query does not always report it.
            violations.Add("job_memory");
        }

        var record = new ExitRecord
        {
            AttemptId = _spec.AttemptId,
            ExitCodeKind = "exited",
            ExitStatus = exitCode,
            ServiceResult = exitCode == 0 ? "success" : "exit-code",
            RecordedAt = HelperFiles.Now(_clock),
            CpuUserMs = (long)accounting.UserTime.TotalMilliseconds,
            CpuKernelMs = (long)accounting.KernelTime.TotalMilliseconds,
            MemPeakBytes = accounting.PeakJobMemory,
            IoReadBytes = accounting.ReadBytes,
            IoWriteBytes = accounting.WriteBytes,
            LimitViolations = violations,
            LeftoversTerminated = leftovers,
        };
        HelperFiles.WriteAtomically(_files.ExitPath, record.ToJson());
        _report(new HolderReport { Event = "recorded", ExitCode = exitCode });
        return record;
    }
}

/// <summary>
/// The attempt's disk guard in its holder (06 section 5): it watches the node heartbeat on its own monotonic clock and, once the
/// heartbeat has not changed for <c>guard_takeover_ms</c>, checks the captured output every 100 ms against
/// <c>max_attempt_output_bytes</c>: <c>TERMINATE</c> stops the attempt at once (<c>TerminateJobObject</c>), <c>NOTIFY</c> records the
/// crossing and leaves it running. Every action (and each takeover and stand-down) is appended to <c>guard-events.jsonl</c>; the guard
/// never writes the node store. When the heartbeat is fresh again it stands down. The temporary-directory and low-space limits join
/// with AF-STOR-01.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class OutputGuard : IDisposable
{
    /// <summary>The output check interval while in charge (the node's tailer interval).</summary>
    public static readonly TimeSpan CheckInterval = TimeSpan.FromMilliseconds(100);

    /// <summary>How often the heartbeat is read.</summary>
    public static readonly TimeSpan HeartbeatInterval = TimeSpan.FromMilliseconds(250);

    private readonly GuardSpec _spec;
    private readonly string _eventsPath;
    private readonly JobObject _job;
    private readonly SafeHandle[] _outputs;
    private readonly TimeProvider _clock;
    private readonly HeartbeatWatch _watch;
    private readonly ManualResetEventSlim _stop = new();
    private Thread? _thread;

    /// <summary>Creates the guard.</summary>
    public OutputGuard(GuardSpec spec, string eventsPath, JobObject job, SafeHandle[] outputs, TimeProvider? clock = null)
    {
        _spec = spec ?? throw new ArgumentNullException(nameof(spec));
        _eventsPath = eventsPath ?? throw new ArgumentNullException(nameof(eventsPath));
        _job = job ?? throw new ArgumentNullException(nameof(job));
        _outputs = outputs ?? throw new ArgumentNullException(nameof(outputs));
        _clock = clock ?? TimeProvider.System;
        _watch = new HeartbeatWatch(spec.HeartbeatPath, TimeSpan.FromMilliseconds(Math.Clamp(spec.TakeoverMs, 2000, 60_000)), _clock);
    }

    /// <summary>True once the guard stopped the attempt.</summary>
    public bool Stopped { get; private set; }

    /// <summary>Starts the guard thread.</summary>
    public void Start()
    {
        _thread = new Thread(Loop) { IsBackground = true, Name = "arcforges-guard" };
        _thread.Start();
    }

    /// <summary>Stops the guard.</summary>
    public void Dispose()
    {
        _stop.Set();
        _thread?.Join(TimeSpan.FromSeconds(2));
        _stop.Dispose();
    }

    private void Loop()
    {
        var inCharge = false;
        var notified = false;
        var lastPoll = long.MinValue;
        while (!_stop.Wait(CheckInterval))
        {
            if (lastPoll == long.MinValue || _clock.GetElapsedTime(lastPoll) >= HeartbeatInterval)
            {
                _watch.Poll();
                lastPoll = _clock.GetTimestamp();
            }

            if (!_watch.Stale)
            {
                if (inCharge)
                {
                    inCharge = false;
                    Append(GuardEventKinds.StandDown, null, null);
                }

                continue;
            }

            if (!inCharge)
            {
                inCharge = true;
                Append(GuardEventKinds.Takeover, null, null);
            }

            if (Stopped || _spec.MaxOutputBytes <= 0)
            {
                continue;
            }

            long total = 0;
            foreach (var output in _outputs)
            {
                if (Native.GetFileSizeEx(output, out var size))
                {
                    total += size;
                }
            }

            if (total <= _spec.MaxOutputBytes)
            {
                continue;
            }

            if (string.Equals(_spec.DiskLimitAction, "NOTIFY", StringComparison.OrdinalIgnoreCase))
            {
                if (!notified)
                {
                    notified = true;
                    Append(GuardEventKinds.Notify, "OUTPUT_LIMIT", total);
                }

                continue;
            }

            // TERMINATE: at once, without the graceful phase (04 section 6 step 4).
            _job.Terminate(AttemptRunner.TerminatedExitCode);
            Stopped = true;
            Append(GuardEventKinds.Terminate, "OUTPUT_LIMIT", total);
        }
    }

    private void Append(string kind, string? reason, long? output)
    {
        try
        {
            new GuardEvent
            {
                AttemptId = _spec.AttemptId,
                At = HelperFiles.Now(_clock),
                Event = kind,
                Reason = reason,
                OutputBytes = output,
                LimitBytes = reason is null ? null : _spec.MaxOutputBytes,
                HeartbeatAgeMs = (long)_watch.Age.TotalMilliseconds,
                HeartbeatInstance = _watch.Last?.Instance ?? string.Empty,
            }.Append(_eventsPath);
        }
        catch (IOException)
        {
            // The record is best effort; the stop itself already happened.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
