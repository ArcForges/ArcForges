// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;

namespace ArcForges.Node.Core.Execution;

/// <summary>What the supervisor is built from.</summary>
public sealed class ExecutionOptions
{
    /// <summary>The store.</summary>
    public required NodeStore Store { get; init; }

    /// <summary>The command processor.</summary>
    public required CommandProcessor Processor { get; init; }

    /// <summary>The log.</summary>
    public required NodeLog Log { get; init; }

    /// <summary>The clock.</summary>
    public required TimeProvider Clock { get; init; }

    /// <summary>The data root.</summary>
    public required string DataRoot { get; init; }

    /// <summary>The execution platform, or <see langword="null"/> when none could be started.</summary>
    public IExecutionPlatform? Platform { get; init; }

    /// <summary>
    /// True when the platform does not enforce CPU and memory limits (an observe-only or partial node, 03 section 8): attempts are recorded
    /// with <c>unenforced=true</c>.
    /// </summary>
    public bool Unenforced { get; init; }

    /// <summary>The sealed task secrets.</summary>
    public required TaskSecrets Secrets { get; init; }

    /// <summary>Completes once the node data key is loaded (or failed to load).</summary>
    public Task KeysReady { get; init; } = Task.CompletedTask;

    /// <summary>Launch and end steps (toolchain adapters).</summary>
    public ILaunchStepProvider? Steps { get; init; }

    /// <summary>Controlled faults (test mode).</summary>
    public ExecutionFaults Faults { get; init; } = ExecutionFaults.None;

    /// <summary>The heartbeat writer.</summary>
    public required NodeHeartbeatWriter Heartbeat { get; init; }

    /// <summary>The platform's observation sources (03 section 1), or <see langword="null"/> for a node that observes nothing.</summary>
    public IResourceSampler? Sampler { get; init; }

    /// <summary>The tool-level concurrency hook of the adapters (03 section 5.3), or <see langword="null"/>.</summary>
    public Scheduling.IToolConcurrency? Tools { get; init; }

    /// <summary>Test seam: the resource monitor evaluates as if this node were alone on the machine (<see cref="MachineIsolation"/>).</summary>
    internal bool IsolatedFromMachineLoad { get; init; }

    /// <summary>
    /// Test seam (fault injection, 16-testing-strategy section 1), set only by in-process component tests: called on the thread of a
    /// stop's forced phase right after it terminated an attempt whose start had not completed, before the supervisor arranges the
    /// termination that follows the start, so a test can complete the start exactly there. The executable never sets it.
    /// </summary>
    internal Action<IAttemptHandle>? ForcedBeforeStart { get; init; }

    /// <summary>
    /// Test seam (fault injection), set only by in-process component tests: called by the continuation that follows a forced phase's pending
    /// start, once the start completed with a root, before it terminates the attempt again (<see langword="false"/>) and after it
    /// (<see langword="true"/>), so a test can let a verification run first, or let the launch go on right after that termination. The
    /// executable never sets it.
    /// </summary>
    internal Action<IAttemptHandle, bool>? StartObserved { get; init; }

    /// <summary>
    /// Test seam (fault injection), set only by in-process component tests: called by the forced phase after the grace period (the one a
    /// STOPPING attempt recovered after a restart gets at once) before it reads the start and terminates (<see langword="false"/>), and right
    /// after the termination (<see langword="true"/>), so a test can let the launch go on exactly there. The executable never sets it.
    /// </summary>
    internal Action<IAttemptHandle, bool>? ForcedPhase { get; init; }
}

/// <summary>A validated submission, prepared outside the writer (04 section 1; AD-0006 section 1).</summary>
public sealed class SubmitPlan
{
    /// <summary>The spec split into its stored parts.</summary>
    public required SubmittedEnvironment Parts { get; init; }

    /// <summary>The owner (set by the node from the connection).</summary>
    public required ActorRef Owner { get; init; }

    /// <summary>The title.</summary>
    public required string Title { get; init; }

    /// <summary>The redacted command summary.</summary>
    public required string Summary { get; init; }

    /// <summary>The command fingerprint.</summary>
    public required string Fingerprint { get; init; }

    /// <summary>The <c>join_existing</c> identity.</summary>
    public required byte[] CommandDigest { get; init; }

    /// <summary>The kind.</summary>
    public TaskKind Kind { get; init; } = TaskKind.Command;

    /// <summary>The pool.</summary>
    public required string Pool { get; init; }

    /// <summary>The priority.</summary>
    public Priority Priority { get; init; } = Priority.Normal;

    /// <summary>The effective side-effect class.</summary>
    public SideEffectClass SideEffect { get; init; } = SideEffectClass.Unknown;

    /// <summary>Who established it.</summary>
    public SideEffectSource SideEffectSource { get; init; } = SideEffectSource.Default;

    /// <summary>Warnings for the receipt.</summary>
    public List<string> Warnings { get; init; } = [];

    /// <summary>The meta command ID.</summary>
    public required Id CommandId { get; init; }

    /// <summary>The dependencies (04 section 8): the task waits in WAITING_DEPENDENCY until each condition holds.</summary>
    public IReadOnlyList<(byte[] TaskId, DependencyCondition Condition)> Dependencies { get; init; } = [];

    /// <summary>The caller's keys (03 section 4), stored with the task (<c>task_concurrency_key</c>, source caller).</summary>
    public IReadOnlyList<Scheduling.HeldKey> Keys { get; init; } = [];

    /// <summary>The owner's session (set by the node; sessions arrive with AF-AI-01), or <see langword="null"/>.</summary>
    public byte[]? SessionId { get; init; }

    /// <summary>The task's workspace (the longest registered root containing the working directory), or <see langword="null"/>.</summary>
    public byte[]? WorkspaceId { get; init; }
}

/// <summary>A caller of <c>cancel_when_caller_gone</c>: the submitting client process.</summary>
/// <param name="ProcessId">Its PID.</param>
/// <param name="StartTicks">Its start time (ticks).</param>
public readonly record struct CallerKey(int ProcessId, long StartTicks);

/// <summary>
/// The execution supervisor (architecture 02 section 1; 04): admission (03 section 4, in <c>ExecutionSupervisor.Scheduling.cs</c>), launch
/// through the platform, the enforcement loop (output tailer and index, the output limit, timeouts and CPU-time limits, service readiness,
/// the cancellation sequence, exit detection and the node heartbeat), finalization from the durable exit records with the automatic
/// retries of AD-0006 section 4, recovery after a node restart or a machine reboot (LOST), and <c>cancel_when_caller_gone</c>.
/// </summary>
public sealed partial class ExecutionSupervisor : INodeRecoveryParticipant, IAsyncDisposable, IPressureResponse
{
    /// <summary>The tailer interval (04 section 4).</summary>
    public static readonly TimeSpan TailInterval = TimeSpan.FromMilliseconds(100);

    /// <summary>The verification window after the forced phase (04 section 6 step 5).</summary>
    public static readonly TimeSpan VerifyWindow = TimeSpan.FromSeconds(5);

    /// <summary>The ancestry scan interval (04 section 3).</summary>
    public static readonly TimeSpan EscapeScanInterval = TimeSpan.FromSeconds(5);

    /// <summary>How long finalization waits for a stop's graceful phase to record what it did.</summary>
    private static readonly TimeSpan GracefulPhaseBound = TimeSpan.FromSeconds(15);

    /// <summary>The delay before a finalization that failed on a store error is retried.</summary>
    public static readonly TimeSpan FinalizeRetry = TimeSpan.FromSeconds(5);

    /// <summary>The bound within which a caller that is gone has its <c>cancel_when_caller_gone</c> tasks cancelled (AD-0006 section 7).</summary>
    public static readonly TimeSpan CallerGoneGrace = TimeSpan.FromSeconds(5);

    /// <summary>How often a disconnected caller's process is checked.</summary>
    private static readonly TimeSpan CallerPollInterval = TimeSpan.FromMilliseconds(250);

    /// <summary>The tolerance between a process start time read now and the one the session recorded.</summary>
    private static readonly TimeSpan CallerStartTolerance = TimeSpan.FromMilliseconds(50);

    private readonly NodeStore _store;
    private readonly CommandProcessor _processor;
    private readonly NodeLog _log;
    private readonly TimeProvider _clock;
    private readonly string _dataRoot;
    private readonly TaskSecrets _secrets;
    private readonly Task _keysReady;
    private readonly ILaunchStepProvider? _steps;
    private readonly ExecutionFaults _faults;
    private readonly Action<IAttemptHandle>? _forcedBeforeStart;
    private readonly Action<IAttemptHandle, bool>? _startObserved;
    private readonly Action<IAttemptHandle, bool>? _forcedPhase;
    private readonly ConcurrentDictionary<string, RunningAttempt> _running = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AsyncPulse> _taskPulses = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CallerKey> _bindings = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<CallerKey, int> _callerConnections = new();
    private readonly AsyncPulse _admission = new();
    private int _kicked;
    private readonly AsyncPulse _loopWake = new();
    private readonly CancellationTokenSource _stop = new();

    /// <summary><see cref="_stop"/>'s token, taken once: it stays readable after the source is disposed (always after it was cancelled).</summary>
    private readonly CancellationToken _stopping;
    private readonly HeartbeatMonitor _tailerMonitor;
    private ExecutionSettings _settings;
    private Thread? _loop;
    private Task _admissionLoop = Task.CompletedTask;
    private long _lastSettingsRead;
    private readonly Lock _settingsLock = new();
    private int _launching;
    private readonly Lock _preemptGate = new();
    private readonly CriticalShedding _shedding = new();
    private RunningAttempt? _lastVictim;
    private bool _onlyProtectedReported;

    /// <summary>Creates the supervisor.</summary>
    public ExecutionSupervisor(ExecutionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _store = options.Store;
        _stopping = _stop.Token;
        _processor = options.Processor;
        _log = options.Log;
        _clock = options.Clock;
        _dataRoot = options.DataRoot;
        Platform = options.Platform;
        _secrets = options.Secrets;
        _keysReady = options.KeysReady;
        _steps = options.Steps;
        _faults = options.Faults;
        _forcedBeforeStart = options.ForcedBeforeStart;
        _startObserved = options.StartObserved;
        _forcedPhase = options.ForcedPhase;
        Unenforced = options.Unenforced;
        Heartbeat = options.Heartbeat;
        NodeName = IdText.Format(_store.Metadata.NodeId.Span);
        var capacity = Platform?.Capacity ?? new MachineCapacity(Environment.ProcessorCount, GC.GetGCMemoryInfo().TotalAvailableMemoryBytes);
        Capacity = capacity;
        var initialPolicy = _store.Policies.Current();
        _settings = new ExecutionSettings(initialPolicy.Document, capacity.LogicalProcessors, capacity.PhysicalMemoryBytes) { PolicyRevision = initialPolicy.Revision };
        _lastSettingsRead = _clock.GetTimestamp();
        _tailerMonitor = Heartbeat.AddMonitor("output-tailer", TimeSpan.FromSeconds(5));
        Tools = options.Tools;
        PlatformCalls = new SerialWork(_log);
        Adoptions = new Adoptions(this, _store, _processor, _log);
        if (options.Sampler is { } sampler)
        {
            Resources = new ResourceMonitor(sampler, this, _store, _processor, _log, _clock) { IsolatedFromMachineLoad = options.IsolatedFromMachineLoad };
            Resources.AddResponse(this);
        }

        if (_faults.Take("hang-probe-after") is { } probeHang)
        {
            Heartbeat.AddProbe(new FaultProbe(probeHang, _clock));
        }
    }

    /// <inheritdoc />
    public string Name => "attempts";

    /// <summary>The platform, or <see langword="null"/>.</summary>
    public IExecutionPlatform? Platform { get; }

    /// <summary>Attempts run without enforced CPU and memory limits (recorded <c>unenforced</c>; 03 section 8).</summary>
    public bool Unenforced { get; }

    /// <summary>The node ID's base32 text (container names).</summary>
    public string NodeName { get; }

    /// <summary>The machine's capacity.</summary>
    public MachineCapacity Capacity { get; }

    /// <summary>The heartbeat writer.</summary>
    public NodeHeartbeatWriter Heartbeat { get; }

    /// <summary>The resource monitor (03 sections 1, 2 and 7), or <see langword="null"/> without a sampler.</summary>
    public ResourceMonitor? Resources { get; }

    /// <summary>The adopted processes (04 section 10).</summary>
    public Adoptions Adoptions { get; }

    /// <summary>The settings in force (re-read from the policy every 10 s).</summary>
    public ExecutionSettings Settings
    {
        get
        {
            if (_clock.GetElapsedTime(Interlocked.Read(ref _lastSettingsRead)) > TimeSpan.FromSeconds(10))
            {
                // One reader at a time: a read that began before a policy commit can no longer overwrite the settings PolicyChanged read after
                // it (which left the old settings in force for up to 10 s).
                lock (_settingsLock)
                {
                    if (_clock.GetElapsedTime(Interlocked.Read(ref _lastSettingsRead)) > TimeSpan.FromSeconds(10))
                    {
                        Interlocked.Exchange(ref _lastSettingsRead, _clock.GetTimestamp());
                        try
                        {
                            var policy = _store.Policies.Current();
                            Volatile.Write(ref _settings, new ExecutionSettings(policy.Document, Capacity.LogicalProcessors, Capacity.PhysicalMemoryBytes)
                            {
                                PolicyRevision = policy.Revision,
                            });
                        }
                        catch (Microsoft.Data.Sqlite.SqliteException exception)
                        {
                            _log.Warning("execution.settings.read_failed", new LogField("errorType", exception.GetType().Name));
                        }
                    }
                }
            }

            return Volatile.Read(ref _settings);
        }
    }

    /// <summary>Attempts the supervisor runs now.</summary>
    public int RunningCount => _running.Count;

    /// <summary>The attempts the supervisor runs now.</summary>
    public IEnumerable<RunningAttempt> RunningAttempts => _running.Values;

    /// <summary>The running attempt with <paramref name="attemptName"/>, or <see langword="null"/>.</summary>
    public RunningAttempt? Running(string attemptName) => _running.TryGetValue(attemptName, out var attempt) ? attempt : null;

    /// <summary>The pulse of a task: state changes and output of its current attempt.</summary>
    public AsyncPulse TaskPulse(ReadOnlySpan<byte> taskId) => _taskPulses.GetOrAdd(IdText.Format(taskId), _ => new AsyncPulse());

    /// <summary>Completes once the node data key finished loading.</summary>
    public Task KeysReady => _keysReady;

    // ------------------------------------------------------------------------------------------------------------------- recovery

    /// <inheritdoc />
    public async Task RecoverAsync(RecoveryReport report, CommandProcessor processor, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        var live = _store.Read(TaskRecords.LiveAttempts);
        var gapStart = _store.Read(reader => reader.Scalar("SELECT max(at) FROM event_journal WHERE generation < (SELECT journal_generation FROM store_meta);") as long?);
        foreach (var row in live)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = IdText.Format(row.AttemptId);
            var files = new AttemptFiles(_dataRoot, name);
            var task = _store.Read(reader => TaskRecords.GetRow(reader, row.TaskId));
            if (report.BootChanged && !string.Equals(row.BootIdentity, _store.Metadata.BootIdentity, StringComparison.Ordinal))
            {
                await RecordLostAsync(row, $"boot_changed: boot_id_old={row.BootIdentity}, boot_id_new={_store.Metadata.BootIdentity}", "boot_changed").ConfigureAwait(false);
                continue;
            }

            var root = row.RootPid is { } pid && row.RootStart is { } start ? new RootProcess(pid, StoreTime.FromMicroseconds(start)) : null;

            // The node was stopping it: the stop continues below, and a launch the node no longer controls may still start the command, so the
            // platform awaits that start (only then: any other recovered attempt completes its start at once, and a forced phase that stops it
            // later watches such a launch, TerminateEachLaunchProcess).
            var stopping = row.State is AttemptState.Stopping or AttemptState.Finalizing;
            IAttemptHandle? handle = null;
            try
            {
                handle = Platform?.Reopen(NodeName, files, root, stopping);
            }
            catch (Win32Exception exception)
            {
                _log.Warning("execution.recover.reopen_failed", new LogField("attempt", name), new LogField("error", exception.NativeErrorCode));
            }
            catch (Exception exception) when (exception is IOException or TimeoutException or InvalidOperationException)
            {
                // Linux: the user manager did not answer; without a container the exit record (if any) still finalizes the attempt.
                _log.Warning("execution.recover.reopen_failed", new LogField("attempt", name), new LogField("errorType", exception.GetType().Name),
                    new LogField("error", NodeLog.OneLine(exception.Message)));
            }

            var running = new RunningAttempt(row.AttemptId, row.TaskId, name, row.Number, files)
            {
                Handle = handle,
                NodeGap = true,
                ApproximateNext = true,
                RootRecorded = row.RootPid is not null,
                KillWithNode = task?.Spec.Resources?.KillWithNode == true,
                DiscardOutput = task?.Spec.Output?.Capture == OutputCapture.Discard,
                TimeoutMs = task?.Spec.HasTimeoutMs == true ? task.Spec.TimeoutMs : null,
                CpuLimitMs = task?.Spec.HasCpuTimeLimitMs == true ? task.Spec.CpuTimeLimitMs : null,
                StopSignal = task?.Spec.Resources is { HasStopSignal: true } stopResources ? stopResources.StopSignal : null,
                Priority = task?.Priority ?? Priority.Normal,
                Preemptible = task?.Spec.Resources?.Preemptible == true,
                Pausable = task?.Spec.Resources?.Pausable == true,
                WorkingDirectory = task?.Spec.WorkingDirectory,
                Readiness = task is { } service ? Scheduling.ServiceReadiness.For(service.Spec) : null,
            };
            if (task?.Spec.Resources is { HasCancelGraceMs: true } resources)
            {
                running.CancelGrace = TimeSpan.FromMilliseconds(resources.CancelGraceMs);
            }

            // Admission accounts a recovered attempt as it was admitted: its pool, owner scope, request, CPU grant and the keys it holds.
            var accounting = _store.Read(reader => RecoveredLoad(reader, row.TaskId, row.AttemptId));
            if (accounting is { } load)
            {
                running.Pool = load.Pool;
                running.Session = load.Session;
                running.Workspace = load.Workspace;
                running.MemExpected = load.Expected;
                running.MemCeiling = load.Ceiling;
                running.CpuGrant = Math.Min(load.Cpu, Settings.BudgetCpu);
                running.Observe(load.Accounted);
                running.Ready = load.Ready;
                running.Paused = row.State == AttemptState.Paused;

                // A frozen attempt keeps the cause of its pause across the restart (task.state_reason): a pressure-frozen one thaws after 30 s
                // at Normal with its launch MemoryHigh (below), one paused by PauseTask waits for ResumeTask.
                running.PausedByPressure = running.Paused && IsPressureFrozen(task?.StateReason);
                if (running.Paused)
                {
                    running.PausedSince = _clock.GetTimestamp();
                }

                running.MemoryHighBytes = Math.Min((long)(1.25 * load.Expected), load.Ceiling);
                running.Keys.AddRange(load.Keys);
            }

            if (row.StartedAt is { } startedAt)
            {
                var elapsed = _clock.GetUtcNow() - StoreTime.FromMicroseconds(startedAt);
                running.StartedTimestamp = _clock.GetTimestamp() - (long)(Math.Max(0, elapsed.TotalSeconds) * TimeProvider.System.TimestampFrequency);
            }

            if (handle is null && !File.Exists(files.ExitPath))
            {
                running.Dispose();
                await RecordLostAsync(row, "container_missing: the attempt's job no longer exists and no exit record was written", "container_missing").ConfigureAwait(false);
                continue;
            }

            if (stopping)
            {
                // The node was stopping it: the stop continues (forced, since the graceful phase cannot be resumed). The node may have
                // stopped in the middle of the launch: a start that completes after the forced phase is terminated again (Enforce).
                running.StopReason = row.Reason ?? (row.State == AttemptState.Stopping ? TerminationReason.Cancelled : null);
                running.StopDetail = row.Detail;
                running.GraceDeadline = _clock.GetTimestamp();
            }

            running.OpenTail();
            if (handle is not null)
            {
                handle.Changed += () => _loopWake.Pulse();
            }

            _running[name] = running;
            await _processor.ExecuteAsync(context =>
            {
                var now = context.Transaction.NowMicroseconds;
                context.Transaction.Execute("UPDATE attempt SET node_gap = 1, rev = rev + 1 WHERE attempt_id = $id;", ("$id", row.AttemptId));
                context.Transaction.Execute(
                    "INSERT OR IGNORE INTO timeline_segment (attempt_id, start_at, end_at, category, confidence, evidence) VALUES ($id, $start, $end, 'node_gap', 3, $evidence);",
                    ("$id", row.AttemptId), ("$start", Math.Min(gapStart ?? row.StartedAt ?? now, now)), ("$end", now),
                    ("$evidence", "the node was not running; the attempt continued under its holder"));
                EmitAttempt(context, row.AttemptId, null);
                return 0;
            }).ConfigureAwait(false);
            _log.Info("execution.recovered", new LogField("attempt", name), new LogField("container", handle?.ContainerName ?? "-"),
                new LogField("exitRecorded", File.Exists(files.ExitPath)), new LogField("portReassociated", handle is not null));
        }

        AcknowledgeRecordedAttempts(live);
        await Adoptions.RecoverAsync(report.BootChanged).ConfigureAwait(false);
        Heartbeat.RecoveryDone = true;
    }

    /// <summary>
    /// The exit acknowledgement follows the record's commit, so a node that stopped between the two leaves a holder waiting on an
    /// attempt the store already records as finished. Every attempt directory with a durable exit record that is not live is
    /// acknowledged again (an ack event that no longer opens has no holder left).
    /// </summary>
    private void AcknowledgeRecordedAttempts(List<AttemptRow> live)
    {
        if (Platform is null)
        {
            return;
        }

        var logs = Path.Combine(_dataRoot, "logs");
        if (!Directory.Exists(logs))
        {
            return;
        }

        var liveNames = live.Select(row => IdText.Format(row.AttemptId)).ToHashSet(StringComparer.Ordinal);
        foreach (var directory in Directory.EnumerateDirectories(logs))
        {
            var name = Path.GetFileName(directory);
            if (liveNames.Contains(name) || !File.Exists(Path.Combine(directory, AttemptFiles.Exit)))
            {
                continue;
            }

            if (Platform.AcknowledgeRecorded(NodeName, name))
            {
                _log.Info("execution.recover.acknowledged", new LogField("attempt", name));
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------------------ lifecycle

    /// <summary>Starts the enforcement loop, the admission loop and the heartbeat probes.</summary>
    public void Start()
    {
        Heartbeat.Start();
        _loop = new Thread(EnforcementLoop) { IsBackground = true, Name = "arcforges-enforcement" };
        _loop.Start();
        _admissionLoop = Task.Run(AdmissionLoopAsync);
        Resources?.Start();
        Adoptions.Start();
        Kick();
    }

    /// <summary>Wakes the admission loop; a kick that arrives during a pass runs another pass right after it (a kick is never lost).</summary>
    public void Kick()
    {
        Volatile.Write(ref _kicked, 1);
        _admission.Pulse();
    }

    /// <summary>
    /// The node's shutdown (02 section 2): admissions stop; <c>kill_with_node</c> attempts are terminated and recorded
    /// (<c>NODE_SHUTDOWN</c>); every other attempt keeps running under its holder, whose guard takes over the disk limits.
    /// </summary>
    public async Task StopAsync()
    {
        if (Resources is { } resources)
        {
            await resources.StopAsync().ConfigureAwait(false);
        }

        await _stop.CancelAsync().ConfigureAwait(false);
        _loopWake.Pulse();
        _loop?.Join(TimeSpan.FromSeconds(2));
        await PlatformCalls.DisposeAsync().ConfigureAwait(false);
        try
        {
            await _admissionLoop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
        }

        foreach (var attempt in _running.Values.Where(attempt => attempt.KillWithNode))
        {
            Stop(attempt.Name, TerminationReason.NodeShutdown, null, graceful: false);
            if (attempt.StopRecording is { } stop)
            {
                await stop.ConfigureAwait(false);
            }
        }

        var deadline = _clock.GetTimestamp();
        foreach (var attempt in _running.Values.Where(attempt => attempt.KillWithNode))
        {
            while (!File.Exists(attempt.Files.ExitPath) && _clock.GetElapsedTime(deadline) < TimeSpan.FromSeconds(3))
            {
                await Task.Delay(20).ConfigureAwait(false);
            }

            await FinalizeAsync(attempt, incomplete: !File.Exists(attempt.Files.ExitPath)).ConfigureAwait(false);
        }

        foreach (var attempt in _running.Values)
        {
            // The holder keeps the jobs; the node only releases its handles.
            attempt.Dispose();
        }

        _running.Clear();
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (!_stop.IsCancellationRequested)
        {
            await StopAsync().ConfigureAwait(false);
        }

        Resources?.Dispose();
        Adoptions.Dispose();
        _stop.Dispose();
    }

    // ---------------------------------------------------------------------------------------------------------------- pressure

    /// <summary>
    /// The pressure response of 03 sections 5.4 and 7 (R-RES-009, R-RES-014), called on the monitor's thread after every evaluation: at
    /// Critical (and with <c>pressure.cancel_on_critical</c>) preemptible attempts are stopped one at a time, from the lowest priority up and
    /// the most recently started first, without the graceful phase (<c>PREEMPTED</c>), only as many as needed (<see cref="CriticalShedding"/>):
    /// a stop is due only while available memory is below the Critical threshold at that evaluation, or once per newly observed OOM kill,
    /// and never before the previous victim has finalized and one more sample was taken. Non-preemptible attempts are never stopped for
    /// pressure; when only they remain while available memory is below the Critical threshold, a critical <c>MEMORY_PRESSURE</c> finding
    /// leaves the decision to the user. Tight (admission) and the Pressure-level freeze or requeue join with the scheduler (AF-SCHED-01)
    /// through <see cref="IPressureResponse"/>.
    /// </summary>
    void IPressureResponse.Respond(PressureLevel level, PressureLevel previous, ResourceState state)
    {
        SchedulerRespond(level, previous, state);
        var victimRunning = _lastVictim is { } last && _running.TryGetValue(last.Name, out var current) && ReferenceEquals(current, last);
        var due = _shedding.ShouldStop(level, state.RawPressure, state.MemoryCritical, state.NewOomKills, victimRunning);
        if (level != PressureLevel.Critical)
        {
            _onlyProtectedReported = false;
            return;
        }

        var settings = Settings;
        if (!due || !settings.Pressure.CancelOnCritical || _stop.IsCancellationRequested)
        {
            return;
        }

        RunningAttempt? victim;
        lock (_preemptGate)
        {
            var candidates = _running.Values.ToList();
            var chosen = CriticalShedding.Victim(candidates.Select(attempt =>
            {
                var eligible = attempt.Preemptible && attempt.Handle is not null && !attempt.Finalizing && attempt.StopReason is null && attempt.StopRecording is null;
                return new ShedCandidate(attempt.Name, attempt.Priority, attempt.StartedTimestamp, attempt.Preemptible, attempt.Handle is not null,
                    attempt.Finalizing, attempt.StopReason is not null || attempt.StopRecording is not null, eligible && OomKilled(attempt.Handle!));
            }));
            victim = chosen is null ? null : candidates.First(attempt => attempt.Name == chosen.Name);
        }

        if (victim is not null)
        {
            if (Preempt(victim, state))
            {
                _lastVictim = victim;
                _shedding.Stopped();
            }

            return;
        }

        if (!_onlyProtectedReported && _running.Values.Any(attempt => !attempt.Finalizing) && state.MemoryCritical)
        {
            _onlyProtectedReported = true;
            _ = RecordAsync(context =>
            {
                ExecutionFindings.Raise(context, FindingKind.MemoryPressure, Severity.Error, "node", _store.Metadata.NodeId.Span,
                    "Critical memory pressure with only non-preemptible work",
                    "Available memory is below the Critical threshold and every running attempt is non-preemptible, so the node stops none of them; "
                    + "the decision is yours (03 section 5.4). The operating system's own limits still apply.",
                    [("available_bytes", state.AvailableMemory.ToString(CultureInfo.InvariantCulture)),
                        ("capacity_bytes", state.CapacityMemory.ToString(CultureInfo.InvariantCulture)), ("trigger", state.PressureTrigger),
                        ("running_attempts", _running.Count.ToString(CultureInfo.InvariantCulture))]);
                return 0;
            });
        }
    }

    /// <summary>
    /// True when the attempt's own container recorded an OOM kill (Linux <c>memory.events oom_kill</c> > 0); an unreadable container
    /// counts as not OOM-killed.
    /// </summary>
    private static bool OomKilled(IAttemptHandle handle)
    {
        try
        {
            return handle.Accounting().LimitViolations.Contains("oom_kill");
        }
        catch (Exception exception) when (exception is Win32Exception or IOException or InvalidOperationException or ObjectDisposedException
            or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Stops a preemptible attempt at Critical pressure: STOPPING is recorded with the trigger, then the container is stopped at once. False
    /// when the attempt was already being stopped for another reason.
    /// </summary>
    private bool Preempt(RunningAttempt attempt, ResourceState state)
    {
        var detail = string.Create(CultureInfo.InvariantCulture,
            $"preempted at critical memory pressure ({state.PressureTrigger}; {state.AvailableMemory} of {state.CapacityMemory} bytes available); stopped without the graceful phase");
        lock (attempt)
        {
            if (attempt.StopReason is not null || attempt.StopRecording is not null)
            {
                return false;
            }
        }

        _log.Warning("execution.preempted", new LogField("attempt", attempt.Name), new LogField("priority", attempt.Priority),
            new LogField("trigger", state.PressureTrigger), new LogField("availableBytes", state.AvailableMemory));
        Stop(attempt.Name, TerminationReason.Preempted, null, graceful: false, detail);
        return true;
    }

    private async Task RecordAsync(Func<CommandContext, int> command)
    {
        try
        {
            await _processor.ExecuteAsync(command).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException or ObjectDisposedException
            or InvalidOperationException)
        {
            _log.Warning("execution.pressure.record_failed", new LogField("errorType", exception.GetType().Name));
        }
    }

    // --------------------------------------------------------------------------------------------------------------------- submit

    /// <summary>Persists a submission in the writer (AD-0006 section 1: before the receipt) and journals it.</summary>
    public TaskServiceSubmitTaskValue Submit(CommandContext context, SubmitPlan plan)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(plan);
        var transaction = context.Transaction;
        var now = transaction.NowMicroseconds;
        var taskId = StoreIds.NewUuid7(transaction.Clock);
        var spec = plan.Parts.RedactedSpec;
        byte[]? envDigest = plan.Parts.Snapshot is { } snapshot ? EnvSnapshots.Reference(transaction, snapshot) : null;
        var specBytes = spec.ToByteArray();
        var labels = JsonSerializer.Serialize(new Dictionary<string, string>(spec.Labels, StringComparer.Ordinal), ExecutionJsonContext.Default.DictionaryStringString);

        // 04 section 8: a task with dependencies starts in WAITING_DEPENDENCY; the admission pass queues or cancels it.
        var waiting = plan.Dependencies.Count > 0;
        transaction.Execute(
            """
            INSERT INTO task (task_id, state, state_reason, kind, title, command_summary, spec, env_digest, spec_digest, owner, owner_origin, owner_session_id,
                              workspace_id, pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint, command_digest, created_at,
                              queued_at, pinned, labels_json, rev)
            VALUES ($id, $state, $reason, $kind, $title, $summary, $spec, $env, $specDigest, $owner, $origin, $session, $workspace, $pool, $priority, $priority,
                    $sideEffect, $source, $fingerprint, $digest, $now, $now, $pinned, $labels, 0);
            """,
            ("$id", taskId), ("$state", waiting ? (int)TaskState.WaitingDependency : (int)TaskState.Queued), ("$reason", waiting ? Scheduling.BlockingReasons.Dependency : null),
            ("$kind", (int)plan.Kind), ("$title", plan.Title), ("$summary", plan.Summary), ("$spec", specBytes), ("$env", envDigest),
            ("$specDigest", System.Security.Cryptography.SHA256.HashData(specBytes)), ("$owner", plan.Owner.ToByteArray()), ("$origin", (int)plan.Owner.Origin),
            ("$session", plan.SessionId), ("$workspace", plan.WorkspaceId), ("$pool", plan.Pool), ("$priority", (int)plan.Priority), ("$sideEffect", (int)plan.SideEffect),
            ("$source", (int)plan.SideEffectSource), ("$fingerprint", plan.Fingerprint), ("$digest", plan.CommandDigest), ("$now", now),
            ("$pinned", spec.Output?.Pin == true ? 1 : 0), ("$labels", labels));
        foreach (var (dependsOn, condition) in plan.Dependencies)
        {
            transaction.Execute("INSERT INTO task_dependency (task_id, depends_on_task_id, condition) VALUES ($id, $on, $condition);",
                ("$id", taskId), ("$on", dependsOn), ("$condition", (int)condition));
        }

        foreach (var key in plan.Keys)
        {
            transaction.Execute("INSERT INTO task_concurrency_key (task_id, concurrency_key, mode, source, released_at) VALUES ($id, $key, $mode, $source, NULL);",
                ("$id", taskId), ("$key", key.Key.Text), ("$mode", (int)key.Mode), ("$source", (int)key.Source));
        }

        if (plan.Parts.Secrets is { } secrets)
        {
            _secrets.Seal(transaction, taskId, secrets);
        }

        var task = EmitTask(context, taskId, null)!;
        var value = new TaskServiceSubmitTaskValue
        {
            Receipt = new Receipt { CommandId = plan.CommandId, Effect = EffectCertainty.Happened },
            TaskId = task.TaskId,
            State = task.State,
            Queue = task.Queue ?? new QueueInfo(),
        };
        value.Warnings.Add(plan.Warnings);
        return value;
    }

    /// <summary>After a submission committed: binds the caller and wakes the admission loop.</summary>
    public void Submitted(ReadOnlySpan<byte> taskId, CallerKey? caller)
    {
        if (caller is { } key)
        {
            _bindings[IdText.Format(taskId)] = key;
        }

        Kick();
    }

    // ------------------------------------------------------------------------------------------------------------------- control

    /// <summary>Cancels a task in the writer; returns its state and the attempt to stop afterwards (04 section 6).</summary>
    public (TaskState State, ArcError? Error, string? StopAttempt) Cancel(CommandContext context, ReadOnlySpan<byte> taskId, string reason)
    {
        ArgumentNullException.ThrowIfNull(context);
        var transaction = context.Transaction;
        var row = TaskRecords.GetRow(transaction, taskId);
        if (row is null || row.Purged)
        {
            return (TaskState.Unspecified, NodeErrors.NotFound("task", taskId), null);
        }

        if (row.Terminal)
        {
            return (row.State, null, null);
        }

        if (row.Spec.Kind == TaskKind.Adopted)
        {
            // 04 section 10: cancelling an adopted task terminates its adoption container.
            return (Adoptions.Cancel(context, taskId, reason) ?? row.State, null, null);
        }

        if (row.State is TaskState.Queued or TaskState.WaitingDependency or TaskState.RetryWait or TaskState.Placing)
        {
            transaction.Execute(
                "UPDATE task SET state = 9, state_reason = $reason, finished_at = $now, retry_at = NULL, reserved_for_large = 0, rev = rev + 1 WHERE task_id = $id;",
                ("$reason", Truncate(reason)), ("$now", transaction.NowMicroseconds), ("$id", taskId.ToArray()));
            TaskSecrets.SchedulePurge(transaction, taskId, transaction.NowMicroseconds, Settings.SecretRetention);
            EmitTask(context, taskId, row.State);
            return (TaskState.Cancelled, null, null);
        }

        if (row.CurrentAttemptId is { } attemptId)
        {
            // The event names the state the attempt left: STARTING when the cancel arrives while it is being launched, not always RUNNING.
            var attemptState = (AttemptState)Convert.ToInt32(transaction.Scalar("SELECT state FROM attempt WHERE attempt_id = $id;", ("$id", attemptId)),
                CultureInfo.InvariantCulture);
            var stopping = transaction.Execute(
                "UPDATE attempt SET state = 7, termination_reason = $cause, detail = $detail, rev = rev + 1 WHERE attempt_id = $id AND state IN (3, 4, 5, 6);",
                ("$cause", (int)TerminationReason.Cancelled), ("$detail", Truncate(reason)), ("$id", attemptId));
            transaction.Execute("UPDATE task SET state_reason = $reason, rev = rev + 1 WHERE task_id = $id;", ("$reason", Truncate(reason)), ("$id", taskId.ToArray()));
            if (stopping == 1)
            {
                EmitAttempt(context, attemptId, attemptState);
            }

            EmitTask(context, taskId, row.State);
            return (row.State, null, IdText.Format(attemptId));
        }

        return (row.State, null, null);
    }

    /// <summary>
    /// The forced phase of a stop (the caller holds the attempt's lock): the container is terminated at once, which also ends a launch step
    /// that runs in it. While the command is still being started the container may still be empty, and the holder or the unit may start the
    /// command afterwards; so when the start had not completed before the termination, one more termination is owed to that late start
    /// (<see cref="TerminateWhenStarted"/>).
    /// </summary>
    private void ForceWhenStarted(RunningAttempt attempt, IAttemptHandle handle, TerminationReason reason)
    {
        // Read before the termination: a start that completed before it is ended by it; any later one is ended again.
        var startPending = !handle.Started.IsCompleted;
        if (Force(attempt, handle, reason) && startPending)
        {
            TerminateWhenStarted(attempt, handle, reason);
        }
    }

    /// <summary>
    /// After a forced phase (the termination, or a limit stop) that ran while the attempt's start had not completed (the caller holds the
    /// attempt's lock): one more termination is owed to the late start (<see cref="RunningAttempt.TerminationOwed"/>). Whichever comes first
    /// makes it:
    /// <list type="bullet">
    /// <item>the start completing with a root: a continuation registered after the termination whatever the start did meanwhile, so it runs
    /// at once when the start already completed;</item>
    /// <item>a verification after the window that finds processes in the container: the late start entered it before the node saw the start
    /// complete, and the verification terminates it instead of recording TERMINATION_INCOMPLETE (<see cref="Enforce"/>).</item>
    /// </list>
    /// The debt is settled by either, and by a start that completes without a root (the launch failed or was stopped). Nothing creates it again,
    /// because an attempt is forced once. So a start that never completes (a holder that never resumes, a unit whose start never runs) costs
    /// nothing and loops nowhere, and a process that survives the terminations is still recorded TERMINATION_INCOMPLETE, at most one window
    /// later. Each process that enters a re-opened container is terminated at once too, whether or not the start was pending
    /// (<see cref="TerminateEachLaunchProcess"/>). Every termination counts the verification window anew. Nothing is terminated after the
    /// node began to stop (it released the handles), once the attempt is being recorded or no longer supervised, or through a handle disposed
    /// meanwhile.
    /// </summary>
    private void TerminateWhenStarted(RunningAttempt attempt, IAttemptHandle handle, TerminationReason reason)
    {
        attempt.TerminationOwed = true;
        _forcedBeforeStart?.Invoke(handle);
        _ = handle.Started.ContinueWith(started =>
        {
            var root = started.IsCompletedSuccessfully ? started.Result : null;
            if (root is null)
            {
                // No command started: the launch failure (or the stopped launch step) finalizes the attempt.
                lock (attempt)
                {
                    attempt.TerminationOwed = false;
                }

                return;
            }

            _startObserved?.Invoke(handle, false);
            try
            {
                TerminateAgain(attempt, handle, reason);
            }
            finally
            {
                _startObserved?.Invoke(handle, true);
            }
        }, TaskScheduler.Default);
    }

    /// <summary>
    /// Every forced phase, before its termination (the caller holds the attempt's lock): each process reported to enter the container afterwards
    /// (<see cref="IAttemptHandle.LaunchProcessEntered"/>, raised only by a handle re-opened after a restart while its launch may still go on)
    /// is terminated at once, whether or not the start was still pending. A handle re-opened for a stop completes its start on the first
    /// process that enters, possibly a launch step that ended before the forced phase; the holder's next process can then enter after the
    /// termination with nothing owed to it. A handle re-opened for an attempt the node was not stopping completed its start at once, so the
    /// forced phase arms it here (<see cref="IAttemptHandle.WatchLaunch"/>): when it now watches a launch that may still go on, one more
    /// termination is owed to that late start (<see cref="RunningAttempt.TerminationOwed"/>), made by its first report or by a verification
    /// that finds it first, as in <see cref="TerminateWhenStarted"/>. Subscribed before the termination, so none that enters after it is
    /// missed, and once per attempt (a termination that threw is retried by the next pass).
    /// </summary>
    private void TerminateEachLaunchProcess(RunningAttempt attempt, IAttemptHandle handle, TerminationReason reason)
    {
        if (attempt.LaunchProcessesWatched)
        {
            return;
        }

        attempt.LaunchProcessesWatched = true;
        handle.LaunchProcessEntered += entered => _ = Task.Run(() => TerminateAgain(attempt, handle, reason));
        if (handle.WatchLaunch())
        {
            attempt.TerminationOwed = true;
        }
    }

    /// <summary>
    /// The owed termination of a late start (<see cref="TerminateWhenStarted"/>), or of a process that entered a re-opened container
    /// (<see cref="TerminateEachLaunchProcess"/>); takes the attempt's lock.
    /// </summary>
    private void TerminateAgain(RunningAttempt attempt, IAttemptHandle handle, TerminationReason reason)
    {
        lock (attempt)
        {
            attempt.TerminationOwed = false;
            if (!attempt.Finalizing && !_stopping.IsCancellationRequested && _running.TryGetValue(attempt.Name, out var current) && current == attempt)
            {
                TerminateNow(attempt, handle, reason);
            }
        }
    }

    /// <summary>Terminates the attempt once (a stop and the launch can both get here); never one that is already being recorded.</summary>
    private bool Force(RunningAttempt attempt, IAttemptHandle handle, TerminationReason reason)
    {
        if (attempt.Forced || attempt.Finalizing)
        {
            return false;
        }

        attempt.Forced = true;
        TerminateEachLaunchProcess(attempt, handle, reason);
        TerminateNow(attempt, handle, reason);
        return true;
    }

    private void TerminateNow(RunningAttempt attempt, IAttemptHandle handle, TerminationReason reason)
    {
        try
        {
            handle.Terminate();
        }
        catch (ObjectDisposedException)
        {
            // The node is stopping and released the handle: the holder or the unit keeps the attempt for the next start.
            return;
        }

        TerminateEscaped(attempt, reason);
        attempt.VerifyDeadline = _clock.GetTimestamp() + (long)(VerifyWindow.TotalSeconds * TimeProvider.System.TimestampFrequency);
        _loopWake.Pulse();
    }

    /// <summary>
    /// Starts the stop sequence of a running attempt (04 section 6): the graceful phase (Windows: CTRL_BREAK through the helper and
    /// WM_CLOSE; Linux: <c>KillUnit("all", stop_signal)</c>), <paramref name="grace"/>, then the forced phase. Limit stops
    /// (<paramref name="graceful"/> false with <c>OUTPUT_LIMIT</c> or <c>DISK_LIMIT</c>) stop at once without the graceful phase; on Linux
    /// the unit is frozen before it is killed.
    /// </summary>
    public void Stop(string attemptName, TerminationReason reason, TimeSpan? grace, bool graceful = true, string? detail = null)
    {
        if (!_running.TryGetValue(attemptName, out var attempt))
        {
            return;
        }

        lock (attempt)
        {
            if (attempt.Finalizing)
            {
                return;
            }

            if (attempt.StopRecording is { } pending)
            {
                if (!graceful)
                {
                    _ = ForceAfterRecordingAsync(pending, attempt);
                }

                return;
            }

            attempt.StopRecording = RecordStopAndApplyAsync(attempt, reason, grace, graceful, detail ?? attempt.StopDetail);
        }
    }

    private async Task ForceAfterRecordingAsync(Task pending, RunningAttempt attempt)
    {
        await pending.ConfigureAwait(false);
        if (attempt.StopReason is { } reason)
        {
            ApplyRecordedStop(attempt, reason, null, graceful: false);
        }
    }

    private async Task RecordStopAndApplyAsync(RunningAttempt attempt, TerminationReason reason, TimeSpan? grace, bool graceful, string? detail)
    {
        for (var tries = 0; ; tries++)
        {
            try
            {
                var stop = await _processor.ExecuteAsync(context =>
                {
                    var transaction = context.Transaction;
                    var previous = TaskRecords.GetAttemptRow(transaction, attempt.AttemptId);
                    if (previous is null || previous.State is AttemptState.Finalizing or AttemptState.Finished)
                    {
                        return (Apply: false, Cause: reason, Detail: (string?)null);
                    }

                    if (previous.State == AttemptState.Stopping)
                    {
                        return (Apply: true, Cause: previous.Reason ?? TerminationReason.Cancelled, Detail: previous.Detail);
                    }

                    if (transaction.Execute(
                        "UPDATE attempt SET state = 7, termination_reason = $cause, detail = $detail, rev = rev + 1 WHERE attempt_id = $id AND state IN (3, 4, 5, 6);",
                        ("$cause", (int)reason), ("$detail", detail is null ? null : Truncate(detail)), ("$id", attempt.AttemptId)) != 1)
                    {
                        return (Apply: false, Cause: reason, Detail: (string?)null);
                    }

                    EmitAttempt(context, attempt.AttemptId, previous.State);
                    if (detail is not null)
                    {
                        transaction.Execute("UPDATE task SET state_reason = $reason, rev = rev + 1 WHERE task_id = $id;",
                            ("$reason", Truncate(detail)), ("$id", attempt.TaskId));
                        EmitTask(context, attempt.TaskId, null);
                    }

                    return (Apply: true, Cause: reason, Detail: detail);
                }).ConfigureAwait(false);
                if (stop.Apply)
                {
                    lock (attempt)
                    {
                        attempt.StopDetail ??= stop.Detail;
                    }

                    ApplyRecordedStop(attempt, stop.Cause, grace, graceful);
                }

                return;
            }
            catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException or IOException)
            {
                _log.Warning("execution.stop.record_failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
                // The stop remains pending; it is never applied ahead of its durable cause. Shutdown leaves an unrecorded holder
                // unacknowledged for recovery rather than declaring a successful result.
                if (_stop.IsCancellationRequested && tries >= 10)
                {
                    throw;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(200 * (tries + 1), 1_000))).ConfigureAwait(false);
            }
        }
    }

    private void ApplyRecordedStop(RunningAttempt attempt, TerminationReason reason, TimeSpan? grace, bool graceful)
    {
        try
        {
            ApplyStop(attempt, reason, grace, graceful);
        }
        catch (Exception exception) when (exception is Win32Exception or IOException or InvalidOperationException or TimeoutException)
        {
            _log.Warning("execution.stop.apply_failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
            lock (attempt)
            {
                // The durable intent survives a failed platform call; the enforcement loop retries the forced phase.
                attempt.StopReason ??= reason;
                attempt.Forced = false;
                attempt.GraceDeadline = _clock.GetTimestamp();
            }

            _loopWake.Pulse();
        }
    }

    private void ApplyStop(RunningAttempt attempt, TerminationReason reason, TimeSpan? grace, bool graceful)
    {
        var attemptName = attempt.Name;
        lock (attempt)
        {
            if (attempt.StopReason is not null)
            {
                if (graceful || attempt.Forced)
                {
                    return;
                }
            }
            else
            {
                attempt.StopReason = reason;
            }

            if (attempt.Handle is null)
            {
                // Still being launched: there is nothing to stop yet, and the launch applies the forced phase once the handle exists.
                // Marking it forced here would skip that, and the command would run on past the stop (TERMINATION_INCOMPLETE).
                return;
            }

            if ((reason == TerminationReason.Preempted ? _faults.Take("hold-preempt-before-stop") : _faults.Take("hold-stop-before-stop")) is { } hold)
            {
                _log.Warning(reason == TerminationReason.Preempted ? "node.fault.hold_preempt_before_stop" : "node.fault.hold_stop_before_stop",
                    new LogField("attempt", attempt.Name));
                Thread.Sleep(hold);
            }

            // The escaped processes as the stop begins: once the root has exited, a scan may no longer find them (on Linux they are
            // re-parented to the user manager), and the stop sequence terminates the recorded ones (04 section 6 step 4).
            ScanEscaped(attempt, attempt.Handle);
            if (!graceful || attempt.Handle.Root is null)
            {
                // A limit stop is a forced phase too: read before it, as in ForceWhenStarted.
                var startPending = !attempt.Handle.Started.IsCompleted;
                if (!graceful && reason is TerminationReason.OutputLimit or TerminationReason.DiskLimit or TerminationReason.Preempted)
                {
                    TerminateEachLaunchProcess(attempt, attempt.Handle, reason);
                    var how = attempt.Handle.StopAtLimit();
                    _log.Info("execution.limit_stop", new LogField("attempt", attemptName), new LogField("reason", reason),
                        new LogField("container", attempt.Handle.ContainerName), new LogField("stop", how));
                }
                else
                {
                    ForceWhenStarted(attempt, attempt.Handle, reason);
                    return;
                }

                TerminateEscaped(attempt, reason);
                attempt.Forced = true;
                attempt.VerifyDeadline = _clock.GetTimestamp() + (long)(VerifyWindow.TotalSeconds * TimeProvider.System.TimestampFrequency);
                _loopWake.Pulse();
                if (startPending)
                {
                    TerminateWhenStarted(attempt, attempt.Handle, reason);
                }

                return;
            }
        }

        var period = grace ?? attempt.CancelGrace;
        var phase = new Task(() =>
        {
            GracefulOutcome? outcome = null;
            try
            {
                if (attempt.Paused)
                {
                    // A frozen attempt cannot act on the graceful signal: it is thawed first (its launch MemoryHigh restored).
                    if (attempt.MemoryHighBytes > 0)
                    {
                        attempt.Handle.SetMemoryHigh(attempt.MemoryHighBytes);
                    }

                    attempt.Handle.Thaw();
                    attempt.Paused = false;
                }

                outcome = attempt.Handle.RequestGracefulStop(attempt.StopSignal);
            }
            catch (Exception exception) when (exception is Win32Exception or IOException or InvalidOperationException or TimeoutException)
            {
                _log.Warning("execution.stop.graceful_failed", new LogField("attempt", attemptName), new LogField("errorType", exception.GetType().Name));
            }

            lock (attempt)
            {
                attempt.StopDetail = outcome is null
                    ? "the graceful phase failed; the grace period applies"
                    : !OperatingSystem.IsWindows()
                        ? outcome.ConsoleSignalled
                            ? $"{attempt.StopSignal ?? "SIGTERM"} sent to every process of the attempt"
                            : $"graceful signal not delivered ({outcome.Reason})"
                        : outcome.ConsoleSignalled
                            ? $"CTRL_BREAK_EVENT delivered; WM_CLOSE posted to {outcome.WindowsClosed} window(s)"
                            : $"graceful signal not delivered ({outcome.Reason}); WM_CLOSE posted to {outcome.WindowsClosed} window(s)";
                attempt.GraceDeadline = _clock.GetTimestamp() + (long)(period.TotalSeconds * TimeProvider.System.TimestampFrequency);
            }

            _log.Info("execution.stop.graceful", new LogField("attempt", attemptName), new LogField("reason", reason),
                new LogField("consoleSignalled", outcome?.ConsoleSignalled ?? false), new LogField("windowsClosed", outcome?.WindowsClosed ?? 0),
                new LogField("graceMs", (long)period.TotalMilliseconds));
            _loopWake.Pulse();
        });

        // Kept before it starts: the root may exit on the signal before the phase records its detail, and finalization waits for it.
        attempt.GracefulPhase = phase;
        phase.Start(TaskScheduler.Default);
    }

    /// <summary>
    /// A manual retry (SM-TASK FAILED|CANCELLED|LOST -> QUEUED; AD-0006 section 4 rules shown as warnings). <paramref name="demand"/> replaces
    /// the fields it sets in the task's hint (a larger memory grant after an OOM kill).
    /// </summary>
    public (TaskServiceRetryTaskValue? Value, ArcError? Error) Retry(CommandContext context, ReadOnlySpan<byte> taskId, Id commandId, ResourceDemand? demand = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        var transaction = context.Transaction;
        var row = TaskRecords.GetRow(transaction, taskId);
        if (row is null || row.Purged)
        {
            return (null, NodeErrors.NotFound("task", taskId));
        }

        if (row.State is not (TaskState.Failed or TaskState.Cancelled or TaskState.Lost))
        {
            return (null, NodeErrors.InvalidState(row.State.ToString().ToUpperInvariant(), "only FAILED, CANCELLED or LOST tasks can be retried"));
        }

        if (row.Spec.Kind == TaskKind.Adopted)
        {
            // 04 section 10: an adopted process was started outside ArcForges; there is nothing to run again.
            return (null, NodeErrors.InvalidState("ADOPTED", "an adopted task cannot be retried"));
        }

        var unseal = _secrets.Unseal(transaction, taskId);
        if (unseal.Status == UnsealStatus.Unavailable)
        {
            return (null, unseal.Error);
        }

        if (demand is not null)
        {
            var spec = row.Spec.Clone();
            spec.Resources ??= new ResourceSpec();
            spec.Resources.Hint ??= new ResourceDemand();
            if (demand.HasCpuMillicores)
            {
                spec.Resources.Hint.CpuMillicores = demand.CpuMillicores;
            }

            if (demand.HasMemExpectedBytes)
            {
                spec.Resources.Hint.MemExpectedBytes = demand.MemExpectedBytes;
            }

            if (demand.HasMemCeilingBytes)
            {
                spec.Resources.Hint.MemCeilingBytes = demand.MemCeilingBytes;
            }

            var bytes = spec.ToByteArray();
            transaction.Execute("UPDATE task SET spec = $spec, spec_digest = $digest WHERE task_id = $id;",
                ("$spec", bytes), ("$digest", System.Security.Cryptography.SHA256.HashData(bytes)), ("$id", taskId.ToArray()));
        }

        transaction.Execute(
            "UPDATE task SET state = 1, state_reason = 'retry', queued_at = $now, finished_at = NULL, retry_at = NULL, effective_priority = priority, aged_at = NULL, rev = rev + 1 WHERE task_id = $id;",
            ("$now", transaction.NowMicroseconds), ("$id", taskId.ToArray()));
        transaction.Execute("UPDATE task_secret SET purge_after = NULL WHERE task_id = $id AND key_id <> 'purged';", ("$id", taskId.ToArray()));
        EmitTask(context, taskId, row.State);
        var value = new TaskServiceRetryTaskValue
        {
            Receipt = new Receipt { CommandId = commandId, Effect = EffectCertainty.Happened },
            State = TaskState.Queued,
        };
        if (row.SideEffect is SideEffectClass.SideEffecting or SideEffectClass.Unknown)
        {
            value.Warnings.Add(row.SideEffect == SideEffectClass.SideEffecting
                ? "The task is side-effecting: running it again repeats its external effects."
                : "The task's side effects are unknown: running it again may repeat external effects.");
        }

        return (value, null);
    }

    /// <summary>Pins or unpins a task's records and output.</summary>
    public ArcError? Pin(CommandContext context, ReadOnlySpan<byte> taskId, bool pinned)
    {
        ArgumentNullException.ThrowIfNull(context);
        var changed = context.Transaction.Execute("UPDATE task SET pinned = $pinned, rev = rev + 1 WHERE task_id = $id AND purged_at IS NULL;",
            ("$pinned", pinned ? 1 : 0), ("$id", taskId.ToArray()));
        if (changed == 0)
        {
            return NodeErrors.NotFound("task", taskId);
        }

        EmitTask(context, taskId, null);
        return null;
    }

    /// <summary>
    /// <c>PurgeTaskRecord</c>: a terminal task's sealed values are purged now, its attempts' output is marked purged (the files are removed
    /// after the commit) and its detailed records (timeline segments, process records, samples) deleted; summary counters remain.
    /// </summary>
    public (List<string> Directories, ArcError? Error) Purge(CommandContext context, ReadOnlySpan<byte> taskId)
    {
        ArgumentNullException.ThrowIfNull(context);
        var transaction = context.Transaction;
        var row = TaskRecords.GetRow(transaction, taskId);
        if (row is null || row.Purged)
        {
            return ([], NodeErrors.NotFound("task", taskId));
        }

        if (!row.Terminal)
        {
            return ([], NodeErrors.InvalidState(row.State.ToString().ToUpperInvariant(), "only a terminal task's record can be purged"));
        }

        var attempts = TaskRecords.ListAttempts(transaction, taskId);
        foreach (var attempt in attempts)
        {
            var id = attempt.AttemptId.Value.ToByteArray();
            transaction.Execute("DELETE FROM timeline_segment WHERE attempt_id = $id;", ("$id", id));
            transaction.Execute("DELETE FROM process_record WHERE attempt_id = $id;", ("$id", id));
            transaction.Execute("DELETE FROM phase_event WHERE attempt_id = $id;", ("$id", id));
            transaction.Execute("DELETE FROM resource_sample WHERE scope = 3 AND subject_id = $id;", ("$id", id));
            transaction.Execute("UPDATE attempt SET output_purged = 1, detail = NULL, leftover_images_json = '[]', rev = rev + 1 WHERE attempt_id = $id;", ("$id", id));
        }

        TaskSecrets.PurgeNow(transaction, taskId);
        if (row.EnvDigest is { } digest)
        {
            EnvSnapshots.Release(transaction, digest);
            transaction.Execute("UPDATE task SET env_digest = NULL WHERE task_id = $id;", ("$id", taskId.ToArray()));
        }

        var redacted = new TaskSpec { Command = new CommandSpec(), WorkingDirectory = string.Empty };
        transaction.Execute(
            "UPDATE task SET purged_at = $now, spec = $spec, labels_json = '{}', rev = rev + 1 WHERE task_id = $id;",
            ("$now", transaction.NowMicroseconds), ("$spec", redacted.ToByteArray()), ("$id", taskId.ToArray()));
        EmitTask(context, taskId, null);
        return ([.. attempts.Select(attempt => new AttemptFiles(_dataRoot, IdText.Format(attempt.AttemptId)).Directory)], null);
    }

    /// <summary><c>ReleaseCallerBinding</c>: <c>cancel_when_caller_gone</c> no longer applies (natural idempotency).</summary>
    public (TaskState State, ArcError? Error) ReleaseCaller(CommandContext context, ReadOnlySpan<byte> taskId)
    {
        ArgumentNullException.ThrowIfNull(context);
        var row = TaskRecords.GetRow(context.Transaction, taskId);
        if (row is null || row.Purged)
        {
            return (TaskState.Unspecified, NodeErrors.NotFound("task", taskId));
        }

        if (row.CallerReleasedAt is null)
        {
            context.Transaction.Execute("UPDATE task SET caller_released_at = $now, rev = rev + 1 WHERE task_id = $id;",
                ("$now", context.Transaction.NowMicroseconds), ("$id", taskId.ToArray()));
        }

        _bindings.TryRemove(IdText.Format(taskId), out _);
        return (row.State, null);
    }

    /// <summary>A client process opened a connection (counted for <c>cancel_when_caller_gone</c>).</summary>
    public void CallerConnected(CallerKey caller) => _callerConnections.AddOrUpdate(caller, 1, (_, count) => count + 1);

    /// <summary>
    /// A client process closed a connection. While it has none, the node checks every 250 ms whether the process still exists: once it is
    /// gone (killed or interrupted), its bound tasks are cancelled at once, within 5 s of its end (AD-0006 section 7: interrupts before
    /// the hand-off still cancel). A process that is alive and reconnects (a lost connection) keeps its bindings.
    /// </summary>
    public void CallerDisconnected(CallerKey caller)
    {
        var remaining = _callerConnections.AddOrUpdate(caller, 0, (_, count) => Math.Max(0, count - 1));
        if (remaining > 0 || !_bindings.Values.Contains(caller))
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                while (CallerAlive(caller))
                {
                    await Task.Delay(CallerPollInterval, _stop.Token).ConfigureAwait(false);
                    if (_callerConnections.TryGetValue(caller, out var count) && count > 0)
                    {
                        return;
                    }
                }

                await CancelBoundAsync(caller).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The node stops; bindings are not durable.
            }
        });
    }

    /// <summary>Cancels the tasks bound to a caller that is gone; a full command queue is retried, so no binding is lost.</summary>
    private async Task CancelBoundAsync(CallerKey caller)
    {
        foreach (var (task, key) in _bindings.ToArray())
        {
            if (key != caller || !IdText.TryParse(task, out var taskId))
            {
                continue;
            }

            for (var tries = 0; ; tries++)
            {
                try
                {
                    var (_, error, stop) = await _processor.ExecuteAsync(context =>
                    {
                        var row = TaskRecords.GetRow(context.Transaction, taskId);
                        return row is null || row.Terminal || row.CallerReleasedAt is not null
                            ? (TaskState.Unspecified, (ArcError?)null, (string?)null)
                            : Cancel(context, taskId, "caller_gone");
                    }).ConfigureAwait(false);
                    _bindings.TryRemove(task, out _);
                    if (stop is not null)
                    {
                        Stop(stop, TerminationReason.Cancelled, null);
                    }

                    _log.Info("execution.caller_gone", new LogField("task", task), new LogField("cancelled", error is null));
                    Kick();
                    break;
                }
                catch (CommandQueueFullException)
                {
                    _log.Warning("execution.caller_gone.queue_full", new LogField("task", task), new LogField("tries", tries + 1));
                    await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(100 * (tries + 1), 1_000)), _stop.Token).ConfigureAwait(false);
                }
            }
        }
    }

    /// <summary>True while the process of <paramref name="caller"/> (its ID and start time) still exists.</summary>
    private static bool CallerAlive(CallerKey caller)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(caller.ProcessId);
            return !process.HasExited && Math.Abs(process.StartTime.ToUniversalTime().Ticks - caller.StartTicks) < CallerStartTolerance.Ticks;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException)
        {
            return false;
        }
    }

    // ------------------------------------------------------------------------------------------------------------------------ stdin

    /// <summary>Grants the stdin of a task's running attempt to one attach; false when another holds it or the task has no STREAM stdin.</summary>
    public bool ClaimStdin(ReadOnlySpan<byte> taskId, string attachId)
    {
        var task = IdText.Format(taskId);
        var attempt = _running.Values.FirstOrDefault(running => IdText.Format(running.TaskId) == task);
        if (attempt?.Handle?.StdinWriter is null)
        {
            return false;
        }

        lock (attempt.StdinGate)
        {
            if (attempt.StdinAttach is not null && attempt.StdinAttach != attachId)
            {
                return false;
            }

            attempt.StdinAttach = attachId;
            return true;
        }
    }

    /// <summary>Releases an attach's stdin claim.</summary>
    public void ReleaseStdin(string attachId)
    {
        foreach (var attempt in _running.Values)
        {
            lock (attempt.StdinGate)
            {
                if (attempt.StdinAttach == attachId)
                {
                    attempt.StdinAttach = null;
                }
            }
        }
    }

    /// <summary><c>WriteTaskInput</c>: ordered, deduplicated writes by offset.</summary>
    public (ulong AcceptedThrough, ArcError? Error) WriteInput(ReadOnlySpan<byte> taskId, string attachId, ulong offset, ReadOnlySpan<byte> data)
    {
        var attempt = StdinAttempt(taskId, attachId, out var error);
        if (attempt is null)
        {
            return (0, error);
        }

        lock (attempt.StdinGate)
        {
            var accepted = (ulong)attempt.StdinAccepted;
            if (attempt.StdinClosed)
            {
                return (accepted, NodeErrors.InvalidState("CLOSED", "stdin was closed"));
            }

            if (offset + (ulong)data.Length <= accepted)
            {
                return (accepted, null);
            }

            if (offset != accepted)
            {
                return (accepted, NodeErrors.RevisionConflict((long)accepted, (long)offset));
            }

            try
            {
                attempt.Handle!.StdinWriter!.Write(data);
                attempt.Handle.StdinWriter.Flush();
            }
            catch (IOException)
            {
                return (accepted, NodeErrors.InvalidState("CLOSED", "the process closed its stdin"));
            }

            attempt.StdinAccepted += data.Length;
            return ((ulong)attempt.StdinAccepted, null);
        }
    }

    /// <summary><c>CloseTaskInput</c>.</summary>
    public ArcError? CloseInput(ReadOnlySpan<byte> taskId, string attachId)
    {
        var attempt = StdinAttempt(taskId, attachId, out var error);
        if (attempt is null)
        {
            return error;
        }

        lock (attempt.StdinGate)
        {
            if (!attempt.StdinClosed)
            {
                attempt.StdinClosed = true;
                attempt.Handle!.StdinWriter!.Dispose();
            }
        }

        return null;
    }

    // ------------------------------------------------------------------------------------------------------------- enforcement loop

    private void EnforcementLoop()
    {
        var hangAfter = _faults.Take("hang-tailer-after");
        var started = _clock.GetTimestamp();
        var lastPersist = _clock.GetTimestamp();
        while (!_stop.IsCancellationRequested)
        {
            var nanos = (_clock.GetUtcNow().UtcTicks - DateTime.UnixEpoch.Ticks) * 100;
            foreach (var attempt in _running.Values)
            {
                if (attempt.Finalizing)
                {
                    continue;
                }

                try
                {
                    Enforce(attempt, nanos);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException)
                {
                    _log.Warning("execution.enforce.failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
                }
            }

            _tailerMonitor.Completed();
            if (_clock.GetElapsedTime(lastPersist) >= TimeSpan.FromSeconds(5))
            {
                lastPersist = _clock.GetTimestamp();
                PersistOffsets();
            }

            Heartbeat.Tick();
            if (hangAfter is { } hang && _clock.GetElapsedTime(started) >= hang)
            {
                _log.Warning("node.fault.hang_tailer", new LogField("afterMs", (long)hang.TotalMilliseconds));
                _stop.Token.WaitHandle.WaitOne();
                return;
            }

            _loopWake.Next.Wait(TailInterval);
        }
    }

    private void Enforce(RunningAttempt attempt, long nanos)
    {
        if (attempt.Tail(nanos))
        {
            attempt.Changed.Pulse();
            TaskPulse(attempt.TaskId).Pulse();
        }

        var settings = Settings;
        // Under NOTIFY the check is done once the finding is raised; under TERMINATE the stop ends it. Only then is the guard's file read.
        if (settings.MaxOutputBytes > 0 && attempt.OutputBytes > settings.MaxOutputBytes && attempt.StopReason is null
            && !(settings.DiskLimitAction == "NOTIFY" && attempt.OutputNotified))
        {
            // The guard may have acted on the limit while the node was down (06 section 5): its decision stands and is recorded as GUARD.
            var guard = GuardEvent.ReadAll(attempt.Files.GuardEventsPath);
            if (settings.DiskLimitAction == "NOTIFY")
            {
                attempt.OutputNotified = true;
                var notified = guard.FirstOrDefault(item => item.Event == GuardEventKinds.Notify);
                RaiseOutputFinding(attempt, notified?.OutputBytes ?? attempt.OutputBytes, notified?.LimitBytes ?? settings.MaxOutputBytes, notified is null ? "NODE" : "GUARD");
            }
            else if (guard.FirstOrDefault(item => item.Event == GuardEventKinds.Terminate) is { } guardStop)
            {
                // The job is already terminated; the node records the guard's stop and lets the exit be collected.
                attempt.LimitEnforcedBy = "GUARD";
                attempt.StopDetail = $"stopped by the attempt's guard while the node was down ({guardStop.OutputBytes} bytes of output, limit {guardStop.LimitBytes})";
                Stop(attempt.Name, guardStop.Reason == "DISK_LIMIT" ? TerminationReason.DiskLimit : TerminationReason.OutputLimit, null, graceful: false);
            }
            else
            {
                // TERMINATE: at once, without the graceful phase (04 section 6 step 4).
                attempt.LimitEnforcedBy = "NODE";
                Stop(attempt.Name, TerminationReason.OutputLimit, null, graceful: false);
                _log.Info("execution.output_limit", new LogField("attempt", attempt.Name), new LogField("outputBytes", attempt.OutputBytes),
                    new LogField("limitBytes", settings.MaxOutputBytes));
            }
        }

        var handle = attempt.Handle;

        // Linux observes its units here (a failed unit whose ExecStopPost systemd skipped is recorded from the unit's own properties).
        handle?.Refresh();
        if (File.Exists(attempt.Files.ExitPath))
        {
            BeginFinalize(attempt, incomplete: false);
            return;
        }

        if (handle is null)
        {
            // Still launching.
            return;
        }

        if (attempt.NodeGap && attempt.StartedTimestamp is null && attempt.StopReason is null && handle.Root is { } recoveredRoot)
        {
            // The start may have completed while this node was down or after its re-open. Keep the known start clock, never recovery time.
            _ = OnStartedAsync(attempt, recoveredRoot, handle.StartedAt ?? recoveredRoot.StartTime);
        }

        CheckReadiness(attempt, handle);
        if (attempt.StopReason is null && attempt.StartedTimestamp is { } since)
        {
            // Frozen time does not count toward the wall-clock timeout (a paused attempt makes no progress).
            if (attempt.TimeoutMs is { } timeout && _clock.GetElapsedTime(since) - attempt.PausedTime(_clock) >= TimeSpan.FromMilliseconds(timeout))
            {
                Stop(attempt.Name, TerminationReason.TimedOut, null);
            }
            else if (attempt.CpuLimitMs is { } cpuLimit && (attempt.LastCpuCheck == long.MinValue || _clock.GetElapsedTime(attempt.LastCpuCheck) >= TimeSpan.FromSeconds(1)))
            {
                attempt.LastCpuCheck = _clock.GetTimestamp();
                var accounting = handle.Accounting();
                if ((ulong)(accounting.CpuUserMs + accounting.CpuKernelMs) >= cpuLimit)
                {
                    Stop(attempt.Name, TerminationReason.CpuTimeExceeded, null);
                }
            }
        }

        if (attempt.LastEscapeScan == long.MinValue || _clock.GetElapsedTime(attempt.LastEscapeScan) >= EscapeScanInterval)
        {
            attempt.LastEscapeScan = _clock.GetTimestamp();
            ScanEscaped(attempt, handle);
        }

        lock (attempt)
        {
            var now = _clock.GetTimestamp();
            if (attempt.StopReason is { } stopReason && !attempt.Forced && attempt.GraceDeadline is { } grace && now >= grace)
            {
                // The forced phase after the grace period. A STOPPING attempt recovered after a node restart gets here at once, possibly in the
                // middle of its launch (its handle's start still pending): read before the termination, as in ForceWhenStarted.
                _forcedPhase?.Invoke(handle, false);
                var startPending = !handle.Started.IsCompleted;
                TerminateEachLaunchProcess(attempt, handle, stopReason);
                handle.Terminate();
                TerminateEscaped(attempt, stopReason);
                attempt.Forced = true;
                attempt.VerifyDeadline = now + (long)(VerifyWindow.TotalSeconds * TimeProvider.System.TimestampFrequency);
                _forcedPhase?.Invoke(handle, true);
                if (startPending)
                {
                    TerminateWhenStarted(attempt, handle, stopReason);
                }
            }
            else if (attempt.Forced && attempt.VerifyDeadline is { } verify && now >= verify && handle.Accounting().ActiveProcesses is var active and > 0)
            {
                if (attempt.TerminationOwed)
                {
                    // The late start entered the container before the node saw the start complete (TerminateWhenStarted): it is terminated,
                    // not recorded as left over, and the window counts from this termination.
                    attempt.TerminationOwed = false;
                    _log.Info("execution.stop.late_start", new LogField("attempt", attempt.Name), new LogField("processes", active));
                    TerminateNow(attempt, handle, attempt.StopReason ?? TerminationReason.Cancelled);
                }
                else
                {
                    BeginFinalize(attempt, incomplete: true);
                }
            }
        }
    }

    /// <summary>
    /// The ancestry scan (04 section 3, every 5 s): a process outside the attempt's job that descends from one of its processes is
    /// recorded as <c>ESCAPED</c> (process_record, label 3) and raises an <c>ESCAPED_PROCESS</c> finding about the attempt (R-RES-012).
    /// It is not controlled; the stop sequence terminates it when it runs as the node's user (04 section 6 step 4). The scan never throws
    /// into its caller (a stop, the enforcement pass): a found process is kept in <see cref="RunningAttempt.KnownEscaped"/> at once, and a
    /// record write that cannot be queued or does not commit is written again by the next scan.
    /// </summary>
    private void ScanEscaped(RunningAttempt attempt, IAttemptHandle handle)
    {
        IReadOnlyList<EscapedProcess> escaped;
        try
        {
            escaped = handle.ScanEscaped();
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or UnauthorizedAccessException)
        {
            _log.Warning("execution.escape_scan.failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
            escaped = [];
        }

        var found = escaped.Where(process => attempt.KnownEscaped.TryAdd((process.Pid, process.StartTime.UtcTicks), process.Image)).ToList();
        foreach (var process in found)
        {
            attempt.UnrecordedEscaped[(process.Pid, process.StartTime.UtcTicks)] = process;
        }

        if (found.Count > 0)
        {
            _log.Warning("execution.escaped", new LogField("attempt", attempt.Name),
                new LogField("processes", string.Join(", ", found.Select(process => $"{process.Image} ({process.Pid}, parent {process.ParentPid})"))));
        }

        RecordEscaped(attempt);
    }

    /// <summary>
    /// Queues the write of the attempt's escaped processes that are not recorded yet (one write at a time). A full command queue or a
    /// failed commit leaves them in <see cref="RunningAttempt.UnrecordedEscaped"/> for the next scan; nothing is thrown.
    /// </summary>
    private void RecordEscaped(RunningAttempt attempt)
    {
        if (attempt.UnrecordedEscaped.IsEmpty || Interlocked.CompareExchange(ref attempt.EscapedWriting, 1, 0) != 0)
        {
            return;
        }

        var pending = attempt.UnrecordedEscaped.Values.ToList();
        Task<int> write;
        try
        {
            if (_faults.Take("escaped-record-queue-full") is not null)
            {
                throw new CommandQueueFullException();
            }

            write = _processor.ExecuteAsync(context => WriteEscaped(context, attempt, pending));
        }
        catch (CommandQueueFullException exception)
        {
            Volatile.Write(ref attempt.EscapedWriting, 0);
            _log.Warning("execution.escaped.record_deferred", new LogField("attempt", attempt.Name), new LogField("processes", pending.Count),
                new LogField("errorType", exception.GetType().Name));
            return;
        }

        _ = write.ContinueWith(done =>
        {
            if (done.IsCompletedSuccessfully)
            {
                foreach (var process in pending)
                {
                    attempt.UnrecordedEscaped.TryRemove((process.Pid, process.StartTime.UtcTicks), out _);
                }
            }
            else
            {
                _log.Warning("execution.escaped.record_deferred", new LogField("attempt", attempt.Name), new LogField("processes", pending.Count),
                    new LogField("errorType", done.Exception?.InnerException?.GetType().Name ?? "Canceled"));
            }

            Volatile.Write(ref attempt.EscapedWriting, 0);
        }, TaskScheduler.Default);
    }

    /// <summary>
    /// Records escaped processes (process_record, label ESCAPED) and raises each one's finding once: a process already recorded as ESCAPED is
    /// only seen again, so a write that is repeated (a retry, or finalization) changes nothing else.
    /// </summary>
    private static int WriteEscaped(CommandContext context, RunningAttempt attempt, IReadOnlyCollection<EscapedProcess> processes)
    {
        var now = context.Transaction.NowMicroseconds;
        foreach (var process in processes)
        {
            var start = StoreTime.ToMicroseconds(process.StartTime);
            var label = context.Transaction.Scalar("SELECT label FROM process_record WHERE attempt_id = $attempt AND pid = $pid AND start_at = $start;",
                ("$attempt", attempt.AttemptId), ("$pid", process.Pid), ("$start", start));
            var recorded = label is not null and not DBNull && Convert.ToInt32(label, CultureInfo.InvariantCulture) == (int)ProcessLabel.Escaped;
            context.Transaction.Execute(
                """
                INSERT INTO process_record (attempt_id, pid, start_at, parent_pid, executable, arguments_redacted, first_seen, last_seen, mem_peak_bytes, label)
                VALUES ($attempt, $pid, $start, $parent, $image, NULL, $now, $now, 0, $label)
                ON CONFLICT (attempt_id, pid, start_at) DO UPDATE SET last_seen = $now, label = $label;
                """,
                ("$attempt", attempt.AttemptId), ("$pid", process.Pid), ("$start", start),
                ("$parent", process.ParentPid), ("$image", process.Image), ("$now", now), ("$label", (int)ProcessLabel.Escaped));
            if (recorded)
            {
                continue;
            }

            ExecutionFindings.Raise(context, FindingKind.EscapedProcess, Severity.Warning, "attempt", attempt.AttemptId,
                "A process escaped its attempt's job",
                "A descendant of the attempt runs outside its job (created through WMI, a service broker or another parent), so the job's limits "
                + "and kill do not reach it. The stop sequence terminates it when it runs as your user (04 section 6).",
                [("attempt", attempt.Name), ("pid", process.Pid.ToString(CultureInfo.InvariantCulture)),
                    ("parent_pid", process.ParentPid.ToString(CultureInfo.InvariantCulture)), ("image", process.Image),
                    ("same_user", process.SameUser ? "true" : "false")]);
        }

        return 0;
    }

    /// <summary>
    /// Terminates the attempt's same-user escaped processes when the node stops it (04 section 6 step 4: <c>terminate_escaped</c>, true for
    /// cancellation, timeouts and limit stops; false for node shutdown, where the attempt itself is left to run or dies with the node). It
    /// runs with the forced phase and again when the stop sequence ends (finalization), however the root ended: a root that exits on the
    /// graceful signal leaves its escaped processes to this step too. An attempt the node did not stop keeps its escaped processes.
    /// The processes are the ones the node recorded for the attempt: those the ancestry scan found while this node ran (a scan runs first),
    /// and the attempt's ESCAPED process records, which a node restart keeps. A fresh scan alone is not enough: once the root has exited, an
    /// escaped process on Linux is re-parented to the user manager and no longer descends from the attempt. Each process is identified by
    /// its ID and start time, so a reused ID is never terminated, and only the node's user's processes are
    /// (<see cref="IExecutionPlatform.TerminateProcess"/>); a process already dealt with is not touched again.
    /// </summary>
    private void TerminateEscaped(RunningAttempt attempt, TerminationReason reason)
    {
        if (reason == TerminationReason.NodeShutdown || Platform is not { } platform)
        {
            return;
        }

        if (attempt.Handle is { } handle)
        {
            ScanEscaped(attempt, handle);
        }

        var recorded = new Dictionary<(int Pid, long StartMicros), (DateTimeOffset Start, string Image)>();
        foreach (var ((pid, ticks), image) in attempt.KnownEscaped)
        {
            var start = new DateTimeOffset(ticks, TimeSpan.Zero);
            recorded.TryAdd((pid, StoreTime.ToMicroseconds(start)), (start, image));
        }

        try
        {
            foreach (var (pid, micros, image) in _store.Read(reader => EscapedRecords(reader, attempt.AttemptId)))
            {
                recorded.TryAdd((pid, micros), (StoreTime.FromMicroseconds(micros), image));
            }
        }
        catch (Microsoft.Data.Sqlite.SqliteException exception)
        {
            _log.Warning("execution.escaped.records_failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
        }

        var terminated = new List<string>();
        foreach (var (key, (start, image)) in recorded)
        {
            if (attempt.EscapedHandled.ContainsKey(key))
            {
                continue;
            }

            ProcessTermination outcome;
            try
            {
                outcome = platform.TerminateProcess(key.Pid, start);
            }
            catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or UnauthorizedAccessException)
            {
                _log.Warning("execution.escaped.terminate_failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
                continue;
            }

            if (outcome != ProcessTermination.Failed)
            {
                attempt.EscapedHandled.TryAdd(key, true);
            }

            if (outcome == ProcessTermination.Terminated)
            {
                terminated.Add(string.Create(CultureInfo.InvariantCulture, $"{image} ({key.Pid})"));
            }
        }

        if (terminated.Count > 0)
        {
            attempt.EscapedTerminated.AddRange(terminated);
            _log.Info("execution.escaped.terminated", new LogField("attempt", attempt.Name), new LogField("processes", string.Join(", ", terminated)));
        }
    }

    /// <summary>The attempt's ESCAPED process records (process_record, label 3): pid, start (store microseconds) and image.</summary>
    private static List<(int Pid, long StartMicros, string Image)> EscapedRecords(StoreReader reader, byte[] attemptId)
    {
        using var command = reader.CreateCommand("SELECT pid, start_at, executable FROM process_record WHERE attempt_id = $id AND label = $label;");
        command.Parameters.AddWithValue("$id", attemptId);
        command.Parameters.AddWithValue("$label", (int)ProcessLabel.Escaped);
        using var rows = command.ExecuteReader();
        var records = new List<(int Pid, long StartMicros, string Image)>();
        while (rows.Read())
        {
            records.Add((rows.GetInt32(0), rows.GetInt64(1), rows.GetString(2)));
        }

        return records;
    }

    // ---------------------------------------------------------------------------------------------------------------- admission

    private void Launch(RunningAttempt attempt, Admitted admitted, IExecutionPlatform platform, ExecutionSettings settings, Scheduling.ToolInvocation? tool)
    {
        var row = admitted.Row;
        var files = attempt.Files;
        var snapshot = row.EnvDigest is { } digest ? _store.Read(reader => EnvSnapshots.Get(reader, digest)) : null;
        var unseal = _secrets.Unseal(row.TaskId);
        if (unseal.Status == UnsealStatus.Unavailable)
        {
            throw new InvalidOperationException("the task's sealed environment values are unavailable: " + unseal.UnavailableReason);
        }

        var spec = SubmittedEnvironment.Restore(row.Spec, snapshot, unseal.Values);
        if (tool is not null)
        {
            // 03 section 5.3: the adapter's invocation carries the tool-level setting for the CPU grant (never called a limit).
            spec.Command = new CommandSpec { Argv = new ArgvCommand() };
            spec.Command.Argv.Argv.Add(tool.Argv);
        }
        Directory.CreateDirectory(files.Directory);
        Directory.CreateDirectory(files.TempDirectory);
        var environment = ResolveEnvironment(spec, row, attempt, platform);
        var prepared = platform.Prepare(new CommandRequest
        {
            Argv = spec.Command.FormCase == CommandSpec.FormOneofCase.Argv ? [.. spec.Command.Argv.Argv] : null,
            Shell = spec.Command.FormCase == CommandSpec.FormOneofCase.Shell ? spec.Command.Shell.Kind : ShellKind.Unspecified,
            Script = spec.Command.FormCase == CommandSpec.FormOneofCase.Shell ? spec.Command.Shell.Script : null,
            ShellPath = spec.Command.FormCase == CommandSpec.FormOneofCase.Shell && spec.Command.Shell.HasShellPath ? spec.Command.Shell.ShellPath : null,
            WorkingDirectory = spec.WorkingDirectory,
            Environment = environment,
            TempDirectory = files.TempDirectory,
        });
        var stdinKind = StdinKind.None;
        string? stdinPath = null;
        switch (spec.Stdin?.Mode ?? StdinMode.None)
        {
            case StdinMode.Bytes:
                stdinKind = StdinKind.File;
                stdinPath = Path.Combine(files.TempDirectory, "stdin.bin");
                File.WriteAllBytes(stdinPath, spec.Stdin!.Data.ToByteArray());
                break;
            case StdinMode.File:
                stdinKind = StdinKind.File;
                stdinPath = spec.Stdin!.FilePath;
                break;
            case StdinMode.Stream:
                stdinKind = StdinKind.Stream;
                break;
        }

        HelperFiles.WriteAtomically(files.GuardPath, new GuardSpec
        {
            AttemptId = attempt.Name,
            OutputFiles = attempt.DiscardOutput ? [] : [files.StdoutPath, files.StderrPath],
            TempDirectory = files.TempDirectory,
            Volumes = [.. new[] { spec.WorkingDirectory, files.TempDirectory, files.Directory }.Select(path => Path.GetPathRoot(path) ?? path).Distinct(StringComparer.OrdinalIgnoreCase)],
            MaxOutputBytes = settings.MaxOutputBytes,
            MaxTmpBytes = settings.MaxTmpBytes,
            MaxTmpEntries = settings.MaxTmpEntries,
            CriticalFreeBytes = settings.CriticalFreeBytes,
            DiskLimitAction = settings.DiskLimitAction,
            TakeoverMs = settings.GuardTakeoverMs,
            HeartbeatPath = AttemptFiles.HeartbeatPath(_dataRoot),
            Preemptible = spec.Resources?.Preemptible == true,
            Pausable = false,
        }.ToJson());
        var (launchSteps, endSteps) = _steps?.StepsFor(spec, files) ?? ([], []);
        var handle = platform.Launch(new AttemptLaunch
        {
            NodeName = NodeName,
            Files = files,
            Command = prepared,
            Environment = [.. environment.Select(pair => pair.Key + "=" + pair.Value)],
            WorkingDirectory = spec.WorkingDirectory,
            Stdin = stdinKind,
            StdinPath = stdinPath,
            Limits = new ContainerLimits
            {
                CpuWeight = ExecutionSettings.Weight(row.Priority),
                CommitLimitBytes = (long)(settings.CommitFactor * admitted.Ceiling),
                CommitNotificationBytes = admitted.Ceiling,

                // Linux (03 section 5.2): MemoryHigh = 1.25 x mem_expected, MemoryMax = mem_ceiling, MemorySwapMax = swap_allowance.
                MemoryHighBytes = attempt.MemoryHighBytes = Math.Min((long)(1.25 * admitted.Expected), admitted.Ceiling),
                MemoryMaxBytes = admitted.Ceiling,
                SwapMaxBytes = settings.SwapAllowance,
            },
            KillWithNode = attempt.KillWithNode,
            DiscardOutput = attempt.DiscardOutput,
            LaunchSteps = launchSteps,
            EndSteps = endSteps,
        });
        attempt.Handle = handle;
        handle.Changed += () => _loopWake.Pulse();
        attempt.OpenTail();
        lock (attempt)
        {
            if (attempt.StopReason is { } stop && !attempt.Forced)
            {
                // Cancelled while it was being launched: there is no root to signal yet, so the forced phase applies.
                ForceWhenStarted(attempt, handle, stop);
            }
        }

        _log.Info("execution.launched", new LogField("attempt", attempt.Name), new LogField("container", handle.ContainerName),
            new LogField("killWithNode", attempt.KillWithNode), new LogField("launchSteps", launchSteps.Count), new LogField("endSteps", endSteps.Count));
        _ = handle.Started.ContinueWith(started => OnStartedAsync(attempt, started.IsCompletedSuccessfully ? started.Result : null), TaskScheduler.Default).Unwrap();
    }

    private async Task OnStartedAsync(RunningAttempt attempt, RootProcess? root, DateTimeOffset? recoveredStart = null)
    {
        if (root is null)
        {
            // The launch failed: the exit record (with launch.json) finalizes the attempt as SPAWN_FAILED.
            _loopWake.Pulse();
            return;
        }

        if (OperatingSystem.IsWindows() && recoveredStart is null && StartedRecord.TryRead(attempt.Files.StartedPath, attempt.Name) is null)
        {
            _log.Warning("execution.started.evidence_unavailable", new LogField("attempt", attempt.Name));
        }

        var elapsed = recoveredStart is { } start ? Math.Max(0, (_clock.GetUtcNow() - start).TotalSeconds) : 0;
        attempt.StartedTimestamp = _clock.GetTimestamp() - (long)(elapsed * TimeProvider.System.TimestampFrequency);
        try
        {
            await _processor.ExecuteAsync(context =>
            {
                var changed = context.Transaction.Execute(
                    "UPDATE attempt SET state = 4, root_pid = $pid, root_start = $start, started_at = $now, rev = rev + 1 WHERE attempt_id = $id AND state = 3;",
                    ("$pid", root.Pid), ("$start", StoreTime.ToMicroseconds(root.StartTime)),
                    ("$now", recoveredStart is { } startedAt ? StoreTime.ToMicroseconds(startedAt) : context.Transaction.NowMicroseconds), ("$id", attempt.AttemptId));
                if (changed == 1)
                {
                    EmitAttempt(context, attempt.AttemptId, AttemptState.Starting);
                    EmitTask(context, attempt.TaskId, null);
                }

                return 0;
            }).ConfigureAwait(false);
            attempt.RootRecorded = true;
            TaskPulse(attempt.TaskId).Pulse();
        }
        catch (CommandQueueFullException)
        {
            _log.Warning("execution.started.unrecorded", new LogField("attempt", attempt.Name));
        }
    }

    /// <summary>
    /// The environment a submission resolves to before the ArcForges variables (04 section 2: inherit base, unset, set), used to
    /// validate the command at submission (the program lookup uses its <c>PATH</c> and <c>PATHEXT</c>).
    /// </summary>
    public static Dictionary<string, string> ValidationEnvironment(TaskSpec spec, StringComparer names)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(names);
        var environment = new Dictionary<string, string>(names);
        var settings = spec.Environment;
        switch (settings?.Inherit ?? EnvironmentInherit.Node)
        {
            case EnvironmentInherit.Caller:
                foreach (var (name, value) in settings!.CallerEnvironment)
                {
                    environment[name] = value;
                }

                break;
            case EnvironmentInherit.Node:
                foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
                {
                    environment[(string)entry.Key] = (string?)entry.Value ?? string.Empty;
                }

                break;
        }

        if (settings is not null)
        {
            foreach (var name in settings.Unset)
            {
                environment.Remove(name);
            }

            foreach (var (name, value) in settings.Set)
            {
                environment[name] = value;
            }
        }

        return environment;
    }

    private Dictionary<string, string> ResolveEnvironment(TaskSpec spec, TaskRow row, RunningAttempt attempt, IExecutionPlatform platform)
    {
        var environment = ValidationEnvironment(spec, platform.EnvironmentNames);
        AddArcForgesVariables(environment, row, attempt);
        return environment;
    }

    private void AddArcForgesVariables(Dictionary<string, string> environment, TaskRow row, RunningAttempt attempt)
    {
        environment["ARCFORGES_TASK_ID"] = IdText.Format(row.TaskId);
        environment["ARCFORGES_ATTEMPT_ID"] = attempt.Name;
        environment["ARCFORGES_NODE_ID"] = NodeName;
        if (row.Owner.SessionId is { Value.Length: 16 } session)
        {
            environment["ARCFORGES_SESSION"] = IdText.Format(session);
        }

        // 06 section 4: TMP, TEMP and TMPDIR point to the attempt's temporary directory.
        environment["TMP"] = attempt.Files.TempDirectory;
        environment["TEMP"] = attempt.Files.TempDirectory;
        environment["TMPDIR"] = attempt.Files.TempDirectory;
    }

    // ------------------------------------------------------------------------------------------------------------- finalization

    private async Task RecordFinalizingAsync(RunningAttempt attempt)
    {
        Task? stopping;
        lock (attempt)
        {
            stopping = attempt.StopRecording;
        }

        if (stopping is not null)
        {
            await stopping.ConfigureAwait(false);
        }

        for (var tries = 0; ; tries++)
        {
            try
            {
                var pending = await _processor.ExecuteAsync(context =>
                {
                    var transaction = context.Transaction;
                    var previous = TaskRecords.GetAttemptRow(transaction, attempt.AttemptId);
                    if (previous is not null && transaction.Execute(
                        "UPDATE attempt SET state = 8, rev = rev + 1 WHERE attempt_id = $id AND state IN (3, 4, 5, 6, 7);",
                        ("$id", attempt.AttemptId)) == 1)
                    {
                        EmitAttempt(context, attempt.AttemptId, previous.State);
                        EmitTask(context, attempt.TaskId, null);
                    }

                    return previous;
                }).ConfigureAwait(false);
                if (pending is { State: AttemptState.Stopping or AttemptState.Finalizing })
                {
                    lock (attempt)
                    {
                        // A cancellation may win the writer immediately before FINALIZING, after BeginFinalize took its lock.
                        // The live path must use the same committed intent that a crash and recovery would restore.
                        attempt.StopReason ??= pending.Reason ?? (pending.State == AttemptState.Stopping ? TerminationReason.Cancelled : null);
                        attempt.StopDetail ??= pending.Detail;
                    }
                }

                return;
            }
            catch (CommandQueueFullException) when (!_stop.IsCancellationRequested || tries < 10)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(200 * (tries + 1), 1_000))).ConfigureAwait(false);
            }
        }
    }

    private void BeginFinalize(RunningAttempt attempt, bool incomplete)
    {
        lock (attempt)
        {
            attempt.FinalizeIncomplete |= incomplete;
            if (attempt.Finalizing || (attempt.FinalizeNotBefore is { } notBefore && _clock.GetTimestamp() < notBefore))
            {
                return;
            }

            attempt.Finalizing = true;
            incomplete = attempt.FinalizeIncomplete;
        }

        _ = Task.Run(() => FinalizeAsync(attempt, incomplete));
    }

    /// <summary>
    /// Records a finished attempt and only then acknowledges its exit record, so the holder releases the jobs only after the result is
    /// durable. A full command queue is waited out; a store error defers the attempt (it stays supervised and finalization is retried
    /// after <see cref="FinalizeRetry"/>); at node shutdown it stays unacknowledged and the next start records it from its exit record.
    /// An attempt is never dropped without either a record or a kept holder.
    /// </summary>
    private async Task FinalizeAsync(RunningAttempt attempt, bool incomplete)
    {
        var recorded = false;
        try
        {
            await RecordFinalizingAsync(attempt).ConfigureAwait(false);
            if (_faults.Take("hold-finalizing") is { } finalizingHold)
            {
                await Task.Delay(finalizingHold).ConfigureAwait(false);
            }

            attempt.Tail((_clock.GetUtcNow().UtcTicks - DateTime.UnixEpoch.Ticks) * 100);
            if (_faults.Take("finalize-throw") is not null)
            {
                throw new NotSupportedException("test fault finalize-throw");
            }

            var exit = ExitRecord.TryRead(attempt.Files.ExitPath);
            var launch = LaunchRecord.TryRead(attempt.Files.LaunchPath);
            var guard = GuardEvent.ReadAll(attempt.Files.GuardEventsPath);
            var handle = attempt.Handle;
            ContainerAccounting? accounting = null;
            if (exit is null && handle is not null)
            {
                try
                {
                    accounting = handle.Accounting();
                }
                catch (Win32Exception)
                {
                }
            }

            if (attempt.StopReason is { } stopped)
            {
                // The root may have exited on the graceful signal before the graceful phase recorded what it did: its detail is awaited. The
                // phase's own calls are bounded (the signal helper; on Linux the thaw and KillUnit calls of a paused attempt); the wait is capped
                // at GracefulPhaseBound and ends at once when the node stops.
                if (attempt.GracefulPhase is { } phase)
                {
                    await Task.WhenAny(phase, Task.Delay(GracefulPhaseBound, _stopping)).ConfigureAwait(false);
                }

                // The stop sequence ends here, however the root ended (graceful or forced): its escaped processes are terminated (04 section 6
                // step 4), with the result in the stop's detail.
                lock (attempt)
                {
                    TerminateEscaped(attempt, stopped);
                }
            }

            var remaining = incomplete && handle is not null ? handle.Processes() : [];
            var outcome = Outcome(attempt, exit, launch, guard, incomplete, remaining, handle?.MemoryLimitHit == true);
            var settings = Settings;
            for (var tries = 0; ; tries++)
            {
                try
                {
                    await _processor.ExecuteAsync(context => RecordFinished(context, attempt, exit, accounting, outcome, guard, settings, handle?.Root)).ConfigureAwait(false);
                    recorded = true;
                    break;
                }
                catch (CommandQueueFullException)
                {
                    // The queue drains; the attempt waits its turn (bounded backoff), however long that takes. At shutdown it stops
                    // trying after about 5 s and is left to the next start (the holder keeps its exit record).
                    if (_stop.IsCancellationRequested && tries >= 10)
                    {
                        break;
                    }

                    if (tries % 50 == 49)
                    {
                        _log.Warning("execution.finalize.queue_full", new LogField("attempt", attempt.Name), new LogField("tries", tries + 1));
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(200 * (1 << Math.Min(tries, 3)), 1_000))).ConfigureAwait(false);
                }
            }

            if (recorded && _faults.Take("kill-before-ack") is { } killAfter)
            {
                _log.Warning("node.fault.kill_before_ack", new LogField("attempt", attempt.Name));
                await Task.Delay(killAfter).ConfigureAwait(false);
                using var self = System.Diagnostics.Process.GetCurrentProcess();
                self.Kill();
            }

            if (recorded)
            {
                Acknowledge(attempt, handle);
                _log.Info("execution.finished", new LogField("attempt", attempt.Name), new LogField("reason", outcome.Reason),
                    new LogField("exitCode", exit?.ExitStatus ?? -1), new LogField("outputBytes", attempt.OutputBytes),
                    new LogField("limitEnforcedBy", outcome.LimitEnforcedBy ?? "-"));
            }
            else
            {
                _log.Info("execution.finalize.deferred_to_restart", new LogField("attempt", attempt.Name));
            }
        }
        catch (Exception exception) when (exception is IOException or Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            _log.Error("execution.finalize.failed", exception);
        }
#pragma warning disable CA1031 // Any other failure must not leave the attempt finalizing forever: it is logged by type and retried.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("execution.finalize.unexpected", exception, new LogField("attempt", attempt.Name), new LogField("recorded", recorded));
            if (recorded)
            {
                Acknowledge(attempt, handle: null);
            }
        }

        if (!recorded && !_stop.IsCancellationRequested)
        {
            // Not recorded: the attempt stays supervised, unacknowledged, and its finalization is retried later.
            lock (attempt)
            {
                attempt.FinalizeNotBefore = _clock.GetTimestamp() + (long)(FinalizeRetry.TotalSeconds * TimeProvider.System.TimestampFrequency);
                attempt.Finalizing = false;
            }

            return;
        }

        // Recorded, or left unacknowledged for the next start at shutdown (the holder keeps the jobs and the exit record).
        _running.TryRemove(attempt.Name, out _);
        try
        {
            attempt.Changed.Pulse();
            attempt.Dispose();
            TaskPulse(attempt.TaskId).Pulse();
            if (recorded)
            {
                CleanupTemp(attempt);
            }
        }
#pragma warning disable CA1031 // The attempt is recorded and released; a cleanup failure is logged, never thrown into a fire-and-forget task.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Warning("execution.finalize.cleanup_failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
        }

        Kick();
    }

    /// <summary>
    /// Acknowledges a recorded attempt's exit record through its handle, or by name when the handle cannot (disposed or failed), so the
    /// holder is released now rather than at the next start.
    /// </summary>
    private void Acknowledge(RunningAttempt attempt, IAttemptHandle? handle)
    {
        try
        {
            if (handle is not null)
            {
                handle.Acknowledge();
                return;
            }
        }
        catch (Exception exception) when (exception is ObjectDisposedException or Win32Exception or InvalidOperationException)
        {
            _log.Warning("execution.ack.handle_failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
        }

        try
        {
            Platform?.AcknowledgeRecorded(NodeName, attempt.Name);
        }
        catch (Exception exception) when (exception is ObjectDisposedException or Win32Exception or InvalidOperationException)
        {
            _log.Warning("execution.ack.by_name_failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
        }
    }

    private static AttemptOutcome Outcome(RunningAttempt attempt, ExitRecord? exit, LaunchRecord? launch, List<GuardEvent> guard, bool incomplete,
        IReadOnlyList<ContainerProcess> remaining, bool memoryHit)
    {
        // Linux records a signal as exit_code_kind killed or dumped with the signal number; Windows always records an exit code.
        var signalled = exit?.ExitCodeKind is "killed" or "dumped";
        var exitCode = exit is null || signalled ? (int?)null : exit.ExitStatus;
        int? signal = signalled ? exit!.ExitStatus : null;
        bool? coreDumped = signalled ? exit!.ExitCodeKind == "dumped" : null;
        if (launch is not null)
        {
            // A stop (a cancel, a timeout) during the launch steps ends them, and they fail as stopped: the attempt ends for the stop's reason
            // (SM-TASK RUNNING -> CANCELLED for a cancel), not as SPAWN_FAILED. 04 section 7 keeps DID_NOT_HAPPEN for SPAWN_FAILED and
            // POLICY_DENIED only, so the effect is HAPPENED, as on Linux, where the steps and the command share one process.
            return attempt.StopReason is { } stopped
                ? new AttemptOutcome(stopped, EffectCertainty.Happened, null, $"stopped during launch step {launch.Step}; the command did not start", null)
                : new AttemptOutcome(TerminationReason.SpawnFailed, EffectCertainty.DidNotHappen, launch.ExitCode, $"launch step {launch.Step} failed: {launch.Error}", null);
        }

        if (incomplete && attempt.StopReason != TerminationReason.NodeShutdown)
        {
            return new AttemptOutcome(TerminationReason.TerminationIncomplete, EffectCertainty.Happened, exitCode,
                "processes remained after the forced phase: " + string.Join(", ", remaining.Select(process => $"{process.Image} ({process.Pid})")), null, signal, coreDumped);
        }

        if (attempt.StopReason is { } stop)
        {
            var limitBy = stop is TerminationReason.OutputLimit or TerminationReason.DiskLimit ? attempt.LimitEnforcedBy ?? "NODE" : null;
            return new AttemptOutcome(stop, EffectCertainty.Happened, exitCode, attempt.StopDetailText, limitBy, signal, coreDumped);
        }

        if (guard.FirstOrDefault(item => item.Event == GuardEventKinds.Terminate) is { } guardStop)
        {
            return new AttemptOutcome(guardStop.Reason == "DISK_LIMIT" ? TerminationReason.DiskLimit : TerminationReason.OutputLimit, EffectCertainty.Happened,
                exitCode, $"stopped by the attempt's guard while the node was down ({guardStop.OutputBytes} bytes of output, limit {guardStop.LimitBytes})", "GUARD",
                signal, coreDumped);
        }

        if (exit is not null && (exit.ServiceResult == "oom-kill" || exit.OomKills > 0))
        {
            // Linux (04 section 7): memory.events oom_kill increased, or SERVICE_RESULT=oom-kill (OOMPolicy=stop ended the unit).
            return new AttemptOutcome(TerminationReason.OomKilled, EffectCertainty.Happened, exitCode,
                $"the OOM killer ended the attempt at its memory limit (peak {exit.MemPeakBytes} bytes)", null, signal, coreDumped);
        }

        if (exit is not null && exit.ExitStatus != 0 && (memoryHit || exit.LimitViolations.Contains("job_memory")))
        {
            return new AttemptOutcome(TerminationReason.MemoryLimit, EffectCertainty.Happened, exitCode, "the attempt reached its commit limit", null, signal, coreDumped);
        }

        return new AttemptOutcome(TerminationReason.Exited, EffectCertainty.Happened, exitCode, null, null, signal, coreDumped);
    }

    private int RecordFinished(CommandContext context, RunningAttempt attempt, ExitRecord? exit, ContainerAccounting? accounting, AttemptOutcome outcome,
        List<GuardEvent> guard, ExecutionSettings settings, RootProcess? root)
    {
        var transaction = context.Transaction;
        var now = transaction.NowMicroseconds;
        var task = TaskRecords.GetRow(transaction, attempt.TaskId);
        var previous = TaskRecords.GetAttemptRow(transaction, attempt.AttemptId);
        if (previous is not null)
        {
            // Escaped processes whose record write never committed are recorded with the attempt (a node restart then still knows them);
            // only while its row exists, which process_record references.
            WriteEscaped(context, attempt, [.. attempt.UnrecordedEscaped.Values]);
        }

        if (task is null || previous is null || previous.State == AttemptState.Finished)
        {
            return 0;
        }

        if (previous.State != AttemptState.Finalizing)
        {
            throw new InvalidOperationException("A completed attempt must commit FINALIZING before its final record.");
        }

        uint? windowsStatus = OperatingSystem.IsWindows() && outcome.ExitCode is { } code && unchecked((uint)code) >= 0xC0000000 ? unchecked((uint)code) : null;
        var leftovers = exit?.LeftoversTerminated ?? [];
        var cpu = exit is not null ? exit.CpuUserMs + exit.CpuKernelMs : (accounting?.CpuUserMs ?? 0) + (accounting?.CpuKernelMs ?? 0);
        transaction.Execute(
            """
            UPDATE attempt SET state = 9, finished_at = $now, exit_code = $exit, signal = $signal, core_dumped = $core, windows_status = $status, termination_reason = $reason, effect = $effect,
                   detail = $detail, leftover_count = $leftovers, leftover_images_json = $images, cpu_time_ms = $cpu, mem_peak_bytes = $mem,
                   io_read_bytes = $read, io_write_bytes = $write, stdout_bytes = $stdout, stderr_bytes = $stderr, stdout_offset = $stdout,
                   stderr_offset = $stderr, index_offset = $index, limit_enforced_by = $limitBy,
                   root_pid = coalesce(root_pid, $pid), root_start = coalesce(root_start, $start), started_at = coalesce(started_at, $start),
                   rev = rev + 1
            WHERE attempt_id = $id;
            """,
            ("$now", now), ("$exit", outcome.ExitCode), ("$signal", outcome.Signal), ("$core", outcome.CoreDumped is { } dumped ? (dumped ? 1 : 0) : null),
            ("$status", windowsStatus is { } value ? (long)value : null), ("$reason", (int)outcome.Reason),
            ("$effect", (int)outcome.Effect), ("$detail", outcome.Detail), ("$leftovers", leftovers.Count),
            ("$images", JsonSerializer.Serialize(leftovers.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), ExecutionJsonContext.Default.ListString)),
            ("$cpu", cpu), ("$mem", exit?.MemPeakBytes ?? accounting?.MemPeakBytes ?? 0), ("$read", exit?.IoReadBytes ?? accounting?.IoReadBytes ?? 0),
            ("$write", exit?.IoWriteBytes ?? accounting?.IoWriteBytes ?? 0), ("$stdout", attempt.StdoutIndexed), ("$stderr", attempt.StderrIndexed),
            ("$index", attempt.IndexRecords), ("$limitBy", outcome.LimitEnforcedBy), ("$pid", root?.Pid), ("$start", root is null ? null : StoreTime.ToMicroseconds(root.StartTime)),
            ("$id", attempt.AttemptId));
        var state = outcome.Reason switch
        {
            TerminationReason.Exited when outcome.ExitCode == 0 => TaskState.Succeeded,
            TerminationReason.Cancelled or TerminationReason.NodeShutdown => TaskState.Cancelled,
            TerminationReason.Lost => TaskState.Lost,
            _ => TaskState.Failed,
        };
        var peak = Math.Max(attempt.PeakObserved, exit?.MemPeakBytes ?? accounting?.MemPeakBytes ?? 0);
        if (task.CurrentAttemptId is { } current && current.AsSpan().SequenceEqual(attempt.AttemptId) && !task.Terminal)
        {
            if (state is TaskState.Failed or TaskState.Lost && task.State != TaskState.Cancelled
                && ScheduleRetry(context, task, attempt.Number, outcome.Reason, succeeded: false, peak))
            {
                state = TaskState.RetryWait;
            }
            else
            {
                transaction.Execute(
                    "UPDATE task SET state = $state, state_reason = coalesce(state_reason, $reason), finished_at = $now, rev = rev + 1 WHERE task_id = $id;",
                    ("$state", (int)state), ("$reason", outcome.Reason.ToString().ToUpperInvariant()), ("$now", now), ("$id", attempt.TaskId));
                TaskSecrets.SchedulePurge(transaction, attempt.TaskId, now, settings.SecretRetention);
            }
        }

        EmitAttempt(context, attempt.AttemptId, previous.State);
        EmitTask(context, attempt.TaskId, task.State);
        if (outcome.Reason == TerminationReason.TerminationIncomplete)
        {
            ExecutionFindings.Raise(context, FindingKind.TerminationIncomplete, Severity.Error, "attempt", attempt.AttemptId,
                "Processes survived the attempt's termination", outcome.Detail ?? string.Empty, [("attempt", attempt.Name)]);
        }

        if (leftovers.Count > 0)
        {
            ExecutionFindings.Raise(context, FindingKind.LeftoverProcesses, Severity.Info, "node", _store.Metadata.NodeId.Span,
                "Processes were left running after their attempts ended",
                "Long-lived helpers belong in SERVICE tasks; the leftovers were terminated after leftover_grace (04 section 3).",
                [("attempt", attempt.Name), ("images", string.Join(", ", leftovers))]);
        }

        if (guard.FirstOrDefault(item => item.Event == GuardEventKinds.Notify) is { } notify && !attempt.OutputNotified)
        {
            RaiseOutputFinding(context, attempt, notify.OutputBytes ?? 0, notify.LimitBytes ?? 0, "GUARD");
        }
        else if (settings.DiskLimitAction == "NOTIFY" && settings.MaxOutputBytes > 0 && attempt.OutputBytes > settings.MaxOutputBytes && !attempt.OutputNotified)
        {
            // The attempt ended before an enforcement pass saw its output cross the limit (it wrote faster than the tail interval): the final
            // tail still finds it, and NOTIFY still owes its finding (06 section 5).
            attempt.OutputNotified = true;
            RaiseOutputFinding(context, attempt, attempt.OutputBytes, settings.MaxOutputBytes, "NODE");
        }

        return 0;
    }

    private async Task SpawnFailedAsync(RunningAttempt? attempt, string detail)
    {
        if (attempt is null)
        {
            return;
        }

        attempt.Finalizing = true;
        try
        {
            await RecordFinalizingAsync(attempt).ConfigureAwait(false);
            var reason = attempt.StopReason ?? TerminationReason.SpawnFailed;
            var outcome = new AttemptOutcome(reason,
                reason == TerminationReason.SpawnFailed ? EffectCertainty.DidNotHappen : EffectCertainty.Happened, null, detail, null);
            await _processor.ExecuteAsync(context => RecordFinished(context, attempt, null, null, outcome, [], Settings, attempt.Handle?.Root))
                .ConfigureAwait(false);
        }
        finally
        {
            _running.TryRemove(attempt.Name, out _);
            attempt.Dispose();
            TaskPulse(attempt.TaskId).Pulse();
            CleanupTemp(attempt);
            Kick();
        }
    }

    private async Task RecordLostAsync(AttemptRow row, string evidence, string reason)
    {
        await _processor.ExecuteAsync(context =>
        {
            var transaction = context.Transaction;
            var now = transaction.NowMicroseconds;
            transaction.Execute(
                "UPDATE attempt SET state = 9, finished_at = $now, termination_reason = 8, effect = 3, detail = $detail, rev = rev + 1 WHERE attempt_id = $id;",
                ("$now", now), ("$detail", evidence), ("$id", row.AttemptId));
            var task = TaskRecords.GetRow(transaction, row.TaskId);
            if (task is not null && !task.Terminal && task.CurrentAttemptId is { } current && current.AsSpan().SequenceEqual(row.AttemptId)
                && !ScheduleRetry(context, task, row.Number, TerminationReason.Lost, succeeded: false, peak: 0))
            {
                // 04 section 9: a LOST attempt of a retryable task schedules a retry; others wait for a decision (RetryTask).
                transaction.Execute("UPDATE task SET state = 10, state_reason = $reason, finished_at = $now, rev = rev + 1 WHERE task_id = $id;",
                    ("$reason", reason), ("$now", now), ("$id", row.TaskId));
                TaskSecrets.SchedulePurge(transaction, row.TaskId, now, Settings.SecretRetention);
            }

            EmitAttempt(context, row.AttemptId, row.State);
            EmitTask(context, row.TaskId, task?.State);
            return 0;
        }).ConfigureAwait(false);
        _log.Warning("execution.lost", new LogField("attempt", IdText.Format(row.AttemptId)), new LogField("reason", reason));
    }

    private void RaiseOutputFinding(RunningAttempt attempt, long output, long limit, string by)
    {
        _ = _processor.ExecuteAsync(context =>
        {
            RaiseOutputFinding(context, attempt, output, limit, by);
            return 0;
        });
    }

    private static void RaiseOutputFinding(CommandContext context, RunningAttempt attempt, long output, long limit, string by) =>
        ExecutionFindings.Raise(context, FindingKind.QuotaExceeded, Severity.Warning, "attempt", attempt.AttemptId,
            "An attempt's output exceeded max_attempt_output_bytes",
            "storage.disk_limit_action is NOTIFY: the attempt continues and its output is kept, because the process writes the files itself (06 section 5).",
            [("attempt", attempt.Name), ("output_bytes", output.ToString(CultureInfo.InvariantCulture)),
                ("limit_bytes", limit.ToString(CultureInfo.InvariantCulture)), ("detected_by", by)]);

    private void PersistOffsets()
    {
        var snapshot = _running.Values.Where(attempt => !attempt.Finalizing && !attempt.DiscardOutput)
            .Select(attempt => (attempt.AttemptId, attempt.StdoutIndexed, attempt.StderrIndexed, attempt.IndexRecords)).ToList();
        if (snapshot.Count == 0)
        {
            return;
        }

        try
        {
            _ = _processor.ExecuteAsync(context =>
            {
                foreach (var (id, stdout, stderr, index) in snapshot)
                {
                    context.Transaction.Execute(
                        "UPDATE attempt SET stdout_offset = $stdout, stderr_offset = $stderr, index_offset = $index, stdout_bytes = $stdout, stderr_bytes = $stderr WHERE attempt_id = $id AND state < 9;",
                        ("$stdout", stdout), ("$stderr", stderr), ("$index", index), ("$id", id));
                }

                return 0;
            });
        }
        catch (CommandQueueFullException)
        {
        }
    }

    private void CleanupTemp(RunningAttempt attempt)
    {
        try
        {
            var failed = _store.Read(reader => TaskRecords.GetAttemptRow(reader, attempt.AttemptId))?.Reason is { } reason && reason != TerminationReason.Exited;
            if (failed && Settings.KeepFailedTmp)
            {
                return;
            }

            if (Directory.Exists(attempt.Files.TempDirectory))
            {
                Directory.Delete(attempt.Files.TempDirectory, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Microsoft.Data.Sqlite.SqliteException)
        {
            _log.Debug("execution.tmp.cleanup_failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
        }
    }

    /// <summary>Housekeeping: removes kept temporary directories of failed attempts older than <c>keep_failed_tmp_hours</c>.</summary>
    public int RemoveExpiredTemp()
    {
        var root = Path.Combine(_dataRoot, "tmp");
        if (!Directory.Exists(root))
        {
            return 0;
        }

        var removed = 0;
        var cutoff = _clock.GetUtcNow().UtcDateTime - TimeSpan.FromHours(Settings.KeepFailedTmpHours);
        foreach (var directory in Directory.EnumerateDirectories(root))
        {
            if (_running.ContainsKey(Path.GetFileName(directory)))
            {
                continue;
            }

            try
            {
                if (Directory.GetLastWriteTimeUtc(directory) < cutoff)
                {
                    Directory.Delete(directory, recursive: true);
                    removed++;
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }

        return removed;
    }

    private RunningAttempt? StdinAttempt(ReadOnlySpan<byte> taskId, string attachId, out ArcError? error)
    {
        var task = IdText.Format(taskId);
        var attempt = _running.Values.FirstOrDefault(running => IdText.Format(running.TaskId) == task);
        if (attempt?.Handle?.StdinWriter is null)
        {
            error = NodeErrors.InvalidState("NOT_RUNNING", "the task has no running attempt with STREAM stdin");
            return null;
        }

        lock (attempt.StdinGate)
        {
            if (attempt.StdinAttach != attachId)
            {
                error = NodeErrors.NotAttached();
                return null;
            }
        }

        error = null;
        return attempt;
    }

    // ------------------------------------------------------------------------------------------------------------------- journal

    /// <summary>Journals the task on topic TASKS and returns its view.</summary>
    public ManagedTask? EmitTask(CommandContext context, ReadOnlySpan<byte> taskId, TaskState? previous)
    {
        ArgumentNullException.ThrowIfNull(context);
        var task = TaskRecords.GetTask(context.Transaction, taskId, full: false);
        if (task is null)
        {
            return null;
        }

        var changed = new TaskChanged { Task = task };
        if (previous is { } state)
        {
            changed.PreviousState = state;
        }

        context.Emit(EventTopic.Tasks, new NodeEvent { Task = changed });
        TaskPulse(taskId).Pulse();
        return task;
    }

    private static void EmitAttempt(CommandContext context, ReadOnlySpan<byte> attemptId, AttemptState? previous)
    {
        var attempt = TaskRecords.GetAttempt(context.Transaction, attemptId);
        if (attempt is null)
        {
            return;
        }

        var changed = new AttemptChanged { Attempt = attempt };
        if (previous is { } state)
        {
            changed.PreviousState = state;
        }

        context.Emit(EventTopic.Tasks, new NodeEvent { Attempt = changed });
    }

    private static string Truncate(string text) => text.Length <= 500 ? text : text[..500];

    /// <summary>What a recovered attempt is accounted with (its task's pool and scope, its request, peak and held keys).</summary>
    private static RecoveredAccounting? RecoveredLoad(StoreReader reader, byte[] taskId, byte[] attemptId)
    {
        using var command = reader.CreateCommand(
            """
            SELECT t.pool, t.owner_session_id, t.workspace_id, a.request_cpu_millicores, a.request_mem_expected_bytes, a.request_mem_ceiling_bytes,
                   a.accounted_mem_bytes, t.ready
            FROM attempt a JOIN task t ON t.task_id = a.task_id WHERE a.attempt_id = $id;
            """);
        command.Parameters.AddWithValue("$id", attemptId);
        using var rows = command.ExecuteReader();
        if (!rows.Read())
        {
            return null;
        }

        var accounting = new RecoveredAccounting(rows.GetString(0), rows.IsDBNull(1) ? null : IdText.Format((byte[])rows.GetValue(1)),
            rows.IsDBNull(2) ? null : IdText.Format((byte[])rows.GetValue(2)), rows.GetInt64(3), rows.GetInt64(4), rows.GetInt64(5), rows.GetInt64(6),
            rows.GetInt32(7) == 1, []);
        rows.Close();
        return accounting with { Keys = HeldKeys(reader, taskId) };
    }

    private sealed record RecoveredAccounting(string Pool, string? Session, string? Workspace, long Cpu, long Expected, long Ceiling, long Accounted, bool Ready,
        List<Scheduling.HeldKey> Keys);

    private sealed record Admitted(TaskRow Row, int Number, long Expected, long Ceiling);

    private sealed record AttemptOutcome(TerminationReason Reason, EffectCertainty Effect, int? ExitCode, string? Detail, string? LimitEnforcedBy,
        int? Signal = null, bool? CoreDumped = null);
}
