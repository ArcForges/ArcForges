// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
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

    /// <summary>The execution platform, or <see langword="null"/> where this build has none (Linux until AF-EXEC-02).</summary>
    public IExecutionPlatform? Platform { get; init; }

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
}

/// <summary>A caller of <c>cancel_when_caller_gone</c>: the submitting client process.</summary>
/// <param name="ProcessId">Its PID.</param>
/// <param name="StartTicks">Its start time (ticks).</param>
public readonly record struct CallerKey(int ProcessId, long StartTicks);

/// <summary>
/// The execution supervisor (architecture 02 section 1; 04): admission (the interim global FIFO with <c>global_max_running</c> until
/// AF-SCHED-01), launch through the platform, the enforcement loop (output tailer and index, the output limit, timeouts and CPU-time
/// limits, the cancellation sequence, exit detection and the node heartbeat), finalization from the durable exit records, recovery
/// after a node restart or a machine reboot (LOST), and <c>cancel_when_caller_gone</c>.
/// </summary>
public sealed class ExecutionSupervisor : INodeRecoveryParticipant, IAsyncDisposable
{
    /// <summary>The tailer interval (04 section 4).</summary>
    public static readonly TimeSpan TailInterval = TimeSpan.FromMilliseconds(100);

    /// <summary>The verification window after the forced phase (04 section 6 step 5).</summary>
    public static readonly TimeSpan VerifyWindow = TimeSpan.FromSeconds(5);

    /// <summary>The ancestry scan interval (04 section 3).</summary>
    public static readonly TimeSpan EscapeScanInterval = TimeSpan.FromSeconds(5);

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
    private readonly ConcurrentDictionary<string, RunningAttempt> _running = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AsyncPulse> _taskPulses = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CallerKey> _bindings = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<CallerKey, int> _callerConnections = new();
    private readonly AsyncPulse _admission = new();
    private readonly AsyncPulse _loopWake = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly HeartbeatMonitor _tailerMonitor;
    private ExecutionSettings _settings;
    private Thread? _loop;
    private Task _admissionLoop = Task.CompletedTask;
    private long _lastSettingsRead;
    private int _launching;

    /// <summary>Creates the supervisor.</summary>
    public ExecutionSupervisor(ExecutionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _store = options.Store;
        _processor = options.Processor;
        _log = options.Log;
        _clock = options.Clock;
        _dataRoot = options.DataRoot;
        Platform = options.Platform;
        _secrets = options.Secrets;
        _keysReady = options.KeysReady;
        _steps = options.Steps;
        _faults = options.Faults;
        Heartbeat = options.Heartbeat;
        NodeName = IdText.Format(_store.Metadata.NodeId.Span);
        var capacity = Platform?.Capacity ?? new MachineCapacity(Environment.ProcessorCount, GC.GetGCMemoryInfo().TotalAvailableMemoryBytes);
        Capacity = capacity;
        _settings = new ExecutionSettings(_store.Policies.Current().Document, capacity.LogicalProcessors, capacity.PhysicalMemoryBytes);
        _lastSettingsRead = _clock.GetTimestamp();
        _tailerMonitor = Heartbeat.AddMonitor("output-tailer", TimeSpan.FromSeconds(5));
        if (_faults.Take("hang-probe-after") is { } probeHang)
        {
            Heartbeat.AddProbe(new FaultProbe(probeHang, _clock));
        }
    }

    /// <inheritdoc />
    public string Name => "attempts";

    /// <summary>The platform, or <see langword="null"/>.</summary>
    public IExecutionPlatform? Platform { get; }

    /// <summary>The node ID's base32 text (container names).</summary>
    public string NodeName { get; }

    /// <summary>The machine's capacity.</summary>
    public MachineCapacity Capacity { get; }

    /// <summary>The heartbeat writer.</summary>
    public NodeHeartbeatWriter Heartbeat { get; }

    /// <summary>The settings in force (re-read from the policy every 10 s).</summary>
    public ExecutionSettings Settings
    {
        get
        {
            if (_clock.GetElapsedTime(Interlocked.Read(ref _lastSettingsRead)) > TimeSpan.FromSeconds(10))
            {
                Interlocked.Exchange(ref _lastSettingsRead, _clock.GetTimestamp());
                try
                {
                    Volatile.Write(ref _settings, new ExecutionSettings(_store.Policies.Current().Document, Capacity.LogicalProcessors, Capacity.PhysicalMemoryBytes));
                }
                catch (Microsoft.Data.Sqlite.SqliteException exception)
                {
                    _log.Warning("execution.settings.read_failed", new LogField("errorType", exception.GetType().Name));
                }
            }

            return Volatile.Read(ref _settings);
        }
    }

    /// <summary>Attempts the supervisor runs now.</summary>
    public int RunningCount => _running.Count;

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
            IAttemptHandle? handle = null;
            try
            {
                handle = Platform?.Reopen(NodeName, files, root);
            }
            catch (Win32Exception exception)
            {
                _log.Warning("execution.recover.reopen_failed", new LogField("attempt", name), new LogField("error", exception.NativeErrorCode));
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
            };
            if (task?.Spec.Resources is { HasCancelGraceMs: true } resources)
            {
                running.CancelGrace = TimeSpan.FromMilliseconds(resources.CancelGraceMs);
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

            if (row.State == AttemptState.Stopping && row.Reason is null)
            {
                // The node was stopping it: the stop continues (forced, since the graceful phase cannot be resumed).
                running.StopReason = TerminationReason.Cancelled;
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
        Kick();
    }

    /// <summary>Wakes the admission loop.</summary>
    public void Kick() => _admission.Pulse();

    /// <summary>
    /// The node's shutdown (02 section 2): admissions stop; <c>kill_with_node</c> attempts are terminated and recorded
    /// (<c>NODE_SHUTDOWN</c>); every other attempt keeps running under its holder, whose guard takes over the disk limits.
    /// </summary>
    public async Task StopAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        _loopWake.Pulse();
        _loop?.Join(TimeSpan.FromSeconds(2));
        try
        {
            await _admissionLoop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
        }

        foreach (var attempt in _running.Values.Where(attempt => attempt.KillWithNode))
        {
            attempt.StopReason ??= TerminationReason.NodeShutdown;
            attempt.Handle?.Terminate();
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

        _stop.Dispose();
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
        transaction.Execute(
            """
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, env_digest, spec_digest, owner, owner_origin, pool, priority,
                              effective_priority, side_effect, side_effect_source, command_fingerprint, command_digest, created_at, queued_at, pinned,
                              labels_json, rev)
            VALUES ($id, 1, $kind, $title, $summary, $spec, $env, $specDigest, $owner, $origin, $pool, $priority, $priority, $sideEffect, $source,
                    $fingerprint, $digest, $now, $now, $pinned, $labels, 0);
            """,
            ("$id", taskId), ("$kind", (int)plan.Kind), ("$title", plan.Title), ("$summary", plan.Summary), ("$spec", specBytes), ("$env", envDigest),
            ("$specDigest", System.Security.Cryptography.SHA256.HashData(specBytes)), ("$owner", plan.Owner.ToByteArray()), ("$origin", (int)plan.Owner.Origin),
            ("$pool", plan.Pool), ("$priority", (int)plan.Priority), ("$sideEffect", (int)plan.SideEffect), ("$source", (int)plan.SideEffectSource),
            ("$fingerprint", plan.Fingerprint), ("$digest", plan.CommandDigest), ("$now", now), ("$pinned", spec.Output?.Pin == true ? 1 : 0), ("$labels", labels));
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

        if (row.State is TaskState.Queued or TaskState.WaitingDependency or TaskState.RetryWait or TaskState.Placing)
        {
            transaction.Execute(
                "UPDATE task SET state = 9, state_reason = $reason, finished_at = $now, rev = rev + 1 WHERE task_id = $id;",
                ("$reason", Truncate(reason)), ("$now", transaction.NowMicroseconds), ("$id", taskId.ToArray()));
            TaskSecrets.SchedulePurge(transaction, taskId, transaction.NowMicroseconds, Settings.SecretRetention);
            EmitTask(context, taskId, row.State);
            return (TaskState.Cancelled, null, null);
        }

        if (row.CurrentAttemptId is { } attemptId)
        {
            transaction.Execute(
                "UPDATE attempt SET state = 7, rev = rev + 1 WHERE attempt_id = $id AND state IN (3, 4, 5, 6);",
                ("$id", attemptId));
            transaction.Execute("UPDATE task SET state_reason = $reason, rev = rev + 1 WHERE task_id = $id;", ("$reason", Truncate(reason)), ("$id", taskId.ToArray()));
            EmitAttempt(context, attemptId, AttemptState.Running);
            EmitTask(context, taskId, row.State);
            return (row.State, null, IdText.Format(attemptId));
        }

        return (row.State, null, null);
    }

    /// <summary>
    /// Starts the stop sequence of a running attempt (04 section 6): the graceful phase (CTRL_BREAK through the helper and WM_CLOSE),
    /// <paramref name="grace"/>, then the forced phase. Limit stops (<paramref name="graceful"/> false) terminate at once.
    /// </summary>
    public void Stop(string attemptName, TerminationReason reason, TimeSpan? grace, bool graceful = true)
    {
        if (!_running.TryGetValue(attemptName, out var attempt))
        {
            return;
        }

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

            if (!graceful || attempt.Handle is null || attempt.Handle.Root is null)
            {
                attempt.Handle?.Terminate();
                TerminateEscaped(attempt, reason);
                attempt.Forced = true;
                attempt.VerifyDeadline = _clock.GetTimestamp() + (long)(VerifyWindow.TotalSeconds * TimeProvider.System.TimestampFrequency);
                _loopWake.Pulse();
                return;
            }
        }

        var period = grace ?? attempt.CancelGrace;
        _ = Task.Run(() =>
        {
            GracefulOutcome? outcome = null;
            try
            {
                outcome = attempt.Handle.RequestGracefulStop();
            }
            catch (Exception exception) when (exception is Win32Exception or IOException or InvalidOperationException)
            {
                _log.Warning("execution.stop.graceful_failed", new LogField("attempt", attemptName), new LogField("errorType", exception.GetType().Name));
            }

            lock (attempt)
            {
                attempt.StopDetail = outcome is null
                    ? "the graceful phase failed; the grace period applies"
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
    }

    /// <summary>A manual retry (SM-TASK FAILED|CANCELLED|LOST -> QUEUED; AD-0006 section 4 rules shown as warnings).</summary>
    public (TaskServiceRetryTaskValue? Value, ArcError? Error) Retry(CommandContext context, ReadOnlySpan<byte> taskId, Id commandId)
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

        var unseal = _secrets.Unseal(transaction, taskId);
        if (unseal.Status == UnsealStatus.Unavailable)
        {
            return (null, unseal.Error);
        }

        transaction.Execute(
            "UPDATE task SET state = 1, state_reason = 'retry', queued_at = $now, finished_at = NULL, rev = rev + 1 WHERE task_id = $id;",
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

        if (attempt.StopReason is null && attempt.StartedTimestamp is { } since)
        {
            if (attempt.TimeoutMs is { } timeout && _clock.GetElapsedTime(since) >= TimeSpan.FromMilliseconds(timeout))
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
            if (attempt.StopReason is not null && !attempt.Forced && attempt.GraceDeadline is { } grace && now >= grace)
            {
                handle.Terminate();
                TerminateEscaped(attempt, attempt.StopReason.Value);
                attempt.Forced = true;
                attempt.VerifyDeadline = now + (long)(VerifyWindow.TotalSeconds * TimeProvider.System.TimestampFrequency);
            }
            else if (attempt.Forced && attempt.VerifyDeadline is { } verify && now >= verify && handle.Accounting().ActiveProcesses > 0)
            {
                BeginFinalize(attempt, incomplete: true);
            }
        }
    }

    /// <summary>
    /// The ancestry scan (04 section 3, every 5 s): a process outside the attempt's job that descends from one of its processes is
    /// recorded as <c>ESCAPED</c> (process_record, label 3) and raises an <c>ESCAPED_PROCESS</c> finding about the attempt (R-RES-012).
    /// It is not controlled; the stop sequence terminates it when it runs as the node's user (04 section 6 step 4).
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
            return;
        }

        var found = escaped.Where(process => attempt.KnownEscaped.Add((process.Pid, process.StartTime.UtcTicks))).ToList();
        if (found.Count == 0)
        {
            return;
        }

        _log.Warning("execution.escaped", new LogField("attempt", attempt.Name),
            new LogField("processes", string.Join(", ", found.Select(process => $"{process.Image} ({process.Pid}, parent {process.ParentPid})"))));
        _ = _processor.ExecuteAsync(context =>
        {
            var now = context.Transaction.NowMicroseconds;
            foreach (var process in found)
            {
                context.Transaction.Execute(
                    """
                    INSERT INTO process_record (attempt_id, pid, start_at, parent_pid, executable, arguments_redacted, first_seen, last_seen, mem_peak_bytes, label)
                    VALUES ($attempt, $pid, $start, $parent, $image, NULL, $now, $now, 0, $label)
                    ON CONFLICT (attempt_id, pid, start_at) DO UPDATE SET last_seen = $now, label = $label;
                    """,
                    ("$attempt", attempt.AttemptId), ("$pid", process.Pid), ("$start", StoreTime.ToMicroseconds(process.StartTime)),
                    ("$parent", process.ParentPid), ("$image", process.Image), ("$now", now), ("$label", (int)ProcessLabel.Escaped));
                ExecutionFindings.Raise(context, FindingKind.EscapedProcess, Severity.Warning, "attempt", attempt.AttemptId,
                    "A process escaped its attempt's job",
                    "A descendant of the attempt runs outside its job (created through WMI, a service broker or another parent), so the job's limits "
                    + "and kill do not reach it. The stop sequence terminates it when it runs as your user (04 section 6).",
                    [("attempt", attempt.Name), ("pid", process.Pid.ToString(CultureInfo.InvariantCulture)),
                        ("parent_pid", process.ParentPid.ToString(CultureInfo.InvariantCulture)), ("image", process.Image),
                        ("same_user", process.SameUser ? "true" : "false")]);
            }

            return 0;
        });
    }

    /// <summary>
    /// Terminates the attempt's same-user escaped processes when the node stops it (04 section 6 step 4: <c>terminate_escaped</c>, true for
    /// cancellation, timeouts and limit stops; false for node shutdown, where the attempt itself is left to run or dies with the node).
    /// </summary>
    private void TerminateEscaped(RunningAttempt attempt, TerminationReason reason)
    {
        if (reason == TerminationReason.NodeShutdown || attempt.Handle is not { } handle)
        {
            return;
        }

        IReadOnlyList<string> terminated;
        try
        {
            terminated = handle.TerminateEscaped();
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or UnauthorizedAccessException)
        {
            _log.Warning("execution.escaped.terminate_failed", new LogField("attempt", attempt.Name), new LogField("errorType", exception.GetType().Name));
            return;
        }

        if (terminated.Count > 0)
        {
            attempt.StopDetail = (attempt.StopDetail is null ? string.Empty : attempt.StopDetail + "; ") + "escaped processes terminated: " + string.Join(", ", terminated);
            _log.Info("execution.escaped.terminated", new LogField("attempt", attempt.Name), new LogField("processes", string.Join(", ", terminated)));
        }
    }

    // ---------------------------------------------------------------------------------------------------------------- admission

    private async Task AdmissionLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                await _admission.WaitAsync(TimeSpan.FromSeconds(1), _stop.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (Platform is null)
            {
                continue;
            }

            try
            {
                var free = Settings.GlobalMaxRunning - _running.Count - Volatile.Read(ref _launching);
                if (free <= 0)
                {
                    continue;
                }

                foreach (var taskId in _store.Read(reader => TaskRecords.QueuedInOrder(reader, free)))
                {
                    if (_stop.IsCancellationRequested)
                    {
                        return;
                    }

                    await StartAttemptAsync(taskId).ConfigureAwait(false);
                }
            }
            catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException or IOException)
            {
                _log.Warning("execution.admission.failed", new LogField("errorType", exception.GetType().Name));
            }
        }
    }

    private async Task StartAttemptAsync(byte[] taskId)
    {
        var platform = Platform!;
        var settings = Settings;
        var attemptId = StoreIds.NewUuid7(_clock);
        var name = IdText.Format(attemptId);
        var files = new AttemptFiles(_dataRoot, name);
        Interlocked.Increment(ref _launching);
        RunningAttempt? attempt = null;
        try
        {
            var admitted = await _processor.ExecuteAsync(context =>
            {
                var transaction = context.Transaction;
                var row = TaskRecords.GetRow(transaction, taskId);
                if (row is null || row.State != TaskState.Queued)
                {
                    return null;
                }

                var number = row.AttemptCount + 1;
                var (cpu, expected, ceiling, source) = settings.Request(row.Spec.Resources?.Hint);
                var now = transaction.NowMicroseconds;
                transaction.Execute(
                    """
                    INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, container_name, boot_identity, request_cpu_millicores,
                                         request_mem_expected_bytes, request_mem_ceiling_bytes, request_source, accounted_mem_bytes, cpu_weight, created_at, rev)
                    VALUES ($id, $task, $number, 1, 3, $node, $container, $boot, $cpu, $expected, $ceiling, $source, $expected, $weight, $now, 0);
                    """,
                    ("$id", attemptId), ("$task", taskId), ("$number", number), ("$node", _store.Metadata.NodeId.ToArray()),
                    ("$container", "Local\\ArcForges." + NodeName + "." + name), ("$boot", _store.Metadata.BootIdentity), ("$cpu", cpu),
                    ("$expected", expected), ("$ceiling", ceiling), ("$source", (int)source), ("$weight", ExecutionSettings.Weight(row.Priority)), ("$now", now));
                transaction.Execute(
                    "UPDATE task SET state = 4, state_reason = NULL, current_attempt_id = $attempt, attempt_count = $number, started_at = coalesce(started_at, $now), rev = rev + 1 WHERE task_id = $id;",
                    ("$attempt", attemptId), ("$number", number), ("$now", now), ("$id", taskId));
                EmitAttempt(context, attemptId, AttemptState.Created);
                EmitTask(context, taskId, TaskState.Queued);
                return new Admitted(row, number, ceiling);
            }).ConfigureAwait(false);
            if (admitted is null)
            {
                return;
            }

            var spec = admitted.Row.Spec;
            attempt = new RunningAttempt(attemptId, taskId, name, admitted.Number, files)
            {
                KillWithNode = spec.Resources?.KillWithNode == true,
                DiscardOutput = spec.Output?.Capture == OutputCapture.Discard,
                TimeoutMs = spec.HasTimeoutMs ? spec.TimeoutMs : null,
                CpuLimitMs = spec.HasCpuTimeLimitMs ? spec.CpuTimeLimitMs : null,
            };
            if (spec.Resources is { HasCancelGraceMs: true } resources)
            {
                attempt.CancelGrace = TimeSpan.FromMilliseconds(resources.CancelGraceMs);
            }

            _running[name] = attempt;
            Launch(attempt, admitted, platform, settings);
        }
        catch (CommandRefusedException exception)
        {
            await SpawnFailedAsync(attempt, $"{exception.Code}: {exception.Reason}").ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException
            or NodeDataKeyUnavailableException or ArgumentException)
        {
            _log.Warning("execution.launch.failed", new LogField("attempt", name), new LogField("errorType", exception.GetType().Name),
                new LogField("error", NodeLog.OneLine(exception.Message)));
            await SpawnFailedAsync(attempt, "the attempt could not be launched: " + NodeLog.OneLine(exception.Message)).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Decrement(ref _launching);
        }
    }

    private void Launch(RunningAttempt attempt, Admitted admitted, IExecutionPlatform platform, ExecutionSettings settings)
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
            if (attempt.StopReason is not null && !attempt.Forced)
            {
                // Cancelled while it was being launched: there is no root to signal yet, so the forced phase applies.
                handle.Terminate();
                attempt.Forced = true;
                attempt.VerifyDeadline = _clock.GetTimestamp() + (long)(VerifyWindow.TotalSeconds * TimeProvider.System.TimestampFrequency);
            }
        }

        _log.Info("execution.launched", new LogField("attempt", attempt.Name), new LogField("container", handle.ContainerName),
            new LogField("killWithNode", attempt.KillWithNode), new LogField("launchSteps", launchSteps.Count), new LogField("endSteps", endSteps.Count));
        _ = handle.Started.ContinueWith(started => OnStartedAsync(attempt, started.IsCompletedSuccessfully ? started.Result : null), TaskScheduler.Default).Unwrap();
    }

    private async Task OnStartedAsync(RunningAttempt attempt, RootProcess? root)
    {
        if (root is null)
        {
            // The launch failed: the exit record (with launch.json) finalizes the attempt as SPAWN_FAILED.
            _loopWake.Pulse();
            return;
        }

        attempt.StartedTimestamp = _clock.GetTimestamp();
        try
        {
            await _processor.ExecuteAsync(context =>
            {
                var changed = context.Transaction.Execute(
                    "UPDATE attempt SET state = 4, root_pid = $pid, root_start = $start, started_at = $now, rev = rev + 1 WHERE attempt_id = $id AND state = 3;",
                    ("$pid", root.Pid), ("$start", StoreTime.ToMicroseconds(root.StartTime)), ("$now", context.Transaction.NowMicroseconds), ("$id", attempt.AttemptId));
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
            attempt.Tail((_clock.GetUtcNow().UtcTicks - DateTime.UnixEpoch.Ticks) * 100);
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
                handle?.Acknowledge();
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
        attempt.Changed.Pulse();
        attempt.Dispose();
        TaskPulse(attempt.TaskId).Pulse();
        if (recorded)
        {
            CleanupTemp(attempt);
        }

        Kick();
    }

    private static AttemptOutcome Outcome(RunningAttempt attempt, ExitRecord? exit, LaunchRecord? launch, List<GuardEvent> guard, bool incomplete,
        IReadOnlyList<ContainerProcess> remaining, bool memoryHit)
    {
        var exitCode = exit?.ExitStatus;
        if (launch is not null)
        {
            return new AttemptOutcome(TerminationReason.SpawnFailed, EffectCertainty.DidNotHappen, launch.ExitCode, $"launch step {launch.Step} failed: {launch.Error}", null);
        }

        if (incomplete && attempt.StopReason != TerminationReason.NodeShutdown)
        {
            return new AttemptOutcome(TerminationReason.TerminationIncomplete, EffectCertainty.Happened, exitCode,
                "processes remained after the forced phase: " + string.Join(", ", remaining.Select(process => $"{process.Image} ({process.Pid})")), null);
        }

        if (attempt.StopReason is { } stop)
        {
            var limitBy = stop is TerminationReason.OutputLimit or TerminationReason.DiskLimit ? attempt.LimitEnforcedBy ?? "NODE" : null;
            return new AttemptOutcome(stop, EffectCertainty.Happened, exitCode, attempt.StopDetail, limitBy);
        }

        if (guard.FirstOrDefault(item => item.Event == GuardEventKinds.Terminate) is { } guardStop)
        {
            return new AttemptOutcome(guardStop.Reason == "DISK_LIMIT" ? TerminationReason.DiskLimit : TerminationReason.OutputLimit, EffectCertainty.Happened,
                exitCode, $"stopped by the attempt's guard while the node was down ({guardStop.OutputBytes} bytes of output, limit {guardStop.LimitBytes})", "GUARD");
        }

        if (exit is not null && exit.ExitStatus != 0 && (memoryHit || exit.LimitViolations.Contains("job_memory")))
        {
            return new AttemptOutcome(TerminationReason.MemoryLimit, EffectCertainty.Happened, exitCode, "the attempt reached its commit limit", null);
        }

        return new AttemptOutcome(TerminationReason.Exited, EffectCertainty.Happened, exitCode, null, null);
    }

    private int RecordFinished(CommandContext context, RunningAttempt attempt, ExitRecord? exit, ContainerAccounting? accounting, AttemptOutcome outcome,
        List<GuardEvent> guard, ExecutionSettings settings, RootProcess? root)
    {
        var transaction = context.Transaction;
        var now = transaction.NowMicroseconds;
        var task = TaskRecords.GetRow(transaction, attempt.TaskId);
        var previous = TaskRecords.GetAttemptRow(transaction, attempt.AttemptId);
        if (task is null || previous is null || previous.State == AttemptState.Finished)
        {
            return 0;
        }

        uint? windowsStatus = outcome.ExitCode is { } code && unchecked((uint)code) >= 0xC0000000 ? unchecked((uint)code) : null;
        var leftovers = exit?.LeftoversTerminated ?? [];
        var cpu = exit is not null ? exit.CpuUserMs + exit.CpuKernelMs : (accounting?.CpuUserMs ?? 0) + (accounting?.CpuKernelMs ?? 0);
        transaction.Execute(
            """
            UPDATE attempt SET state = 9, finished_at = $now, exit_code = $exit, windows_status = $status, termination_reason = $reason, effect = $effect,
                   detail = $detail, leftover_count = $leftovers, leftover_images_json = $images, cpu_time_ms = $cpu, mem_peak_bytes = $mem,
                   io_read_bytes = $read, io_write_bytes = $write, stdout_bytes = $stdout, stderr_bytes = $stderr, stdout_offset = $stdout,
                   stderr_offset = $stderr, index_offset = $index, limit_enforced_by = $limitBy,
                   root_pid = coalesce(root_pid, $pid), root_start = coalesce(root_start, $start), started_at = coalesce(started_at, $start),
                   rev = rev + 1
            WHERE attempt_id = $id;
            """,
            ("$now", now), ("$exit", outcome.ExitCode), ("$status", windowsStatus is { } value ? (long)value : null), ("$reason", (int)outcome.Reason),
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
        if (task.CurrentAttemptId is { } current && current.AsSpan().SequenceEqual(attempt.AttemptId) && !task.Terminal)
        {
            transaction.Execute(
                "UPDATE task SET state = $state, state_reason = coalesce(state_reason, $reason), finished_at = $now, rev = rev + 1 WHERE task_id = $id;",
                ("$state", (int)state), ("$reason", outcome.Reason.ToString().ToUpperInvariant()), ("$now", now), ("$id", attempt.TaskId));
            TaskSecrets.SchedulePurge(transaction, attempt.TaskId, now, settings.SecretRetention);
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
            await _processor.ExecuteAsync(context =>
            {
                var transaction = context.Transaction;
                var now = transaction.NowMicroseconds;
                var previous = TaskRecords.GetAttemptRow(transaction, attempt.AttemptId);
                transaction.Execute(
                    "UPDATE attempt SET state = 9, finished_at = $now, termination_reason = 9, effect = 1, detail = $detail, rev = rev + 1 WHERE attempt_id = $id;",
                    ("$now", now), ("$detail", detail), ("$id", attempt.AttemptId));
                transaction.Execute(
                    "UPDATE task SET state = 8, state_reason = 'SPAWN_FAILED', finished_at = $now, rev = rev + 1 WHERE task_id = $id;",
                    ("$now", now), ("$id", attempt.TaskId));
                TaskSecrets.SchedulePurge(transaction, attempt.TaskId, now, Settings.SecretRetention);
                EmitAttempt(context, attempt.AttemptId, previous?.State);
                EmitTask(context, attempt.TaskId, TaskState.Running);
                return 0;
            }).ConfigureAwait(false);
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
            if (task is not null && !task.Terminal && task.CurrentAttemptId is { } current && current.AsSpan().SequenceEqual(row.AttemptId))
            {
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

    private sealed record Admitted(TaskRow Row, int Number, long Ceiling);

    private sealed record AttemptOutcome(TerminationReason Reason, EffectCertainty Effect, int? ExitCode, string? Detail, string? LimitEnforcedBy);
}
