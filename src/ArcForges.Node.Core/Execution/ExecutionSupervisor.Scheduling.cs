// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Execution;

/// <summary>A queued task as the last admission pass saw it (<c>QueueService.GetQueue</c> and <c>ExplainTask</c>).</summary>
/// <param name="TaskId">The task ID.</param>
/// <param name="Title">Its title.</param>
/// <param name="Pool">Its pool.</param>
/// <param name="Effective">Its effective class after aging.</param>
/// <param name="Owner">Its owner.</param>
/// <param name="QueuedAt">When it was queued (microseconds).</param>
/// <param name="Request">Its request.</param>
/// <param name="Aged">Aging raised its class.</param>
/// <param name="Keys">The effective keys it asks for.</param>
public sealed record QueuedView(byte[] TaskId, string Title, string Pool, Priority Effective, ActorRef Owner, long QueuedAt, ResourceDemand Request, bool Aged,
    IReadOnlyList<HeldKey> Keys);

/// <summary>What the last admission pass computed (03 section 4), for the queue views.</summary>
public sealed class QueueSnapshot
{
    /// <summary>When the pass ran.</summary>
    public required DateTimeOffset At { get; init; }

    /// <summary>The pass's outcome.</summary>
    public required AdmissionResult Result { get; init; }

    /// <summary>The queued tasks the pass considered, by base32 ID.</summary>
    public required IReadOnlyDictionary<string, QueuedView> Tasks { get; init; }

    /// <summary>The pools with their effective limits.</summary>
    public required IReadOnlyList<PoolLimits> Pools { get; init; }

    /// <summary><c>B_cpu</c>.</summary>
    public long BudgetCpu { get; init; }

    /// <summary><c>B_mem</c>.</summary>
    public long BudgetMemory { get; init; }

    /// <summary>The pressure level in force.</summary>
    public PressureLevel Pressure { get; init; } = PressureLevel.Normal;

    /// <summary><c>global_max_running</c>.</summary>
    public int GlobalMaxRunning { get; init; }

    /// <summary>The empty snapshot.</summary>
    public static QueueSnapshot Empty(DateTimeOffset at, long budgetCpu, long budgetMemory, int globalMax, PressureLevel pressure) => new()
    {
        At = at,
        Result = new AdmissionResult(),
        Tasks = new Dictionary<string, QueuedView>(StringComparer.Ordinal),
        Pools = [],
        BudgetCpu = budgetCpu,
        BudgetMemory = budgetMemory,
        GlobalMaxRunning = globalMax,
        Pressure = pressure,
    };
}

/// <summary>Controls recovered Task attempts, pressure, root limits and persisted pool settings.</summary>
public sealed partial class ExecutionSupervisor
{
    /// <summary>Root limits rise at most this often (03 section 5.1 hysteresis; a fall applies at once, L-31).</summary>
    public static readonly TimeSpan RootLimitInterval = TimeSpan.FromSeconds(10);

    /// <summary>Pressure-frozen attempts thaw after this long at Normal (03 section 7).</summary>
    public static readonly TimeSpan ThawAfterNormal = TimeSpan.FromSeconds(30);

    /// <summary>The <c>node_setting</c> row of the paused pools (<c>PausePool</c>): a JSON list of names, <c>*</c> for all.</summary>
    public const string PausedPoolsSetting = "queue.paused_pools";

    private readonly Lock _rootGate = new();
    private (long Cpu, long Memory) _rootBudget = (-1, -1);
    private long _rootAppliedAt = long.MinValue;
    private long _normalSince = long.MinValue;
    private HashSet<string>? _pausedPools;

    /// <summary>The root limits last applied from the measured budgets, or <see langword="null"/> while the startup limits hold.</summary>
    public RootLimits? AppliedRootLimits { get; private set; }

    /// <summary>Called on the platform-call queue after new root limits were applied (the node refreshes its capability report's facts).</summary>
    public Action<RootLimits>? RootLimitsApplied { get; set; }

    /// <summary>The tool-level concurrency hook (03 section 5.3), or <see langword="null"/> without adapters.</summary>
    public IToolConcurrency? Tools { get; }

    /// <summary>The platform calls posted by the pressure hooks (tests wait for them).</summary>
    internal SerialWork PlatformCalls { get; }

    /// <summary>The policy changed: refresh the settings for recovered attempts.</summary>
    public void PolicyChanged()
    {
        lock (_settingsLock)
        {
            Interlocked.Exchange(ref _lastSettingsRead, long.MinValue / 2);
        }

        _ = Settings;
    }

    /// <summary>True when a dependency's condition holds (SUCCEEDED: succeeded; FINISHED: any terminal state; READY: the service is ready).</summary>
    public static bool DependencySatisfied(DependencyCondition condition, TaskState state, bool ready) => condition switch
    {
        DependencyCondition.Finished => TaskRecords.IsTerminal(state),
        DependencyCondition.Ready => ready,
        _ => state == TaskState.Succeeded,
    };

    /// <summary>The feasibility class as <c>AdmissionExplanation.feasibility</c> text.</summary>
    public static string Word(Feasibility feasibility) => feasibility switch
    {
        Feasibility.ExceedsBudget => "EXCEEDS_BUDGET",
        Feasibility.ExceedsCapacity => "EXCEEDS_CAPACITY",
        _ => "FEASIBLE",
    };

    private HashSet<string> PausedPools()
    {
        if (Volatile.Read(ref _pausedPools) is { } cached)
        {
            return cached;
        }

        var json = _store.Read(reader => reader.Scalar("SELECT value_json FROM node_setting WHERE name = $name;", ("$name", PausedPoolsSetting)) as string);
        var pools = new HashSet<string>(json is null ? [] : JsonSerializer.Deserialize(json, ExecutionJsonContext.Default.ListString) ?? [], StringComparer.Ordinal);
        Volatile.Write(ref _pausedPools, pools);
        return pools;
    }

    /// <summary>The paused pools (<c>*</c> when every pool is paused).</summary>
    public IReadOnlySet<string> PausedPoolNames => PausedPools();

    /// <summary>Records the paused setting for one pool or all pools.</summary>
    public void SetPoolPaused(CommandContext context, string? pool, bool paused)
    {
        ArgumentNullException.ThrowIfNull(context);
        var current = new HashSet<string>(PausedPools(), StringComparer.Ordinal);
        if (pool is null)
        {
            current.Clear();
            if (paused)
            {
                current.Add("*");
            }
        }
        else if (paused)
        {
            current.Add(pool);
        }
        else
        {
            current.Remove(pool);
            current.Remove("*");
        }

        var json = JsonSerializer.Serialize(current.Order(StringComparer.Ordinal).ToList(), ExecutionJsonContext.Default.ListString);
        context.Transaction.Execute(
            """
            INSERT INTO node_setting (name, value_json, updated_at, rev) VALUES ($name, $value, $now, 0)
            ON CONFLICT (name) DO UPDATE SET value_json = $value, updated_at = $now, rev = rev + 1;
            """,
            ("$name", PausedPoolsSetting), ("$value", json), ("$now", context.Transaction.NowMicroseconds));
        Volatile.Write(ref _pausedPools, current);
    }

    /// <summary>The keys a task holds (not released), read for a recovered attempt.</summary>
    private static List<HeldKey> HeldKeys(StoreReader reader, byte[] taskId)
    {
        using var command = reader.CreateCommand("SELECT concurrency_key, mode, source FROM task_concurrency_key WHERE task_id = $id AND released_at IS NULL;");
        command.Parameters.AddWithValue("$id", taskId);
        using var rows = command.ExecuteReader();
        var result = new List<HeldKey>();
        while (rows.Read())
        {
            if (ConcurrencyKey.TryParse(rows.GetString(0), out var key, out _))
            {
                result.Add(new HeldKey(key!, (KeyMode)rows.GetInt32(1), (KeySource)rows.GetInt32(2)));
            }
        }

        return result;
    }

    /// <summary>The workspace a working directory belongs to: the registered workspace with the longest root that contains it (04 section 1).</summary>
    public static byte[]? WorkspaceOf(StoreReader reader, string workingDirectory)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(workingDirectory);
        using var command = reader.CreateCommand("SELECT workspace_id, root_path FROM workspace WHERE removed_at IS NULL AND kind IN (1, 2);");
        using var rows = command.ExecuteReader();
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var directory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(workingDirectory));
        byte[]? best = null;
        var bestLength = -1;
        while (rows.Read())
        {
            var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rows.GetString(1)));
            // Native filesystem roots already end in a separator ("/", "C:\\", UNC roots). Do not double it.
            var prefix = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
            var alternate = Path.EndsInDirectorySeparator(root) ? root : root + Path.AltDirectorySeparatorChar;
            var inside = string.Equals(directory, root, comparison)
                || directory.StartsWith(prefix, comparison) || directory.StartsWith(alternate, comparison);
            if (inside && root.Length > bestLength)
            {
                best = (byte[])rows.GetValue(0);
                bestLength = root.Length;
            }
        }

        return best;
    }

    // ---------------------------------------------------------------------------------------------------------------- retries

    /// <summary>
    /// The automatic retry of a finished attempt (AD-0006 section 4; SM-TASK RUNNING -> RETRY_WAIT): when the rules allow it the task waits for
    /// its backoff (<c>retry_at</c>) instead of becoming terminal; after an OOM kill the next attempt's hint gets a larger memory grant.
    /// Returns true when the task now waits for a retry.
    /// </summary>
    private bool ScheduleRetry(CommandContext context, TaskRow task, int attemptNumber, TerminationReason reason, bool succeeded, long peak)
    {
        var transaction = context.Transaction;
        var settings = Settings;
        var hint = task.Spec.Resources?.Hint;
        var (_, expected, ceiling, _) = settings.Request(hint);
        var decision = RetryRules.Decide(task.Spec, task.SideEffect, task.SideEffectSource, reason, succeeded, attemptNumber, ceiling < settings.MaxTaskMemory);
        if (decision is null)
        {
            return false;
        }

        var now = transaction.NowMicroseconds;
        if (decision.LargerMemory)
        {
            var (grownExpected, grownCeiling) = RetryRules.LargerGrant(expected, ceiling, peak, settings.MaxTaskMemory);
            var spec = task.Spec.Clone();
            spec.Resources ??= new ResourceSpec();
            spec.Resources.Hint ??= new ResourceDemand();
            spec.Resources.Hint.MemExpectedBytes = (ulong)grownExpected;
            spec.Resources.Hint.MemCeilingBytes = (ulong)grownCeiling;
            var bytes = spec.ToByteArray();
            transaction.Execute("UPDATE task SET spec = $spec, spec_digest = $digest WHERE task_id = $id;",
                ("$spec", bytes), ("$digest", System.Security.Cryptography.SHA256.HashData(bytes)), ("$id", task.TaskId));
        }

        transaction.Execute("UPDATE task SET state = 6, state_reason = $reason, retry_at = $at, rev = rev + 1 WHERE task_id = $id;",
            ("$reason", Truncate(decision.Reason)), ("$at", now + (long)decision.Delay.TotalMicroseconds), ("$id", task.TaskId));
        _log.Info("execution.retry.scheduled", new LogField("task", IdText.Format(task.TaskId)), new LogField("attempt", attemptNumber),
            new LogField("reason", reason), new LogField("delayMs", (long)decision.Delay.TotalMilliseconds), new LogField("largerMemory", decision.LargerMemory));
        return true;
    }

    // ---------------------------------------------------------------------------------------------------------------- readiness and keys

    /// <summary>The readiness check of a SERVICE attempt (04 section 8), on the enforcement loop.</summary>
    private void CheckReadiness(RunningAttempt attempt, IAttemptHandle handle)
    {
        if (attempt.Readiness is not { } readiness || attempt.Ready || attempt.ReadinessTimedOut || attempt.StartedTimestamp is not { } since || handle.Root is null)
        {
            return;
        }

        var elapsed = _clock.GetElapsedTime(since) - attempt.PausedTime(_clock);
        var outcome = readiness.Check(attempt.Files, Platform, () => [.. handle.Processes().Select(process => process.Pid)], elapsed, _clock);
        if (outcome == ReadinessOutcome.Waiting)
        {
            return;
        }

        if (outcome == ReadinessOutcome.Ready)
        {
            attempt.Ready = true;
            _log.Info("execution.service.ready", new LogField("attempt", attempt.Name), new LogField("condition", readiness.Describe()),
                new LogField("afterMs", (long)elapsed.TotalMilliseconds));

            // 03 section 4: a SERVICE releases ws:<workspace> (from SERIAL or access = EXCLUSIVE) once it is ready.
            var released = ReleaseKeys(attempt, key => key.Source == KeySource.Workspace && key.Key.Kind == KeyKind.Workspace);
            _ = RecordAsync(context =>
            {
                context.Transaction.Execute("UPDATE task SET ready = 1, rev = rev + 1 WHERE task_id = $id;", ("$id", attempt.TaskId));
                MarkReleased(context, attempt, released);
                EmitTask(context, attempt.TaskId, null);
                return 0;
            });
        }
        else
        {
            attempt.ReadinessTimedOut = true;
            _log.Warning("execution.service.readiness_timeout", new LogField("attempt", attempt.Name), new LogField("condition", readiness.Describe()),
                new LogField("timeoutMs", (long)readiness.Timeout.TotalMilliseconds));
            var reason = string.Create(CultureInfo.InvariantCulture,
                $"readiness_timeout: {readiness.Describe()} did not hold within {readiness.Timeout.TotalSeconds:0.#} s; the service keeps running");
            _ = RecordAsync(context =>
            {
                context.Transaction.Execute("UPDATE task SET state_reason = $reason, rev = rev + 1 WHERE task_id = $id;", ("$reason", reason), ("$id", attempt.TaskId));
                EmitTask(context, attempt.TaskId, null);
                return 0;
            });
        }
    }

    /// <summary>
    /// Early release of keys (03 section 4 "Lifetime"): an adapter's phase detector calls this when a run operation's program started
    /// (<c>dotnet run</c>, <c>cargo run</c>, <c>npm start</c>), so a long-running program does not block other work. Returns false when the
    /// attempt is not running.
    /// </summary>
    public bool ReleaseKeysAtProgramStart(string attemptName)
    {
        if (!_running.TryGetValue(attemptName, out var attempt))
        {
            return false;
        }

        var released = ReleaseKeys(attempt, _ => true);
        _log.Info("execution.keys.released", new LogField("attempt", attemptName), new LogField("keys", string.Join(", ", released.Select(key => key.Key.Text))),
            new LogField("why", "the run operation's program started"));
        _ = RecordAsync(context =>
        {
            MarkReleased(context, attempt, released);
            EmitTask(context, attempt.TaskId, null);
            return 0;
        });
        return true;
    }

    private static List<HeldKey> ReleaseKeys(RunningAttempt attempt, Func<HeldKey, bool> which)
    {
        lock (attempt)
        {
            var released = attempt.Keys.Where(which).ToList();
            attempt.Keys.RemoveAll(key => released.Contains(key));
            return released;
        }
    }

    private static void MarkReleased(CommandContext context, RunningAttempt attempt, List<HeldKey> released)
    {
        foreach (var key in released)
        {
            context.Transaction.Execute("UPDATE task_concurrency_key SET released_at = $now WHERE task_id = $id AND concurrency_key = $key;",
                ("$now", context.Transaction.NowMicroseconds), ("$id", attempt.TaskId), ("$key", key.Key.Text));
        }
    }

    // ---------------------------------------------------------------------------------------------------------------- pressure and root limits

    /// <summary>
    /// The scheduler's part of the pressure hook (03 sections 5.1 and 7; R-RES-009), on the monitor's thread and never blocking it (platform
    /// calls are posted to <see cref="PlatformCalls"/>): the root limits follow the measured budgets with hysteresis (more than 5% of capacity;
    /// a fall at once, a rise at most every 10 s, L-31) and shrink at once on entering Tight. At Pressure the freeze (Linux) or the requeue
    /// (Windows) applies (at Critical only the monitor's shedding acts); after 30 s at Normal the
    /// frozen attempts thaw in priority order.
    /// </summary>
    private void SchedulerRespond(PressureLevel level, PressureLevel previous, ResourceState state)
    {
        var settings = Settings;
        UpdateRootLimits(settings, state, force: level >= PressureLevel.Tight && previous < PressureLevel.Tight);
        var now = _clock.GetTimestamp();
        if (level >= PressureLevel.Pressure)
        {
            // Critical has its own action, stopping preemptible attempts one at a time from the lowest class until the level recovers
            // (only as many as needed; the resource monitor's CriticalShedding): the Pressure actions do not add to it.
            _normalSince = long.MinValue;
            if (level == PressureLevel.Pressure)
            {
                ApplyPressure(settings, state);
            }
        }
        else if (level == PressureLevel.Normal)
        {
            if (_normalSince == long.MinValue)
            {
                _normalSince = now;
            }
            else if (_clock.GetElapsedTime(_normalSince, now) >= ThawAfterNormal)
            {
                ThawPressureFrozen();
            }
        }
        else
        {
            _normalSince = long.MinValue;
        }
    }

    /// <summary>
    /// Applies root limits from <c>B</c> (03 section 5.1, L-31) when they changed by more than 5% of capacity: a fall at once, a rise once 10 s
    /// passed since the last update, and any change at once when forced.
    /// </summary>
    private void UpdateRootLimits(ExecutionSettings settings, ResourceState state, bool force)
    {
        if (Platform is not { } platform)
        {
            return;
        }

        RootLimits limits;
        (long Cpu, long Memory) next;
        lock (_rootGate)
        {
            var applied = _rootBudget.Cpu < 0 ? (settings.BudgetCpu, settings.ManagedMemory) : _rootBudget;
            var due = _rootAppliedAt == long.MinValue || _clock.GetElapsedTime(_rootAppliedAt) >= RootLimitInterval;
            if (NextRootBudget(applied, (state.BudgetCpu, state.BudgetMemory), (settings.CapacityCpu, settings.CapacityMemory), due, force) is not { } budget)
            {
                return;
            }

            next = budget;
            _rootBudget = next;
            _rootAppliedAt = _clock.GetTimestamp();
            limits = settings.RootLimits(next.Cpu, next.Memory);
            AppliedRootLimits = limits;
        }

        _log.Info("execution.root_limits", new LogField("cpuRate", limits.CpuRate), new LogField("memoryHigh", limits.NotificationBytes),
            new LogField("budgetCpu", next.Cpu), new LogField("budgetMemory", next.Memory), new LogField("forced", force));
        PlatformCalls.Post("root-limits", () =>
        {
            platform.UpdateRootLimits(limits);
            RootLimitsApplied?.Invoke(limits);
        });
    }

    /// <summary>
    /// The budget the root limits take next (03 section 5.1, amended by L-31), or <see langword="null"/> to keep <paramref name="applied"/>.
    /// A change counts when it exceeds 5% of capacity. Forced (entering Tight): any change applies at once. Once <paramref name="due"/> (10 s
    /// since the last update), any counted change applies the measured budget, as before. Before that, only a counted fall applies at once,
    /// to the dimension that fell; the other dimension keeps its applied value, so a rise still waits for the interval.
    /// </summary>
    internal static (long Cpu, long Memory)? NextRootBudget((long Cpu, long Memory) applied, (long Cpu, long Memory) measured,
        (long Cpu, long Memory) capacity, bool due, bool force)
    {
        if (force)
        {
            return measured != applied ? measured : null;
        }

        var cpu = Math.Sign(measured.Cpu - applied.Cpu) * (Math.Abs(measured.Cpu - applied.Cpu) > capacity.Cpu / 20 ? 1 : 0);
        var memory = Math.Sign(measured.Memory - applied.Memory) * (Math.Abs(measured.Memory - applied.Memory) > capacity.Memory / 20 ? 1 : 0);
        if (cpu == 0 && memory == 0)
        {
            return null;
        }

        if (due)
        {
            return measured;
        }

        return cpu < 0 || memory < 0 ? (cpu < 0 ? measured.Cpu : applied.Cpu, memory < 0 ? measured.Memory : applied.Memory) : null;
    }

    /// <summary>
    /// The Pressure level's actions (03 section 7): on Linux, pausable BACKGROUND and LOW attempts are frozen and their MemoryHigh lowered
    /// to current usage to force reclaim (<c>pressure.freeze_on_pressure</c>); on Windows, preemptible BACKGROUND attempts are requeued:
    /// cancelled with the graceful phase (<c>PREEMPTED</c>), then queued again only if the retry rules allow. Non-preemptible and
    /// non-pausable attempts are never touched.
    /// </summary>
    private void ApplyPressure(ExecutionSettings settings, ResourceState state)
    {
        foreach (var attempt in _running.Values)
        {
            if (attempt.Handle is not { } handle || attempt.Finalizing || attempt.StopReason is not null || !attempt.RootRecorded)
            {
                continue;
            }

            if (OperatingSystem.IsWindows())
            {
                if (attempt.Preemptible && attempt.Priority == Priority.Background)
                {
                    Requeue(attempt, state);
                }

                continue;
            }

            if (settings.Pressure.FreezeOnPressure && attempt.Pausable && attempt.Priority is Priority.Background or Priority.Low && handle.CanPause)
            {
                lock (attempt)
                {
                    if (attempt.Paused || attempt.PauseInFlight)
                    {
                        continue;
                    }

                    attempt.PauseInFlight = true;
                }

                var memory = Math.Max(1024 * 1024, attempt.Usage?.MemoryBytes ?? attempt.PeakObserved);
                var trigger = string.Create(CultureInfo.InvariantCulture,
                    $"{PressureFrozen}: frozen at memory pressure ({state.PressureTrigger}; {state.AvailableMemory} of {state.CapacityMemory} bytes available); MemoryHigh lowered to {memory} bytes");
                PlatformCalls.Post("freeze " + attempt.Name, () => Freeze(attempt, handle, trigger, pressure: true, lowerMemoryTo: memory));
            }
        }
    }

    /// <summary>Requeues a preemptible attempt at Pressure (Windows): STOPPING is recorded with the trigger, then the graceful stop runs.</summary>
    private void Requeue(RunningAttempt attempt, ResourceState state)
    {
        var detail = string.Create(CultureInfo.InvariantCulture,
            $"requeued at memory pressure ({state.PressureTrigger}; {state.AvailableMemory} of {state.CapacityMemory} bytes available)");
        lock (attempt)
        {
            if (attempt.StopReason is not null || attempt.StopRecording is not null)
            {
                return;
            }
        }

        _log.Warning("execution.requeued", new LogField("attempt", attempt.Name), new LogField("priority", attempt.Priority), new LogField("trigger", state.PressureTrigger));
        _ = StopAsync(attempt.Name, TerminationReason.Preempted, null, graceful: true, detail);
    }

    /// <summary>
    /// Freezes an attempt (on the platform-call queue): PAUSING, <c>FreezeUnit</c>, then PAUSED for the attempt and the task; after a pressure
    /// freeze its MemoryHigh is lowered to <paramref name="lowerMemoryTo"/> (current usage).
    /// </summary>
    private void Freeze(RunningAttempt attempt, IAttemptHandle handle, string reason, bool pressure, long? lowerMemoryTo)
    {
        try
        {
            if (attempt.Finalizing || attempt.StopReason is not null || _stop.IsCancellationRequested)
            {
                return;
            }

            _ = RecordAsync(context => SetPaused(context, attempt, AttemptState.Pausing, null));
            handle.Freeze();
            lock (attempt)
            {
                attempt.Paused = true;
                attempt.PausedByPressure = pressure;
                attempt.PausedSince = _clock.GetTimestamp();
            }

            _ = RecordAsync(context => SetPaused(context, attempt, AttemptState.Paused, reason));
            _log.Info("execution.paused", new LogField("attempt", attempt.Name), new LogField("pressure", pressure), new LogField("reason", reason));
            if (lowerMemoryTo is { } memory)
            {
                handle.SetMemoryHigh(memory);
            }
        }
        finally
        {
            attempt.PauseInFlight = false;
        }
    }

    /// <summary>Thaws a frozen attempt (on the platform-call queue): its launch MemoryHigh comes back first, then <c>ThawUnit</c>, then RUNNING.</summary>
    private void Thaw(RunningAttempt attempt, IAttemptHandle handle, string reason)
    {
        try
        {
            if (!attempt.Paused || attempt.Finalizing)
            {
                return;
            }

            if (attempt.PausedByPressure && attempt.MemoryHighBytes > 0)
            {
                handle.SetMemoryHigh(attempt.MemoryHighBytes);
            }

            handle.Thaw();
            lock (attempt)
            {
                attempt.Paused = false;
                attempt.PausedByPressure = false;
                if (attempt.PausedSince != long.MinValue)
                {
                    attempt.PausedTicks += _clock.GetTimestamp() - attempt.PausedSince;
                    attempt.PausedSince = long.MinValue;
                }
            }

            _ = RecordAsync(context => SetPaused(context, attempt, AttemptState.Running, reason));
            _log.Info("execution.resumed", new LogField("attempt", attempt.Name), new LogField("reason", reason));
        }
        finally
        {
            attempt.PauseInFlight = false;
        }
    }

    /// <summary>
    /// The token that starts the <c>state_reason</c> of a task frozen at Pressure: the persisted cause of the pause, so that an attempt
    /// recovered PAUSED after a node restart is known to be pressure-frozen and thaws after 30 s at Normal with its launch MemoryHigh.
    /// </summary>
    public const string PressureFrozen = "pressure_frozen";

    /// <summary>True when a PAUSED task's <c>state_reason</c> records a pressure freeze (not a PauseTask).</summary>
    public static bool IsPressureFrozen(string? stateReason) =>
        stateReason is not null && stateReason.StartsWith(PressureFrozen + ":", StringComparison.Ordinal);

    /// <summary>After 30 s at Normal, the pressure-frozen attempts thaw in priority order (the highest class first, 03 section 7).</summary>
    private void ThawPressureFrozen()
    {
        foreach (var attempt in _running.Values.Where(attempt => attempt.Paused && attempt.PausedByPressure && !attempt.PauseInFlight && attempt.Handle is not null)
            .OrderBy(attempt => attempt.Priority).ThenBy(attempt => attempt.StartedTimestamp ?? long.MaxValue).ToList())
        {
            attempt.PauseInFlight = true;
            var handle = attempt.Handle!;
            PlatformCalls.Post("thaw " + attempt.Name, () => Thaw(attempt, handle, "thawed after 30 s at Normal pressure"));
        }
    }

    private int SetPaused(CommandContext context, RunningAttempt attempt, AttemptState state, string? reason)
    {
        var transaction = context.Transaction;
        var previous = TaskRecords.GetAttemptRow(transaction, attempt.AttemptId);
        if (previous is null || previous.State is AttemptState.Stopping or AttemptState.Finalizing or AttemptState.Finished)
        {
            return 0;
        }

        if (transaction.Execute("UPDATE attempt SET state = $state, rev = rev + 1 WHERE attempt_id = $id AND state IN (4, 5, 6);", ("$state", (int)state), ("$id", attempt.AttemptId)) == 1)
        {
            EmitAttempt(context, attempt.AttemptId, previous.State);
        }

        var taskState = state is AttemptState.Paused ? TaskState.Paused : state is AttemptState.Running ? TaskState.Running : (TaskState?)null;
        if (taskState is { } next)
        {
            transaction.Execute("UPDATE task SET state = $state, state_reason = $reason, rev = rev + 1 WHERE task_id = $id AND state IN (4, 5);",
                ("$state", (int)next), ("$reason", reason is null ? null : Truncate(reason)), ("$id", attempt.TaskId));
            EmitTask(context, attempt.TaskId, next == TaskState.Paused ? TaskState.Running : TaskState.Paused);
        }

        return 0;
    }

    /// <summary>
    /// <c>PauseTask</c> (R-EXE-011; SM-ATTEMPT RUNNING -> PAUSING -> PAUSED): the platform must support pause (STATE/pause_unsupported on
    /// Windows) and the task must be RUNNING and pausable; pausing a paused task succeeds. The freeze is posted to the platform-call queue;
    /// <paramref name="done"/> completes once it ran.
    /// </summary>
    public ArcError? PauseTask(StoreReader reader, ReadOnlySpan<byte> taskId, out Task done)
    {
        ArgumentNullException.ThrowIfNull(reader);
        done = Task.CompletedTask;
        var row = TaskRecords.GetRow(reader, taskId);
        if (row is null || row.Purged)
        {
            return NodeErrors.NotFound("task", taskId);
        }

        var task = IdText.Format(taskId);
        var attempt = _running.Values.FirstOrDefault(running => IdText.Format(running.TaskId) == task);
        if (attempt?.Handle is { } candidate && !candidate.CanPause || (attempt is null && Platform is not null && OperatingSystem.IsWindows()))
        {
            return NodeErrors.PauseUnsupported();
        }

        if (row.State == TaskState.Paused || attempt is { Paused: true })
        {
            return null;
        }

        if (row.State != TaskState.Running || attempt?.Handle is not { } handle || !attempt.RootRecorded || attempt.StopReason is not null)
        {
            return NodeErrors.InvalidState(row.State.ToString().ToUpperInvariant(), "only a RUNNING task can be paused");
        }

        if (row.Spec.Resources?.Pausable != true)
        {
            return NodeErrors.InvalidState("NOT_PAUSABLE", "the task was not submitted with resources.pausable = true");
        }

        lock (attempt)
        {
            if (attempt.PauseInFlight)
            {
                return null;
            }

            attempt.PauseInFlight = true;
        }

        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        done = completion.Task;
        PlatformCalls.Post("pause " + attempt.Name, () =>
        {
            try
            {
                Freeze(attempt, handle, "paused by PauseTask", pressure: false, lowerMemoryTo: null);
            }
            finally
            {
                completion.TrySetResult();
            }
        });
        return null;
    }

    /// <summary><c>ResumeTask</c> (SM-ATTEMPT PAUSED -> RUNNING); <paramref name="done"/> completes once the thaw ran.</summary>
    public ArcError? ResumeTask(StoreReader reader, ReadOnlySpan<byte> taskId, out Task done)
    {
        ArgumentNullException.ThrowIfNull(reader);
        done = Task.CompletedTask;
        var row = TaskRecords.GetRow(reader, taskId);
        if (row is null || row.Purged)
        {
            return NodeErrors.NotFound("task", taskId);
        }

        var task = IdText.Format(taskId);
        var attempt = _running.Values.FirstOrDefault(running => IdText.Format(running.TaskId) == task);
        if (attempt?.Handle is not { } handle || !(attempt.Paused || attempt.PauseInFlight))
        {
            return NodeErrors.InvalidState(row.State.ToString().ToUpperInvariant(), "only a PAUSED task can be resumed");
        }

        attempt.PauseInFlight = true;
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        done = completion.Task;
        PlatformCalls.Post("resume " + attempt.Name, () =>
        {
            try
            {
                Thaw(attempt, handle, "resumed by ResumeTask");
            }
            finally
            {
                completion.TrySetResult();
            }
        });
        return null;
    }

    /// <summary>
    /// <c>SetTaskPriority</c> (api-catalogue: "change priority or pool of a queued task, or priority (CPU weight) of a running one"): a
    /// waiting task (QUEUED, WAITING_DEPENDENCY, RETRY_WAIT) takes the new class and, when given, the new pool, and its aging restarts from
    /// the new class; a RUNNING or PAUSED task takes the new class and its attempt's container the class's CPU weight (03 section 5.2; a pool
    /// change is refused for it). A finished task is <c>STATE/invalid_state</c>.
    /// </summary>
    public (QueueInfo? Queue, ArcError? Error) SetPriority(CommandContext context, ReadOnlySpan<byte> taskId, Priority? priority, string? pool)
    {
        ArgumentNullException.ThrowIfNull(context);
        var transaction = context.Transaction;
        var row = TaskRecords.GetRow(transaction, taskId);
        if (row is null || row.Purged)
        {
            return (null, NodeErrors.NotFound("task", taskId));
        }

        if (row.State is TaskState.Running or TaskState.Paused)
        {
            if (pool is not null)
            {
                return (null, NodeErrors.InvalidArgument("pool: queued tasks only"));
            }

            var running = priority ?? row.Priority;
            var weight = ExecutionSettings.Weight(running);
            transaction.Execute("UPDATE task SET priority = $priority, effective_priority = $priority, rev = rev + 1 WHERE task_id = $id;",
                ("$priority", (int)running), ("$id", taskId.ToArray()));
            if (row.CurrentAttemptId is { } attemptId)
            {
                transaction.Execute("UPDATE attempt SET cpu_weight = $weight, rev = rev + 1 WHERE attempt_id = $id;", ("$weight", weight), ("$id", attemptId));
                var name = IdText.Format(attemptId);
                if (_running.TryGetValue(name, out var attempt) && attempt.Handle is { } handle)
                {
                    attempt.Priority = running;
                    PlatformCalls.Post("cpu-weight " + name, () => handle.SetCpuWeight(weight));
                }
            }

            EmitTask(context, taskId, row.State);
            return (new QueueInfo(), null);
        }

        if (row.State is not (TaskState.Queued or TaskState.WaitingDependency or TaskState.RetryWait or TaskState.Placing))
        {
            return (null, NodeErrors.InvalidState(row.State.ToString().ToUpperInvariant(), "a finished task's priority does not change"));
        }

        var newPriority = priority ?? row.Priority;
        transaction.Execute(
            "UPDATE task SET priority = $priority, effective_priority = $priority, aged_at = $now, pool = $pool, rev = rev + 1 WHERE task_id = $id;",
            ("$priority", (int)newPriority), ("$now", transaction.NowMicroseconds), ("$pool", pool ?? row.Pool), ("$id", taskId.ToArray()));
        EmitTask(context, taskId, row.State);
        return (new QueueInfo { Position = TaskRecords.QueuePosition(transaction, taskId) }, null);
    }
}
