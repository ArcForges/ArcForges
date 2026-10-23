// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
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

/// <summary>
/// The scheduler half of the supervisor (AF-SCHED-01; 03 sections 3, 4, 5 and 7; 04 section 8; AD-0006 section 4): the admission pass over
/// the queued tasks (<see cref="AdmissionEngine"/>), dependencies and service readiness, automatic retries for asserted classes, keys with
/// their early release, the root limits from the measured budgets with hysteresis, the pressure actions of Tight (only INTERACTIVE, the
/// root CPU cap shrinks at once) and Pressure (Linux: freeze pausable BACKGROUND and LOW attempts and lower their MemoryHigh to current
/// usage; Windows: requeue preemptible BACKGROUND attempts), the thaw after 30 s at Normal, pause and resume, and pool pausing. Admission
/// runs on events (submit, exit, budget or level change) and every 2 s while anything is queued, waiting or retrying; an idle node waits
/// for an event only.
/// </summary>
public sealed partial class ExecutionSupervisor
{
    /// <summary>The periodic admission pass while work is queued (03 section 4: at least every 2 s).</summary>
    public static readonly TimeSpan AdmissionInterval = TimeSpan.FromSeconds(2);

    /// <summary>Root limits change at most this often (03 section 5.1 hysteresis).</summary>
    public static readonly TimeSpan RootLimitInterval = TimeSpan.FromSeconds(10);

    /// <summary>Pressure-frozen attempts thaw after this long at Normal (03 section 7).</summary>
    public static readonly TimeSpan ThawAfterNormal = TimeSpan.FromSeconds(30);

    /// <summary>The <c>node_setting</c> row of the paused pools (<c>PausePool</c>): a JSON list of names, <c>*</c> for all.</summary>
    public const string PausedPoolsSetting = "queue.paused_pools";

    private const int MaxQueuedRead = 10_000;
    private readonly AdmissionEngine _engine = new();
    private readonly Dictionary<string, CachedRequest> _requests = new(StringComparer.Ordinal);
    private readonly HashSet<string> _infeasibleRaised = new(StringComparer.Ordinal);
    private readonly HashSet<string> _starvingRaised = new(StringComparer.Ordinal);
    private readonly Lock _rootGate = new();
    private QueueSnapshot? _queue;
    private volatile bool _workPending = true;
    private (long Cpu, long Memory) _rootBudget = (-1, -1);
    private long _rootAppliedAt = long.MinValue;
    private long _normalSince = long.MinValue;
    private (long Cpu, long Memory, PressureLevel Level) _kickedAt = (-1, -1, PressureLevel.Normal);
    private HashSet<string>? _pausedPools;

    /// <summary>The last admission pass, or <see langword="null"/> before the first.</summary>
    public QueueSnapshot? Queue => Volatile.Read(ref _queue);

    /// <summary>The root limits last applied from the measured budgets, or <see langword="null"/> while the startup limits hold.</summary>
    public RootLimits? AppliedRootLimits { get; private set; }

    /// <summary>Called on the platform-call queue after new root limits were applied (the node refreshes its capability report's facts).</summary>
    public Action<RootLimits>? RootLimitsApplied { get; set; }

    /// <summary>The tool-level concurrency hook (03 section 5.3), or <see langword="null"/> without adapters.</summary>
    public IToolConcurrency? Tools { get; }

    /// <summary>The platform calls posted by the pressure hooks (tests wait for them).</summary>
    internal SerialWork PlatformCalls { get; }

    /// <summary>The policy changed: the settings are read again and admission runs.</summary>
    public void PolicyChanged()
    {
        Interlocked.Exchange(ref _lastSettingsRead, long.MinValue / 2);
        _ = Settings;
        _workPending = true;
        Kick();
    }

    // ---------------------------------------------------------------------------------------------------------------- the pass

    private async Task AdmissionLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            // The pulse is taken before the kick flag is read: a kick after this point completes it, one before it set the flag.
            var pulse = _admission.Next;
            if (Interlocked.Exchange(ref _kicked, 0) == 0)
            {
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                await Task.WhenAny(pulse, Task.Delay(_workPending ? AdmissionInterval : Timeout.InfiniteTimeSpan, wait.Token)).ConfigureAwait(false);
                await wait.CancelAsync().ConfigureAwait(false);
                Interlocked.Exchange(ref _kicked, 0);
            }

            if (_stop.IsCancellationRequested)
            {
                return;
            }

            if (Platform is null)
            {
                continue;
            }

            try
            {
                await AdmitAsync().ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException or IOException
                or InvalidProtocolBufferException)
            {
                _workPending = true;
                _log.Warning("execution.admission.failed", new LogField("errorType", exception.GetType().Name), new LogField("error", NodeLog.OneLine(exception.Message)));
            }
        }
    }

    /// <summary>One admission pass: retries whose backoff elapsed and satisfied dependencies are queued, then the queued tasks are admitted.</summary>
    private async Task AdmitAsync()
    {
        var settings = Settings;
        var (waiting, retrying, retryDue) = _store.Read(reader =>
        {
            var now = reader.NowMicroseconds;
            using var command = reader.CreateCommand(
                "SELECT (SELECT count(*) FROM task WHERE state = 2), (SELECT count(*) FROM task WHERE state = 6), (SELECT count(*) FROM task WHERE state = 6 AND retry_at <= $now);");
            command.Parameters.AddWithValue("$now", now);
            using var rows = command.ExecuteReader();
            rows.Read();
            return (rows.GetInt64(0), rows.GetInt64(1), rows.GetInt64(2));
        });
        if (waiting > 0 || retryDue > 0)
        {
            await _processor.ExecuteAsync(context => Promote(context, settings)).ConfigureAwait(false);
        }

        var (rows, keys, workspaces, reservation) = _store.Read(reader => (QueuedRows(reader), QueuedKeys(reader), Workspaces(reader), CurrentReservation(reader)));
        _workPending = rows.Count > 0 || waiting > 0 || retrying > 0;
        var resources = Resources?.Current;
        var budgetCpu = resources?.BudgetCpu ?? settings.BudgetCpu;
        var budgetMemory = resources?.BudgetMemory ?? Math.Max(0, settings.MaxShareMemory);
        var pressure = resources?.Pressure ?? PressureLevel.Normal;
        if (rows.Count == 0)
        {
            Volatile.Write(ref _queue, QueueSnapshot.Empty(_clock.GetUtcNow(), budgetCpu, budgetMemory, settings.GlobalMaxRunning, pressure));
            foreach (var key in _requests.Keys.ToList())
            {
                _requests.Remove(key);
            }

            _infeasibleRaised.Clear();
            _starvingRaised.Clear();
            return;
        }

        var now = StoreTime.ToMicroseconds(_clock.GetUtcNow());
        var paused = PausedPools();
        var pools = settings.PoolPolicies.Select(pool => new PoolLimits(pool.Name, pool.HasWeight ? (int)Math.Clamp(pool.Weight, 1u, 100u) : 1,
            Math.Min(ExecutionSettings.MaxParallel(pool.HasMaxParallelMode ? pool.MaxParallelMode : ParallelismMode.Auto, pool.MaxParallelFixed, budgetCpu),
                PoolRule(settings, pool.Name, budgetCpu)),
            paused.Contains("*") || paused.Contains(pool.Name))).ToList();
        var candidates = new List<QueuedCandidate>(rows.Count);
        var views = new Dictionary<string, QueuedView>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var request = Request(row, settings);
            var effectiveKeys = EffectiveKeys(row, keys.GetValueOrDefault(row.Name) ?? [], workspaces);
            candidates.Add(new QueuedCandidate
            {
                Task = row.Name,
                Pool = row.Pool,
                BasePriority = row.Priority,
                EffectivePriority = row.Effective,
                Owner = OwnerKey(row.Owner, row.Session),
                Session = row.Session is { } session ? IdText.Format(session) : null,
                Workspace = row.Workspace is { } workspace ? IdText.Format(workspace) : null,
                QueuedAt = row.QueuedAt,
                AgingFrom = row.AgingFrom,
                Sequence = row.CreatedAt,
                Cpu = request.Cpu,
                MemExpected = request.Expected,
                Keys = effectiveKeys,
                LapsedAt = row.LapsedAt,
            });
            var demand = new ResourceDemand
            {
                CpuMillicores = (uint)Math.Min(request.Cpu, uint.MaxValue),
                MemExpectedBytes = (ulong)request.Expected,
                MemCeilingBytes = (ulong)request.Ceiling,
                Source = request.Source,
            };
            views[row.Name] = new QueuedView(row.TaskId, row.Title, row.Pool, row.Effective, row.Owner, row.QueuedAt, demand, row.Effective != row.Priority, effectiveKeys);
        }

        var running = _running.Values.Select(attempt =>
        {
            lock (attempt)
            {
                return new RunningLoad(IdText.Format(attempt.TaskId), attempt.Pool, attempt.Session, attempt.Workspace, attempt.AccountedMemory, attempt.CpuGrant,
                    [.. attempt.Keys], attempt.Light);
            }
        }).ToList();
        var input = new AdmissionInput
        {
            Now = now,
            BudgetCpu = budgetCpu,
            BudgetMemory = budgetMemory,
            CapacityMemory = settings.CapacityMemory,
            ReserveMemory = settings.ReserveMemory,
            UnmanagedMemory = resources?.UnmanagedMemory ?? 0,
            MaxTaskMemory = settings.MaxTaskMemory,
            OvercommitCpu = settings.OvercommitCpu,
            GlobalMaxRunning = settings.GlobalMaxRunning,
            GlobalParallelism = Rule(settings, ParallelismScope.Global, string.Empty),
            WorkspaceParallelism = Rules(settings, ParallelismScope.Workspace, candidates.Select(candidate => candidate.Workspace), 0),
            SessionParallelism = Rules(settings, ParallelismScope.Session, candidates.Select(candidate => candidate.Session), settings.MaxRunningPerSession),
            Pressure = pressure,
            StarvationBound = (long)settings.StarvationBound.TotalMicroseconds,
            LargeTaskBypass = (long)settings.LargeTaskBypass.TotalMicroseconds,
            ReservationMax = (long)settings.ReservationMax.TotalMicroseconds,
            Pools = pools,
            Running = running,
            Queued = candidates,
            Reservation = reservation,
            WorkspaceRoot = workspace => workspaces.TryGetValue(workspace, out var info) ? info.Root : null,
        };
        var result = _engine.Pass(input);
        Volatile.Write(ref _queue, new QueueSnapshot
        {
            At = _clock.GetUtcNow(),
            Result = result,
            Tasks = views,
            Pools = pools,
            BudgetCpu = budgetCpu,
            BudgetMemory = budgetMemory,
            Pressure = pressure,
            GlobalMaxRunning = settings.GlobalMaxRunning,
        });
        await RecordPassAsync(rows, input, result).ConfigureAwait(false);
        var byName = rows.ToDictionary(row => row.Name, StringComparer.Ordinal);
        foreach (var admission in result.Admitted)
        {
            if (_stop.IsCancellationRequested)
            {
                return;
            }

            var row = byName[admission.Task];
            await StartAttemptAsync(row, admission, Request(row, settings), views[row.Name].Keys, settings).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Queues RETRY_WAIT tasks whose backoff elapsed (SM-TASK RETRY_WAIT -> QUEUED) and resolves WAITING_DEPENDENCY tasks (04 section 8):
    /// queued when every dependency's condition holds (SUCCEEDED, FINISHED or READY), CANCELLED with <c>dependency_failed</c> when a
    /// SUCCEEDED dependency failed or was cancelled or lost, or a READY dependency ended or timed out without becoming ready.
    /// </summary>
    private int Promote(CommandContext context, ExecutionSettings settings)
    {
        var transaction = context.Transaction;
        var now = transaction.NowMicroseconds;
        var due = new List<byte[]>();
        using (var command = transaction.CreateCommand("SELECT task_id FROM task WHERE state = 6 AND retry_at <= $now;"))
        {
            command.Parameters.AddWithValue("$now", now);
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                due.Add((byte[])rows.GetValue(0));
            }
        }

        foreach (var taskId in due)
        {
            transaction.Execute(
                "UPDATE task SET state = 1, state_reason = 'retry', queued_at = $now, retry_at = NULL, effective_priority = priority, aged_at = NULL, rev = rev + 1 WHERE task_id = $id AND state = 6;",
                ("$now", now), ("$id", taskId));
            EmitTask(context, taskId, TaskState.RetryWait);
        }

        var edges = new Dictionary<string, List<(byte[] Task, byte[] On, DependencyCondition Condition, TaskState State, bool Ready, string? Reason)>>(StringComparer.Ordinal);
        using (var command = transaction.CreateCommand(
            """
            SELECT d.task_id, d.depends_on_task_id, d.condition, t.state, t.ready, t.state_reason
            FROM task_dependency d JOIN task w ON w.task_id = d.task_id JOIN task t ON t.task_id = d.depends_on_task_id
            WHERE w.state = 2;
            """))
        {
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                var task = (byte[])rows.GetValue(0);
                var key = IdText.Format(task);
                if (!edges.TryGetValue(key, out var list))
                {
                    edges[key] = list = [];
                }

                list.Add((task, (byte[])rows.GetValue(1), (DependencyCondition)rows.GetInt32(2), (TaskState)rows.GetInt32(3), rows.GetInt32(4) == 1,
                    rows.IsDBNull(5) ? null : rows.GetString(5)));
            }
        }

        foreach (var (_, dependencies) in edges)
        {
            var taskId = dependencies[0].Task;
            var failed = dependencies.FirstOrDefault(edge => DependencyFailed(edge.Condition, edge.State, edge.Ready, edge.Reason));
            if (failed.Task is not null)
            {
                var reason = $"dependency_failed: task {IdText.Format(failed.On)} is {failed.State.ToString().ToUpperInvariant()}"
                    + (failed.Condition == DependencyCondition.Ready ? " without becoming ready" : string.Empty);
                transaction.Execute("UPDATE task SET state = 9, state_reason = $reason, finished_at = $now, rev = rev + 1 WHERE task_id = $id AND state = 2;",
                    ("$reason", Truncate(reason)), ("$now", now), ("$id", taskId));
                TaskSecrets.SchedulePurge(transaction, taskId, now, settings.SecretRetention);
                EmitTask(context, taskId, TaskState.WaitingDependency);
                continue;
            }

            if (dependencies.All(edge => DependencySatisfied(edge.Condition, edge.State, edge.Ready)))
            {
                transaction.Execute("UPDATE task SET state = 1, state_reason = NULL, queued_at = $now, rev = rev + 1 WHERE task_id = $id AND state = 2;",
                    ("$now", now), ("$id", taskId));
                EmitTask(context, taskId, TaskState.WaitingDependency);
            }
        }

        return 0;
    }

    /// <summary>True when a dependency's condition holds (SUCCEEDED: succeeded; FINISHED: any terminal state; READY: the service is ready).</summary>
    public static bool DependencySatisfied(DependencyCondition condition, TaskState state, bool ready) => condition switch
    {
        DependencyCondition.Finished => TaskRecords.IsTerminal(state),
        DependencyCondition.Ready => ready,
        _ => state == TaskState.Succeeded,
    };

    /// <summary>True when a dependency's condition can no longer hold.</summary>
    public static bool DependencyFailed(DependencyCondition condition, TaskState state, bool ready, string? reason) => condition switch
    {
        DependencyCondition.Finished => false,
        DependencyCondition.Ready => !ready && (TaskRecords.IsTerminal(state) || (reason?.StartsWith("readiness_timeout", StringComparison.Ordinal) ?? false)),
        _ => state is TaskState.Failed or TaskState.Cancelled or TaskState.Lost,
    };

    /// <summary>
    /// Records what the pass decided: each waiting task's blocking reason (<c>state_reason</c>, only when it changed), aging, the
    /// reservation, and the findings <c>TASK_INFEASIBLE</c> (at once) and <c>QUEUE_STARVATION</c> (after twice the starvation bound).
    /// </summary>
    private async Task RecordPassAsync(List<QueuedRow> rows, AdmissionInput input, AdmissionResult result)
    {
        var admitted = result.Admitted.Select(admission => admission.Task).ToHashSet(StringComparer.Ordinal);
        var reasons = new List<(QueuedRow Row, string Reason)>();
        foreach (var row in rows)
        {
            if (!admitted.Contains(row.Name) && result.Waiting.TryGetValue(row.Name, out var verdict) && verdict.Reason != row.StateReason)
            {
                reasons.Add((row, verdict.Reason));
            }
        }

        var infeasible = result.Feasibility.Where(pair => pair.Value == Feasibility.ExceedsCapacity && !_infeasibleRaised.Contains(pair.Key)).Select(pair => pair.Key).ToList();
        var starving = result.Starving.Where(task => !_starvingRaised.Contains(task)).ToList();
        _infeasibleRaised.IntersectWith(result.Feasibility.Where(pair => pair.Value == Feasibility.ExceedsCapacity).Select(pair => pair.Key));
        _starvingRaised.IntersectWith(result.Starving);
        var reservationChanged = input.Reservation?.Task != result.Reservation?.Task;
        if (reasons.Count == 0 && result.Aged.Count == 0 && !reservationChanged && infeasible.Count == 0 && starving.Count == 0)
        {
            return;
        }

        var byName = rows.ToDictionary(row => row.Name, StringComparer.Ordinal);
        var settings = Settings;
        await RecordAsync(context =>
        {
            var transaction = context.Transaction;
            var now = transaction.NowMicroseconds;
            var changed = new HashSet<string>(StringComparer.Ordinal);
            foreach (var (row, reason) in reasons)
            {
                if (transaction.Execute("UPDATE task SET state_reason = $reason, rev = rev + 1 WHERE task_id = $id AND state = 1;", ("$reason", reason), ("$id", row.TaskId)) == 1)
                {
                    changed.Add(row.Name);
                }
            }

            foreach (var (name, priority) in result.Aged)
            {
                var aging = byName[name];
                if (transaction.Execute(
                    "UPDATE task SET effective_priority = $priority, rev = rev + 1 WHERE task_id = $id AND state = 1 AND priority = $base AND effective_priority = $was AND coalesce(aged_at, -1) = $from;",
                    ("$priority", (int)priority), ("$id", aging.TaskId), ("$base", (int)aging.Priority), ("$was", (int)aging.Effective), ("$from", aging.AgedAt ?? -1)) == 1)
                {
                    changed.Add(name);
                }
            }

            if (reservationChanged)
            {
                transaction.Execute(
                    "UPDATE task SET reserved_for_large = 0, reservation_lapsed_at = CASE WHEN $lapsed = 1 THEN $now ELSE reservation_lapsed_at END, rev = rev + 1 WHERE reserved_for_large = 1;",
                    ("$lapsed", input.Reservation is { } old && result.Lapsed.Contains(old.Task) ? 1 : 0), ("$now", now));
                if (input.Reservation is { } previous && byName.TryGetValue(previous.Task, out var previousRow))
                {
                    changed.Add(previousRow.Name);
                }

                if (result.Reservation is { } taken && byName.TryGetValue(taken.Task, out var row))
                {
                    transaction.Execute("UPDATE task SET reserved_for_large = 1, reserved_since = $now, rev = rev + 1 WHERE task_id = $id AND state = 1;",
                        ("$now", now), ("$id", row.TaskId));
                    changed.Add(row.Name);
                    _log.Info("execution.reservation.taken", new LogField("task", row.Name), new LogField("reason", result.Waiting.GetValueOrDefault(row.Name)?.Reason ?? "-"));
                }

                if (input.Reservation is { } ended)
                {
                    _log.Info("execution.reservation.ended", new LogField("task", ended.Task), new LogField("lapsed", result.Lapsed.Contains(ended.Task)));
                }
            }

            foreach (var name in infeasible)
            {
                var row = byName[name];
                var request = Request(row, settings);
                ExecutionFindings.Raise(context, FindingKind.TaskInfeasible, Severity.Error, "task", row.TaskId, "A queued task can never run under the current reserve",
                    "Its memory request exceeds the managed share C_mem - R_mem or max_task_memory, so it is never admitted and never holds the large-task "
                    + "reservation (03 section 4). Lower the reserve, give a smaller hint, or cancel it.",
                    [("task", name), ("mem_expected_bytes", Text(request.Expected)), ("max_share_bytes", Text(result.MaxShareMemory)),
                        ("max_task_memory_bytes", Text(settings.MaxTaskMemory)), ("estimate_source", request.Source.ToString().ToUpperInvariant())]);
                _infeasibleRaised.Add(name);
            }

            foreach (var name in starving)
            {
                var row = byName[name];
                var verdict = result.Waiting.GetValueOrDefault(name);
                ExecutionFindings.Raise(context, FindingKind.QueueStarvation, Severity.Warning, "task", row.TaskId, "A task waited longer than twice the starvation bound",
                    "Consider a higher priority or another pool, closing applications that use the memory it waits for, or a smaller hint.",
                    [("task", name), ("waited_ms", Text((now - row.QueuedAt) / 1000)), ("blocking_reason", verdict?.Reason ?? "-"),
                        ("feasibility", Word(result.Feasibility.GetValueOrDefault(name)))]);
                _starvingRaised.Add(name);
            }

            foreach (var name in changed)
            {
                EmitTask(context, byName[name].TaskId, null);
            }

            return 0;
        }).ConfigureAwait(false);
    }

    /// <summary>The feasibility class as <c>AdmissionExplanation.feasibility</c> text.</summary>
    public static string Word(Feasibility feasibility) => feasibility switch
    {
        Feasibility.ExceedsBudget => "EXCEEDS_BUDGET",
        Feasibility.ExceedsCapacity => "EXCEEDS_CAPACITY",
        _ => "FEASIBLE",
    };

    private static string Text(long value) => value.ToString(CultureInfo.InvariantCulture);

    /// <summary>The DRR owner (03 section 4): the session, or the client user for non-agent submissions.</summary>
    public static string OwnerKey(ActorRef owner, byte[]? session)
    {
        ArgumentNullException.ThrowIfNull(owner);
        return session is { Length: 16 } ? "session:" + IdText.Format(session) : "user:" + (owner.HasOsUser ? owner.OsUser : string.Empty);
    }

    /// <summary>
    /// The effective keys at admission (03 section 4): the caller's (and the adapter's, unless the workspace's mode is SHARED), plus
    /// <c>ws:&lt;workspace&gt;</c> exclusively for <c>access = EXCLUSIVE</c> or the workspace's mode SERIAL, read now (the mode applies at
    /// admission, not at submission).
    /// </summary>
    private static List<HeldKey> EffectiveKeys(QueuedRow row, List<HeldKey> stored, IReadOnlyDictionary<string, WorkspaceInfo> workspaces)
    {
        var keys = stored.Where(key => key.Source != KeySource.Workspace).ToList();
        if (row.Workspace is not { } workspaceId)
        {
            return keys;
        }

        var workspace = IdText.Format(workspaceId);
        var mode = workspaces.TryGetValue(workspace, out var info) ? info.Mode : WorkspaceConcurrency.AdapterKeys;
        if (mode == WorkspaceConcurrency.Shared)
        {
            keys.RemoveAll(key => key.Source == KeySource.Adapter);
        }

        if (row.Spec.Concurrency?.Access == WorkspaceAccess.Exclusive || mode == WorkspaceConcurrency.Serial)
        {
            keys.Add(new HeldKey(ConcurrencyKey.ForWorkspace(workspace), KeyMode.Exclusive, KeySource.Workspace));
        }

        return keys;
    }

    private (long Cpu, long Expected, long Ceiling, EstimateSource Source) Request(QueuedRow row, ExecutionSettings settings)
    {
        if (_requests.TryGetValue(row.Name, out var cached) && cached.Digest.AsSpan().SequenceEqual(row.SpecDigest))
        {
            return cached.Request;
        }

        var request = settings.Request(row.Spec.Resources?.Hint, light: false);
        _requests[row.Name] = new CachedRequest(row.SpecDigest, request);
        return request;
    }

    private static int PoolRule(ExecutionSettings settings, string pool, long budgetCpu) =>
        Rule(settings, ParallelismScope.Pool, pool) is { } limit ? limit : int.MaxValue;

    /// <summary>The limit of a FIXED or DISABLED parallelism rule for a scope and target; AUTO (or none) is <see langword="null"/>.</summary>
    private static int? Rule(ExecutionSettings settings, ParallelismScope scope, string target)
    {
        var rule = settings.ParallelismRules.LastOrDefault(rule => rule.Scope == scope && string.Equals(rule.Target, target, StringComparison.OrdinalIgnoreCase));
        return rule?.Mode switch
        {
            ParallelismMode.Disabled => 1,
            ParallelismMode.Fixed => (int)Math.Clamp(rule.Fixed, 1u, 256u),
            _ => null,
        };
    }

    private static Dictionary<string, int> Rules(ExecutionSettings settings, ParallelismScope scope, IEnumerable<string?> targets, int fallback)
    {
        var limits = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var target in targets.OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var rule = Rule(settings, scope, target);
            var limit = rule is { } value && fallback > 0 ? Math.Min(value, fallback) : rule ?? (fallback > 0 ? fallback : null);
            if (limit is { } effective)
            {
                limits[target] = effective;
            }
        }

        return limits;
    }

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

    /// <summary><c>PausePool</c> and <c>ResumePool</c> (in the writer): admission from one pool, or from every pool, stops or resumes.</summary>
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

    /// <summary>After a pool pause or resume committed.</summary>
    public void PoolsChanged()
    {
        _workPending = true;
        Kick();
    }

    private static List<QueuedRow> QueuedRows(StoreReader reader)
    {
        using var command = reader.CreateCommand(
            """
            SELECT task_id, pool, priority, effective_priority, owner, owner_session_id, workspace_id, coalesce(queued_at, created_at), created_at,
                   reservation_lapsed_at, spec, spec_digest, state_reason, kind, title, aged_at
            FROM task WHERE state = 1 ORDER BY queued_at, created_at, task_id LIMIT $limit;
            """);
        command.Parameters.AddWithValue("$limit", MaxQueuedRead);
        using var rows = command.ExecuteReader();
        var result = new List<QueuedRow>();
        while (rows.Read())
        {
            var taskId = (byte[])rows.GetValue(0);
            result.Add(new QueuedRow(taskId, IdText.Format(taskId), rows.GetString(1), (Priority)rows.GetInt32(2), (Priority)rows.GetInt32(3),
                ActorRef.Parser.ParseFrom((byte[])rows.GetValue(4)), rows.IsDBNull(5) ? null : (byte[])rows.GetValue(5), rows.IsDBNull(6) ? null : (byte[])rows.GetValue(6),
                rows.GetInt64(7), rows.GetInt64(8), rows.IsDBNull(9) ? null : rows.GetInt64(9), TaskSpec.Parser.ParseFrom((byte[])rows.GetValue(10)),
                (byte[])rows.GetValue(11), rows.IsDBNull(12) ? null : rows.GetString(12), (TaskKind)rows.GetInt32(13), rows.GetString(14),
                rows.IsDBNull(15) ? null : rows.GetInt64(15)));
        }

        return result;
    }

    private static Dictionary<string, List<HeldKey>> QueuedKeys(StoreReader reader)
    {
        using var command = reader.CreateCommand(
            "SELECT k.task_id, k.concurrency_key, k.mode, k.source FROM task_concurrency_key k JOIN task t ON t.task_id = k.task_id WHERE t.state = 1;");
        using var rows = command.ExecuteReader();
        var result = new Dictionary<string, List<HeldKey>>(StringComparer.Ordinal);
        while (rows.Read())
        {
            if (!ConcurrencyKey.TryParse(rows.GetString(1), out var key, out _))
            {
                continue;
            }

            var task = IdText.Format((byte[])rows.GetValue(0));
            if (!result.TryGetValue(task, out var list))
            {
                result[task] = list = [];
            }

            list.Add(new HeldKey(key!, (KeyMode)rows.GetInt32(2), (KeySource)rows.GetInt32(3)));
        }

        return result;
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

    private static Dictionary<string, WorkspaceInfo> Workspaces(StoreReader reader)
    {
        using var command = reader.CreateCommand("SELECT workspace_id, root_path, concurrency_mode FROM workspace WHERE removed_at IS NULL AND kind IN (1, 2);");
        using var rows = command.ExecuteReader();
        var result = new Dictionary<string, WorkspaceInfo>(StringComparer.OrdinalIgnoreCase);
        while (rows.Read())
        {
            result[IdText.Format((byte[])rows.GetValue(0))] = new WorkspaceInfo(rows.GetString(1), (WorkspaceConcurrency)rows.GetInt32(2));
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
            var inside = string.Equals(directory, root, comparison)
                || directory.StartsWith(root + Path.DirectorySeparatorChar, comparison) || directory.StartsWith(root + Path.AltDirectorySeparatorChar, comparison);
            if (inside && root.Length > bestLength)
            {
                best = (byte[])rows.GetValue(0);
                bestLength = root.Length;
            }
        }

        return best;
    }

    private static Reservation? CurrentReservation(StoreReader reader)
    {
        using var command = reader.CreateCommand("SELECT task_id, reserved_since FROM task WHERE reserved_for_large = 1 AND state = 1 ORDER BY reserved_since LIMIT 1;");
        using var rows = command.ExecuteReader();
        return rows.Read() ? new Reservation(IdText.Format((byte[])rows.GetValue(0)), rows.GetInt64(1)) : null;
    }

    // ---------------------------------------------------------------------------------------------------------------- start

    /// <summary>
    /// Starts an admitted task: in one command the attempt is created with its request and the task becomes RUNNING with its effective keys
    /// held (03 section 4: the workspace key from the mode in force now); the tool-level setting is chosen from the CPU grant (03 section 5.3).
    /// </summary>
    private async Task StartAttemptAsync(QueuedRow queued, Admission grant, (long Cpu, long Expected, long Ceiling, EstimateSource Source) request,
        IReadOnlyList<HeldKey> keys, ExecutionSettings settings)
    {
        var platform = Platform!;
        var taskId = queued.TaskId;
        var attemptId = StoreIds.NewUuid7(_clock);
        var name = IdText.Format(attemptId);
        var files = new AttemptFiles(_dataRoot, name);
        var tool = queued.Spec.Command?.FormCase == CommandSpec.FormOneofCase.Argv ? Tools?.Apply(queued.Spec, grant.CpuGrant) : null;
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
                var now = transaction.NowMicroseconds;
                transaction.Execute(
                    """
                    INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, container_name, boot_identity, request_cpu_millicores,
                                         request_mem_expected_bytes, request_mem_ceiling_bytes, request_source, accounted_mem_bytes, cpu_weight, tool, operation,
                                         tool_parallelism, unenforced, created_at, rev)
                    VALUES ($id, $task, $number, 1, 3, $node, $container, $boot, $cpu, $expected, $ceiling, $source, $expected, $weight, $tool, $operation,
                            $parallelism, $unenforced, $now, 0);
                    """,
                    ("$id", attemptId), ("$task", taskId), ("$number", number), ("$node", _store.Metadata.NodeId.ToArray()),
                    ("$container", platform.ContainerName(NodeName, name)), ("$boot", _store.Metadata.BootIdentity), ("$cpu", Math.Max(1, request.Cpu)),
                    ("$expected", request.Expected), ("$ceiling", request.Ceiling), ("$source", (int)request.Source), ("$weight", ExecutionSettings.Weight(row.Priority)),
                    ("$tool", tool?.Tool), ("$operation", tool?.Operation), ("$parallelism", tool?.Parallelism), ("$unenforced", Unenforced ? 1 : 0), ("$now", now));
                foreach (var key in keys)
                {
                    transaction.Execute(
                        """
                        INSERT INTO task_concurrency_key (task_id, concurrency_key, mode, source, released_at) VALUES ($task, $key, $mode, $source, NULL)
                        ON CONFLICT (task_id, concurrency_key) DO UPDATE SET mode = $mode, source = $source, released_at = NULL;
                        """,
                        ("$task", taskId), ("$key", key.Key.Text), ("$mode", (int)key.Mode), ("$source", (int)key.Source));
                }

                transaction.Execute(
                    """
                    UPDATE task SET state = 4, state_reason = NULL, current_attempt_id = $attempt, attempt_count = $number, started_at = coalesce(started_at, $now),
                                    reserved_for_large = 0, ready = 0, rev = rev + 1
                    WHERE task_id = $id;
                    """,
                    ("$attempt", attemptId), ("$number", number), ("$now", now), ("$id", taskId));
                EmitAttempt(context, attemptId, AttemptState.Created);
                EmitTask(context, taskId, TaskState.Queued);
                return new Admitted(row, number, request.Expected, request.Ceiling);
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
                StopSignal = spec.Resources is { HasStopSignal: true } stopResources ? stopResources.StopSignal : null,
                Priority = admitted.Row.Priority,
                Preemptible = spec.Resources?.Preemptible == true,
                Pausable = spec.Resources?.Pausable == true,
                WorkingDirectory = spec.WorkingDirectory,
                Pool = queued.Pool,
                Session = queued.Session is { } session ? IdText.Format(session) : null,
                Workspace = queued.Workspace is { } workspace ? IdText.Format(workspace) : null,
                MemExpected = request.Expected,
                MemCeiling = request.Ceiling,
                CpuGrant = grant.CpuGrant,
                Readiness = ServiceReadiness.For(spec),
            };
            attempt.Keys.AddRange(keys);
            if (spec.Resources is { HasCancelGraceMs: true } resources)
            {
                attempt.CancelGrace = TimeSpan.FromMilliseconds(resources.CancelGraceMs);
            }

            _running[name] = attempt;

            // A cancel committed between the admission and this registration found no running attempt to stop and only marked the attempt
            // STOPPING: it is taken over here, and the launch applies the forced phase once the handle exists (the stop is never lost).
            if (_store.Read(reader => Convert.ToInt32(reader.Scalar("SELECT state FROM attempt WHERE attempt_id = $id;", ("$id", attemptId)), CultureInfo.InvariantCulture))
                == (int)AttemptState.Stopping)
            {
                lock (attempt)
                {
                    attempt.StopReason ??= TerminationReason.Cancelled;
                }
            }

            _log.Info("execution.admitted", new LogField("attempt", name), new LogField("task", queued.Name), new LogField("pool", queued.Pool),
                new LogField("cpuGrant", grant.CpuGrant), new LogField("memExpected", request.Expected),
                new LogField("accountedAfter", _running.Values.Sum(running => running.AccountedMemory)), new LogField("budgetMemory", Queue?.BudgetMemory ?? -1),
                new LogField("toolParallelism", tool?.Parallelism ?? 0));
            Launch(attempt, admitted, platform, settings, tool);
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
        _workPending = true;
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
            }).ContinueWith(_ => Kick(), TaskScheduler.Default);
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
            }).ContinueWith(_ => Kick(), TaskScheduler.Default);
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
        }).ContinueWith(_ => Kick(), TaskScheduler.Default);
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
    /// calls are posted to <see cref="PlatformCalls"/>): the root limits follow the measured budgets with hysteresis (more than 5% of capacity,
    /// at most every 10 s) and shrink at once on entering Tight; admission is woken when the budgets or the level changed while work waits;
    /// at Pressure the freeze (Linux) or the requeue (Windows) applies (at Critical only the monitor's shedding acts); after 30 s at Normal the
    /// frozen attempts thaw in priority order.
    /// </summary>
    private void SchedulerRespond(PressureLevel level, PressureLevel previous, ResourceState state)
    {
        var settings = Settings;
        UpdateRootLimits(settings, state, force: level >= PressureLevel.Tight && previous < PressureLevel.Tight);
        var (kickedCpu, kickedMemory, kickedLevel) = _kickedAt;
        if (_workPending && (level != kickedLevel || Math.Abs(state.BudgetCpu - kickedCpu) > settings.CapacityCpu / 20
            || Math.Abs(state.BudgetMemory - kickedMemory) > settings.CapacityMemory / 20))
        {
            _kickedAt = (state.BudgetCpu, state.BudgetMemory, level);
            Kick();
        }

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

    /// <summary>Applies root limits from <c>B</c> (03 section 5.1) when they changed by more than 5% of capacity and 10 s passed, or at once when forced.</summary>
    private void UpdateRootLimits(ExecutionSettings settings, ResourceState state, bool force)
    {
        if (Platform is not { } platform)
        {
            return;
        }

        RootLimits limits;
        lock (_rootGate)
        {
            var (cpu, memory) = _rootBudget.Cpu < 0 ? (settings.BudgetCpu, settings.ManagedMemory) : _rootBudget;
            var changed = Math.Abs(state.BudgetCpu - cpu) > settings.CapacityCpu / 20 || Math.Abs(state.BudgetMemory - memory) > settings.CapacityMemory / 20;
            var due = _rootAppliedAt == long.MinValue || _clock.GetElapsedTime(_rootAppliedAt) >= RootLimitInterval;
            if (!(force ? state.BudgetCpu != cpu || state.BudgetMemory != memory : changed && due))
            {
                return;
            }

            _rootBudget = (state.BudgetCpu, state.BudgetMemory);
            _rootAppliedAt = _clock.GetTimestamp();
            limits = settings.RootLimits(state.BudgetCpu, state.BudgetMemory);
            AppliedRootLimits = limits;
        }

        _log.Info("execution.root_limits", new LogField("cpuRate", limits.CpuRate), new LogField("memoryHigh", limits.NotificationBytes),
            new LogField("budgetCpu", state.BudgetCpu), new LogField("budgetMemory", state.BudgetMemory), new LogField("forced", force));
        PlatformCalls.Post("root-limits", () =>
        {
            platform.UpdateRootLimits(limits);
            RootLimitsApplied?.Invoke(limits);
        });
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
            if (attempt.StopReason is not null)
            {
                return;
            }

            attempt.StopDetail = detail;
        }

        _log.Warning("execution.requeued", new LogField("attempt", attempt.Name), new LogField("priority", attempt.Priority), new LogField("trigger", state.PressureTrigger));
        _ = RecordAsync(context =>
        {
            var transaction = context.Transaction;
            var previous = TaskRecords.GetAttemptRow(transaction, attempt.AttemptId);
            if (transaction.Execute("UPDATE attempt SET state = 7, rev = rev + 1 WHERE attempt_id = $id AND state IN (3, 4, 5, 6);", ("$id", attempt.AttemptId)) == 1
                && previous is not null)
            {
                EmitAttempt(context, attempt.AttemptId, previous.State);
            }

            transaction.Execute("UPDATE task SET state_reason = $reason, rev = rev + 1 WHERE task_id = $id;", ("$reason", Truncate(detail)), ("$id", attempt.TaskId));
            EmitTask(context, attempt.TaskId, null);
            return 0;
        });
        _ = Task.Run(() => Stop(attempt.Name, TerminationReason.Preempted, null, graceful: true));
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
        _workPending = true;
        return (new QueueInfo { Position = TaskRecords.QueuePosition(transaction, taskId) }, null);
    }
    private sealed record CachedRequest(byte[] Digest, (long Cpu, long Expected, long Ceiling, EstimateSource Source) Request);

    private sealed record WorkspaceInfo(string Root, WorkspaceConcurrency Mode);

    /// <summary>A queued task row as the admission pass reads it.</summary>
    /// <param name="AgedAt"><c>aged_at</c>: when SetTaskPriority last changed the waiting task's class (its aging restarts there).</param>
    private sealed record QueuedRow(byte[] TaskId, string Name, string Pool, Priority Priority, Priority Effective, ActorRef Owner, byte[]? Session, byte[]? Workspace,
        long QueuedAt, long CreatedAt, long? LapsedAt, TaskSpec Spec, byte[] SpecDigest, string? StateReason, TaskKind Kind, string Title, long? AgedAt)
    {
        /// <summary>The start of the aging clock: the later of the queueing and the last SetTaskPriority.</summary>
        public long AgingFrom => AgedAt is { } changed ? Math.Max(QueuedAt, changed) : QueuedAt;
    }
}
