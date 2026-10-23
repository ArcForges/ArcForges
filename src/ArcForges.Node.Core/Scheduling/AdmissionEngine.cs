// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Scheduling;

/// <summary>The blocking reasons of <c>QueueInfo.blocking_reason</c> (tasks.proto) that admission produces.</summary>
public static class BlockingReasons
{
    /// <summary>Memory is short: <c>mem_expected &gt; avail_mem</c>, or memory pressure restricts admission.</summary>
    public const string BudgetMemory = "budget_memory";

    /// <summary>CPU is short: <c>cpu_load + c &gt; overcommit_cpu x B_cpu</c>.</summary>
    public const string BudgetCpu = "budget_cpu";

    /// <summary>The task fits only if unmanaged load falls (03 section 4 feasibility).</summary>
    public const string ExceedsBudget = "exceeds_budget";

    /// <summary>The task can never run under the current reserve.</summary>
    public const string ExceedsCapacity = "exceeds_capacity";

    /// <summary>A key conflicts with keys running attempts hold.</summary>
    public const string ExclusiveKey = "exclusive_key";

    /// <summary>The pool's (or the workspace's or session's) parallelism limit is reached, or the pool is paused.</summary>
    public const string PoolLimit = "pool_limit";

    /// <summary><c>global_max_running</c> (or a global parallelism rule) is reached.</summary>
    public const string GlobalLimit = "global_limit";

    /// <summary>A dependency's condition does not hold yet.</summary>
    public const string Dependency = "dependency";

    /// <summary>The large-task reservation holds the task back.</summary>
    public const string LargeTaskReserved = "large_task_reserved";
}

/// <summary>The memory feasibility classes of 03 section 4.</summary>
public enum Feasibility
{
    /// <summary><c>mem_expected &lt;= idle_budget_mem</c>.</summary>
    Feasible,

    /// <summary><c>idle_budget_mem &lt; mem_expected &lt;= max_share_mem</c>.</summary>
    ExceedsBudget,

    /// <summary><c>mem_expected &gt; max_share_mem</c> or <c>&gt; max_task_memory</c>.</summary>
    ExceedsCapacity,
}

/// <summary>A pool as admission sees it: its weight, its effective parallelism limit and whether it is paused.</summary>
/// <param name="Name">The pool name.</param>
/// <param name="Weight">The round-robin weight (1..100).</param>
/// <param name="MaxParallel">The effective <c>max_parallel</c> (AUTO already resolved against <c>B_cpu</c>).</param>
/// <param name="Paused">Admission from the pool is paused (<c>PausePool</c>).</param>
public sealed record PoolLimits(string Name, int Weight, int MaxParallel, bool Paused);

/// <summary>A queued task as admission sees it (03 sections 3 and 4). Times in microseconds of the store clock.</summary>
public sealed class QueuedCandidate
{
    /// <summary>The task (base32).</summary>
    public required string Task { get; init; }

    /// <summary>The pool.</summary>
    public required string Pool { get; init; }

    /// <summary>The submitted priority class.</summary>
    public Priority BasePriority { get; init; } = Priority.Normal;

    /// <summary>The effective class (after aging).</summary>
    public Priority EffectivePriority { get; init; } = Priority.Normal;

    /// <summary>The deficit-round-robin owner: the session, or the client user for non-agent submissions.</summary>
    public required string Owner { get; init; }

    /// <summary>The owner's weight (default 1).</summary>
    public int OwnerWeight { get; init; } = 1;

    /// <summary>The session (for a session parallelism rule), or <see langword="null"/>.</summary>
    public string? Session { get; init; }

    /// <summary>The workspace (for a workspace parallelism rule), or <see langword="null"/>.</summary>
    public string? Workspace { get; init; }

    /// <summary>When the task was queued.</summary>
    public long QueuedAt { get; init; }

    /// <summary>
    /// When its aging clock started, or <see langword="null"/> for <see cref="QueuedAt"/>: SetTaskPriority restarts it (persisted in
    /// <c>task.aged_at</c>), so a changed class ages from the change, not from the queueing.
    /// </summary>
    public long? AgingFrom { get; init; }

    /// <summary>A tie-breaker of FIFO order (the creation time).</summary>
    public long Sequence { get; init; }

    /// <summary><c>cpu_demand</c> in millicores.</summary>
    public long Cpu { get; init; }

    /// <summary><c>mem_expected</c>.</summary>
    public long MemExpected { get; init; }

    /// <summary>The effective keys the task would hold.</summary>
    public IReadOnlyList<HeldKey> Keys { get; init; } = [];

    /// <summary>A light routed command (08 section 4.1): outside pool limits and the reservation.</summary>
    public bool Light { get; init; }

    /// <summary>When its reservation lapsed, or <see langword="null"/>.</summary>
    public long? LapsedAt { get; init; }
}

/// <summary>A running attempt as admission accounts it.</summary>
/// <param name="Task">The task (base32).</param>
/// <param name="Pool">Its pool.</param>
/// <param name="Session">Its session, or <see langword="null"/>.</param>
/// <param name="Workspace">Its workspace, or <see langword="null"/>.</param>
/// <param name="AccountedMemory"><c>max(mem_expected, peak_observed)</c>.</param>
/// <param name="CpuGranted">The CPU it was granted.</param>
/// <param name="Keys">The keys it still holds (released keys are left out).</param>
/// <param name="Light">A light routed command (not counted against its pool).</param>
public sealed record RunningLoad(string Task, string Pool, string? Session, string? Workspace, long AccountedMemory, long CpuGranted, IReadOnlyList<HeldKey> Keys,
    bool Light = false);

/// <summary>The large-task reservation in force (persisted in <c>task.reserved_for_large</c> and <c>reserved_since</c>).</summary>
/// <param name="Task">The task holding it.</param>
/// <param name="Since">When it was taken.</param>
public sealed record Reservation(string Task, long Since);

/// <summary>What one admission pass works with (03 sections 2 and 4). Memory in bytes, CPU in millicores, times in microseconds.</summary>
public sealed class AdmissionInput
{
    /// <summary>Now.</summary>
    public long Now { get; init; }

    /// <summary><c>B_cpu</c>.</summary>
    public long BudgetCpu { get; init; }

    /// <summary><c>B_mem</c>.</summary>
    public long BudgetMemory { get; init; }

    /// <summary><c>C_mem</c>.</summary>
    public long CapacityMemory { get; init; }

    /// <summary><c>R_mem</c>.</summary>
    public long ReserveMemory { get; init; }

    /// <summary><c>U_mem</c> (smoothed).</summary>
    public long UnmanagedMemory { get; init; }

    /// <summary><c>max_task_memory</c>.</summary>
    public long MaxTaskMemory { get; init; } = long.MaxValue;

    /// <summary><c>overcommit_cpu</c>.</summary>
    public double OvercommitCpu { get; init; } = 1.5;

    /// <summary><c>global_max_running</c>.</summary>
    public int GlobalMaxRunning { get; init; } = 64;

    /// <summary>A global parallelism rule (FIXED n, DISABLED 1), or <see langword="null"/>.</summary>
    public int? GlobalParallelism { get; init; }

    /// <summary>Workspace parallelism rules (workspace to limit).</summary>
    public IReadOnlyDictionary<string, int> WorkspaceParallelism { get; init; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Session parallelism rules (session to limit).</summary>
    public IReadOnlyDictionary<string, int> SessionParallelism { get; init; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The pressure level in force (03 section 7: Tight and Pressure admit only INTERACTIVE; Critical admits nothing).</summary>
    public PressureLevel Pressure { get; init; } = PressureLevel.Normal;

    /// <summary><c>starvation_bound</c> (aging).</summary>
    public long StarvationBound { get; init; } = 10L * 60 * 1_000_000;

    /// <summary><c>large_task_bypass</c>.</summary>
    public long LargeTaskBypass { get; init; } = 2L * 60 * 1_000_000;

    /// <summary><c>large_task_reservation_max</c>.</summary>
    public long ReservationMax { get; init; } = 30L * 60 * 1_000_000;

    /// <summary>The pools (a queued task's pool missing here is admitted as a weight-1 pool limited by <c>B_cpu</c>).</summary>
    public IReadOnlyList<PoolLimits> Pools { get; init; } = [];

    /// <summary>The running attempts.</summary>
    public IReadOnlyList<RunningLoad> Running { get; init; } = [];

    /// <summary>The queued tasks.</summary>
    public IReadOnlyList<QueuedCandidate> Queued { get; init; } = [];

    /// <summary>The reservation in force, or <see langword="null"/>.</summary>
    public Reservation? Reservation { get; init; }

    /// <summary>
    /// Backfill (03 section 4): an <c>ACTIVE DURATION</c> p90 from operational memory for a task, or <see langword="null"/> without a fact
    /// (then there is no backfill).
    /// </summary>
    public Func<QueuedCandidate, long?>? Duration { get; init; }

    /// <summary>The reservation's estimated start (the drain estimate from the running attempts' own facts), or <see langword="null"/>.</summary>
    public long? ReservationStart { get; init; }

    /// <summary>Resolves a workspace to its root path (tool keys scoped by a path inside it).</summary>
    public Func<string, string?>? WorkspaceRoot { get; init; }
}

/// <summary>A task admission chose: start it with this grant.</summary>
/// <param name="Task">The task.</param>
/// <param name="CpuGrant">The CPU grant: <c>min(cpu_demand, B_cpu)</c> (03 section 4: CPU is compressible).</param>
/// <param name="MemExpected">Its <c>mem_expected</c>, counted against <c>avail_mem</c>.</param>
public sealed record Admission(string Task, long CpuGrant, long MemExpected);

/// <summary>Why a queued task waits, with the numbers <c>ExplainTask</c> shows.</summary>
/// <param name="Task">The task.</param>
/// <param name="Reason">The blocking reason (<see cref="BlockingReasons"/>).</param>
/// <param name="Feasibility">Its memory feasibility class.</param>
/// <param name="Position">Its 1-based position in its pool's admission order.</param>
/// <param name="BlockingKeys">Exclusive keys held by running tasks that conflict with its keys.</param>
/// <param name="Holders">The tasks holding them.</param>
/// <param name="Text">A sentence for people.</param>
public sealed record Verdict(string Task, string Reason, Feasibility Feasibility, int Position, IReadOnlyList<string> BlockingKeys, IReadOnlyList<string> Holders,
    string Text);

/// <summary>The outcome of one admission pass.</summary>
public sealed class AdmissionResult
{
    /// <summary>The tasks to start, in admission order.</summary>
    public List<Admission> Admitted { get; } = [];

    /// <summary>Why every other queued task waits.</summary>
    public Dictionary<string, Verdict> Waiting { get; } = new(StringComparer.Ordinal);

    /// <summary>Tasks whose effective class aging raised (task to new class).</summary>
    public Dictionary<string, Priority> Aged { get; } = new(StringComparer.Ordinal);

    /// <summary>The feasibility of every queued task.</summary>
    public Dictionary<string, Feasibility> Feasibility { get; } = new(StringComparer.Ordinal);

    /// <summary>The reservation after the pass, or <see langword="null"/>.</summary>
    public Reservation? Reservation { get; set; }

    /// <summary>Tasks whose reservation lapsed in this pass.</summary>
    public List<string> Lapsed { get; } = [];

    /// <summary>Queued tasks that waited longer than twice the starvation bound (<c>QUEUE_STARVATION</c>).</summary>
    public List<string> Starving { get; } = [];

    /// <summary>Every queued task in the order the pass considered it (the admission order of <c>GetQueue</c>).</summary>
    public List<string> Order { get; } = [];

    /// <summary><c>avail_mem</c> after the pass.</summary>
    public long AvailableMemory { get; set; }

    /// <summary><c>cpu_load</c> after the pass.</summary>
    public long CpuLoad { get; set; }

    /// <summary><c>cpu_limit = overcommit_cpu x B_cpu</c>.</summary>
    public long CpuLimit { get; set; }

    /// <summary>The sum of accounted memory after the pass.</summary>
    public long AccountedMemory { get; set; }

    /// <summary><c>idle_budget_mem</c>.</summary>
    public long IdleBudgetMemory { get; set; }

    /// <summary><c>max_share_mem</c>.</summary>
    public long MaxShareMemory { get; set; }

    /// <summary>Running attempts per pool after the pass (light commands excluded).</summary>
    public Dictionary<string, int> PoolRunning { get; } = new(StringComparer.Ordinal);

    /// <summary>All running attempts after the pass.</summary>
    public int GlobalRunning { get; set; }
}

/// <summary>
/// The admission algorithm of 03 section 4 (R-RES-005, R-EXE-013, R-EXE-014, R-EXE-019): pools in weighted round-robin order; within a pool
/// the effective priority class strictly, deficit round robin across owners within a class and FIFO within an owner; aging one class per
/// <c>starvation_bound</c> waited, up to HIGH; CPU demand clamped to <c>B_cpu</c>; memory never overcommitted (<c>avail_mem</c> from
/// accounted memory); the feasibility classes; keys; one bounded large-task reservation with backfill and lapse; light routed commands
/// outside pool limits and the reservation; the pressure restrictions of 03 section 7. The engine keeps the round-robin state between
/// passes (it is not persisted: a restarted node starts the rotation afresh) and is not thread-safe: one admission loop drives it.
/// </summary>
public sealed class AdmissionEngine
{
    private readonly Dictionary<(string Pool, Priority Class), DeficitRing> _rings = [];
    private readonly Dictionary<string, long> _poolCredit = new(StringComparer.Ordinal);

    /// <summary>The memory feasibility class of a request (03 section 4).</summary>
    public static Feasibility Classify(long memExpected, long maxShareMemory, long idleBudgetMemory, long maxTaskMemory) =>
        memExpected > Math.Min(maxShareMemory, maxTaskMemory) ? Scheduling.Feasibility.ExceedsCapacity
        : memExpected > idleBudgetMemory ? Scheduling.Feasibility.ExceedsBudget
        : Scheduling.Feasibility.Feasible;

    /// <summary>
    /// The effective class of a task whose aging clock started at <paramref name="queuedAt"/> (its queueing, or the last SetTaskPriority)
    /// in <paramref name="basePriority"/>: one class per bound waited, up to HIGH.
    /// </summary>
    public static Priority Aged(Priority basePriority, Priority effective, long queuedAt, long now, long bound)
    {
        if (basePriority <= Priority.High || bound <= 0)
        {
            return effective == Priority.Unspecified ? basePriority : effective;
        }

        var steps = (int)Math.Min(4, Math.Max(0, (now - queuedAt) / bound));
        var target = (Priority)Math.Max((int)Priority.High, (int)basePriority - steps);
        var current = effective == Priority.Unspecified ? basePriority : effective;
        return (Priority)Math.Min((int)current, (int)target);
    }

    /// <summary>When aging next raises the class, or <see langword="null"/> once it is HIGH or above.</summary>
    public static long? AgesAt(Priority effective, long queuedAt, long now, long bound)
    {
        if (effective <= Priority.High || bound <= 0)
        {
            return null;
        }

        var steps = Math.Max(0, (now - queuedAt) / bound);
        return queuedAt + ((steps + 1) * bound);
    }

    /// <summary>Runs one pass.</summary>
    public AdmissionResult Pass(AdmissionInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var result = new AdmissionResult();
        var now = input.Now;
        var maxShare = input.CapacityMemory - input.ReserveMemory;
        var idleBudget = input.CapacityMemory - input.ReserveMemory - input.UnmanagedMemory;
        result.MaxShareMemory = maxShare;
        result.IdleBudgetMemory = idleBudget;

        // Aging and feasibility are properties of each task, independent of the order: TASK_INFEASIBLE is raised at once.
        var effective = new Dictionary<string, Priority>(StringComparer.Ordinal);
        foreach (var task in input.Queued)
        {
            var aged = Aged(task.BasePriority, task.EffectivePriority, task.AgingFrom ?? task.QueuedAt, now, input.StarvationBound);
            effective[task.Task] = aged;
            if (aged != task.EffectivePriority)
            {
                result.Aged[task.Task] = aged;
            }

            result.Feasibility[task.Task] = Classify(task.MemExpected, maxShare, idleBudget, input.MaxTaskMemory);
            if (input.StarvationBound > 0 && now - task.QueuedAt > 2 * input.StarvationBound)
            {
                result.Starving.Add(task.Task);
            }
        }

        // Accounting of the running attempts.
        var accounted = input.Running.Sum(running => running.AccountedMemory);
        var availMem = input.BudgetMemory - accounted;
        var cpuLoad = input.Running.Sum(running => running.CpuGranted);
        var cpuLimit = (long)(input.OvercommitCpu * input.BudgetCpu);
        var globalRunning = input.Running.Count;
        var poolRunning = new Dictionary<string, int>(StringComparer.Ordinal);
        var workspaceRunning = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var sessionRunning = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var holders = new KeyHolders(input.WorkspaceRoot);
        foreach (var running in input.Running)
        {
            Count(running.Light ? null : running.Pool, running.Workspace, running.Session, poolRunning, workspaceRunning, sessionRunning);
            holders.Add(running.Task, running.Keys);
        }

        // The reservation: it lapses after large_task_reservation_max, or once its task is no longer feasible.
        var byTask = input.Queued.ToDictionary(task => task.Task, StringComparer.Ordinal);
        var reservation = input.Reservation;
        if (reservation is not null)
        {
            if (!byTask.TryGetValue(reservation.Task, out _))
            {
                reservation = null;
            }
            else if (now - reservation.Since >= input.ReservationMax || result.Feasibility[reservation.Task] != Scheduling.Feasibility.Feasible)
            {
                result.Lapsed.Add(reservation.Task);
                reservation = null;
            }
        }

        // The queues: per pool, per effective class, per owner in FIFO order.
        var pools = input.Pools.ToDictionary(pool => pool.Name, StringComparer.Ordinal);
        foreach (var task in input.Queued.Where(task => !pools.ContainsKey(task.Pool)))
        {
            pools[task.Pool] = new PoolLimits(task.Pool, 1, (int)Math.Max(1, input.BudgetCpu / 1000), Paused: false);
        }

        var queues = new Dictionary<string, PoolQueue>(StringComparer.Ordinal);
        foreach (var task in input.Queued.OrderBy(task => task.QueuedAt).ThenBy(task => task.Sequence).ThenBy(task => task.Task, StringComparer.Ordinal))
        {
            if (!queues.TryGetValue(task.Pool, out var queue))
            {
                queues[task.Pool] = queue = new PoolQueue(task.Pool);
            }

            queue.Add(task, effective[task.Task]);
        }

        foreach (var queue in queues.Values)
        {
            foreach (var (priority, owners) in queue.Classes)
            {
                Ring(queue.Pool, priority).Sync(owners.Keys);
            }
        }

        foreach (var key in _rings.Keys.Where(key => !queues.TryGetValue(key.Pool, out var queue) || !queue.Classes.ContainsKey(key.Class)).ToList())
        {
            _rings.Remove(key);
        }

        // The reservation is taken before the walk (03 section 4: "the longest-waiting qualifying task holds it"): among the tasks that
        // waited longer than large_task_bypass, pass every admission gate and do not fit beside the running work, the one queued first.
        if (reservation is null)
        {
            var qualifying = input.Queued
                .Where(candidate => !candidate.Light && now - candidate.QueuedAt > input.LargeTaskBypass && !result.Lapsed.Contains(candidate.Task)
                    && (candidate.LapsedAt is not { } lapsed || now - lapsed >= input.ReservationMax)
                    && Gate(candidate, effective[candidate.Task], pools[candidate.Pool]) is null
                    && Short(candidate))
                .OrderBy(candidate => candidate.QueuedAt).ThenBy(candidate => candidate.Sequence).ThenBy(candidate => candidate.Task, StringComparer.Ordinal)
                .FirstOrDefault();
            if (qualifying is not null)
            {
                reservation = new Reservation(qualifying.Task, now);
            }
        }

        // The walk: the pool with the most round-robin credit offers its next candidate (strict class, then the deficit round robin);
        // an admission moves the pool's credit and the owner's deficit, a refusal only marks the candidate decided for this pass. A
        // waiting task's position counts only the tasks of its pool still waiting before it (not those admitted earlier in the pass).
        var positions = new Dictionary<string, int>(StringComparer.Ordinal);
        while (true)
        {
            var active = queues.Values.Where(queue => queue.HasUndecided).ToList();
            if (active.Count == 0)
            {
                break;
            }

            var pool = active.OrderByDescending(queue => Credit(queue.Pool) + pools[queue.Pool].Weight).ThenBy(queue => queue.Pool, StringComparer.Ordinal).First();
            var (candidate, priority, commit) = pool.Next(this);
            pool.Decided.Add(candidate.Task);
            result.Order.Add(candidate.Task);
            var position = positions.GetValueOrDefault(pool.Pool) + 1;
            var limits = pools[pool.Pool];
            var feasibility = result.Feasibility[candidate.Task];
            var clamped = Math.Min(candidate.Cpu, Math.Max(0, input.BudgetCpu));
            Verdict Wait(string reason, string text, KeyConflict? conflict = null) =>
                new(candidate.Task, reason, feasibility, position, conflict?.Keys ?? [], conflict?.Holders ?? [], text);

            Verdict? verdict = Gate(candidate, priority, limits) is { } gate ? Wait(gate.Reason, gate.Text, gate.Conflict) : null;
            if (verdict is null && reservation is not null && reservation.Task != candidate.Task && !candidate.Light && priority >= effective[reservation.Task]
                && !Backfills(input, candidate) && Delays(byTask[reservation.Task], candidate, clamped, availMem, cpuLoad, cpuLimit, input.BudgetCpu))
            {
                verdict = Wait(BlockingReasons.LargeTaskReserved, $"the large-task reservation of task {reservation.Task} holds back tasks of its class and below");
            }
            else if (verdict is null)
            {
                var memoryShort = candidate.MemExpected > availMem;
                var cpuShort = cpuLoad + clamped > cpuLimit;
                if (memoryShort || cpuShort)
                {
                    verdict = memoryShort
                        ? Wait(BlockingReasons.BudgetMemory, string.Create(CultureInfo.InvariantCulture,
                            $"mem_expected {candidate.MemExpected} B exceeds avail_mem {Math.Max(0, availMem)} B (B_mem {input.BudgetMemory} B, accounted {accounted} B)"))
                        : Wait(BlockingReasons.BudgetCpu, string.Create(CultureInfo.InvariantCulture,
                            $"cpu_load {cpuLoad} + grant {clamped} exceeds cpu_limit {cpuLimit} millicores"));
                }
            }

            if (verdict is not null)
            {
                positions[pool.Pool] = position;
                result.Waiting[candidate.Task] = verdict;
                continue;
            }

            commit();
            _poolCredit[pool.Pool] = Credit(pool.Pool);
            var total = active.Sum(queue => pools[queue.Pool].Weight);
            foreach (var queue in active)
            {
                _poolCredit[queue.Pool] = Credit(queue.Pool) + pools[queue.Pool].Weight;
            }

            _poolCredit[pool.Pool] -= total;
            result.Admitted.Add(new Admission(candidate.Task, clamped, candidate.MemExpected));
            availMem -= candidate.MemExpected;
            accounted += candidate.MemExpected;
            cpuLoad += clamped;
            globalRunning++;
            Count(candidate.Light ? null : candidate.Pool, candidate.Workspace, candidate.Session, poolRunning, workspaceRunning, sessionRunning);
            holders.Add(candidate.Task, candidate.Keys);
            if (reservation?.Task == candidate.Task)
            {
                reservation = null;
            }
        }

        foreach (var pool in _poolCredit.Keys.Where(pool => !queues.ContainsKey(pool)).ToList())
        {
            _poolCredit.Remove(pool);
        }

        result.Reservation = reservation;
        result.AvailableMemory = availMem;
        result.CpuLoad = cpuLoad;
        result.CpuLimit = cpuLimit;
        result.AccountedMemory = accounted;
        result.GlobalRunning = globalRunning;
        foreach (var (pool, count) in poolRunning)
        {
            result.PoolRunning[pool] = count;
        }

        return result;

        // The admission gates before the reservation and the resources (feasibility, a paused pool, pressure, the global, pool, workspace
        // and session limits, keys), against the state of the walk so far; null when the candidate passes them all.
        (string Reason, string Text, KeyConflict? Conflict)? Gate(QueuedCandidate candidate, Priority priority, PoolLimits limits)
        {
            var feasibility = result.Feasibility[candidate.Task];
            if (feasibility == Scheduling.Feasibility.ExceedsCapacity)
            {
                return (BlockingReasons.ExceedsCapacity, string.Create(CultureInfo.InvariantCulture,
                    $"mem_expected {candidate.MemExpected} B exceeds the managed share {maxShare} B or max_task_memory {input.MaxTaskMemory} B; it can never run under the current reserve"), null);
            }

            if (feasibility == Scheduling.Feasibility.ExceedsBudget)
            {
                return (BlockingReasons.ExceedsBudget, string.Create(CultureInfo.InvariantCulture,
                    $"mem_expected {candidate.MemExpected} B exceeds the idle budget {idleBudget} B; it fits only if unmanaged memory ({input.UnmanagedMemory} B) falls"), null);
            }

            if (limits.Paused)
            {
                return (BlockingReasons.PoolLimit, $"admission from pool '{limits.Name}' is paused", null);
            }

            if (input.Pressure >= PressureLevel.Critical)
            {
                return (BlockingReasons.BudgetMemory, "admission stops at Critical memory pressure (03 section 7)", null);
            }

            if (input.Pressure >= PressureLevel.Tight && priority != Priority.Interactive)
            {
                return (BlockingReasons.BudgetMemory, $"only INTERACTIVE tasks are admitted at {input.Pressure.ToString().ToUpperInvariant()} pressure (03 section 7)", null);
            }

            if (globalRunning >= input.GlobalMaxRunning)
            {
                return (BlockingReasons.GlobalLimit, string.Create(CultureInfo.InvariantCulture, $"{globalRunning} attempts run; global_max_running is {input.GlobalMaxRunning}"), null);
            }

            if (input.GlobalParallelism is { } global && globalRunning >= global)
            {
                return (BlockingReasons.GlobalLimit, string.Create(CultureInfo.InvariantCulture, $"global parallelism is limited to {global}"), null);
            }

            if (!candidate.Light && poolRunning.GetValueOrDefault(limits.Name) >= limits.MaxParallel)
            {
                return (BlockingReasons.PoolLimit, string.Create(CultureInfo.InvariantCulture,
                    $"pool '{limits.Name}' runs {poolRunning.GetValueOrDefault(limits.Name)} of max_parallel {limits.MaxParallel}"), null);
            }

            if (candidate.Workspace is { } workspace && input.WorkspaceParallelism.TryGetValue(workspace, out var workspaceLimit)
                && workspaceRunning.GetValueOrDefault(workspace) >= workspaceLimit)
            {
                return (BlockingReasons.PoolLimit, string.Create(CultureInfo.InvariantCulture, $"workspace {workspace} parallelism is limited to {workspaceLimit}"), null);
            }

            if (candidate.Session is { } session && input.SessionParallelism.TryGetValue(session, out var sessionLimit)
                && sessionRunning.GetValueOrDefault(session) >= sessionLimit)
            {
                return (BlockingReasons.PoolLimit, string.Create(CultureInfo.InvariantCulture, $"session {session} parallelism is limited to {sessionLimit}"), null);
            }

            return holders.Conflict(candidate.Task, [.. candidate.Keys]) is { } conflict
                ? (BlockingReasons.ExclusiveKey, $"keys held by running tasks conflict: {string.Join(", ", conflict.Keys)}", conflict)
                : null;
        }

        // Short of memory or CPU beside the running work (the clamped grant against cpu_limit).
        bool Short(QueuedCandidate candidate) =>
            candidate.MemExpected > availMem || cpuLoad + Math.Min(candidate.Cpu, Math.Max(0, input.BudgetCpu)) > cpuLimit;
    }

    private static void Count(string? pool, string? workspace, string? session, Dictionary<string, int> pools, Dictionary<string, int> workspaces,
        Dictionary<string, int> sessions)
    {
        if (pool is not null)
        {
            pools[pool] = pools.GetValueOrDefault(pool) + 1;
        }

        if (workspace is not null)
        {
            workspaces[workspace] = workspaces.GetValueOrDefault(workspace) + 1;
        }

        if (session is not null)
        {
            sessions[session] = sessions.GetValueOrDefault(session) + 1;
        }
    }

    /// <summary>A held-back task backfills when its duration fact ends before the reservation's estimated start.</summary>
    private static bool Backfills(AdmissionInput input, QueuedCandidate candidate) =>
        input.ReservationStart is { } start && input.Duration?.Invoke(candidate) is { } duration && input.Now + duration <= start;

    /// <summary>
    /// True when admitting <paramref name="candidate"/> would delay the reserved task: afterwards the reserved task's memory or clamped
    /// CPU would no longer fit (the reservation holds back only what takes the resource it is short of).
    /// </summary>
    private static bool Delays(QueuedCandidate reserved, QueuedCandidate candidate, long clamped, long availMem, long cpuLoad, long cpuLimit, long budgetCpu)
    {
        var reservedCpu = Math.Min(reserved.Cpu, Math.Max(0, budgetCpu));
        return reserved.MemExpected > availMem - candidate.MemExpected || cpuLoad + clamped + reservedCpu > cpuLimit;
    }

    private long Credit(string pool) => _poolCredit.GetValueOrDefault(pool);

    private DeficitRing Ring(string pool, Priority priority)
    {
        if (!_rings.TryGetValue((pool, priority), out var ring))
        {
            _rings[(pool, priority)] = ring = new DeficitRing();
        }

        return ring;
    }

    /// <summary>One pool's queue for a pass: per class, per owner, FIFO.</summary>
    private sealed class PoolQueue(string pool)
    {
        public string Pool { get; } = pool;

        public SortedDictionary<Priority, Dictionary<string, List<QueuedCandidate>>> Classes { get; } = [];

        public Dictionary<string, int> Weights { get; } = new(StringComparer.Ordinal);

        public HashSet<string> Decided { get; } = new(StringComparer.Ordinal);

        public bool HasUndecided => Classes.Values.Any(owners => owners.Values.Any(tasks => tasks.Any(task => !Decided.Contains(task.Task))));

        public void Add(QueuedCandidate task, Priority priority)
        {
            if (!Classes.TryGetValue(priority, out var owners))
            {
                Classes[priority] = owners = new Dictionary<string, List<QueuedCandidate>>(StringComparer.Ordinal);
            }

            if (!owners.TryGetValue(task.Owner, out var tasks))
            {
                owners[task.Owner] = tasks = [];
            }

            tasks.Add(task);
            Weights[task.Owner] = Math.Max(1, task.OwnerWeight);
        }

        /// <summary>The next candidate: the highest class with undecided tasks, the owner the deficit round robin serves, its oldest task.</summary>
        public (QueuedCandidate Candidate, Priority Class, Action Commit) Next(AdmissionEngine engine)
        {
            foreach (var (priority, owners) in Classes)
            {
                QueuedCandidate? Head(string owner) => owners.TryGetValue(owner, out var tasks) ? tasks.FirstOrDefault(task => !Decided.Contains(task.Task)) : null;
                if (!owners.Keys.Any(owner => Head(owner) is not null))
                {
                    continue;
                }

                var ring = engine.Ring(Pool, priority);
                var (owner, commit) = ring.Peek(candidate => Head(candidate) is not null, candidate => Weights.GetValueOrDefault(candidate, 1));
                return (Head(owner)!, priority, commit);
            }

            throw new InvalidOperationException("No undecided candidate.");
        }
    }

    /// <summary>
    /// Deficit round robin across the owners of one pool and class (03 section 4): an owner gets its weight as quantum when the rotation
    /// arrives at it and is served while its deficit covers the cost of one admission (1). A peek simulates the rotation; only an admission
    /// commits it, so refused candidates neither earn nor spend credit. An owner whose candidates are all refused in a pass is passed over
    /// without losing its deficit; an owner with nothing queued leaves the ring (deficit reset).
    /// </summary>
    private sealed class DeficitRing
    {
        private readonly List<string> _owners = [];
        private readonly Dictionary<string, int> _deficit = new(StringComparer.Ordinal);
        private int _cursor;
        private bool _arrived;

        public void Sync(IEnumerable<string> owners)
        {
            var present = owners.ToHashSet(StringComparer.Ordinal);
            for (var index = _owners.Count - 1; index >= 0; index--)
            {
                if (!present.Contains(_owners[index]))
                {
                    _deficit.Remove(_owners[index]);
                    _owners.RemoveAt(index);
                    if (index < _cursor)
                    {
                        _cursor--;
                    }
                    else if (index == _cursor)
                    {
                        _arrived = false;
                    }
                }
            }

            foreach (var owner in present.Order(StringComparer.Ordinal).Where(owner => !_deficit.ContainsKey(owner)))
            {
                _owners.Add(owner);
                _deficit[owner] = 0;
            }

            if (_cursor >= _owners.Count)
            {
                _cursor = 0;
                _arrived = false;
            }
        }

        public (string Owner, Action Commit) Peek(Func<string, bool> eligible, Func<string, int> weight)
        {
            var deficit = new Dictionary<string, int>(_deficit, StringComparer.Ordinal);
            var cursor = _cursor;
            var arrived = _arrived;
            var bound = _owners.Count * 3;
            for (var step = 0; step <= bound; step++)
            {
                var owner = _owners[cursor];
                if (eligible(owner))
                {
                    if (!arrived)
                    {
                        deficit[owner] = Math.Min(deficit[owner] + weight(owner), 2 * weight(owner));
                        arrived = true;
                    }

                    if (deficit[owner] >= 1)
                    {
                        var (finalCursor, finalArrived) = (cursor, arrived);
                        return (owner, () =>
                        {
                            foreach (var (name, value) in deficit)
                            {
                                _deficit[name] = value;
                            }

                            _deficit[owner] -= 1;
                            _cursor = finalCursor;
                            _arrived = finalArrived;
                        }
                        );
                    }
                }

                cursor = (cursor + 1) % _owners.Count;
                arrived = false;
            }

            throw new InvalidOperationException("The deficit round robin found no eligible owner.");
        }
    }
}
