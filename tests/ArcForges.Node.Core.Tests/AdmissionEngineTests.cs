// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Scheduling;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The admission algorithm of 03 section 4 as units (R-RES-005, R-EXE-013, R-EXE-014, R-EXE-019): CPU clamping and the large-task
/// reservation, accounted memory, the feasibility classes, the reservation's lapse and backfill, the deficit round robin across owners,
/// pool weights, strict classes, aging, pool, global, workspace and session limits, light commands, the pressure restrictions and keys.
/// The engine takes its inputs (budgets, running loads, queued tasks, the time) as arguments: a scripted pass is a test seam for the
/// algorithm, not a fake of the node (the real scheduler runs real tasks in the component and closed-loop tests).
/// </summary>
public sealed class AdmissionEngineTests
{
    private const long MiB = 1024L * 1024;
    private const long GiB = 1024 * MiB;
    private const long Second = 1_000_000;
    private const long Minute = 60 * Second;

    private static AdmissionInput Input(long now, IReadOnlyList<QueuedCandidate> queued, IReadOnlyList<RunningLoad>? running = null, long budgetCpu = 2_600,
        long budgetMemory = 8 * GiB, int poolLimit = 64, Reservation? reservation = null, PressureLevel pressure = PressureLevel.Normal,
        IReadOnlyList<PoolLimits>? pools = null, long unmanaged = 0) => new()
        {
            Now = now,
            BudgetCpu = budgetCpu,
            BudgetMemory = budgetMemory,
            CapacityMemory = 16 * GiB,
            ReserveMemory = 4 * GiB,
            UnmanagedMemory = unmanaged,
            MaxTaskMemory = 12 * GiB,
            GlobalMaxRunning = 64,
            Pools = pools ?? [new PoolLimits("default", 1, poolLimit, Paused: false)],
            Running = running ?? [],
            Queued = queued,
            Reservation = reservation,
            Pressure = pressure,
        };

    private static QueuedCandidate Task(string name, long queuedAt = 0, long cpu = 1_000, long mem = 512 * MiB, string owner = "user:", string pool = "default",
        Priority priority = Priority.Normal, IReadOnlyList<HeldKey>? keys = null, bool light = false, string? workspace = null, string? session = null) => new()
        {
            Task = name,
            Pool = pool,
            BasePriority = priority,
            EffectivePriority = priority,
            Owner = owner,
            QueuedAt = queuedAt,
            Sequence = queuedAt,
            Cpu = cpu,
            MemExpected = mem,
            Keys = keys ?? [],
            Light = light,
            Workspace = workspace,
            Session = session,
        };

    private static RunningLoad Running(string name, long cpu = 1_000, long mem = 512 * MiB, string pool = "default", IReadOnlyList<HeldKey>? keys = null,
        string? workspace = null, string? session = null) => new(name, pool, session, workspace, mem, cpu, keys ?? []);

    private static HeldKey Key(string text, KeyMode mode = KeyMode.Exclusive) => new(ConcurrencyKey.Parse(text), mode, KeySource.Caller);

    // ------------------------------------------------------------------------------------------------------------------ CPU

    [Fact]
    public void ACpuEstimateAboveTheBudgetStartsWithTheClampedGrantOnAnIdleNode()
    {
        // 03 section 4: on a 4-processor node B_cpu is 2,600 when idle; a dotnet build estimated at 4,000 millicores is granted 2,600.
        var result = new AdmissionEngine().Pass(Input(0, [Task("big", cpu: 4_000)]));
        var admitted = Assert.Single(result.Admitted);
        Assert.Equal("big", admitted.Task);
        Assert.Equal(2_600, admitted.CpuGrant);
        Assert.Equal(3, ToolParallelism.For(2_600, 32));
    }

    [Fact]
    public void ALargeCpuTaskTakesTheReservationOnABusyNodeInsteadOfBeingStarvedBySmallerTasks()
    {
        var engine = new AdmissionEngine();
        var running = new List<RunningLoad> { Running("r1", 1_000), Running("r2", 1_000) };

        // cpu_limit = 1.5 x 2,600 = 3,900: the clamped 2,600 does not fit beside 2,000; a 1,000 task does.
        var early = engine.Pass(Input(Minute, [Task("big", queuedAt: 0, cpu: 4_000), Task("small", queuedAt: 1, cpu: 1_000)], running));
        Assert.Equal(BlockingReasons.BudgetCpu, early.Waiting["big"].Reason);
        Assert.Equal("small", Assert.Single(early.Admitted).Task);
        Assert.Null(early.Reservation);

        // After large_task_bypass (2 min) the big task reserves; a smaller task of its class is held back even though it would fit.
        running.Add(Running("small", 1_000));
        running.RemoveAt(0);
        var later = engine.Pass(Input(3 * Minute, [Task("big", queuedAt: 0, cpu: 4_000), Task("small2", queuedAt: 2 * Minute, cpu: 600)], running));
        Assert.Equal("big", later.Reservation?.Task);
        Assert.Empty(later.Admitted);
        Assert.Equal(BlockingReasons.LargeTaskReserved, later.Waiting["small2"].Reason);

        // Once running work drains, the reserved task starts with its clamped grant before the smaller one.
        var drained = engine.Pass(Input(4 * Minute, [Task("big", queuedAt: 0, cpu: 4_000), Task("small2", queuedAt: 2 * Minute, cpu: 600)], [Running("small", 1_000)],
            reservation: later.Reservation));
        Assert.Equal(2_600, drained.Admitted.Single(admission => admission.Task == "big").CpuGrant);
        Assert.Null(drained.Reservation);
    }

    // ------------------------------------------------------------------------------------------------------------------ memory

    [Fact]
    public void MemoryIsNeverOvercommittedAtAdmissionAndRunningAttemptsCountAtTheirPeak()
    {
        // B_mem 8 GiB: three 3 GiB tasks, of which two fit (6 GiB), the third waits for budget_memory.
        var result = new AdmissionEngine().Pass(Input(0, [Task("a", 0, mem: 3 * GiB), Task("b", 1, mem: 3 * GiB), Task("c", 2, mem: 3 * GiB)]));
        Assert.Equal(["a", "b"], result.Admitted.Select(admission => admission.Task));
        Assert.Equal(BlockingReasons.BudgetMemory, result.Waiting["c"].Reason);
        Assert.True(result.AccountedMemory <= 8 * GiB);

        // A running attempt counts at max(mem_expected, peak_observed): one that grew to 6 GiB leaves room for none of them.
        var grown = new AdmissionEngine().Pass(Input(0, [Task("a", 0, mem: 3 * GiB)], [Running("r", mem: 6 * GiB)]));
        Assert.Empty(grown.Admitted);
        Assert.Equal(BlockingReasons.BudgetMemory, grown.Waiting["a"].Reason);
    }

    [Fact]
    public void AnExceedsCapacityTaskNeverHoldsTheReservationOrBlocksFeasibleWork()
    {
        // max_share_mem = 16 - 4 = 12 GiB; a 13 GiB request can never run.
        var engine = new AdmissionEngine();
        var queued = new[] { Task("huge", 0, mem: 13 * GiB), Task("ok", 1, mem: GiB) };
        var result = engine.Pass(Input(10 * Minute, queued));
        Assert.Equal(Feasibility.ExceedsCapacity, result.Feasibility["huge"]);
        Assert.Equal(BlockingReasons.ExceedsCapacity, result.Waiting["huge"].Reason);
        Assert.Null(result.Reservation);
        Assert.Equal("ok", Assert.Single(result.Admitted).Task);

        // Above max_task_memory is exceeds_capacity too.
        Assert.Equal(Feasibility.ExceedsCapacity, AdmissionEngine.Classify(13 * GiB, 20 * GiB, 20 * GiB, 12 * GiB));
    }

    [Fact]
    public void AnExceedsBudgetTaskWaitsWithoutReservingUntilUnmanagedLoadFalls()
    {
        // idle_budget_mem = 16 - 4 - 6 = 6 GiB; a 7 GiB request fits the share (12 GiB) but not the idle budget.
        var engine = new AdmissionEngine();
        var result = engine.Pass(Input(10 * Minute, [Task("wide", 0, mem: 7 * GiB), Task("ok", 1, mem: GiB)], budgetMemory: 6 * GiB, unmanaged: 6 * GiB));
        Assert.Equal(Feasibility.ExceedsBudget, result.Feasibility["wide"]);
        Assert.Equal(BlockingReasons.ExceedsBudget, result.Waiting["wide"].Reason);
        Assert.Null(result.Reservation);
        Assert.Equal("ok", Assert.Single(result.Admitted).Task);

        // QUEUE_STARVATION after twice the starvation bound (20 min).
        Assert.Contains("wide", engine.Pass(Input(21 * Minute, [Task("wide", 0, mem: 7 * GiB)], budgetMemory: 6 * GiB, unmanaged: 6 * GiB)).Starving);
    }

    [Fact]
    public void TheReservationLapsesAfterItsMaximumAndIsNotRetakenForTheSameInterval()
    {
        var engine = new AdmissionEngine();
        var running = new[] { Running("hog", mem: 7 * GiB) };
        var big = Task("big", 0, mem: 2 * GiB);
        var taken = engine.Pass(Input(3 * Minute, [big], running));
        Assert.Equal(new Reservation("big", 3 * Minute), taken.Reservation);

        // large_task_reservation_max (30 min) after it was taken, the reservation lapses.
        var lapsed = engine.Pass(Input(34 * Minute, [big], running, reservation: taken.Reservation));
        Assert.Null(lapsed.Reservation);
        Assert.Equal(["big"], lapsed.Lapsed);

        // Within large_task_reservation_max of the lapse it cannot reserve again; afterwards it can.
        var lapsedBig = new QueuedCandidate { Task = "big", Pool = "default", Owner = "user:", Cpu = 1_000, MemExpected = 2 * GiB, LapsedAt = 34 * Minute };
        Assert.Null(engine.Pass(Input(40 * Minute, [lapsedBig], running)).Reservation);
        Assert.Equal("big", engine.Pass(Input(65 * Minute, [lapsedBig], running)).Reservation?.Task);

        // A reservation also lapses as soon as its task becomes exceeds_budget.
        var budgetFell = engine.Pass(Input(36 * Minute, [big], running, reservation: new Reservation("big", 35 * Minute), unmanaged: 11 * GiB));
        Assert.Null(budgetFell.Reservation);
        Assert.Contains("big", budgetFell.Lapsed);
    }

    [Fact]
    public void TheReservationHoldsBackOnlyItsClassAndBelowNeverHigherClassesLightCommandsOrBackfill()
    {
        var engine = new AdmissionEngine();
        var running = new[] { Running("hog", mem: 7 * GiB) };
        var reservation = new Reservation("big", 3 * Minute);
        var queued = new[]
        {
            Task("big", 0, mem: 2 * GiB),
            Task("high", 1, mem: 512 * MiB, priority: Priority.High),
            Task("same", 2, mem: 512 * MiB),
            Task("light", 3, mem: 128 * MiB, light: true),
        };
        var result = engine.Pass(Input(4 * Minute, queued, running, reservation: reservation));
        Assert.Contains(result.Admitted, admission => admission.Task == "high");
        Assert.Contains(result.Admitted, admission => admission.Task == "light");
        Assert.Equal(BlockingReasons.LargeTaskReserved, result.Waiting["same"].Reason);

        // Backfill: a held-back task whose duration fact ends before the reservation's estimated start still runs; without a fact it waits.
        var backfill = new AdmissionInput
        {
            Now = 4 * Minute,
            BudgetCpu = 2_600,
            BudgetMemory = 8 * GiB,
            CapacityMemory = 16 * GiB,
            ReserveMemory = 4 * GiB,
            MaxTaskMemory = 12 * GiB,
            Pools = [new PoolLimits("default", 1, 64, false)],
            Running = running,
            Queued = [Task("big", 0, mem: 2 * GiB), Task("quick", 2, mem: 512 * MiB), Task("unknown", 3, mem: 512 * MiB)],
            Reservation = reservation,
            ReservationStart = 10 * Minute,
            Duration = candidate => candidate.Task == "quick" ? Minute : null,
        };
        var filled = new AdmissionEngine().Pass(backfill);
        Assert.Equal("quick", Assert.Single(filled.Admitted).Task);
        Assert.Equal(BlockingReasons.LargeTaskReserved, filled.Waiting["unknown"].Reason);
    }

    // ------------------------------------------------------------------------------------------------------------------ ordering

    [Fact]
    public void DeficitRoundRobinSharesAdmissionsEquallyBetweenTwoOwnersWhateverTheSubmissionOrder()
    {
        // Owner A submitted 20 tasks before owner B submitted 20; with one slot at a time, admissions alternate.
        var engine = new AdmissionEngine();
        var queued = Enumerable.Range(0, 20).Select(index => Task("a" + index, index, owner: "session:A"))
            .Concat(Enumerable.Range(0, 20).Select(index => Task("b" + index, 100 + index, owner: "session:B"))).ToList();
        var admitted = new List<string>();
        for (var pass = 0; pass < 20; pass++)
        {
            var result = engine.Pass(Input(Second * pass, [.. queued], [], poolLimit: 1));
            var task = Assert.Single(result.Admitted).Task;
            admitted.Add(task);
            queued.RemoveAll(candidate => candidate.Task == task);
        }

        Assert.Equal(10, admitted.Count(task => task.StartsWith('a')));
        Assert.Equal(10, admitted.Count(task => task.StartsWith('b')));
        for (var index = 1; index < admitted.Count; index++)
        {
            Assert.NotEqual(admitted[index - 1][0], admitted[index][0]);
        }

        // FIFO within an owner.
        Assert.Equal(Enumerable.Range(0, 10).Select(index => "a" + index), admitted.Where(task => task.StartsWith('a')));
    }

    [Fact]
    public void AnOwnerWithTwiceTheWeightGetsTwiceTheAdmissions()
    {
        var engine = new AdmissionEngine();
        var queued = Enumerable.Range(0, 30).Select(index => new QueuedCandidate
        {
            Task = "a" + index,
            Pool = "default",
            Owner = "A",
            OwnerWeight = 2,
            QueuedAt = index,
            Sequence = index,
            Cpu = 100,
            MemExpected = MiB,
        }).Concat(Enumerable.Range(0, 30).Select(index => Task("b" + index, 1_000 + index, cpu: 100, mem: MiB, owner: "B"))).ToList();
        var admitted = new List<string>();
        for (var pass = 0; pass < 30; pass++)
        {
            var task = Assert.Single(engine.Pass(Input(pass, [.. queued], [], poolLimit: 1)).Admitted).Task;
            admitted.Add(task);
            queued.RemoveAll(candidate => candidate.Task == task);
        }

        Assert.Equal(20, admitted.Count(task => task.StartsWith('a')));
        Assert.Equal(10, admitted.Count(task => task.StartsWith('b')));
    }

    [Fact]
    public void PriorityClassesAreStrictWithinAPoolAndPoolsShareByWeight()
    {
        var strict = new AdmissionEngine().Pass(Input(0, [Task("normal", 0), Task("low", 1, priority: Priority.Low), Task("high", 2, priority: Priority.High)], [], poolLimit: 1));
        Assert.Equal("high", Assert.Single(strict.Admitted).Task);
        Assert.Equal(BlockingReasons.PoolLimit, strict.Waiting["normal"].Reason);

        // Two pools with weights 3 and 1 under a global limit of one admission per pass: 3 of every 4 admissions go to the heavier pool.
        var engine = new AdmissionEngine();
        var queued = Enumerable.Range(0, 40).Select(index => Task("x" + index, index, pool: "x"))
            .Concat(Enumerable.Range(0, 40).Select(index => Task("y" + index, index, pool: "y"))).ToList();
        var pools = new[] { new PoolLimits("x", 3, 64, false), new PoolLimits("y", 1, 64, false) };
        var admitted = new List<string>();
        for (var pass = 0; pass < 40; pass++)
        {
            var input = Input(pass, [.. queued], [], pools: pools);
            var limited = new AdmissionInput
            {
                Now = input.Now,
                BudgetCpu = input.BudgetCpu,
                BudgetMemory = input.BudgetMemory,
                CapacityMemory = input.CapacityMemory,
                ReserveMemory = input.ReserveMemory,
                MaxTaskMemory = input.MaxTaskMemory,
                Pools = pools,
                Queued = input.Queued,
                GlobalMaxRunning = 1,
            };
            var task = Assert.Single(engine.Pass(limited).Admitted).Task;
            admitted.Add(task);
            queued.RemoveAll(candidate => candidate.Task == task);
        }

        Assert.Equal(30, admitted.Count(task => task.StartsWith('x')));
        Assert.Equal(10, admitted.Count(task => task.StartsWith('y')));
    }

    [Fact]
    public void AgingRaisesAWaitingTaskOneClassPerStarvationBoundUpToHigh()
    {
        Assert.Equal(Priority.Background, AdmissionEngine.Aged(Priority.Background, Priority.Background, 0, 9 * Minute, 10 * Minute));
        Assert.Equal(Priority.Low, AdmissionEngine.Aged(Priority.Background, Priority.Background, 0, 10 * Minute, 10 * Minute));
        Assert.Equal(Priority.Normal, AdmissionEngine.Aged(Priority.Background, Priority.Low, 0, 21 * Minute, 10 * Minute));
        Assert.Equal(Priority.High, AdmissionEngine.Aged(Priority.Background, Priority.Normal, 0, 90 * Minute, 10 * Minute));
        Assert.Equal(Priority.Interactive, AdmissionEngine.Aged(Priority.Interactive, Priority.Interactive, 0, 90 * Minute, 10 * Minute));
        Assert.Equal(Priority.High, AdmissionEngine.Aged(Priority.High, Priority.High, 0, 90 * Minute, 10 * Minute));
        Assert.Equal(20 * Minute, AdmissionEngine.AgesAt(Priority.Low, 0, 15 * Minute, 10 * Minute));
        Assert.Null(AdmissionEngine.AgesAt(Priority.High, 0, 15 * Minute, 10 * Minute));

        // R-EXE-014: an aged LOW task overtakes NORMAL tasks submitted after it.
        var result = new AdmissionEngine().Pass(Input(25 * Minute, [Task("old-low", 0, priority: Priority.Low), Task("new-normal", 24 * Minute)], [], poolLimit: 1));
        Assert.Equal(Priority.High, result.Aged["old-low"]);
        Assert.Equal("old-low", Assert.Single(result.Admitted).Task);
    }

    // ------------------------------------------------------------------------------------------------------------------ limits

    [Fact]
    public void ADemotedTaskAgesFromTheChangeNotFromItsQueueing()
    {
        // Queued at 0 as BACKGROUND, at 25 min (2.5 starvation bounds) it has aged to NORMAL; SetTaskPriority then demotes it to LOW, which
        // restarts its aging clock (aged_at = 25 min). Counted from its queueing it would be HIGH at once; from the change it stays LOW
        // until a new bound has elapsed, then rises one class.
        var engine = new AdmissionEngine();
        QueuedCandidate Demoted() => new()
        {
            Task = "demoted",
            Pool = "default",
            BasePriority = Priority.Low,
            EffectivePriority = Priority.Low,
            Owner = "user:",
            QueuedAt = 0,
            AgingFrom = 25 * Minute,
            Cpu = 100,
            MemExpected = 64 * MiB,
        };
        var paused = new List<PoolLimits> { new("default", 1, 64, Paused: true) };
        Assert.Empty(engine.Pass(Input(25 * Minute, [Demoted()], pools: paused)).Aged);
        Assert.Empty(engine.Pass(Input(34 * Minute, [Demoted()], pools: paused)).Aged);
        Assert.Equal(Priority.Normal, engine.Pass(Input(35 * Minute, [Demoted()], pools: paused)).Aged["demoted"]);

        // Without the restart (no aging start) the same task is HIGH at 25 min.
        var counted = Demoted();
        Assert.Equal(Priority.High, engine.Pass(Input(25 * Minute, [new QueuedCandidate
        {
            Task = counted.Task,
            Pool = counted.Pool,
            BasePriority = counted.BasePriority,
            EffectivePriority = counted.EffectivePriority,
            Owner = counted.Owner,
            QueuedAt = counted.QueuedAt,
            Cpu = counted.Cpu,
            MemExpected = counted.MemExpected,
        }], pools: paused)).Aged["demoted"]);
    }

    [Fact]
    public void TheLongestWaitingQualifyingTaskTakesTheReservation()
    {
        // 03 section 4: two tasks waited longer than large_task_bypass and do not fit beside the running work; the walk offers the HIGH one
        // first (strict class), but the NORMAL one has waited longer, so it takes the reservation.
        var engine = new AdmissionEngine();
        var running = new List<RunningLoad> { Running("r1", 1_000), Running("r2", 1_000) };
        // At 9 min neither has aged (the starvation bound is 10 min); both waited longer than large_task_bypass (2 min).
        var result = engine.Pass(Input(9 * Minute,
            [Task("older", queuedAt: 0, cpu: 4_000), Task("newer", queuedAt: 4 * Minute, cpu: 4_000, priority: Priority.High)], running));
        Assert.Equal("older", result.Reservation?.Task);
        Assert.Equal(BlockingReasons.BudgetCpu, result.Waiting["older"].Reason);
        Assert.Equal(BlockingReasons.BudgetCpu, result.Waiting["newer"].Reason);
    }

    [Fact]
    public void AQueuePositionCountsOnlyTheTasksStillWaitingBeforeIt()
    {
        // Two tasks are admitted in this pass and two wait (the pool runs at most two): the waiting ones are positions 1 and 2.
        var result = new AdmissionEngine().Pass(Input(0, [Task("a", queuedAt: 0, cpu: 100), Task("b", queuedAt: 1, cpu: 100), Task("c", queuedAt: 2, cpu: 100),
            Task("d", queuedAt: 3, cpu: 100)], poolLimit: 2));
        Assert.Equal(["a", "b"], result.Admitted.Select(admission => admission.Task));
        Assert.Equal(1, result.Waiting["c"].Position);
        Assert.Equal(2, result.Waiting["d"].Position);
    }

    [Fact]
    public void ParallelismDisabledPerScopeRunsOneTaskAtATime()
    {
        var queued = new[] { Task("t1", 0, workspace: "W", session: "S"), Task("t2", 1, workspace: "W", session: "S") };

        // Pool DISABLED: max_parallel 1.
        Assert.Single(new AdmissionEngine().Pass(Input(0, queued, [], poolLimit: 1)).Admitted);

        // Global, workspace and session rules.
        foreach (var input in new[]
        {
            new AdmissionInput { BudgetCpu = 2_600, BudgetMemory = 8 * GiB, CapacityMemory = 16 * GiB, ReserveMemory = 4 * GiB, Queued = queued, GlobalParallelism = 1 },
            new AdmissionInput { BudgetCpu = 2_600, BudgetMemory = 8 * GiB, CapacityMemory = 16 * GiB, ReserveMemory = 4 * GiB, Queued = queued,
                WorkspaceParallelism = new Dictionary<string, int> { ["W"] = 1 } },
            new AdmissionInput { BudgetCpu = 2_600, BudgetMemory = 8 * GiB, CapacityMemory = 16 * GiB, ReserveMemory = 4 * GiB, Queued = queued,
                SessionParallelism = new Dictionary<string, int> { ["S"] = 1 } },
        })
        {
            var result = new AdmissionEngine().Pass(input);
            Assert.Equal("t1", Assert.Single(result.Admitted).Task);
            Assert.Contains(result.Waiting["t2"].Reason, new[] { BlockingReasons.GlobalLimit, BlockingReasons.PoolLimit });
        }

        // With one task of the scope already running, nothing more starts.
        var busy = new AdmissionEngine().Pass(new AdmissionInput
        {
            BudgetCpu = 2_600,
            BudgetMemory = 8 * GiB,
            CapacityMemory = 16 * GiB,
            ReserveMemory = 4 * GiB,
            Queued = queued,
            Running = [Running("r", workspace: "W")],
            WorkspaceParallelism = new Dictionary<string, int> { ["W"] = 1 },
        });
        Assert.Empty(busy.Admitted);
    }

    [Fact]
    public void LightCommandsSkipPoolLimitsButNotTheGlobalLimit()
    {
        var result = new AdmissionEngine().Pass(Input(0, [Task("light", 0, cpu: 250, mem: 128 * MiB, light: true)], [Running("r")], poolLimit: 1));
        Assert.Equal("light", Assert.Single(result.Admitted).Task);
        var full = new AdmissionInput
        {
            BudgetCpu = 2_600,
            BudgetMemory = 8 * GiB,
            CapacityMemory = 16 * GiB,
            ReserveMemory = 4 * GiB,
            GlobalMaxRunning = 1,
            Queued = [Task("light", 0, light: true)],
            Running = [Running("r")],
        };
        Assert.Equal(BlockingReasons.GlobalLimit, new AdmissionEngine().Pass(full).Waiting["light"].Reason);
    }

    [Fact]
    public void TightPressureAdmitsOnlyInteractiveTasksAndCriticalNone()
    {
        var queued = new[] { Task("normal", 0), Task("interactive", 1, priority: Priority.Interactive) };
        var tight = new AdmissionEngine().Pass(Input(0, queued, pressure: PressureLevel.Tight));
        Assert.Equal("interactive", Assert.Single(tight.Admitted).Task);
        Assert.Equal(BlockingReasons.BudgetMemory, tight.Waiting["normal"].Reason);
        Assert.Empty(new AdmissionEngine().Pass(Input(0, queued, pressure: PressureLevel.Critical)).Admitted);
    }

    [Fact]
    public void APausedPoolAdmitsNothing()
    {
        var result = new AdmissionEngine().Pass(Input(0, [Task("t", 0)], pools: [new PoolLimits("default", 1, 4, Paused: true)]));
        Assert.Empty(result.Admitted);
        Assert.Equal(BlockingReasons.PoolLimit, result.Waiting["t"].Reason);
    }

    // ------------------------------------------------------------------------------------------------------------------ keys

    [Fact]
    public void OverlappingExclusiveKeysWaitWithTheirHoldersWhileSharedKeysRunTogether()
    {
        var running = new[] { Running("holder", keys: [Key("ws:W/src")]) };
        var result = new AdmissionEngine().Pass(Input(0,
        [
            Task("child", 0, keys: [Key("ws:W/src/app")]),
            Task("sibling", 1, keys: [Key("ws:W/docs")]),
            Task("reader", 2, keys: [Key("ws:W/src", KeyMode.Shared)]),
        ], running));
        var child = result.Waiting["child"];
        Assert.Equal(BlockingReasons.ExclusiveKey, child.Reason);
        Assert.Equal(["ws:W/src"], child.BlockingKeys);
        Assert.Equal(["holder"], child.Holders);
        Assert.Equal(BlockingReasons.ExclusiveKey, result.Waiting["reader"].Reason);
        Assert.Equal("sibling", Assert.Single(result.Admitted).Task);

        // Shared keys run together; within one pass the first exclusive holder blocks the next one.
        var shared = new AdmissionEngine().Pass(Input(0, [Task("r1", 0, keys: [Key("ws:W/out", KeyMode.Shared)]), Task("r2", 1, keys: [Key("ws:W/out", KeyMode.Shared)])]));
        Assert.Equal(2, shared.Admitted.Count);
        var writers = new AdmissionEngine().Pass(Input(0, [Task("w1", 0, keys: [Key("name:deploy")]), Task("w2", 1, keys: [Key("name:deploy")])]));
        Assert.Equal("w1", Assert.Single(writers.Admitted).Task);
        Assert.Equal(["w1"], writers.Waiting["w2"].Holders);
    }

    [Fact]
    public void TheKeyOverlapRuleCoversAncestorsPurposesToolsTheWorkspaceKeyAndNames()
    {
        static bool Overlap(string left, string right) => ConcurrencyKey.Parse(left).Overlaps(ConcurrencyKey.Parse(right));

        Assert.True(Overlap("ws:W/a", "ws:W/a"));
        Assert.True(Overlap("ws:W/a", "ws:W/a/b"));
        Assert.True(Overlap("ws:W/a/b", "ws:W/a"));
        Assert.False(Overlap("ws:W/a", "ws:W/ab"));
        Assert.False(Overlap("ws:W/a", "ws:V/a"));

        // Purposes separate two uses of a directory only when both keys carry one and they differ.
        Assert.False(Overlap("ws:W/pkg:deps", "ws:W/pkg:build"));
        Assert.True(Overlap("ws:W/pkg:deps", "ws:W/pkg:deps"));
        Assert.True(Overlap("ws:W/pkg:deps", "ws:W/pkg"));
        Assert.True(Overlap("ws:W/pkg:deps", "ws:W/pkg/sub"));

        // Tool keys overlap only the same tool key; the workspace key overlaps everything of its workspace, tool keys in it included.
        Assert.True(Overlap("tool:dotnet:W", "tool:dotnet:W"));
        Assert.False(Overlap("tool:dotnet:W", "tool:cargo:W"));
        Assert.False(Overlap("tool:dotnet:W", "ws:W/src"));
        Assert.True(Overlap("ws:W", "tool:dotnet:W"));
        Assert.True(Overlap("ws:W", "tool:git:W/sub"));
        Assert.True(Overlap("ws:W", "ws:W/deep/dir:deps"));
        Assert.False(Overlap("ws:W", "tool:dotnet:V"));
        Assert.False(Overlap("ws:W", "name:W"));
        Assert.True(Overlap("name:x", "name:x"));
        Assert.False(Overlap("name:x", "name:y"));

        // A tool key scoped by an absolute path inside the workspace's root.
        Assert.True(ConcurrencyKey.Parse("ws:W").Overlaps(ConcurrencyKey.Parse("tool:cargo:/work/repo/target"), workspace => workspace == "W" ? "/work/repo" : null));

        // Parsing: canonical text, and refused shapes.
        Assert.Equal("ws:W/a/b:deps", ConcurrencyKey.Parse(@"ws:W\a\.\b:deps").Text);
        Assert.Equal(KeyKind.Workspace, ConcurrencyKey.Parse("ws:W/").Kind);
        foreach (var bad in new[] { "", "ws:", "ws:W/../x", "ws:W/a:", "tool:dotnet", "tool::x", "name:", "other:x", new string('x', 201) })
        {
            Assert.False(ConcurrencyKey.TryParse(bad, out _, out _), bad);
        }

        Assert.NotNull(KeyHolders.FromSpec([.. Enumerable.Range(0, 17).Select(index => "name:" + index)], []).Error);
        Assert.NotNull(KeyHolders.FromSpec(["name:a", "name:a"], []).Error);
        Assert.Null(KeyHolders.FromSpec(["name:a"], ["ws:W"]).Error);
    }
}
