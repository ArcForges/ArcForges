// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Resources;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Store.Policy;
using ArcForges.Tests;
using CsCheck;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The pure parts of resource control (03 sections 2, 7 and 9) as units: the budget formulas with the default and the workstation's
/// capacity (03 section 2 example, L-01; R-RES-003), the asymmetric smoothing, the pressure levels with 5 s persistence (R-RES-009,
/// R-RES-014) and the process labels (R-RES-002). The pressure evaluator and the smoother take their samples and time as arguments: a
/// scripted series is a test seam for the arithmetic, not a fake of the operating system (the real samplers are tested on each OS).
/// </summary>
public sealed class ResourceModelTests
{
    private const long GiB = 1024L * 1024 * 1024;

    private static ExecutionSettings Settings(int processors, long memory, Action<ResourcePolicy>? change = null)
    {
        var policy = DefaultPolicy.Create();
        change?.Invoke(policy.Resources);
        return new ExecutionSettings(policy, processors, memory);
    }

    [Fact]
    public void ARootBudgetFallAppliesAtOnceARiseWaitsForTheIntervalAndSmallChangesAreIgnored()
    {
        // 03 section 5.1 as amended by L-31: a change counts above 5% of capacity; a fall applies at once, a rise at most every 10 s.
        var capacity = (Cpu: 8_000L, Memory: 16 * GiB);
        var applied = (Cpu: 6_000L, Memory: 10 * GiB);
        var fiveCpu = capacity.Cpu / 20;
        var fiveMemory = capacity.Memory / 20;

        // A fall of more than 5%: applied at once, also before the interval; only the fallen dimension moves.
        Assert.Equal((4_800L, 10 * GiB), ExecutionSupervisor.NextRootBudget(applied, (4_800, 10 * GiB), capacity, due: false, force: false));
        Assert.Equal((6_000L, 8 * GiB), ExecutionSupervisor.NextRootBudget(applied, (6_000, 8 * GiB), capacity, due: false, force: false));
        Assert.Equal((4_800L, 10 * GiB), ExecutionSupervisor.NextRootBudget(applied, (4_800, 12 * GiB), capacity, due: false, force: false));

        // A rise of more than 5%: waits for the interval, then applies.
        Assert.Null(ExecutionSupervisor.NextRootBudget(applied, (7_200, 10 * GiB), capacity, due: false, force: false));
        Assert.Null(ExecutionSupervisor.NextRootBudget(applied, (6_000, 12 * GiB), capacity, due: false, force: false));
        Assert.Equal((7_200L, 10 * GiB), ExecutionSupervisor.NextRootBudget(applied, (7_200, 10 * GiB), capacity, due: true, force: false));
        Assert.Equal((4_800L, 12 * GiB), ExecutionSupervisor.NextRootBudget(applied, (4_800, 12 * GiB), capacity, due: true, force: false));

        // Changes of at most 5% are ignored in both directions, due or not.
        foreach (var due in (bool[])[false, true])
        {
            Assert.Null(ExecutionSupervisor.NextRootBudget(applied, (applied.Cpu - fiveCpu, applied.Memory), capacity, due, force: false));
            Assert.Null(ExecutionSupervisor.NextRootBudget(applied, (applied.Cpu + fiveCpu, applied.Memory), capacity, due, force: false));
            Assert.Null(ExecutionSupervisor.NextRootBudget(applied, (applied.Cpu, applied.Memory - fiveMemory), capacity, due, force: false));
            Assert.Null(ExecutionSupervisor.NextRootBudget(applied, (applied.Cpu, applied.Memory + fiveMemory), capacity, due, force: false));
        }

        // Just above 5% counts.
        Assert.Equal((applied.Cpu - fiveCpu - 1, applied.Memory),
            ExecutionSupervisor.NextRootBudget(applied, (applied.Cpu - fiveCpu - 1, applied.Memory), capacity, due: false, force: false));

        // Entering Tight forces any change at once, a small rise included; no change is nothing to apply.
        Assert.Equal((6_100L, 10 * GiB), ExecutionSupervisor.NextRootBudget(applied, (6_100, 10 * GiB), capacity, due: false, force: true));
        Assert.Null(ExecutionSupervisor.NextRootBudget(applied, applied, capacity, due: false, force: true));
    }

    [Fact]
    public void TheDefaultReservesAndBudgetsFollowTheDesignExample()
    {
        // 03 section 2: 16 logical processors and 32 GiB give R_cpu = 2,600 and R_mem = 5.2 GiB; D-04 shows the managed share 26.8 GiB.
        var settings = Settings(16, 32 * GiB);
        Assert.Equal(16_000, settings.CapacityCpu);
        Assert.Equal(2_600, settings.ReserveCpu);
        Assert.Equal((long)((2 * GiB) + (0.10 * 32 * GiB)), settings.ReserveMemory);
        Assert.Equal(5.2, settings.ReserveMemory / (double)GiB, 6);
        Assert.Equal(26.8, (settings.CapacityMemory - settings.ReserveMemory) / (double)GiB, 6);

        // D-05's bar: unmanaged 3.1 cores and 9.7 GiB leave B_cpu = 10,300 and B_mem = 32 - 5.2 - 9.7 = 17.1 GiB.
        var (cpu, memory) = settings.Budgets(3_100, (long)(9.7 * GiB));
        Assert.Equal(10_300, cpu);
        Assert.Equal(17.1, memory / (double)GiB, 6);

        // The floors: B_cpu never below min_managed_cpu (1,000), B_mem never below 0.
        Assert.Equal((1_000L, 0L), settings.Budgets(20_000, 40 * GiB));

        // Negative unmanaged use (never produced, but clamped) cannot raise the budget above C - R.
        Assert.Equal((13_400L, settings.CapacityMemory - settings.ReserveMemory), settings.Budgets(-5, -5));
    }

    [Fact]
    public void TheWorkstationsBudgetsFollowL01()
    {
        // L-01: 18 logical processors (Intel Core Ultra 5 125H) and 31.5 GB of memory.
        var memory = (long)(31.5 * GiB);
        var settings = Settings(18, memory);
        Assert.Equal(18_000, settings.CapacityCpu);
        Assert.Equal(1_000 + 1_800, settings.ReserveCpu);
        Assert.Equal((long)((2 * GiB) + (0.10 * memory)), settings.ReserveMemory);
        var (cpu, budgetMemory) = settings.Budgets(0, 0);
        Assert.Equal(15_200, cpu);
        Assert.Equal(26.35, budgetMemory / (double)GiB, 6);

        // The WSL VM is one unmanaged consumer in U (AD-0018): a 4 GiB VM worker lowers B_mem by exactly 4 GiB, with no guest terms.
        Assert.Equal(budgetMemory - (4 * GiB), settings.Budgets(0, 4 * GiB).Memory);
    }

    [Fact]
    public void ThePolicyChangesTheReservesTheFloorAndTheSmoothing()
    {
        var settings = Settings(8, 16 * GiB, resources =>
        {
            resources.ReserveCpuFixedMillicores = 500;
            resources.ReserveCpuFraction = 0.25;
            resources.ReserveMemFixedBytes = (ulong)GiB;
            resources.ReserveMemFraction = 0;
            resources.MinManagedCpuMillicores = 2_000;
            resources.SmoothingAlphaUp = 0.8;
            resources.SmoothingAlphaDown = 0.05;
        });
        Assert.Equal(2_500, settings.ReserveCpu);
        Assert.Equal(GiB, settings.ReserveMemory);
        Assert.Equal(2_000, settings.Budgets(8_000, 0).Cpu);
        Assert.Equal((0.8, 0.05), (settings.AlphaUp, settings.AlphaDown));

        // Out-of-range alphas fall back to the defaults (0.5 up, 0.1 down).
        var defaults = Settings(8, 16 * GiB, resources =>
        {
            resources.SmoothingAlphaUp = 2;
            resources.SmoothingAlphaDown = 0;
        });
        Assert.Equal((0.5, 0.1), (defaults.AlphaUp, defaults.AlphaDown));
    }

    [Fact]
    public void SmoothingRespectsRisingLoadQuicklyAndReleasesItSlowly()
    {
        var smoother = new AsymmetricSmoother();
        Assert.Equal(1_000, smoother.Update(1_000, 0.5, 0.1));
        Assert.Equal(3_000, smoother.Update(5_000, 0.5, 0.1));
        Assert.Equal(4_000, smoother.Update(5_000, 0.5, 0.1));
        Assert.Equal(3_600, smoother.Update(0, 0.5, 0.1), 6);
        Assert.Equal(3_240, smoother.Update(0, 0.5, 0.1), 6);

        // Released slowly: after a 10 s spike, 10 s at zero still leave more than a third of it; respected quickly: 3 s reach 7/8.
        var spike = new AsymmetricSmoother();
        spike.Update(0, 0.5, 0.1);
        for (var second = 0; second < 3; second++)
        {
            spike.Update(8_000, 0.5, 0.1);
        }

        Assert.Equal(7_000, spike.Value!.Value, 6);
        for (var second = 0; second < 10; second++)
        {
            spike.Update(0, 0.5, 0.1);
        }

        Assert.InRange(spike.Value!.Value, 2_400, 2_500);
    }

    [Fact]
    public void SmoothedLoadStaysWithinItsSamplesAndBudgetsNeverRiseWithLoad()
    {
        var settings = Settings(16, 32 * GiB);
        Gen.Select(Gen.Long[0, 64_000].Array[1, 40], Gen.Double[0.05, 1], Gen.Double[0.01, 1]).Sample((samples, up, down) =>
        {
            var smoother = new AsymmetricSmoother();
            foreach (var sample in samples)
            {
                var value = smoother.Update(sample, up, down);
                Assert.InRange(value, samples.Min() - 1e-6, samples.Max() + 1e-6);
            }
        }, iter: PropertyRuns.Iter(2_000));

        Gen.Select(Gen.Long[0, 40_000], Gen.Long[0, 40_000], Gen.Long[0, 64 * GiB], Gen.Long[0, 64 * GiB]).Sample((cpu1, cpu2, mem1, mem2) =>
        {
            var (low, high) = (settings.Budgets(Math.Min(cpu1, cpu2), Math.Min(mem1, mem2)), settings.Budgets(Math.Max(cpu1, cpu2), Math.Max(mem1, mem2)));
            Assert.True(high.Cpu <= low.Cpu && high.Memory <= low.Memory);
            Assert.True(high.Cpu >= settings.MinManagedCpu && high.Memory >= 0);
        }, iter: PropertyRuns.Iter(2_000));
    }

    [Fact]
    public void ALevelChangesOnlyAfterItsConditionHeldForFiveSeconds()
    {
        var limits = Settings(16, 32 * GiB).Pressure;
        Assert.Equal((0.10, 0.05, 0.02, 20.0), (limits.Tight, limits.Pressure, limits.Critical, limits.MemoryPsi));
        var evaluator = new PressureEvaluator();
        var capacity = 32 * GiB;
        PressureLevel At(int second, double availableFraction, double? psi = null, long oom = 0, double cpu = 0) =>
            evaluator.Evaluate(TimeSpan.FromSeconds(second), new PressureInputs((long)(availableFraction * capacity), capacity, 16_000, cpu, psi, oom), limits);

        Assert.Equal(PressureLevel.Normal, At(0, 0.5));

        // Available memory drops below 2%: the raw level is Critical at once, the level in force follows after 5 s of persistence.
        for (var second = 1; second <= 5; second++)
        {
            Assert.Equal(PressureLevel.Normal, At(second, 0.01));
            Assert.Equal(PressureLevel.Critical, evaluator.Raw);
        }

        Assert.Equal(PressureLevel.Critical, At(6, 0.01));
        Assert.Contains("available memory", evaluator.Trigger, StringComparison.Ordinal);

        // Recovery to 3% (Pressure) holds for 5 s before the level falls, and only to the level whose condition held.
        for (var second = 7; second <= 11; second++)
        {
            Assert.Equal(PressureLevel.Critical, At(second, 0.03));
        }

        Assert.Equal(PressureLevel.Pressure, At(12, 0.03));
        for (var second = 13; second <= 17; second++)
        {
            Assert.Equal(PressureLevel.Pressure, At(second, 0.5));
        }

        Assert.Equal(PressureLevel.Normal, At(18, 0.5));

        // A condition that flaps never persists.
        for (var second = 19; second <= 40; second++)
        {
            Assert.Equal(PressureLevel.Normal, At(second, second % 2 == 0 ? 0.01 : 0.5));
        }
    }

    [Fact]
    public void PsiOomKillsAndRisingCpuRaiseTheirLevels()
    {
        var limits = Settings(16, 32 * GiB).Pressure;
        var capacity = 32 * GiB;

        // Linux memory some avg10 above 20 is Pressure.
        var psi = new PressureEvaluator();
        for (var second = 0; second <= 4; second++)
        {
            psi.Evaluate(TimeSpan.FromSeconds(second), new PressureInputs(capacity / 2, capacity, 16_000, 0, 35, 0), limits);
        }

        Assert.Equal(PressureLevel.Pressure, psi.Evaluate(TimeSpan.FromSeconds(5), new PressureInputs(capacity / 2, capacity, 16_000, 0, 35, 0), limits));
        Assert.Contains("memory some avg10 35", psi.Trigger, StringComparison.Ordinal);

        // An OOM kill seen machine-wide holds Critical for 10 s: the level follows after 5 s and falls 5 s after the hold ended.
        var oom = new PressureEvaluator();
        oom.Evaluate(TimeSpan.Zero, new PressureInputs(capacity / 2, capacity, 16_000, 0, null, 3), limits);
        var levels = Enumerable.Range(1, 20)
            .Select(second => oom.Evaluate(TimeSpan.FromSeconds(second), new PressureInputs(capacity / 2, capacity, 16_000, 0, null, 4), limits))
            .ToList();
        Assert.Equal(PressureLevel.Normal, levels[4 - 1]);
        Assert.Equal(PressureLevel.Critical, levels[6 - 1]);
        Assert.Equal(PressureLevel.Critical, levels[15 - 1]);
        Assert.Equal(PressureLevel.Normal, levels[16 - 1]);

        // U_cpu rising by more than 20% of C_cpu within 10 s is Tight.
        var cpu = new PressureEvaluator();
        cpu.Evaluate(TimeSpan.Zero, new PressureInputs(capacity / 2, capacity, 16_000, 1_000, null, 0), limits);
        for (var second = 1; second <= 5; second++)
        {
            Assert.Equal(PressureLevel.Normal, cpu.Evaluate(TimeSpan.FromSeconds(second), new PressureInputs(capacity / 2, capacity, 16_000, 5_000, null, 0), limits));
        }

        Assert.Equal(PressureLevel.Tight, cpu.Evaluate(TimeSpan.FromSeconds(6), new PressureInputs(capacity / 2, capacity, 16_000, 5_000, null, 0), limits));
        Assert.Contains("unmanaged CPU rose", cpu.Trigger, StringComparison.Ordinal);

        // A steady load is not a rise: once the window holds only the high values the condition ends.
        for (var second = 7; second <= 25; second++)
        {
            cpu.Evaluate(TimeSpan.FromSeconds(second), new PressureInputs(capacity / 2, capacity, 16_000, 5_000, null, 0), limits);
        }

        Assert.Equal(PressureLevel.Normal, cpu.Level);
    }

    /// <summary>
    /// A scripted episode through the evaluator and the shedding rule together, the way the supervisor uses them: one evaluation per second,
    /// <paramref name="candidates"/> preemptible attempts, and a stopped victim that finalizes <paramref name="finalizeTicks"/> evaluations
    /// after its stop. <paramref name="available"/> gives the available fraction at a second given the stops so far (memory that a stop
    /// frees); <paramref name="oomKills"/> the machine-wide OOM kill count. Returns the seconds at which an attempt was stopped, comma-separated.
    /// </summary>
    private static string Shed(Func<int, int, double> available, Func<int, long>? oomKills = null, int finalizeTicks = 1, int candidates = 3,
        int seconds = 40)
    {
        var limits = Settings(16, 32 * GiB).Pressure;
        var capacity = 32 * GiB;
        var evaluator = new PressureEvaluator();
        var shedding = new CriticalShedding();
        var stops = new List<int>();
        var finalizesAt = int.MinValue;
        for (var second = 0; second <= seconds; second++)
        {
            var level = evaluator.Evaluate(TimeSpan.FromSeconds(second),
                new PressureInputs((long)(available(second, stops.Count) * capacity), capacity, 16_000, 0, null, oomKills?.Invoke(second) ?? 0), limits);
            if (shedding.ShouldStop(level, evaluator.Raw, evaluator.MemoryCritical, evaluator.NewOomKills, victimRunning: second < finalizesAt)
                && stops.Count < candidates)
            {
                stops.Add(second);
                shedding.Stopped();
                finalizesAt = second + finalizeTicks;
            }
        }

        return string.Join(", ", stops);
    }

    [Fact]
    public void AShortDipShedsOnlyTheAttemptsNeeded()
    {
        // Available memory falls below 2% at 1 s and recovers when the first attempt is stopped: the level enters Critical at 6 s and leaves
        // it 5 s after the recovery, yet exactly one of the three attempts is stopped, and none during the exit persistence.
        Assert.Equal("6", Shed((second, stopped) => second >= 1 && stopped == 0 ? 0.01 : 0.5));

        // Memory recovers only after the second stop: two are stopped, the third keeps running.
        Assert.Equal("6, 8", Shed((second, stopped) => second >= 1 && stopped < 2 ? 0.01 : 0.5));

        // Memory never recovers: all three are stopped, one at a time, each after the previous victim finalized and one more sample.
        Assert.Equal("6, 8, 10", Shed((second, _) => second >= 1 ? 0.01 : 0.5));

        // A victim that takes 4 s to finalize: no other is stopped meanwhile, and the next one only a sample after its exit.
        Assert.Equal("6, 11, 16", Shed((second, _) => second >= 1 ? 0.01 : 0.5, finalizeTicks: 4));

        // Pressure (3%) is never a reason to stop anything; nor is a Critical dip that never persisted.
        Assert.Equal(string.Empty, Shed((second, _) => second >= 1 ? 0.03 : 0.5));
        Assert.Equal(string.Empty, Shed((second, _) => second is >= 1 and <= 4 ? 0.01 : 0.5));
    }

    [Fact]
    public void AnOomKillStopsAtMostOneAttempt()
    {
        // One OOM kill at 3 s with memory above every threshold: the 10 s hold keeps the level Critical from 8 s to 18 s, and exactly one of
        // the three attempts is stopped, never one per second of the hold.
        Assert.Equal("8", Shed((_, _) => 0.5, second => second >= 3 ? 1 : 0));

        // Two kills seen at once answer with at most two stops; a second kill later in the hold with one more.
        Assert.Equal("8, 10", Shed((_, _) => 0.5, second => second >= 3 ? 2 : 0));
        Assert.Equal("8, 10", Shed((_, _) => 0.5, second => second >= 9 ? 2 : second >= 3 ? 1 : 0));

        // A kill answered while memory was critical too is not answered again once memory recovered.
        Assert.Equal("6", Shed((second, stopped) => second >= 1 && stopped == 0 ? 0.01 : 0.5, second => second >= 2 ? 1 : 0));

        // The rule's own state: the kill is unanswered until the stop, and the stop waits for its victim.
        var shedding = new CriticalShedding();
        Assert.False(shedding.ShouldStop(PressureLevel.Normal, PressureLevel.Critical, memoryCritical: false, newOomKills: 1, victimRunning: false));
        Assert.Equal(1L, shedding.UnansweredOomKills);
        Assert.True(shedding.ShouldStop(PressureLevel.Critical, PressureLevel.Critical, false, 0, false));
        shedding.Stopped();
        Assert.Equal(0L, shedding.UnansweredOomKills);
        Assert.True(shedding.AwaitingVictim);
        Assert.False(shedding.ShouldStop(PressureLevel.Critical, PressureLevel.Critical, memoryCritical: true, 0, victimRunning: true));
        Assert.False(shedding.ShouldStop(PressureLevel.Critical, PressureLevel.Critical, memoryCritical: true, 0, victimRunning: false));
        Assert.False(shedding.AwaitingVictim);
        Assert.True(shedding.ShouldStop(PressureLevel.Critical, PressureLevel.Critical, memoryCritical: true, 0, victimRunning: false));

        // Once the raw condition clears, an unanswered kill is forgotten.
        var forgotten = new CriticalShedding();
        forgotten.ShouldStop(PressureLevel.Normal, PressureLevel.Critical, false, 1, false);
        forgotten.ShouldStop(PressureLevel.Normal, PressureLevel.Normal, false, 0, false);
        Assert.Equal(0L, forgotten.UnansweredOomKills);
    }

    [Fact]
    public void TheVictimIsTheLowestPriorityMostRecentPreemptibleAttemptThatIsNotAlreadyEnding()
    {
        ShedCandidate Candidate(string name, Priority priority, long? started, bool preemptible = true, bool hasHandle = true, bool finalizing = false,
            bool stopping = false, bool oomKilled = false) => new(name, priority, started, preemptible, hasHandle, finalizing, stopping, oomKilled);

        List<ShedCandidate> running =
        [
            Candidate("normal", Priority.Normal, 10),
            Candidate("background-old", Priority.Background, 20),
            Candidate("background-new", Priority.Background, 30),
            Candidate("unspecified", Priority.Unspecified, 40),
            Candidate("protected", Priority.Background, 50, preemptible: false),
        ];

        // The lowest priority first, the most recently started first within it; non-preemptible attempts are never chosen.
        Assert.Equal("background-new", CriticalShedding.Victim(running)!.Name);

        // The lowest-priority candidate is OOM-killed by its own limit (OOMPolicy=stop: still ending): it is skipped and the next one is
        // chosen exactly as if it had already ended.
        running[2] = running[2] with { OomKilled = true };
        Assert.Equal("background-old", CriticalShedding.Victim(running)!.Name);
        Assert.Equal("background-old", CriticalShedding.Victim(running.Where(candidate => candidate.Name != "background-new"))!.Name);

        // Not launched, finalizing or already stopping are skipped too; unspecified counts as NORMAL, and an unknown start as the most recent.
        running[1] = running[1] with { Stopping = true };
        Assert.Equal("unspecified", CriticalShedding.Victim(running)!.Name);
        running[3] = running[3] with { Finalizing = true };
        running.Add(Candidate("normal-starting", Priority.Normal, null));
        Assert.Equal("normal-starting", CriticalShedding.Victim(running)!.Name);
        running[^1] = running[^1] with { HasHandle = false };
        Assert.Equal("normal", CriticalShedding.Victim(running)!.Name);
        running[0] = running[0] with { OomKilled = true };
        Assert.Null(CriticalShedding.Victim(running));
    }

    [Fact]
    public void ThePolicyThresholdsApply()
    {
        var limits = Settings(16, 32 * GiB, resources => resources.Pressure = new PressureThresholds
        {
            TightAvailableFraction = 0.5,
            PressureAvailableFraction = 0.4,
            CriticalAvailableFraction = 0.3,
            MemoryPsiSomeAvg10 = 50,
            CancelOnCritical = false,
        }).Pressure;
        Assert.Equal((0.5, 0.4, 0.3, 50.0, false), (limits.Tight, limits.Pressure, limits.Critical, limits.MemoryPsi, limits.CancelOnCritical));
        var evaluator = new PressureEvaluator();
        for (var second = 0; second <= 5; second++)
        {
            evaluator.Evaluate(TimeSpan.FromSeconds(second), new PressureInputs(35, 100, 16_000, 0, 40, 0), limits);
        }

        Assert.Equal(PressureLevel.Pressure, evaluator.Level);
    }

    [Fact]
    public void ProcessesAreLabelledByMembershipAncestryAndImage()
    {
        var attempt = new byte[16];
        attempt[0] = 1;
        var task = new byte[16];
        task[0] = 2;
        var crossing = new ProcessOwner(attempt, task, CrossesVmBoundary: true);
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);
        var context = new ProcessContext
        {
            NodePid = 100,
            NodeImage = "arcforges.exe",
            Managed = new Dictionary<int, ProcessOwner> { [200] = crossing },
            Escaped = [(300, start, crossing)],
            IsVmWorker = VmProcesses.IsWorker,
        };
        ProcessSample Process(int pid, int parent, string image, DateTimeOffset? started = null) => new(pid, parent, started ?? start, image);

        Assert.Equal((ProcessLabel.Managed, crossing), ProcessClassifier.Classify(Process(200, 100, "wsl.exe"), context));
        Assert.Equal((ProcessLabel.NodeSelf, (ProcessOwner?)null), ProcessClassifier.Classify(Process(100, 1, "arcforges.exe"), context));
        Assert.Equal((ProcessLabel.NodeSelf, (ProcessOwner?)null), ProcessClassifier.Classify(Process(150, 100, "ARCFORGES.EXE"), context));
        Assert.Equal((ProcessLabel.Escaped, crossing), ProcessClassifier.Classify(Process(300, 200, "conhost.exe"), context));

        // An escaped process's ID reused by a later process is not escaped (identity is the ID and the creation time).
        Assert.Equal(ProcessLabel.Unmanaged, ProcessClassifier.Classify(Process(300, 4, "conhost.exe", start.AddSeconds(5)), context).Label);

        // The WSL VM's worker is one GUEST_VM consumer, never controlled; the Linux processes inside the VM are not in the table at all.
        foreach (var vm in (string[])["vmmem", "vmmemWSL", "VMMEM.exe"])
        {
            Assert.Equal(ProcessLabel.GuestVm, ProcessClassifier.Classify(Process(400, 4, vm), context).Label);
        }

        Assert.Equal(ProcessLabel.Unmanaged, ProcessClassifier.Classify(Process(500, 1, "Code.exe"), context).Label);
        Assert.Equal(ProcessLabel.Unmanaged, ProcessClassifier.Classify(Process(501, 100, "cmd.exe"), context).Label);

        // Only MANAGED and ADOPTED are ever controlled (R-RES-002).
        Assert.Equal([ProcessLabel.Managed, ProcessLabel.Adopted],
            Enum.GetValues<ProcessLabel>().Where(ProcessClassifier.Controlled));
    }

    [Theory]
    [InlineData("wsl.exe", true)]
    [InlineData(@"C:\WINDOWS\system32\wsl.exe", true)]
    [InlineData("WSLHOST.EXE", true)]
    [InlineData("wslg.exe", true)]
    [InlineData("bash.exe", false)]
    [InlineData("wslservice.exe", false)]
    [InlineData("vmmem", false)]
    public void TheVmLaunchersAreTheWslFrontEnds(string image, bool launcher)
    {
        Assert.Equal(launcher, VmProcesses.IsLauncher(image));
        Assert.Equal(image.StartsWith("vmmem", StringComparison.OrdinalIgnoreCase), VmProcesses.IsWorker(image));
    }

    [Fact]
    public void TheDiskLevelFollowsTheStoragePolicy()
    {
        var settings = Settings(4, 8 * GiB);
        Assert.Equal(DiskPressureLevel.Normal, settings.DiskLevel(1_000 * GiB, 30 * GiB));
        Assert.Equal(DiskPressureLevel.Low, settings.DiskLevel(1_000 * GiB, 19 * GiB));
        Assert.Equal(DiskPressureLevel.Low, settings.DiskLevel(10 * GiB, GiB - 1));
        Assert.Equal(DiskPressureLevel.Critical, settings.DiskLevel(10 * GiB, 256L << 20));
    }
}
