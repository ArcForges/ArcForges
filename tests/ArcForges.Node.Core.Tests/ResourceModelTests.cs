// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Resources;
using ArcForges.Tests;
using CsCheck;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Deterministic tests for Run resource headroom, asymmetric smoothing, pressure persistence and victim selection.
/// </summary>
public sealed class ResourceModelTests
{
    private const long GiB = 1024L * 1024 * 1024;

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
            var lowCpu = ResourceBudgetMath.CpuBudget(16_000, 2_600, Math.Min(cpu1, cpu2), 1_000);
            var highCpu = ResourceBudgetMath.CpuBudget(16_000, 2_600, Math.Max(cpu1, cpu2), 1_000);
            var lowMemory = ResourceBudgetMath.MemoryBudget(32 * GiB, 5 * GiB, Math.Min(mem1, mem2));
            var highMemory = ResourceBudgetMath.MemoryBudget(32 * GiB, 5 * GiB, Math.Max(mem1, mem2));
            Assert.True(highCpu >= 1_000 && highCpu <= lowCpu);
            Assert.True(highMemory >= 0 && highMemory <= lowMemory);
        }, iter: PropertyRuns.Iter(2_000));
    }

    [Fact]
    public void ALevelChangesOnlyAfterItsConditionHeldForFiveSeconds()
    {
        var limits = PressureLimits.FromPolicy(null);
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
    public void MissingSamplesPreserveEffectivePressureAndOomWatermark()
    {
        var limits = PressureLimits.FromPolicy(null);
        var evaluator = new PressureEvaluator();
        PressureLevel At(int second, long available, long kills) => evaluator.Evaluate(TimeSpan.FromSeconds(second),
            new PressureInputs(available, 32 * GiB, 16_000, 0, null, kills), limits);

        for (var second = 0; second < 5; second++)
        {
            Assert.Equal(PressureLevel.Normal, At(second, 0, 3));
        }

        Assert.Equal(PressureLevel.Critical, At(5, 0, 3));
        Assert.Equal(PressureLevel.Critical, At(6, 16 * GiB, 3));
        evaluator.Suspend();
        Assert.Equal(PressureLevel.Critical, At(20, 16 * GiB, 3));
        Assert.Equal(PressureLevel.Normal, evaluator.Raw);

        evaluator.Suspend();
        Assert.Equal(PressureLevel.Critical, At(21, 16 * GiB, 4));
        Assert.Equal(PressureLevel.Critical, evaluator.Raw);
        Assert.Equal(1, evaluator.NewOomKills);
        for (var second = 22; second < 36; second++)
        {
            Assert.Equal(PressureLevel.Critical, At(second, 16 * GiB, 4));
        }

        Assert.Equal(PressureLevel.Normal, At(36, 16 * GiB, 4));
        Assert.Equal(0, evaluator.NewOomKills);
    }

    [Fact]
    public void PsiOomKillsAndRisingCpuRaiseTheirLevels()
    {
        var limits = PressureLimits.FromPolicy(null);
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
        var limits = PressureLimits.FromPolicy(null);
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
        var limits = PressureLimits.FromPolicy(new PressureThresholds
        {
            TightAvailableFraction = 0.5,
            PressureAvailableFraction = 0.4,
            CriticalAvailableFraction = 0.3,
            MemoryPsiSomeAvg10 = 50,
        });
        Assert.Equal((0.5, 0.4, 0.3, 50.0), (limits.Tight, limits.Pressure, limits.Critical, limits.MemoryPsi));
        var evaluator = new PressureEvaluator();
        for (var second = 0; second <= 5; second++)
        {
            evaluator.Evaluate(TimeSpan.FromSeconds(second), new PressureInputs(35, 100, 16_000, 0, 40, 0), limits);
        }

        Assert.Equal(PressureLevel.Pressure, evaluator.Level);
    }

}
