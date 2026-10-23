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
