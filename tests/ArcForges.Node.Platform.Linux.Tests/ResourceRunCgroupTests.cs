// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.Tests;

namespace ArcForges.Node.Platform.Linux.Tests;

[SupportedOSPlatform("linux")]
public sealed class ResourceRunCgroupTests
{
    [Fact]
    [Trait("env", "linux-real")]
    public async Task LiveLimitsUseTheOriginalDelegatedCgroupAndRefuseUnsafeChanges()
    {
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        var cancellationToken = TestContext.Current.CancellationToken;
        var unit = "arcforges-run-" + Guid.NewGuid().ToString("N") + ".service";
        var bound = TimeSpan.FromSeconds(15);
        using var manager = SystemdManager.Connect(SystemdManager.DefaultAddress()!, bound);
        try
        {
            string[] command = ["/usr/bin/sleep", "60"];
            var job = manager.StartTransientUnit(unit,
            [
                new("Description", "ArcForges V2 Run " + unit),
                new("Type", "exec"), new("Restart", "no"), new("KillMode", "control-group"), new("Delegate", true),
                new("CPUAccounting", true), new("MemoryAccounting", true), new("TasksAccounting", true),
                new("CPUQuotaPerSecUSec", 500_000UL), new("CPUQuotaPeriodUSec", 100_000UL), new("CPUWeight", 100UL),
                new("MemoryMax", 64UL << 20), new("MemorySwapMax", 0UL), new("TasksMax", 16UL),
                new("ExecStartEx", new[] { new ExecCommand(command[0], command, false) }),
            ]);
            Assert.Equal("done", manager.WaitJob(job, bound));
            var state = await LinuxRunSystemd.ReadAsync(unit, cancellationToken);
            using var scope = LinuxRunSystemd.OpenOwnerScope(state);
            const string boundary = "fixture-boundary";

            RunResourceLimitReading Read() => Assert.IsType<RunResourceLimitReading>(scope.ReadOwnedLimits(boundary, state.OwnerPid, state.OwnerStartTicks));
            RunResourceWriteResult Apply(RunResourceDimension dimension, ulong value) => scope.ApplyOwnedLimit(dimension, value, state.OwnerPid, state.OwnerStartTicks);

            var initial = Read();
            Assert.Equal(boundary, initial.BoundaryIdentity);
            Assert.Equal(500UL, initial.CpuMillicores);
            Assert.Equal(64UL << 20, initial.MemoryBytes);
            Assert.Equal(16UL, initial.MaxProcesses);
            Assert.Equal(100UL, initial.CpuWeight);
            Assert.Equal(0UL, initial.SwapMaxBytes);

            Assert.Equal(RunResourceWriteStatus.ScopeLost,
                scope.ApplyOwnedLimit(RunResourceDimension.Cpu, 375, state.OwnerPid, state.OwnerStartTicks + 1).Status);
            Assert.Null(scope.ReadOwnedLimits(boundary, state.OwnerPid, state.OwnerStartTicks + 1));
            Assert.Equal(initial, Read());

            Assert.Equal(new(RunResourceWriteStatus.Applied, 250), Apply(RunResourceDimension.Cpu, 250));
            Assert.Equal("25000 100000", LinuxHarness.Read(ProcFs.CgroupRoot + scope.Path, "cpu.max"));
            Assert.Equal(new(RunResourceWriteStatus.Applied, 200), Apply(RunResourceDimension.CpuWeight, 200));
            Assert.Equal(new(RunResourceWriteStatus.Applied, 72UL << 20), Apply(RunResourceDimension.Memory, (72UL << 20) + 1));
            Assert.Equal("75497472", LinuxHarness.Read(ProcFs.CgroupRoot + scope.Path, "memory.max"));

            var refused = Apply(RunResourceDimension.Memory, 48UL << 20);
            Assert.Equal(RunResourceWriteStatus.Unsupported, refused.Status);
            Assert.Equal("linux_live_memory_reduction_unsafe", refused.Reason);
            Assert.Equal(RunResourceWriteStatus.Unsupported, Apply(RunResourceDimension.ProcessCount, 8).Status);
            Assert.Equal(RunResourceWriteStatus.Unsupported, Apply(RunResourceDimension.Swap, 4096).Status);
            Assert.Equal(new RunResourceLimitReading(boundary, 250, 72UL << 20, 16, 200, 0), Read());

            Assert.Equal("done", manager.WaitJob(manager.StopUnit(unit), bound));
            Assert.Null(scope.ReadOwnedLimits(boundary, state.OwnerPid, state.OwnerStartTicks));
            Assert.Equal(RunResourceWriteStatus.ScopeLost, Apply(RunResourceDimension.Cpu, 300).Status);
            Assert.True(scope.IsEmpty());
        }
        finally
        {
            if (manager.State(unit) is { ActiveState: not ("inactive" or "failed") })
            {
                Assert.Equal("done", manager.WaitJob(manager.StopUnit(unit), bound));
            }
        }
    }

    [Fact]
    public void TheNativeLimitNormalizerPreservesBounds()
    {
        var page = (ulong)Environment.SystemPageSize;
        Assert.Null(LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.Cpu, 9));
        Assert.Equal(10UL, LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.Cpu, 10));
        Assert.Null(LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.Memory, page - 1));
        Assert.Equal(page, LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.Memory, page + 1));
        Assert.Equal(0UL, LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.Swap, 0));
        Assert.Null(LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.Swap, page));
        Assert.Null(LinuxRunCgroup.NormalizeRunLimit(RunResourceDimension.CpuWeight, 10_001));
    }
}
