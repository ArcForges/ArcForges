// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
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
        try
        {
            await StartFixtureUnitAsync(unit, cancellationToken);
            var (state, ownedScope) = await LinuxRunSystemd.WaitForReadyAsync(unit, cancellationToken);
            using var scope = ownedScope;
            var cgroup = ProcFs.CgroupRoot + scope.Path;
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
            Assert.Equal("25000 100000", File.ReadAllText(Path.Combine(cgroup, "cpu.max")).TrimEnd('\n'));
            Assert.Equal(new(RunResourceWriteStatus.Applied, 200), Apply(RunResourceDimension.CpuWeight, 200));
            Assert.Equal(new(RunResourceWriteStatus.Applied, 72UL << 20), Apply(RunResourceDimension.Memory, (72UL << 20) + 1));
            Assert.Equal("75497472", File.ReadAllText(Path.Combine(cgroup, "memory.max")).TrimEnd('\n'));

            var refused = Apply(RunResourceDimension.Memory, 48UL << 20);
            Assert.Equal(RunResourceWriteStatus.Unsupported, refused.Status);
            Assert.Equal("linux_live_memory_reduction_unsafe", refused.Reason);
            Assert.Equal(RunResourceWriteStatus.Unsupported, Apply(RunResourceDimension.ProcessCount, 8).Status);
            Assert.Equal(RunResourceWriteStatus.Unsupported, Apply(RunResourceDimension.Swap, 4096).Status);
            Assert.Equal(new RunResourceLimitReading(boundary, 250, 72UL << 20, 16, 200, 0), Read());

            await LinuxRunSystemd.StopAsync(state, scope, cancellationToken);
            Assert.Null(scope.ReadOwnedLimits(boundary, state.OwnerPid, state.OwnerStartTicks));
            Assert.Equal(RunResourceWriteStatus.ScopeLost, Apply(RunResourceDimension.Cpu, 300).Status);
            Assert.True(scope.IsEmpty());
        }
        finally
        {
            var (exitCode, diagnostic) = SystemdTestEnvironment.Systemctl("stop", "--", unit);
            Assert.True(exitCode == 0 || SystemdTestEnvironment.Property(unit, "LoadState") == "not-found", diagnostic);
        }
    }

    private static async Task StartFixtureUnitAsync(string unit, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo("/usr/bin/systemd-run",
        [
            "--user", "--quiet", "--service-type=exec", "--unit=" + unit, "--description=ArcForges V2 Run " + unit,
            "--property=Restart=no", "--property=KillMode=control-group", "--property=Delegate=yes",
            "--property=CPUAccounting=yes", "--property=MemoryAccounting=yes", "--property=TasksAccounting=yes",
            "--property=CPUQuota=50%", "--property=CPUQuotaPeriodSec=100ms", "--property=CPUWeight=100",
            "--property=MemoryMax=67108864", "--property=MemorySwapMax=0", "--property=TasksMax=16",
            "--", "/usr/bin/sleep", "60",
        ])
        {
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var process = Process.Start(start)!;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        var diagnostic = process.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            await process.WaitForExitAsync(deadline.Token);
            Assert.True(process.ExitCode == 0, await diagnostic);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
            {
                process.Kill();
            }

            throw;
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
