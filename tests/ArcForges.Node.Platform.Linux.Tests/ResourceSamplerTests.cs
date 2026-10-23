// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Linux.Tests;

/// <summary>
/// The Linux samplers of 03 section 1 against the kernel's own figures (env=linux-real; R-RES-001: memory within 2%, CPU within 5
/// percentage points): <c>/proc/meminfo</c> read by the test, a busy thread's processor time, and this process's entry in the process
/// table against <c>System.Diagnostics.Process</c>.
/// </summary>
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class ResourceSamplerTests
{
    [Fact]
    public void MachineMemoryMatchesProcMeminfo()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux sampler.");
        var sampler = new LinuxResourceSampler();
        var sample = sampler.Machine();
        var meminfo = File.ReadAllLines("/proc/meminfo").Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .ToDictionary(fields => fields[0].TrimEnd(':'), fields => long.Parse(fields[1], CultureInfo.InvariantCulture) * 1024);
        Assert.Equal(meminfo["MemTotal"], sample.TotalMemoryBytes);
        Assert.InRange(sample.AvailableMemoryBytes, meminfo["MemAvailable"] - (meminfo["MemTotal"] / 50), meminfo["MemAvailable"] + (meminfo["MemTotal"] / 50));
        Assert.Equal(meminfo["Committed_AS"], sample.CommitBytes, (double)meminfo["MemTotal"] / 50);
        Assert.Equal(meminfo["CommitLimit"], sample.CommitLimitBytes);
        Assert.InRange(sample.SwapUsedBytes, 0, meminfo["SwapTotal"]);
        Assert.True(sample.CpuBusyMs > 0 && sample.CpuBusyMs <= sample.CpuTotalMs);
        if (File.Exists("/proc/pressure/memory"))
        {
            Assert.NotNull(sample.Pressure);
            Assert.InRange(sample.Pressure!.MemorySome, 0, 100);
        }

        Assert.True(sample.OomKills >= 0);
    }

    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public void ABusyThreadShowsInTheMachineCpu()
    {
        // isolation=exclusive: a CPU share measurement. One thread spinning for 2 s is one core: at least 0.95 cores of busy time above the
        // idle machine's share would be the exact figure; the bound allows the 5 percentage points of R-RES-001 per core.
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux sampler.");
        var sampler = new LinuxResourceSampler();
        var before = sampler.Machine();
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < TimeSpan.FromSeconds(2))
        {
            Thread.SpinWait(1_000);
        }

        var after = sampler.Machine();
        var busyCores = (after.CpuBusyMs - before.CpuBusyMs) / watch.Elapsed.TotalMilliseconds;
        var totalCores = (after.CpuTotalMs - before.CpuTotalMs) / watch.Elapsed.TotalMilliseconds;
        Assert.InRange(totalCores, Environment.ProcessorCount * 0.9, Environment.ProcessorCount * 1.1);
        Assert.True(busyCores >= 0.95 - (0.05 * Environment.ProcessorCount), $"busy {busyCores:0.00} cores while one thread spun");
    }

    [Fact]
    public void ThisProcessIsInTheTableWithItsIdentityTimesAndMemory()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux sampler.");
        var sampler = new LinuxResourceSampler();
        using var self = Process.GetCurrentProcess();
        var held = GC.AllocateUninitializedArray<byte>(64 << 20);
        Array.Fill(held, (byte)1);
        var entry = Assert.Single(sampler.Processes(), process => process.Pid == Environment.ProcessId);
        var stat = File.ReadAllText($"/proc/{Environment.ProcessId}/stat");
        var parent = int.Parse(stat[(stat.LastIndexOf(')') + 2)..].Split(' ')[1], CultureInfo.InvariantCulture);
        Assert.Equal(parent, entry.ParentPid);
        Assert.InRange((entry.StartTime - self.StartTime.ToUniversalTime()).Duration(), TimeSpan.Zero, TimeSpan.FromSeconds(1.5));
        self.Refresh();
        Assert.InRange(entry.CpuTimeMs, self.TotalProcessorTime.TotalMilliseconds - 300, self.TotalProcessorTime.TotalMilliseconds + 300);
        Assert.True(entry.MemoryBytes >= 64 << 20, $"RSS {entry.MemoryBytes}");

        // The detail: private resident memory (RssAnon + RssShmem) holds the touched array; this process's own I/O and executable are readable.
        var detail = sampler.Detail(entry);
        Assert.True(detail.MemoryBytes >= 64 << 20 && detail.MemoryBytes <= entry.MemoryBytes, $"private {detail.MemoryBytes}, RSS {entry.MemoryBytes}");
        Assert.NotNull(detail.IoReadBytes);
        Assert.NotNull(detail.IoWriteBytes);
        Assert.Equal(Path.GetFileName(Environment.ProcessPath), detail.Executable);
        GC.KeepAlive(held);

        // A process of another user (PID 1) is listed; its I/O is never read as zero.
        var init = sampler.Processes().FirstOrDefault(process => process.Pid == 1);
        if (init is not null && ProcFs.OwnerOf(1) != ProcFs.UserId)
        {
            Assert.Null(sampler.Detail(init).IoReadBytes);
        }
    }
}
