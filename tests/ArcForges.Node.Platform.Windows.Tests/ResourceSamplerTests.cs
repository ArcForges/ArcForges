// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// The Windows samplers of 03 section 1 against independent sources (env=windows-real; R-RES-001: memory within 2%, CPU within 5
/// percentage points): the process table of <c>NtQuerySystemInformation</c> against the Toolhelp snapshot (parents and images) and
/// <c>System.Diagnostics.Process</c> (start time, processor time, working set), and the machine CPU of a busy thread.
/// </summary>
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class ResourceSamplerTests
{
    [Fact]
    public void MachineMemoryAndCommitAreRead()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows sampler.");
        var sample = new WindowsResourceSampler().Machine();
        Assert.Equal(ProcessInfo.PhysicalMemory(), sample.TotalMemoryBytes);
        Assert.InRange(sample.AvailableMemoryBytes, 1, sample.TotalMemoryBytes);
        Assert.InRange(sample.CommitBytes, 1, sample.CommitLimitBytes);
        Assert.True(sample.CpuBusyMs > 0 && sample.CpuBusyMs <= sample.CpuTotalMs);
        Assert.Null(sample.Pressure);
        Assert.Equal(0, sample.OomKills);
    }

    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public void ABusyThreadShowsInTheMachineCpu()
    {
        // isolation=exclusive: a CPU share measurement (one spinning thread is one core, within 5 percentage points per core).
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows sampler.");
        var sampler = new WindowsResourceSampler();
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
    public void TheTableMatchesToolhelpAndTheProcessApi()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows sampler.");
        var sampler = new WindowsResourceSampler();
        var held = GC.AllocateUninitializedArray<byte>(64 << 20);
        Array.Fill(held, (byte)1);
        var table = sampler.Processes();
        var toolhelp = ProcessInfo.Snapshot();
        using var self = Process.GetCurrentProcess();
        var entry = Assert.Single(table, process => process.Pid == Environment.ProcessId);
        var reference = toolhelp.Single(process => process.Pid == Environment.ProcessId);
        Assert.Equal(reference.ParentPid, entry.ParentPid);
        Assert.Equal(reference.Image, entry.Image, StringComparer.OrdinalIgnoreCase);
        Assert.InRange((entry.StartTime - self.StartTime.ToUniversalTime()).Duration(), TimeSpan.Zero, TimeSpan.FromMilliseconds(20));
        self.Refresh();
        Assert.InRange(entry.CpuTimeMs, self.TotalProcessorTime.TotalMilliseconds - 300, self.TotalProcessorTime.TotalMilliseconds + 300);

        // The private working set holds the touched array, and is part of the whole working set.
        Assert.True(entry.MemoryBytes >= 64 << 20, $"private working set {entry.MemoryBytes}");
        Assert.True(entry.MemoryBytes <= self.WorkingSet64 + (16 << 20), $"private working set {entry.MemoryBytes}, working set {self.WorkingSet64}");
        Assert.NotNull(entry.IoReadBytes);
        GC.KeepAlive(held);

        // Every process Toolhelp lists (but for the idle process, and those that started or exited between the two reads) is in the table.
        var ids = table.Select(process => process.Pid).ToHashSet();
        var missing = toolhelp.Where(process => process.Pid != 0 && !ids.Contains(process.Pid)).ToList();
        Assert.True(missing.Count <= 5, $"missing from the table: {string.Join(", ", missing.Select(process => $"{process.Image} ({process.Pid})"))}");
        Assert.Contains(table, process => process.Pid == 4 && process.Image == "System");

        // VM workers, when a WSL VM runs, are found by name (A-L01).
        foreach (var worker in table.Where(process => VmProcesses.IsWorker(process.Image)))
        {
            TestContext.Current.TestOutputHelper?.WriteLine($"VM worker {worker.Image} ({worker.Pid}): private working set {worker.MemoryBytes}, CPU {worker.CpuTimeMs} ms");
        }
    }
}
