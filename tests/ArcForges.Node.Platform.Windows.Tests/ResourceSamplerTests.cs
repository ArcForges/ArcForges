// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// The Windows samplers of 03 section 1 against independent sources (env=windows-real; R-RES-001: memory within 2%, CPU within 5
/// percentage points): every field the process table of <c>NtQuerySystemInformation</c> reads at an undocumented offset against a
/// documented source (the Toolhelp snapshot for parents and images, <c>System.Diagnostics.Process</c> for the start and processor
/// times, <c>GetProcessMemoryInfo</c> for the private working set and <c>GetProcessIoCounters</c> for the transfer counts), and the
/// machine CPU of a busy thread.
/// </summary>
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed partial class ResourceSamplerTests
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

        // Some I/O of this process, so the transfer counts are not trivially zero; the documented counters are read before and after the table.
        var file = Path.Combine(Path.GetTempPath(), $"arcforges-sampler-{Environment.ProcessId}-{Guid.NewGuid():N}");
        File.WriteAllBytes(file, new byte[4 << 20]);
        _ = File.ReadAllBytes(file);
        File.Delete(file);
        // Capture the reference identities before the table, then require every one still running afterwards. The PID alone is
        // insufficient: short-lived processes can start or exit between reads, and a PID can be reused.
        var toolhelp = ProcessInfo.Snapshot();
        var references = toolhelp.Where(process => process.Pid != 0)
            .Select(process => (Process: process, Identity: ArcForges.Tests.ProcessIdentity.Capture(process.Pid)))
            .Where(reference => reference.Identity is not null).ToList();
        Assert.Contains(references, reference => reference.Process.Pid == Environment.ProcessId);
        var (ioBefore, privateBefore) = (Io(), PrivateWorkingSet());
        var table = sampler.Processes();
        var (ioAfter, privateAfter) = (Io(), PrivateWorkingSet());
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
        Assert.InRange(entry.MemoryBytes, Math.Min(privateBefore, privateAfter) - (16 << 20), Math.Max(privateBefore, privateAfter) + (16 << 20));
        GC.KeepAlive(held);

        // The transfer counts lie between the documented counters read just before and just after the table.
        Assert.True(ioBefore.WriteTransferCount >= 4 << 20 && ioBefore.ReadTransferCount >= 4 << 20, "the test's own 4 MiB write and read");
        Assert.InRange((ulong)entry.IoReadBytes!.Value, ioBefore.ReadTransferCount, ioAfter.ReadTransferCount);
        Assert.InRange((ulong)entry.IoWriteBytes!.Value, ioBefore.WriteTransferCount, ioAfter.WriteTransferCount);

        // Queryable identities that existed before the table and still run afterwards must all be present, with no tolerance.
        // Protected processes whose creation cannot be read cannot form a stable reference; System is checked explicitly below.
        var ids = table.Select(process => process.Pid).ToHashSet();
        var missing = references.Where(reference => reference.Identity is { } identity && identity.IsRunning() && !ids.Contains(identity.Pid))
            .Select(reference => $"{reference.Process.Image} ({reference.Identity})").ToList();
        Assert.Empty(missing);
        Assert.Contains(table, process => process.Pid == 4 && process.Image == "System");

        // VM workers, when a WSL VM runs, are found by name (A-L01).
        foreach (var worker in table.Where(process => VmProcesses.IsWorker(process.Image)))
        {
            TestContext.Current.TestOutputHelper?.WriteLine($"VM worker {worker.Image} ({worker.Pid}): private working set {worker.MemoryBytes}, CPU {worker.CpuTimeMs} ms");
        }
    }

    private static IoCounters Io()
    {
        Assert.True(GetProcessIoCounters(GetCurrentProcess(), out var counters), $"GetProcessIoCounters: {Marshal.GetLastPInvokeError()}");
        return counters;
    }

    private static long PrivateWorkingSet()
    {
        var counters = new ProcessMemoryCountersEx2 { Size = (uint)Marshal.SizeOf<ProcessMemoryCountersEx2>() };
        Assert.True(K32GetProcessMemoryInfo(GetCurrentProcess(), ref counters, counters.Size), $"GetProcessMemoryInfo: {Marshal.GetLastPInvokeError()}");
        return (long)counters.PrivateWorkingSetSize;
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessIoCounters(nint process, out IoCounters counters);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool K32GetProcessMemoryInfo(nint process, ref ProcessMemoryCountersEx2 counters, uint size);

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    /// <summary>PROCESS_MEMORY_COUNTERS_EX2 (Windows 10 1809 and later), whose PrivateWorkingSetSize is the table's figure.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMemoryCountersEx2
    {
        public uint Size;
        public uint PageFaultCount;
        public nuint PeakWorkingSetSize;
        public nuint WorkingSetSize;
        public nuint QuotaPeakPagedPoolUsage;
        public nuint QuotaPagedPoolUsage;
        public nuint QuotaPeakNonPagedPoolUsage;
        public nuint QuotaNonPagedPoolUsage;
        public nuint PagefileUsage;
        public nuint PeakPagefileUsage;
        public nuint PrivateUsage;
        public nuint PrivateWorkingSetSize;
        public ulong SharedCommitUsage;
    }
}
