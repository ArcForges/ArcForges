// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Node.Platform.Windows.Mxc;

namespace ArcForges.Node.Platform.Windows.Tests;

[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class ResourceRunJobTests
{
    [Fact(Timeout = 45_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task HeldJobReportsNativeCpuCountAndPeakCommitIndependentlyOfPrivateResidentBytes()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows Job accounting.");
        var cancellationToken = TestContext.Current.CancellationToken;
        var bound = TimeSpan.FromSeconds(12);
        const ulong allocatedBytes = 48UL << 20;
        var root = Directory.CreateTempSubdirectory("arcforges-run-job-");
        var release = Path.Combine(root.FullName, "release");
        var report = Path.Combine(root.FullName, "allocation.json");
        using var job = WindowsMxcJob.Create(new WindowsMxcJobLimits(10_000, 512L << 20, 8));
        try
        {
            var empty = Assert.IsType<RunResourceObservation>(job.ObserveResources());
            Assert.Equal(RunMemoryAccounting.WindowsCommit, empty.Accounting);
            Assert.Equal(0u, empty.ProcessCount);
            Assert.Equal(0ul, empty.ResidentBytes);
            Assert.Null(empty.MemoryBytes);

            var configuredImage = Environment.GetEnvironmentVariable("ARCFORGES_TESTLOAD_PATH");
            var explicitImage = !string.IsNullOrEmpty(configuredImage);
            var image = explicitImage ? configuredImage : Path.Combine(AppContext.BaseDirectory, "arcforges-testload.exe");
            Assert.NotNull(image);
            Assert.True(Path.IsPathFullyQualified(image) && File.Exists(image), "TestLoad must be an existing absolute executable path.");
            var environment = WindowsMxcProcess.TrustedEnvironment(root.FullName).ToList();
            if (!explicitImage)
            {
                // The adjacent framework-dependent apphost needs the test runner's .NET location.
                environment.Add("DOTNET_DISABLE_GUI_ERRORS=1");
                foreach (var name in new[] { "DOTNET_ROOT", "DOTNET_ROOT_X64" })
                {
                    if (Environment.GetEnvironmentVariable(name) is { Length: > 0 } value)
                    {
                        environment.Add(name + "=" + value);
                    }
                }
            }

            using var process = WindowsMxcProcess.CreateSuspended(image,
                ["mem-ramp", "--target-mb", "48", "--step-mb", "16", "--hold-ms", "30000", "--until-file", release, "--report", report],
                root.FullName, environment, job);
            try
            {
                job.RequireMember(process);
                WindowsMxcProcess.Resume(process);
                var observationStarted = Stopwatch.GetTimestamp();
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Assert.False(process.WaitForExit(TimeSpan.Zero), $"TestLoad exited before measurement (0x{process.ExitCode:x8}).");
                    if ((ulong)job.Observe().Accounting.PeakJobMemory >= allocatedBytes
                        && job.ObserveResources() is { ResidentBytes: > 0 })
                    {
                        break;
                    }

                    Assert.True(Stopwatch.GetElapsedTime(observationStarted) < bound,
                        "Timed out waiting for the held TestLoad's native Job commit and resident observations.");
                    await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken);
                }

                var sampler = new WindowsResourceSampler();
                var residentBefore = ReadPrivateResident(sampler, process);
                var started = Stopwatch.GetTimestamp();
                var before = job.Observe();
                var current = Assert.IsType<RunResourceObservation>(job.ObserveResources());
                var after = job.Observe();
                var sampleElapsed = Stopwatch.GetElapsedTime(started);
                var residentAfter = ReadPrivateResident(sampler, process);
                Assert.Equal(process.ProcessId, Assert.Single(before.ProcessIds));
                Assert.Equal(process.ProcessId, Assert.Single(after.ProcessIds));
                Assert.Equal(1u, current.ProcessCount);
                Assert.Null(current.MemoryBytes);
                var resident = Assert.IsType<ulong>(current.ResidentBytes);
                const long residentTolerance = 16L << 20;
                Assert.InRange(resident, (ulong)Math.Max(1, Math.Min(residentBefore, residentAfter) - residentTolerance),
                    (ulong)(Math.Max(residentBefore, residentAfter) + residentTolerance));
                Assert.InRange(Assert.IsType<ulong>(current.PeakMemoryBytes),
                    (ulong)before.Accounting.PeakJobMemory, (ulong)after.Accounting.PeakJobMemory);
                Assert.InRange(Assert.IsType<ulong>(current.CumulativeCpuUsec), CpuUsec(before), CpuUsec(after));
                Assert.True(current.CumulativeCpuUsec > 0);
                var output = TestContext.Current.TestOutputHelper;
                output?.WriteLine(FormattableString.Invariant(
                    $"Windows held Job sample with two native references: {sampleElapsed.TotalMilliseconds:F3} ms. Selected TestLoad override {explicitImage}."));
                output?.WriteLine(FormattableString.Invariant(
                    $"Live Job peak {current.PeakMemoryBytes} bytes, CPU {current.CumulativeCpuUsec} usec, resident {resident} bytes, native process resident {residentBefore}/{residentAfter} bytes."));

                VerifyNativeLimitUpdates(job);

                File.WriteAllText(release, "release");
                Assert.True(process.WaitForExit(bound));
                Assert.Equal(0u, process.ExitCode);
                using (var allocation = JsonDocument.Parse(File.ReadAllBytes(report)))
                {
                    Assert.Equal(allocatedBytes, allocation.RootElement.GetProperty("results").GetProperty("allocatedBytes").GetUInt64());
                }

                _ = await job.WaitForDrainAsync(null, bound, cancellationToken);

                var drained = Assert.IsType<RunResourceObservation>(job.ObserveResources());
                Assert.Equal(0u, drained.ProcessCount);
                Assert.Equal(0ul, drained.ResidentBytes);
                Assert.True(drained.CumulativeCpuUsec >= current.CumulativeCpuUsec);
                Assert.True(drained.PeakMemoryBytes >= current.PeakMemoryBytes);
                Assert.Null(drained.MemoryBytes);
            }
            finally
            {
                if (!process.WaitForExit(TimeSpan.Zero))
                {
                    job.Terminate();
                    Assert.True(process.WaitForExit(bound));
                }
            }
        }
        finally
        {
            File.Delete(release);
            File.Delete(report);
            root.Delete();
        }

        job.Dispose();
        Assert.Null(job.ObserveResources());
    }

    private static void VerifyNativeLimitUpdates(WindowsMxcJob job)
    {
        var processors = WindowsMxcProcess.ResourceProcessorCount();
        var previous = job.ReadResourceLimits();
        const ulong requestedCpu = 501;
        var rate = Assert.IsType<int>(WindowsMxcProcess.ResourceCpuRate(requestedCpu, processors));
        var normalizedCpu = Assert.IsType<ulong>(WindowsMxcJob.NormalizeResourceLimit(RunResourceDimension.Cpu, requestedCpu, processors));
        Assert.InRange(normalizedCpu, 1ul, requestedCpu);
        Assert.Equal(normalizedCpu, WindowsMxcJob.NormalizeResourceLimit(RunResourceDimension.Cpu, normalizedCpu, processors));
        Assert.Null(WindowsMxcProcess.ResourceCpuRate(1, 18));
        Assert.Null(WindowsMxcProcess.ResourceCpuRate(18_001, 18));
        Assert.Equal(new RunResourceWriteResult(RunResourceWriteStatus.Applied, normalizedCpu),
            job.ApplyResourceLimit(RunResourceDimension.Cpu, requestedCpu, processors));
        var cpuChanged = previous with { CpuRate = rate };
        Assert.Equal(cpuChanged, job.ReadResourceLimits());

        const ulong commit = 640UL << 20;
        Assert.Equal(new RunResourceWriteResult(RunResourceWriteStatus.Applied, commit),
            job.ApplyResourceLimit(RunResourceDimension.Memory, commit + 1, processors));
        var enlarged = cpuChanged with { CommitBytes = (long)commit };
        Assert.Equal(enlarged, job.ReadResourceLimits());
        Assert.Equal(new RunResourceWriteResult(RunResourceWriteStatus.Unsupported, Reason: "windows_commit_reduction_unverified"),
            job.ApplyResourceLimit(RunResourceDimension.Memory, (ulong)previous.CommitBytes, processors));
        Assert.Equal(RunResourceWriteStatus.Unsupported,
            job.ApplyResourceLimit(RunResourceDimension.ProcessCount, 1, processors).Status);

        // Match the supervisor's actual query-only Job authority and exercise a real denied setter.
        const uint jobQuery = 4;
        var current = Native.GetCurrentProcess();
        Assert.True(Native.DuplicateHandle(current, job.Handle, current, out var query, jobQuery, inherit: false, options: 0));
        using var queryOnly = JobObject.FromHandle(query, null);
        Assert.Equal((uint)rate, queryOnly.CpuRateControl().Value);
        var refused = Assert.Throws<Win32Exception>(() => queryOnly.SetCpuHardCap(rate + 1));
        Assert.Equal("win32:5", WindowsRunLauncher.NativeCode(refused));
        Assert.Equal(enlarged, job.ReadResourceLimits());
        job.RequireLimits(enlarged);
    }

    private static ulong CpuUsec(WindowsMxcJobObservation value) =>
        (ulong)(value.Accounting.UserTime + value.Accounting.KernelTime).Ticks / 10;

    private static long ReadPrivateResident(WindowsResourceSampler sampler, LaunchedProcess process)
    {
        var child = Assert.Single(sampler.Processes(), item =>
            item.Pid == process.ProcessId && item.StartTime.UtcDateTime.ToFileTimeUtc() == process.CreationFileTime);
        Assert.True(child.MemoryBytes > 0);
        return child.MemoryBytes;
    }
}
