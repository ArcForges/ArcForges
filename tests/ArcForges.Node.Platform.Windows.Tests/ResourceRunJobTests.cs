// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using ArcForges.Node.Platform.Windows.Mxc;

namespace ArcForges.Node.Platform.Windows.Tests;

[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class ResourceRunJobTests
{
    [Fact(Timeout = 45_000)]
    public async Task HeldJobReportsNativeCpuCountAndPeakCommitIndependentlyOfPrivateResidentBytes()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows Job accounting.");
        var cancellationToken = TestContext.Current.CancellationToken;
        var bound = TimeSpan.FromSeconds(12);
        const ulong workingSet = 48UL << 20;
        var root = Directory.CreateTempSubdirectory("arcforges-run-job-");
        var release = Path.Combine(root.FullName, "release");
        using var job = WindowsMxcJob.Create(new WindowsMxcJobLimits(10_000, 512L << 20, 8));
        try
        {
            var empty = Assert.IsType<RunResourceObservation>(job.ObserveResources());
            Assert.Equal(RunMemoryAccounting.WindowsCommit, empty.Accounting);
            Assert.Equal(0u, empty.ProcessCount);
            Assert.Equal(0ul, empty.ResidentBytes);
            Assert.Null(empty.MemoryBytes);

            var image = TestPrograms.TestLoad;
            using var process = WindowsMxcProcess.CreateSuspended(image,
                ["mem-ramp", "--target-mb", "48", "--step-mb", "16", "--hold-ms", "30000", "--until-file", release],
                root.FullName, WindowsMxcProcess.TrustedEnvironment(root.FullName), job);
            try
            {
                job.RequireMember(process);
                WindowsMxcProcess.Resume(process);
                PlatformHarness.WaitFor(() => job.ObserveResources() is { ResidentBytes: >= workingSet }, bound,
                    "the held Job's touched private working set");
                var started = Stopwatch.GetTimestamp();
                var before = job.Observe();
                var current = Assert.IsType<RunResourceObservation>(job.ObserveResources());
                var after = job.Observe();
                var sampleElapsed = Stopwatch.GetElapsedTime(started);
                Assert.Equal(process.ProcessId, Assert.Single(before.ProcessIds));
                Assert.Equal(process.ProcessId, Assert.Single(after.ProcessIds));
                Assert.Equal(1u, current.ProcessCount);
                Assert.Null(current.MemoryBytes);
                Assert.InRange(Assert.IsType<ulong>(current.ResidentBytes), workingSet, ulong.MaxValue);
                Assert.InRange(Assert.IsType<ulong>(current.PeakMemoryBytes),
                    (ulong)before.Accounting.PeakJobMemory, (ulong)after.Accounting.PeakJobMemory);
                Assert.InRange(Assert.IsType<ulong>(current.CumulativeCpuUsec), CpuUsec(before), CpuUsec(after));
                Assert.True(current.CumulativeCpuUsec > 0);
                TestContext.Current.TestOutputHelper?.WriteLine($"Windows held Job sample with two native references: {sampleElapsed.TotalMilliseconds:F3} ms.");

                File.WriteAllText(release, "release");
                Assert.True(process.WaitForExit(bound));
                Assert.Equal(0u, process.ExitCode);
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
            root.Delete();
        }

        job.Dispose();
        Assert.Null(job.ObserveResources());
    }

    private static ulong CpuUsec(WindowsMxcJobObservation value) =>
        (ulong)(value.Accounting.UserTime + value.Accounting.KernelTime).Ticks / 10;
}
