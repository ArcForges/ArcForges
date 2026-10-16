// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// F-W01 (AD-0005 Windows; R-RES-006): real job objects created and limited by an unprivileged process: attempt jobs nested under the
/// root job by root-then-child assignment through a real holder outside the jobs, the root hard CPU cap with weighted attempt jobs,
/// commit limits on attempts and on the root, killing the whole tree, no breakaway, and kill-on-close for <c>kill_with_node</c>
/// attempts. Each test reports whether it ran elevated (the workstation runs them non-elevated; hosted runners are administrators).
/// </summary>
[Trait("env", "windows-real")]
[Collection(SerialPlatformTests.Name)]
[SupportedOSPlatform("windows")]
public sealed class JobTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(30);

    [Fact(Timeout = 120_000)]
    public async Task AttemptJobsNestUnderTheRootJobAndTheHolderRunsOutsideBoth()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job objects.");
        Report();
        using var harness = PlatformHarness.Start();
        var marker = Path.Combine(harness.Root, "marker.txt");
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--hold-ms", "60000", "--marker", marker]);
        await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        var root = handle.Root ?? throw new InvalidOperationException("The holder did not report the root process.");
        PlatformHarness.WaitFor(() => PlatformHarness.Marker(marker).Any(line => line.Event == "ready"), Bound, "the workload to be ready");

        using (var process = ProcessInfo.Open(root.Pid)!)
        using (var holder = ProcessInfo.Open(handle.Holder!.ProcessId)!)
        {
            Assert.True(handle.Job.Contains(process), "The root process is in its attempt job.");
            Assert.True(harness.Platform.RootJob!.Contains(process), "The root process is in the root job.");
            Assert.False(handle.Job.Contains(holder), "The holder runs outside the attempt job.");
            Assert.False(harness.Platform.RootJob.Contains(holder), "The holder runs outside the root job.");
        }

        // The child job is nested in the root: the root's accounting includes it, and ending the root ends the child's processes (V-W02).
        Assert.True(harness.Platform.RootJob!.Accounting().ActiveProcesses >= 1);
        Assert.True(harness.Platform.RootJob.Terminate(AttemptRunner.TerminatedExitCode));
        var rootProcess = PlatformHarness.Identity(root);
        PlatformHarness.WaitFor(() => !rootProcess.IsRunning(), TimeSpan.FromSeconds(5), "the nested attempt to end with the root job");
        var exit = harness.WaitExit(handle, Bound);
        Assert.Equal((int)AttemptRunner.TerminatedExitCode, exit.ExitStatus);
    }

    [Fact(Timeout = 180_000)]
    public async Task TheRootHardCapBoundsWeightedAttemptJobs()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows CPU rate control.");
        Report();
        const int RootRate = 2_500;
        using var harness = PlatformHarness.Start(new RootLimits(RootRate, 16L << 30, 16L << 30));
        var threads = Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture);
        var heavy = harness.Launch([TestPrograms.TestLoad, "cpu", "--threads", threads, "--iterations", "20000000000"], new ContainerLimits { CpuWeight = 9 });
        var light = harness.Launch([TestPrograms.TestLoad, "cpu", "--threads", threads, "--iterations", "20000000000"], new ContainerLimits { CpuWeight = 1 });
        await heavy.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        await light.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        Assert.Equal((Native.CpuRateControlEnable | Native.CpuRateControlWeightBased, 9u), heavy.Job.CpuRateControl());
        Assert.Equal((Native.CpuRateControlEnable | Native.CpuRateControlWeightBased, 1u), light.Job.CpuRateControl());
        Assert.Equal((Native.CpuRateControlEnable | Native.CpuRateControlHardCap, (uint)RootRate), harness.Platform.RootJob!.CpuRateControl());

        Thread.Sleep(1_000);
        var rootBefore = Cpu(harness.Platform.RootJob.Accounting());
        var heavyBefore = Cpu(heavy.Job.Accounting());
        var lightBefore = Cpu(light.Job.Accounting());
        var window = Stopwatch.StartNew();
        Thread.Sleep(5_000);
        var elapsed = window.Elapsed;
        var rootUsed = Cpu(harness.Platform.RootJob.Accounting()) - rootBefore;
        var heavyUsed = Cpu(heavy.Job.Accounting()) - heavyBefore;
        var lightUsed = Cpu(light.Job.Accounting()) - lightBefore;
        var machineShare = rootUsed / (elapsed * Environment.ProcessorCount);
        TestContext.Current.TestOutputHelper?.WriteLine(
            $"root share {machineShare:P1} of the machine (cap {RootRate / 100.0:0.#}%); weight 9: {heavyUsed.TotalSeconds:0.00} s, weight 1: {lightUsed.TotalSeconds:0.00} s");

        // The cap holds (with the scheduler's accounting tolerance), and the weighted attempts share it in favour of the heavier one.
        Assert.True(machineShare <= RootRate / 10_000.0 * 1.15 + 0.01, $"The root used {machineShare:P1} of the machine under a {RootRate / 100.0}% cap.");
        Assert.True(machineShare >= RootRate / 10_000.0 * 0.5, $"The root used only {machineShare:P1}; the load did not saturate the cap.");
        Assert.True(heavyUsed > lightUsed * 2, $"Weight 9 got {heavyUsed.TotalSeconds:0.00} s against weight 1's {lightUsed.TotalSeconds:0.00} s.");
    }

    /// <summary>
    /// The job, not the workload's runtime, must refuse the commit (V-W05). Inside a job with a memory limit the .NET GC sets its own
    /// heap hard limit to 75% of that limit and throws <see cref="OutOfMemoryException"/> there, before the job refuses anything (a hosted
    /// run ended at 167.5 MiB under a 256 MiB limit, below the 170.7 MiB notification limit, so nothing was classified). The mem-ramp
    /// workload therefore runs with its heap limit lifted to 3 GiB (hex without 0x, the form the JIT runtime and Native AOT both read).
    /// </summary>
    private static readonly Dictionary<string, string> LiftedHeapLimit = WithEnvironment("DOTNET_GCHeapHardLimit", "C0000000");

    [Fact(Timeout = 120_000)]
    public void AnAttemptNeverCommitsBeyondItsCommitLimit()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job commit limits.");
        Report();
        const long Limit = 256L << 20;
        const long Step = 32L << 20;
        using var harness = PlatformHarness.Start();
        var handle = harness.Launch([TestPrograms.TestLoad, "mem-ramp", "--target-mb", "1024", "--step-mb", "32"],
            new ContainerLimits { CommitLimitBytes = Limit, CommitNotificationBytes = Limit * 2 / 3 }, environment: LiftedHeapLimit);
        using var sampler = new CommitSampler(handle.Job);
        var exit = harness.WaitExit(handle, Bound);
        TestContext.Current.TestOutputHelper?.WriteLine(
            $"exit {exit.ExitStatus}, sampled commit max {sampler.Max} and peak {exit.MemPeakBytes} of {Limit}, violations [{string.Join(",", exit.LimitViolations)}], limit event {handle.MemoryLimitHit}");

        // The refused allocation fails the attempt; the committed memory never passes the limit.
        Assert.NotEqual(0, exit.ExitStatus);
        Assert.True(sampler.Max <= Limit, $"The attempt committed {sampler.Max}, over its limit {Limit}.");

        // PeakJobMemoryUsed counts a refused request before refusing it, so it may pass the limit by at most one request (one step), and it
        // reaches the limit only when the job refused: a peak far below it means something else (the runtime) stopped the workload.
        Assert.True(exit.MemPeakBytes <= Limit + Step, $"Peak commit {exit.MemPeakBytes} is more than one request over the limit {Limit}.");
        Assert.True(exit.MemPeakBytes >= Limit - Step, $"Peak commit {exit.MemPeakBytes} never reached the limit {Limit}: the job did not refuse the workload.");

        // The holder's exit record classifies the violation from the job's peak accounting, which covers exited processes (V-W03); the
        // completion-port limit message (MemoryLimitHit) is not guaranteed and is only reported above.
        Assert.Contains("job_memory", exit.LimitViolations);
    }

    [Fact(Timeout = 120_000)]
    public void TheRootCommitLimitBoundsAllAttemptsTogether()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job commit limits.");
        Report();
        const long RootLimit = 384L << 20;
        using var harness = PlatformHarness.Start(new RootLimits(10_000, RootLimit, RootLimit));
        // Each attempt alone fits its own 512 MiB limit; together they exceed the root's 384 MiB, so only the root can refuse (the heap
        // limit is lifted as in AnAttemptNeverCommitsBeyondItsCommitLimit, or the runtime would stop each workload at 384 MiB itself).
        var first = harness.Launch([TestPrograms.TestLoad, "mem-ramp", "--target-mb", "300", "--step-mb", "20", "--hold-ms", "4000"],
            new ContainerLimits { CommitLimitBytes = 512L << 20 }, environment: LiftedHeapLimit);
        var second = harness.Launch([TestPrograms.TestLoad, "mem-ramp", "--target-mb", "300", "--step-mb", "20", "--step-ms", "50", "--hold-ms", "4000"],
            new ContainerLimits { CommitLimitBytes = 512L << 20 }, environment: LiftedHeapLimit);
        using var sampler = new CommitSampler(harness.Platform.RootJob!);
        var exits = new[] { harness.WaitExit(first, Bound), harness.WaitExit(second, Bound) };
        var rootPeak = harness.Platform.RootJob!.Accounting().PeakJobMemory;
        TestContext.Current.TestOutputHelper?.WriteLine(
            $"exits {exits[0].ExitStatus}/{exits[1].ExitStatus}; root commit sampled max {sampler.Max}, peak {rootPeak} of {RootLimit} ({sampler.Samples} samples)");
        Assert.True(sampler.Max <= RootLimit, $"The root job committed {sampler.Max}, over its limit {RootLimit}.");
        Assert.True(rootPeak <= RootLimit + (20L << 20), $"The root's peak {rootPeak} is more than one refused request over its limit {RootLimit}.");
        Assert.True(rootPeak >= RootLimit - (20L << 20), $"The root's peak {rootPeak} never reached its limit {RootLimit}: the root did not refuse.");
        Assert.Contains(exits, exit => exit.ExitStatus != 0);
    }

    [Fact(Timeout = 120_000)]
    public void TerminatingTheJobEndsTheWholeProcessTree()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job objects.");
        Report();
        using var harness = PlatformHarness.Start();
        var handle = harness.Launch([TestPrograms.TestLoad, "fork", "--width", "3", "--depth", "2", "--hold-ms", "60000"]);
        PlatformHarness.WaitFor(() => handle.Processes().Count >= 13, Bound, "the 13-process tree");
        var pids = handle.Processes().Select(process => ArcForges.Tests.ProcessIdentity.Capture(process.Pid)).OfType<ArcForges.Tests.ProcessIdentity>().ToList();
        harness.Track(handle);
        handle.Terminate();
        PlatformHarness.WaitFor(() => handle.Job.Accounting().ActiveProcesses == 0, TimeSpan.FromSeconds(5), "the job to be empty");
        Assert.All(pids, process => Assert.False(process.IsRunning()));
        Assert.Equal((int)AttemptRunner.TerminatedExitCode, harness.WaitExit(handle, Bound).ExitStatus);
    }

    [Fact(Timeout = 120_000)]
    public void AProcessCannotBreakAwayFromItsAttemptJob()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job objects.");
        Report();
        using var harness = PlatformHarness.Start();
        var marker = Path.Combine(harness.Root, "marker.txt");
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--child", "breakaway", "--hold-ms", "2000", "--marker", marker]);
        harness.WaitExit(handle, Bound);
        Assert.Contains(PlatformHarness.Marker(marker), line => line.Event == "breakaway-refused");
        Assert.DoesNotContain(PlatformHarness.Marker(marker), line => line.Event == "breakaway-allowed");
        var (flags, _, _) = handle.Job.Limits();
        Assert.Equal(0u, flags & (0x800u | 0x1000u));
    }

    [Fact(Timeout = 120_000)]
    public async Task AKillWithNodeAttemptDiesWhenTheNodeClosesItsJob()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job objects.");
        Report();
        using var harness = PlatformHarness.Start();
        var marker = Path.Combine(harness.Root, "marker.txt");
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--hold-ms", "60000", "--marker", marker], killWithNode: true);
        await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        var rootProcess = PlatformHarness.Identity(handle.Root!);
        Assert.Null(handle.Holder);
        Assert.True((handle.Job.Limits().Flags & Native.JobObjectLimitKillOnJobClose) != 0);
        PlatformHarness.WaitFor(() => PlatformHarness.Marker(marker).Any(line => line.Event == "ready"), Bound, "the workload to be ready");

        // The node's handle is the only one: closing it (the node exiting) ends the attempt.
        handle.Dispose();
        PlatformHarness.WaitFor(() => !rootProcess.IsRunning(), TimeSpan.FromSeconds(5), "the kill_with_node attempt to end");
    }

    private static TimeSpan Cpu(JobAccounting accounting) => accounting.UserTime + accounting.KernelTime;

    private static Dictionary<string, string> WithEnvironment(string name, string value)
    {
        var environment = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(entry => (string)entry.Key, entry => (string?)entry.Value ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        environment[name] = value;
        return environment;
    }

    /// <summary>Samples a job's committed memory every 2 ms until disposed (the bound is checked on what was committed).</summary>
    private sealed class CommitSampler : IDisposable
    {
        private readonly JobObject _job;
        private readonly Thread _thread;
        private volatile bool _stop;

        public CommitSampler(JobObject job)
        {
            _job = job;
            _thread = new Thread(() =>
            {
                while (!_stop)
                {
                    var commit = _job.CurrentCommit();
                    if (commit > Max)
                    {
                        Max = commit;
                    }

                    Samples++;
                    Thread.Sleep(2);
                }
            })
            { IsBackground = true };
            _thread.Start();
        }

        public long Max { get; private set; }

        public long Samples { get; private set; }

        public void Dispose()
        {
            _stop = true;
            _thread.Join();
        }
    }

    private static void Report() =>
        TestContext.Current.TestOutputHelper?.WriteLine($"elevated: {PlatformHarness.IsElevated()}");
}
