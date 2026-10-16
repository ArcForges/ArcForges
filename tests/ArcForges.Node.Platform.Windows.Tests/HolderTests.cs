// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Windows;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// The attempt holder <c>arcforges node exec-wrap</c> (04 section 3; AD-0005 Windows section 3) with real processes: the durable exit
/// record with accounting, launch steps inside the attempt's jobs before the root process, end steps after the root exits and before
/// leftover termination, the leftovers listed, a failing launch step recorded in <c>launch.json</c> (SPAWN_FAILED), and the holder keeping
/// its job openable by name until the ack. Steps are synthetic (<c>arcforges-testload signal</c> recording its PID and time); real sccache
/// steps follow in AF-TOOL-02.
/// </summary>
[Trait("env", "windows-real")]
[Collection(SerialPlatformTests.Name)]
[SupportedOSPlatform("windows")]
public sealed class HolderTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(60);

    [Fact(Timeout = 120_000)]
    public async Task TheHolderRecordsTheExitWithAccountingAndKeepsTheJobUntilAcknowledged()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows exec-wrap holders and job objects.");
        using var harness = PlatformHarness.Start();
        var handle = harness.Launch([TestPrograms.TestLoad, "cpu", "--threads", "1", "--iterations", "200000000"]);
        await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken);
        var exit = harness.WaitExit(handle, Bound);
        Assert.Equal(1, exit.Schema);
        Assert.Equal(handle.Files.AttemptName, exit.AttemptId);
        Assert.Equal(0, exit.ExitStatus);
        Assert.Equal("success", exit.ServiceResult);
        Assert.True(exit.CpuUserMs + exit.CpuKernelMs > 0, "The record carries the job's CPU accounting.");
        Assert.True(exit.MemPeakBytes > 0, "The record carries the peak job commit.");
        Assert.Empty(exit.LeftoversTerminated);

        // Until the node acknowledges, the holder lives and the job stays openable by name (L-14).
        Assert.False(handle.Holder!.WaitForExit(TimeSpan.FromSeconds(1)));
        using (var reopened = JobObject.Open(WindowsExecutionPlatform.JobName(harness.NodeName, handle.Files.AttemptName)))
        {
            Assert.NotNull(reopened);
        }

        handle.Acknowledge();
        Assert.True(handle.Holder.WaitForExit(TimeSpan.FromSeconds(10)), "The holder exits once acknowledged.");
        Assert.Equal(0u, handle.Holder.ExitCode);
    }

    [Fact(Timeout = 120_000)]
    public void LaunchStepsRunInTheJobsBeforeTheRootAndEndStepsBeforeLeftoverTermination()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows exec-wrap holders and job objects.");
        using var harness = PlatformHarness.Start();
        var launchMarker = Path.Combine(harness.Root, "launch.txt");
        var rootMarker = Path.Combine(harness.Root, "root.txt");
        var endMarker = Path.Combine(harness.Root, "end.txt");

        // The root starts a leftover in its own process group (still in the job) and exits at once.
        var handle = harness.Launch(
            [TestPrograms.TestLoad, "signal", "--hold-ms", "1500", "--child", "group", "--child-hold-ms", "60000", "--marker", rootMarker],
            launchSteps: [PlatformHarness.Step("synthetic-launch", TestPrograms.TestLoad, "signal", "--hold-ms", "800", "--marker", launchMarker)],
            endSteps: [PlatformHarness.Step("synthetic-end", TestPrograms.TestLoad, "signal", "--hold-ms", "300", "--marker", endMarker)],
            leftoverGraceMs: 1_000);

        // The launch step runs while the root has not started, inside the attempt's job.
        PlatformHarness.WaitFor(() => PlatformHarness.Marker(launchMarker).Count > 0, Bound, "the launch step");
        var step = PlatformHarness.Marker(launchMarker)[0];
        Assert.Contains(handle.Processes(), process => process.Pid == step.Pid);
        Assert.Null(handle.Root);

        var exit = harness.WaitExit(handle, Bound);
        var root = PlatformHarness.Marker(rootMarker);
        var end = PlatformHarness.Marker(endMarker);
        var launched = root.First(line => line.Event == "ready");
        Assert.True(launched.At >= step.At + 700, "The root started after the launch step finished.");
        Assert.Single(end, line => line.Event == "ready");
        Assert.True(end[0].At <= DateTimeOffset.Parse(exit.RecordedAt, System.Globalization.CultureInfo.InvariantCulture).ToUnixTimeMilliseconds());

        // The root's group child was a leftover: alive while the end step ran, terminated after it, and listed.
        var leftover = root.Where(line => line.Event == "ready").GroupBy(line => line.Pid).Where(group => group.Key != handle.Root!.Pid)
            .Select(group => ArcForges.Tests.ProcessIdentity.CreatedNoLaterThan(group.Key, group.Min(line => line.At))).Single();
        Assert.Contains("arcforges-testload.exe", exit.LeftoversTerminated);
        Assert.False(leftover.IsRunning());
        Assert.Equal(0, exit.ExitStatus);
    }

    [Fact(Timeout = 120_000)]
    public async Task AFailingLaunchStepRecordsTheFailureAndNeverStartsTheCommand()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows exec-wrap holders and job objects.");
        using var harness = PlatformHarness.Start();
        var rootMarker = Path.Combine(harness.Root, "root.txt");
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var handle = harness.Launch([TestPrograms.TestLoad, "signal", "--hold-ms", "100", "--marker", rootMarker],
            launchSteps: [PlatformHarness.Step("failing-step", cmd, "/d", "/c", "exit 3")]);
        Assert.Null(await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken));
        var exit = harness.WaitExit(handle, Bound);
        var launch = handle.TryReadLaunchFailure();
        Assert.NotNull(launch);
        Assert.Equal("failing-step", launch.Step);
        Assert.Equal(3, launch.ExitCode);
        Assert.Contains("exited with code 3", launch.Error, StringComparison.Ordinal);
        Assert.Equal(3, exit.ExitStatus);
        Assert.False(File.Exists(rootMarker), "The command never started.");
    }

    [Fact(Timeout = 120_000)]
    public async Task AProgramThatCannotBeStartedIsAFailedLaunch()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows exec-wrap holders and job objects.");
        using var harness = PlatformHarness.Start();
        var notAProgram = Path.Combine(harness.Root, "not-a-program.exe");
        File.WriteAllText(notAProgram, "this is text, not a Windows program");
        var handle = harness.Launch([notAProgram]);
        Assert.Null(await handle.Started.WaitAsync(Bound, TestContext.Current.CancellationToken));
        harness.WaitExit(handle, Bound);
        var launch = handle.TryReadLaunchFailure();
        Assert.NotNull(launch);
        Assert.Equal("command", launch.Step);
        // ERROR_BAD_EXE_FORMAT or ERROR_EXE_MACHINE_TYPE_MISMATCH, as the OS judges the file.
        Assert.Contains(launch.OsError, (int?[])[193, 216]);
    }

    [Fact(Timeout = 120_000)]
    public void TheAttemptRunsWindowlessWithTheExactEnvironmentAndWorkingDirectory()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows exec-wrap holders and job objects.");
        using var harness = PlatformHarness.Start();
        var work = Directory.CreateDirectory(Path.Combine(harness.Root, "work dir")).FullName;
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = Environment.GetEnvironmentVariable("SystemRoot")!,
            ["ARCFORGES_PROBE"] = "value with spaces ä",
        };
        var handle = harness.Launch([cmd, "/d", "/c", "cd & set ARCFORGES_PROBE & if defined PATH (echo PATH-SET) else (echo NO-PATH)"],
            workingDirectory: work, environment: environment);
        var exit = harness.WaitExit(handle, Bound);
        var output = PlatformHarness.ReadShared(handle.Files.StdoutPath);
        Assert.True(exit.ExitStatus == 0, $"exit {exit.ExitStatus}; stdout: {output}; stderr: {PlatformHarness.ReadShared(handle.Files.StderrPath)}");
        Assert.Contains(work, output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ARCFORGES_PROBE=value with spaces", output, StringComparison.Ordinal);
        Assert.Contains("NO-PATH", output, StringComparison.Ordinal);
    }
}
