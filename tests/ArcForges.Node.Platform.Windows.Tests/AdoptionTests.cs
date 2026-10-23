// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// AF-SEC-01 on real Windows jobs (env=windows-real): the documented gap T-23 (11 section 1; R-RES-012; A-W04, F-W04): a child a job member
/// creates through WMI <c>Win32_Process.Create</c> never joins the job (V-W01) and has no recorded ancestry through a member, so the ancestry
/// scan reports nothing for it; adoption (04 section 10; R-RES-013): a same-user process outside any job joins the root job and then its own
/// adoption job with its children, a process already in a job is refused, a stale identity is not found; termination by ID and start time;
/// and the same-user qualifier at the end of the kill_tree reason (03 section 8).
/// </summary>
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class AdoptionTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(60);

    /// <summary>Windows PowerShell, part of every Windows 11 installation; its CIM cmdlets reach WMI.</summary>
    private static string PowerShell => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

    [Fact(Timeout = 120_000)]
    public void AWmiCreatedChildOfAJobMemberIsNotDetectedAndTheScanReportsNothing()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job objects and WMI.");
        Assert.SkipUnless(File.Exists(PowerShell), "Windows PowerShell is missing.");
        var root = Directory.CreateTempSubdirectory("arcforges-wmi-").FullName;
        var marker = Path.Combine(root, "wmi.txt");
        using var job = JobObject.Create(null);
        LaunchedProcess? member = null;
        ArcForges.Tests.ProcessIdentity? created = null;
        try
        {
            // The job member asks WMI to create the process (the shape of T-23), then waits, so it is a running member while the scan runs.
            member = StartInJob(job, Wmi(TestPrograms.TestLoad, "hold", "--hold-ms", "60000", "--marker", marker) + "; Start-Sleep -Seconds 60");
            PlatformHarness.WaitFor(() => PlatformHarness.Marker(marker).Any(line => line.Event == "ready"), Bound, "the WMI-created process to run");
            var identity = PlatformHarness.MarkerProcesses(marker, "start").Single();
            created = identity;
            using var handle = ProcessInfo.Open(identity.Pid)!;
            Assert.False(job.Contains(handle), "A WMI-created process does not join the creator's job (V-W01).");
            Assert.True(Native.IsProcessInJob(handle, 0, out var inAnyJob) && !inAnyJob, "It is outside every job.");
            var parent = ProcessInfo.Snapshot().Single(entry => entry.Pid == identity.Pid).ParentPid;
            Assert.NotEqual(member.ProcessId, parent);

            using var members = new JobMembers(job);
            foreach (var pid in job.ProcessIds())
            {
                members.Remember(pid);
            }

            Assert.Contains(members.Snapshot(), entry => entry.Pid == member.ProcessId);

            // T-23: the scan detects only descendants whose recorded ancestry passes through a job member; this one is not one of them.
            var escaped = EscapedProcesses.Scan(job, members.Snapshot());
            Assert.Empty(escaped);
        }
        finally
        {
            job.Terminate(AttemptRunner.TerminatedExitCode);
            created?.Kill();
            member?.Dispose();
            Assert.False(created?.IsRunning() ?? false, "The WMI-created process was left running.");
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact(Timeout = 120_000)]
    public void AProcessOutsideAnyJobIsAdoptedWithItsChildrenAndTerminated()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job objects and WMI.");
        Assert.SkipUnless(File.Exists(PowerShell), "Windows PowerShell is missing.");
        using var harness = PlatformHarness.Start();
        var platform = harness.Platform;
        var report = platform.Evaluate();
        Assert.Equal(AdoptSupport.Limited, report.Adopt);
        Assert.EndsWith("; same-user code can change or end ArcForges' containers (T-22), and work launched outside the recorded ancestry never joins them (T-23)",
            report.KillTreeReason, StringComparison.Ordinal);

        // A process outside every job (this test may itself run inside a job, so the process is created through WMI) with a child.
        var marker = Path.Combine(harness.Root, "adopt.txt");
        LaunchedProcess? wmi = null;
        IAdoptedContainer? container = null;
        List<ArcForges.Tests.ProcessIdentity> started = [];
        try
        {
            wmi = ProcessLauncher.Start(new LaunchOptions
            {
                Application = PowerShell,
                CommandLine = WindowsCommandLine.Build([PowerShell, "-NoProfile", "-NonInteractive", "-Command",
                    Wmi(TestPrograms.TestLoad, "signal", "--child", "same", "--hold-ms", "60000", "--marker", marker)]),
                Flags = Native.CreateNoWindow,
            });
            PlatformHarness.WaitFor(() => PlatformHarness.Marker(marker).Count(line => line.Event == "ready") >= 2, Bound, "the process and its child to run");
            started = PlatformHarness.MarkerProcesses(marker, "ready");
            var table = ProcessInfo.Snapshot();
            var rootPid = started.Single(process => table.Single(entry => entry.Pid == process.Pid).ParentPid is var parent && started.All(other => other.Pid != parent)).Pid;
            var childPid = started.Single(process => process.Pid != rootPid).Pid;
            long created;
            using (var probe = ProcessInfo.Open(rootPid)!)
            {
                created = ProcessInfo.CreationFileTime(probe);
            }

            var start = ProcessInfo.FromFileTime(created);
            Assert.True(Assert.Throws<AdoptionRefusedException>(() => platform.Adopt(new AdoptionRequest(harness.NodeName, "x1", rootPid, start.AddSeconds(-30)))).NotFound);
            var result = platform.Adopt(new AdoptionRequest(harness.NodeName, "x" + Guid.NewGuid().ToString("N")[..12], rootPid, start));
            container = result.Container;
            Assert.StartsWith(@"Local\ArcForges." + harness.NodeName + ".x", container.ContainerName, StringComparison.Ordinal);
            Assert.True(result.AdoptedChildren >= 1, string.Join("; ", result.ChildResults));
            Assert.Equal(0, result.FailedChildren);
            Assert.Equal("arcforges-testload.exe", result.Image, ignoreCase: true);
            Assert.Contains(rootPid, container.Processes());
            Assert.Contains(childPid, container.Processes());
            using (var adopted = ProcessInfo.Open(rootPid)!)
            {
                Assert.True(platform.RootJob!.Contains(adopted), "The adopted process is in the root job (V-W01: root first).");
            }

            // Adopting it again is refused as already managed.
            Assert.True(Assert.Throws<AdoptionRefusedException>(() => platform.Adopt(new AdoptionRequest(harness.NodeName, "x2", rootPid, start))).AlreadyManaged);
            container.Terminate();
            PlatformHarness.WaitFor(() => container.Processes().Count == 0, Bound, "the adopted processes to end");
            Assert.All(started, process => Assert.False(process.IsRunning(), $"{process} still runs"));
        }
        finally
        {
            container?.Dispose();
            foreach (var process in started)
            {
                process.Kill();
            }

            wmi?.Kill(AttemptRunner.TerminatedExitCode);
            wmi?.Dispose();
        }
    }

    [Fact(Timeout = 120_000)]
    public void AProcessInAJobIsRefusedAndTerminationNeedsItsIdentity()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job objects.");
        using var harness = PlatformHarness.Start();
        using var job = JobObject.Create(null);
        LaunchedProcess? process = null;
        try
        {
            process = StartInJob(job, "Start-Sleep -Seconds 60");
            var start = ProcessInfo.FromFileTime(process.CreationFileTime);

            // 04 section 10: joining a foreign job would attach the ArcForges jobs to it.
            var refused = Assert.Throws<AdoptionRefusedException>(() => harness.Platform.Adopt(new AdoptionRequest(harness.NodeName, "x" + Guid.NewGuid().ToString("N")[..12],
                process.ProcessId, start)));
            Assert.False(refused.NotFound || refused.AlreadyManaged);
            Assert.Contains("already in a job", refused.Message, StringComparison.Ordinal);

            // Termination by identity: a stale start time is another process (never terminated); the right one is.
            Assert.Equal(ProcessTermination.Gone, harness.Platform.TerminateProcess(process.ProcessId, start.AddSeconds(-30)));
            Assert.True(ProcessInfo.IsRunning(process.Process));
            Assert.Equal(ProcessTermination.Terminated, harness.Platform.TerminateProcess(process.ProcessId, start));
            Assert.True(process.WaitForExit(Bound));
            Assert.Equal(WindowsExecutionPlatform.TerminatedExitCode, (uint)process.ExitCode);
        }
        finally
        {
            job.Terminate(AttemptRunner.TerminatedExitCode);
            process?.Dispose();
        }
    }

    /// <summary>A PowerShell command that creates <paramref name="argv"/> through WMI <c>Win32_Process.Create</c> (outside every job, V-W01).</summary>
    private static string Wmi(params string[] argv)
    {
        var line = WindowsCommandLine.Build(argv).Replace("'", "''", StringComparison.Ordinal);
        return "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = '" + line + "' }; if ($r.ReturnValue -ne 0) { exit 1 }";
    }

    /// <summary>Starts Windows PowerShell running <paramref name="command"/>, suspended, assigns it to <paramref name="job"/>, then resumes it.</summary>
    private static LaunchedProcess StartInJob(JobObject job, string command)
    {
        var process = ProcessLauncher.Start(new LaunchOptions
        {
            Application = PowerShell,
            CommandLine = WindowsCommandLine.Build([PowerShell, "-NoProfile", "-NonInteractive", "-Command", command]),
            Flags = Native.CreateSuspended | Native.CreateNoWindow,
        });
        job.Assign(process.Process);
        process.Resume();
        return process;
    }
}
