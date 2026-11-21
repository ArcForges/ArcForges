// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>Native Windows Job observation and process termination by verified identity.</summary>
/// <remarks>
/// Fresh V1 adoption and the original native refusal remain executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a
/// (source blob c587b4ca9dd4729abd8d3862a4f54729e40a4520).
/// </remarks>
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
            // Whether it is in some other job does not matter here: on some machines every process of the session is in a job (even
            // explorer.exe), and WMI's provider host may run in one.
            Assert.True(Native.IsProcessInJob(handle, 0, out var inAnyJob));
            TestContext.Current.TestOutputHelper?.WriteLine(inAnyJob
                ? "The WMI-created process is in a job, but not the creator's."
                : "The WMI-created process is outside every job.");
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
    public void TerminationRequiresTheOriginalProcessIdentity()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job objects.");
        using var harness = PlatformHarness.Start();
        Assert.EndsWith("; same-user code can change or end ArcForges' containers (T-22), and work launched outside the recorded ancestry never joins them (T-23)",
            harness.Platform.Evaluate().KillTreeReason, StringComparison.Ordinal);
        using var job = JobObject.Create(null);
        LaunchedProcess? process = null;
        try
        {
            process = StartInJob(job, "Start-Sleep -Seconds 60");
            var start = ProcessInfo.FromFileTime(process.CreationFileTime);

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
