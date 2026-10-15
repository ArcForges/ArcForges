// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Windows.Tests;

/// <summary>
/// R-RES-012 (03 section 9; 04 sections 3 and 6): the ancestry scan finds a descendant of an attempt's process that runs outside its job,
/// and the stop sequence terminates it when it runs as the same user. The escaped process is made with the legitimate shape that needs
/// neither WMI nor a broker: it is created with <c>PROC_THREAD_ATTRIBUTE_PARENT_PROCESS</c> set to the attempt's root while the root is
/// still suspended and not yet assigned, so it keeps the job membership it had at creation (outside the attempt job) and its parent ID is
/// the root's. Everything runs inside the test's own process tree and job; nothing is left running.
/// </summary>
[Trait("env", "windows-real")]
[Collection(SerialPlatformTests.Name)]
[SupportedOSPlatform("windows")]
public sealed class EscapedProcessTests
{
    [Fact(Timeout = 60_000)]
    public void AChildCreatedUnderTheRootBeforeItsAssignmentIsFoundEscapedAndTerminated()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job objects.");
        var root = Directory.CreateTempSubdirectory("arcforges-escape-").FullName;
        using var job = JobObject.Create(null);
        LaunchedProcess? attemptRoot = null;
        LaunchedProcess? escapedChild = null;
        try
        {
            using var stdin = ProcessLauncher.OpenNull(write: false);
            using var stdout = ProcessLauncher.OpenNull(write: true);
            attemptRoot = ProcessLauncher.Start(new LaunchOptions
            {
                Application = TestPrograms.TestLoad,
                CommandLine = WindowsCommandLine.Build([TestPrograms.TestLoad, "signal", "--hold-ms", "30000", "--marker", Path.Combine(root, "root.txt")]),
                Flags = Native.CreateSuspended | Native.CreateNoWindow | Native.CreateNewProcessGroup,
                StdInput = stdin,
                StdOutput = stdout,
                StdError = stdout,
            });

            // Created under the suspended, unassigned root: its parent is the root, its job membership the test's.
            escapedChild = ProcessLauncher.Start(new LaunchOptions
            {
                Application = TestPrograms.TestLoad,
                CommandLine = WindowsCommandLine.Build([TestPrograms.TestLoad, "signal", "--hold-ms", "30000", "--marker", Path.Combine(root, "child.txt")]),
                Flags = Native.CreateNoWindow,
                ParentProcess = attemptRoot.Process,
            });
            job.Assign(attemptRoot.Process);
            attemptRoot.Resume();
            PlatformHarness.WaitFor(() => File.Exists(Path.Combine(root, "child.txt")), TimeSpan.FromSeconds(20), "the escaped child to run");

            Assert.True(job.Contains(attemptRoot.Process), "The root is in the attempt job.");
            Assert.False(job.Contains(escapedChild.Process), "The child runs outside the attempt job.");
            var members = new Dictionary<int, long> { [attemptRoot.ProcessId] = attemptRoot.CreationFileTime };
            var escaped = EscapedProcesses.Scan(job, members);

            // The child, and its own descendants (its console host), all outside the job.
            var found = Assert.Single(escaped, process => process.Pid == escapedChild.ProcessId);
            Assert.All(escaped, process => Assert.True(process.Pid == escapedChild.ProcessId || process.ParentPid == escapedChild.ProcessId,
                $"{process.Image} ({process.Pid}) is not a descendant of the escaped child"));
            Assert.Equal(attemptRoot.ProcessId, found.ParentPid);
            Assert.True(found.SameUser);
            Assert.Equal("arcforges-testload.exe", found.Image, ignoreCase: true);

            // The members' own descendants inside the job are never reported, and a stranger is never a descendant.
            Assert.DoesNotContain(escaped, process => process.Pid == Environment.ProcessId);

            var terminated = EscapedProcesses.Terminate(escaped, AttemptRunner.TerminatedExitCode);
            Assert.Contains(terminated, text => text.Contains($"({escapedChild.ProcessId})", StringComparison.Ordinal));
            Assert.True(escapedChild.WaitForExit(TimeSpan.FromSeconds(5)), "The escaped child was terminated.");
            Assert.Equal(AttemptRunner.TerminatedExitCode, escapedChild.ExitCode);
            Assert.True(PlatformHarness.IsRunning(attemptRoot.ProcessId), "Terminating the escaped child leaves the job's processes alone.");

            // With the escaped child gone, nothing is reported.
            Assert.Empty(EscapedProcesses.Scan(job, members));
        }
        finally
        {
            job.Terminate(AttemptRunner.TerminatedExitCode);
            foreach (var process in (LaunchedProcess?[])[escapedChild, attemptRoot])
            {
                if (process is not null)
                {
                    process.Kill(AttemptRunner.TerminatedExitCode);
                    Assert.True(process.WaitForExit(TimeSpan.FromSeconds(10)), "A test process did not end.");
                    process.Dispose();
                }
            }

            Directory.Delete(root, recursive: true);
        }
    }

    [Fact(Timeout = 60_000)]
    public void AnEscapedChildOfAnExitedMemberIsStillFound()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job objects.");
        var root = Directory.CreateTempSubdirectory("arcforges-escape-").FullName;
        using var job = JobObject.Create(null);
        LaunchedProcess? attemptRoot = null;
        LaunchedProcess? escapedChild = null;
        try
        {
            using var stdin = ProcessLauncher.OpenNull(write: false);
            using var stdout = ProcessLauncher.OpenNull(write: true);
            attemptRoot = ProcessLauncher.Start(new LaunchOptions
            {
                Application = TestPrograms.TestLoad,
                CommandLine = WindowsCommandLine.Build([TestPrograms.TestLoad, "signal", "--hold-ms", "500", "--marker", Path.Combine(root, "root.txt")]),
                Flags = Native.CreateSuspended | Native.CreateNoWindow,
                StdInput = stdin,
                StdOutput = stdout,
                StdError = stdout,
            });
            escapedChild = ProcessLauncher.Start(new LaunchOptions
            {
                Application = TestPrograms.TestLoad,
                CommandLine = WindowsCommandLine.Build([TestPrograms.TestLoad, "signal", "--hold-ms", "30000", "--marker", Path.Combine(root, "child.txt")]),
                Flags = Native.CreateNoWindow,
                ParentProcess = attemptRoot.Process,
            });
            var members = new Dictionary<int, long> { [attemptRoot.ProcessId] = attemptRoot.CreationFileTime };
            job.Assign(attemptRoot.Process);
            attemptRoot.Resume();
            Assert.True(attemptRoot.WaitForExit(TimeSpan.FromSeconds(20)), "The root exits after 500 ms.");
            PlatformHarness.WaitFor(() => File.Exists(Path.Combine(root, "child.txt")), TimeSpan.FromSeconds(20), "the escaped child to run");

            var escaped = EscapedProcesses.Scan(job, members);
            var found = Assert.Single(escaped, process => process.Pid == escapedChild.ProcessId);
            Assert.Equal(attemptRoot.ProcessId, found.ParentPid);
            Assert.Contains(EscapedProcesses.Terminate(escaped, AttemptRunner.TerminatedExitCode), text => text.Contains($"({escapedChild.ProcessId})", StringComparison.Ordinal));
            Assert.True(escapedChild.WaitForExit(TimeSpan.FromSeconds(5)));
        }
        finally
        {
            job.Terminate(AttemptRunner.TerminatedExitCode);
            foreach (var process in (LaunchedProcess?[])[escapedChild, attemptRoot])
            {
                if (process is not null)
                {
                    process.Kill(AttemptRunner.TerminatedExitCode);
                    Assert.True(process.WaitForExit(TimeSpan.FromSeconds(10)), "A test process did not end.");
                    process.Dispose();
                }
            }

            Directory.Delete(root, recursive: true);
        }
    }
}
