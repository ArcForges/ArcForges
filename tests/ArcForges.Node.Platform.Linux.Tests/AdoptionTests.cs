// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using ArcForges.Contracts.Node.V1;
using ArcForges.Tests;

namespace ArcForges.Node.Platform.Linux.Tests;

/// <summary>
/// Existing Linux scope recovery, process termination by owner and start identity, and hardening read-back.
/// The original tests of fresh adoption at the native boundary remain executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
/// </summary>
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class AdoptionTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(60);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RequireUnits() => Assert.SkipWhen(SystemdTestEnvironment.SkipReason is { } reason, SystemdTestEnvironment.SkipReason ?? string.Empty);

    [Fact(Timeout = 120_000)]
    public void AnExistingManagedScopeReopensWithItsChildrenAndCanBeTerminated()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var platform = harness.Platform;
        Assert.Equal(AdoptSupport.Unsupported, platform.Evaluate().Adopt);

        // The existing test workload starts in its fixture-owned scope without a new product adoption.
        var scope = LinuxExecutionPlatform.AdoptionPrefix + Guid.NewGuid().ToString("N")[..12] + ".scope";
        var sourceSlice = SystemdTestEnvironment.NewSlice();
        List<string> arguments = ["--user", "--scope", "--unit", scope, "--slice", sourceSlice, "--quiet"];
        if (Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } dotnet)
        {
            arguments.AddRange(["-E", "DOTNET_ROOT=" + dotnet]);
        }

        using var run = Process.Start(new ProcessStartInfo("systemd-run", [.. arguments, TestPrograms.TestLoad, "fork", "--width", "1", "--depth", "1", "--hold-ms", "60000"])
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        })!;
        try
        {
            var pid = 0;
            var child = 0;
            LinuxHarness.WaitFor(() =>
            {
                var exited = run.HasExited;
                Assert.False(exited, exited ? run.StandardError.ReadToEnd() : null);
                var directory = SystemdTestEnvironment.CgroupDirectory(scope);
                if (directory is null || !File.Exists(Path.Combine(directory, "cgroup.procs")))
                {
                    return false;
                }

                var members = File.ReadLines(Path.Combine(directory, "cgroup.procs"))
                    .Select(line => int.Parse(line, CultureInfo.InvariantCulture)).ToHashSet();
                foreach (var member in members)
                {
                    if (ProcFs.Stat(member) is { } stat && members.Contains(stat.ParentPid))
                    {
                        pid = stat.ParentPid;
                        child = member;
                        return true;
                    }
                }

                return false;
            }, Bound, "the fixture tree to run in its scope");

            using var reopened = platform.ReopenAdopted(scope);
            Assert.NotNull(reopened);
            Assert.Equal(scope, reopened.ContainerName);
            Assert.Contains(pid, reopened.Processes());
            Assert.Contains(child, reopened.Processes());
            Assert.EndsWith("/" + sourceSlice + "/" + scope, ProcFs.CgroupOf(pid)!, StringComparison.Ordinal);

            reopened.Terminate();
            LinuxHarness.WaitFor(() =>
            {
                Ct.ThrowIfCancellationRequested();
                try
                {
                    return reopened.Processes().Count == 0;
                }
                catch (LegacyCustodyUnavailableException)
                {
                    // The direct member list can empty before the whole scope is confirmed empty.
                    return false;
                }
            }, Bound, "confirmed empty membership of the reopened scope");
            Assert.True(run.WaitForExit(Bound));
            Assert.Null(ProcFs.StartOf(pid));
            Assert.Null(ProcFs.StartOf(child));
        }
        finally
        {
            Leftovers.Report(SystemdTestEnvironment.Cleanup(sourceSlice, [], [scope]));
        }
    }

    [Fact(Timeout = 120_000)]
    public void TerminationRefusesAnotherUserAndRequiresTheExactProcessStart()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var platform = harness.Platform;

        // Process 1 belongs to the other user. A stale start time also grants no authority over the test process below.
        Assert.SkipWhen(ProcFs.UserId == 0, "The test runs as root.");
        var init = ProcFs.StartOf(1)!.Value.Start;
        Assert.Equal(ProcessTermination.OtherUser, platform.TerminateProcess(1, init));

        using var process = Process.Start(new ProcessStartInfo(TestPrograms.TestLoad, ["hold", "--hold-ms", "60000"]) { RedirectStandardOutput = true })!;
        try
        {
            LinuxHarness.WaitFor(() => ProcFs.StartOf(process.Id) is not null, Bound, "the process to run");
            var start = ProcFs.StartOf(process.Id)!.Value.Start;

            // Termination by identity: a stale start time is another process (never terminated); the right one is.
            Assert.Equal(ProcessTermination.Gone, platform.TerminateProcess(process.Id, start.AddSeconds(-30)));
            Assert.False(process.HasExited);
            Assert.Equal(ProcessTermination.Terminated, platform.TerminateProcess(process.Id, start));
            Assert.True(process.WaitForExit(Bound));
            Assert.Equal(ProcessTermination.Gone, platform.TerminateProcess(process.Id, start));
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill();
            }
        }
    }

    /// <summary>
    /// F-L04 (AD-0007 section 8; A-L04): the hardening probe reads the unit's mount namespace back; where it applied, every attempt unit
    /// carries <c>ReadOnlyPaths=</c> for the installation and <c>InaccessiblePaths=</c> for the protected paths, read back again after its
    /// start, and the command can neither write the installation nor read the protected files. A unit that started without it is reported as
    /// not applied, never as applied; turned off, nothing is applied. The report never presents it as workload isolation.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task UnitHardeningIsReadBackAfterStartAndReportedHonestly()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        var protectedRoot = Directory.CreateTempSubdirectory("arcforges-protected-").FullName;
        try
        {
            var store = Directory.CreateDirectory(Path.Combine(protectedRoot, "store")).FullName;
            await File.WriteAllTextAsync(Path.Combine(store, "node.db"), "store", Ct);
            using var harness = LinuxHarness.Start(options: slice => new LinuxPlatformOptions { Slice = slice, ProtectedPaths = [store, Path.Combine(protectedRoot, "absent")] });
            var platform = harness.Platform;
            var report = platform.HardeningReport;
            Assert.Contains("never workload isolation", report, StringComparison.Ordinal);
            Assert.Contains(platform.Evaluate().PlatformFacts, fact => fact.Name == "unit_hardening" && fact.Value == report);
            var install = Path.GetDirectoryName(TestPrograms.Host)!;
            var script = "if touch \"$1/arcforges-hardening-probe\" 2>/dev/null; then echo wrote; else echo readonly; fi; "
                + "if cat \"$2/node.db\" >/dev/null 2>&1; then echo read; else echo hidden; fi; sleep 2";
            var handle = (LinuxAttemptHandle)harness.Launch(["sh", "-c", script, "sh", install, store]);
            var root = await handle.Started.WaitAsync(Bound, Ct);
            Assert.NotNull(root);
            LinuxHarness.WaitExit(handle, Bound);
            var output = await File.ReadAllTextAsync(handle.Files.StdoutPath, Ct);
            if (report.StartsWith("applied", StringComparison.Ordinal))
            {
                Assert.Equal("readonly\nhidden\n", output);
                Assert.False(File.Exists(Path.Combine(install, "arcforges-hardening-probe")));
                Assert.StartsWith("applied", platform.HardeningReport, StringComparison.Ordinal);
                Assert.Contains("ReadOnlyPaths=" + install, platform.HardeningReport, StringComparison.Ordinal);
            }
            else
            {
                // Where the user manager could not apply it, attempts run without it and nothing says it applied.
                Assert.StartsWith("not applied", report, StringComparison.Ordinal);
                Assert.Equal("wrote\nread\n", output);
                File.Delete(Path.Combine(install, "arcforges-hardening-probe"));
            }

            // The read-back distinguishes: this test process has no such mounts; an attempt read back without it makes the report "not applied".
            Assert.False(LinuxExecutionPlatform.HardeningApplied(Environment.ProcessId, install, [store]));

            // Review round 1: a root that ended before its mount namespace was read is "not verified", never counted as applied.
            int endedPid;
            using (var ended = Process.Start(new ProcessStartInfo("/bin/true"))!)
            {
                endedPid = ended.Id;
                ended.WaitForExit();
            }

            Assert.Null(LinuxExecutionPlatform.HardeningReadBackOf(endedPid, 1, install, [store]));
            var beforeEnded = platform.HardeningReport;
            platform.HardeningReadBack("a-ended", applied: null);
            Assert.Contains("not verified for 1 attempt unit(s): the attempt ended before read-back (last a-ended)", platform.HardeningReport, StringComparison.Ordinal);
            Assert.Equal(beforeEnded.StartsWith("applied", StringComparison.Ordinal), platform.HardeningReport.StartsWith("applied", StringComparison.Ordinal));
            platform.HardeningReadBack("a-test", applied: false);
            Assert.StartsWith("not applied to every attempt", platform.HardeningReport, StringComparison.Ordinal);
            Assert.DoesNotContain("applied (read back", platform.HardeningReport, StringComparison.Ordinal);

            // The kill_tree reason ends with the same-user qualifier (03 section 8; T-22, T-23).
            Assert.EndsWith("; same-user code can change or end ArcForges' containers (T-22), and work launched outside the recorded ancestry never joins them (T-23)",
                platform.Evaluate().KillTreeReason, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(protectedRoot, recursive: true);
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task TurnedOffHardeningIsReportedAsNotApplied()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        using var harness = LinuxHarness.Start(options: slice => new LinuxPlatformOptions { Slice = slice, UnitHardening = false });
        Assert.StartsWith("not applied: turned off", harness.Platform.HardeningReport, StringComparison.Ordinal);
        var handle = (LinuxAttemptHandle)harness.Launch(["sleep", "5"]);
        Assert.NotNull(await handle.Started.WaitAsync(Bound, Ct));
        Assert.Equal(string.Empty, SystemdTestEnvironment.Property(handle.Unit, "ReadOnlyPaths"));
        handle.Terminate();
        LinuxHarness.WaitExit(handle, Bound);
    }
}

/// <summary>
/// The AF-EXEC-02 ancestry-scan repair (AF-SEC-01; 03 section 9; R-RES-012): a recorded member's ID is a parent only while it still names the
/// same process, so after the member exited and an unrelated process reused its ID, that process's children are never escaped (and never
/// killed); the member's own children outside the unit are.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class EscapedScanTests
{
    [Fact]
    public void ChildrenOfAProcessThatReusedAMembersIdAreNotEscaped()
    {
        // Member 100 started at tick 50 and is gone; 100 now names a process started at tick 900, whose child 101 started at tick 950.
        var members = new Dictionary<int, long> { [100] = 50, [200] = 60 };
        var inside = new HashSet<int> { 200 };
        var table = new Dictionary<int, (int Parent, long Start)>
        {
            [100] = (1, 900),
            [101] = (100, 950),
            [200] = (1, 60),
            [201] = (200, 70),
            [202] = (201, 80),
            [203] = (200, 40),
        };
        var escaped = LinuxAttemptHandle.Descendants(members, inside, table);

        // 201 is a child of the live member 200 outside the unit, 202 its descendant; 203 claims 200 as parent but started before it.
        Assert.Equal([201, 202], escaped.Keys.Order());
        Assert.DoesNotContain(101, escaped.Keys);

        // Had 100 still been the recorded member (same start), its child outside the unit would be escaped (control).
        var control = LinuxAttemptHandle.Descendants(new Dictionary<int, long> { [100] = 900 }, new HashSet<int>(), table);
        Assert.Contains(101, control.Keys);
    }
}
