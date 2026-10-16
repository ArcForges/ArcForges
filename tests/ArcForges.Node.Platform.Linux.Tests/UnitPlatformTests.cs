// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using ArcForges.Contracts.Node.V1;
using ArcForges.Tests;

namespace ArcForges.Node.Platform.Linux.Tests;

/// <summary>
/// The Linux platform with the real systemd user manager (env=linux-real; AD-0005 Linux section 2; 04 sections 3 and 6; L-07, L-13,
/// A-L03): every attempt is a transient unit started over D-Bus by the platform itself, never by <c>systemd-run</c>.
/// </summary>
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class UnitPlatformTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(60);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RequireUnits()
    {
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is { } reason, SystemdTestEnvironment.SkipReason ?? string.Empty);
    }

    [Fact(Timeout = 120_000)]
    public async Task EachLimitAppearsInTheUnitsAndTheSlicesCgroupFiles()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var platform = harness.Platform;
        Assert.True(platform.UnitMode, platform.ManagerUnavailableReason);
        var report = platform.Evaluate();
        Assert.Equal(CpuControl.EnforcedShareAndCap, report.Cpu);
        Assert.Equal(MemoryControl.EnforcedSoftAndHard, report.Memory);
        Assert.Equal(ProcessCountControl.Enforced, report.Pids);
        Assert.Equal(PauseSupport.Supported, report.Pause);
        Assert.Equal(KillTreeGuarantee.Guaranteed, report.KillTree);
        Assert.True(report.RestartSurvival);

        var handle = (LinuxAttemptHandle)harness.Launch(["sleep", "30"], new ContainerLimits
        {
            CpuWeight = 9,
            MemoryHighBytes = 48L << 20,
            MemoryMaxBytes = 64L << 20,
            SwapMaxBytes = 0,
            TasksMax = 64,
        });
        var root = await handle.Started.WaitAsync(Bound, Ct);
        Assert.NotNull(root);
        var unit = handle.CgroupDirectory!;
        Assert.EndsWith("/" + harness.Slice + "/" + handle.Unit, unit, StringComparison.Ordinal);

        // L-13 from the node's platform: per-unit CPUWeight, MemoryHigh, MemoryMax, MemorySwapMax, TasksMax and OOMPolicy=kill.
        Assert.Equal("400", LinuxHarness.Read(unit, "cpu.weight"));
        Assert.Equal((48L << 20).ToString(CultureInfo.InvariantCulture), LinuxHarness.Read(unit, "memory.high"));
        Assert.Equal((64L << 20).ToString(CultureInfo.InvariantCulture), LinuxHarness.Read(unit, "memory.max"));
        Assert.Equal("0", LinuxHarness.Read(unit, "memory.swap.max"));
        Assert.Equal("64", LinuxHarness.Read(unit, "pids.max"));
        Assert.Equal("1", LinuxHarness.Read(unit, "memory.oom.group"));

        // The slice carries the root limits (03 section 5.1): CPUQuota, MemoryHigh, MemoryMax, MemorySwapMax and TasksMax.
        var slice = Path.GetDirectoryName(unit)!;
        Assert.Equal((5_000L * Environment.ProcessorCount * 10).ToString(CultureInfo.InvariantCulture) + " 100000", LinuxHarness.Read(slice, "cpu.max"));
        Assert.Equal((8L << 30).ToString(CultureInfo.InvariantCulture), LinuxHarness.Read(slice, "memory.max"));
        Assert.Equal((8L << 30).ToString(CultureInfo.InvariantCulture), LinuxHarness.Read(slice, "memory.high"));
        Assert.Equal("0", LinuxHarness.Read(slice, "memory.swap.max"));
        Assert.Equal("32768", LinuxHarness.Read(slice, "pids.max"));

        // The command is the unit's main process (exec-launch replaced itself with it after the start job), a child of the user manager
        // (not of this process), inside the unit's cgroup.
        Assert.Equal(root!.Pid.ToString(CultureInfo.InvariantCulture), SystemdTestEnvironment.Property(handle.Unit, "MainPID"));
        LinuxHarness.WaitFor(() => ProcFs.Image(root.Pid) == "sleep", Bound, "exec-launch to replace itself with the command");
        Assert.NotEqual(Environment.ProcessId, ProcFs.Stat(root.Pid)!.Value.ParentPid);
        Assert.Equal(unit, ProcFs.CgroupDirectory(ProcFs.CgroupOf(root.Pid)!));

        // A runtime change of the root limits reaches the slice.
        platform.UpdateRootLimits(new RootLimits(2_500, 12L << 30, 2L << 30) { HardMemoryBytes = 4L << 30, SwapAllowanceBytes = 0 });
        Assert.Equal((2_500L * Environment.ProcessorCount * 10).ToString(CultureInfo.InvariantCulture) + " 100000", LinuxHarness.Read(slice, "cpu.max"));
        Assert.Equal((4L << 30).ToString(CultureInfo.InvariantCulture), LinuxHarness.Read(slice, "memory.max"));
        Assert.Equal((2L << 30).ToString(CultureInfo.InvariantCulture), LinuxHarness.Read(slice, "memory.high"));

        handle.Terminate();
        var exit = LinuxHarness.WaitExit(handle, Bound);
        Assert.Equal("killed", exit.ExitCodeKind);
        Assert.Equal(9, exit.ExitStatus);
    }

    [Fact(Timeout = 120_000)]
    public void StdioIsPassedAsFileDescriptorsWithTheExactEnvironmentAndADurableExitRecord()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        using var harness = LinuxHarness.Start();
        // Names and values systemd refuses in Environment= (a space or dash in a name, an exported bash function, a control character)
        // travel through exec-launch and still reach the command exactly.
        List<string> environment =
        [
            "A=1", "PATH=/usr/bin:/bin", "EMPTY=", "QUOTE=a\"b'c", "DOLLAR=$HOME and ${PATH} and $$ and %h", "MULTI=line1\nline2\tx",
            "WITH SPACE=x y", "my-var=1", "BASH_FUNC_f%%=() {  echo hi\n}", "CONTROL=a\u0001b", "UNICODE=äöü 中文",
            ExecLaunchRole.CarrierVariable + "=the caller's own value",
        ];
        var handle = harness.Launch(["/bin/sh", "-c", "printf out; printf err >&2; exit 3"], environment: environment);
        var exit = LinuxHarness.WaitExit(handle, Bound);

        Assert.Equal("exited", exit.ExitCodeKind);
        Assert.Equal(3, exit.ExitStatus);
        Assert.Equal("exit-code", exit.ServiceResult);
        Assert.Equal("exit-record", exit.RecordedBy);
        Assert.True(exit.MemPeakBytes > 0);
        Assert.NotNull(exit.SwapPeakBytes);
        var attemptDirectory = Path.Combine(harness.DataRoot, "logs", ((LinuxAttemptHandle)handle).Files.AttemptName);
        Assert.Equal("out", File.ReadAllText(Path.Combine(attemptDirectory, AttemptFiles.Stdout)));
        Assert.Equal("err", File.ReadAllText(Path.Combine(attemptDirectory, AttemptFiles.Stderr)));

        // Exactly the resolved environment: no variable of the user manager and none systemd adds to services (env prints its own
        // environment directly; a shell would drop the names it cannot hold).
        var printed = harness.Launch(["/usr/bin/env", "-0"], environment: environment);
        Assert.Equal(0, LinuxHarness.WaitExit(printed, Bound).ExitStatus);
        var envDirectory = Path.Combine(harness.DataRoot, "logs", ((LinuxAttemptHandle)printed).Files.AttemptName);
        var received = File.ReadAllText(Path.Combine(envDirectory, AttemptFiles.Stdout)).Split('\0', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(environment.Order(StringComparer.Ordinal), received.Order(StringComparer.Ordinal));
    }

    [Fact(Timeout = 120_000)]
    public void AVariableTheManagerPassesOutsideTheResolvedEnvironmentNeverReachesTheCommand()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // Exactness does not depend on what the user manager adds (seen on a hosted runner: a variable of the image reached the service
        // although UnsetEnvironment= listed the manager's environment): the unit itself carries variables outside the resolved
        // environment here, as a manager would pass them, and exec-launch keeps only the resolved names of steps.json.
        RequireUnits();
        using var harness = LinuxHarness.Start(options: slice => new LinuxPlatformOptions
        {
            Slice = slice,
            ExtraUnitEnvironment = ["ARCFORGES_TEST_MANAGER_EXTRA=leaked", "JAVA_HOME_8_X64=/usr/lib/jvm/x"],
        });
        Assert.True(harness.Platform.UnitMode, harness.Platform.ManagerUnavailableReason);
        List<string> environment = ["A=1", "PATH=/usr/bin:/bin"];
        var endEnvironment = Path.Combine(harness.Root, "end-env.txt");
        var printed = harness.Launch(["/usr/bin/env", "-0"], environment: environment,
            endSteps: [LinuxHarness.Step("env", 10_000, "/bin/sh", "-c", "env > \"$1\"", "sh", endEnvironment)]);
        Assert.Equal(0, LinuxHarness.WaitExit(printed, Bound).ExitStatus);
        var received = File.ReadAllText(Path.Combine(harness.DataRoot, "logs", ((LinuxAttemptHandle)printed).Files.AttemptName, AttemptFiles.Stdout))
            .Split('\0', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(environment.Order(StringComparer.Ordinal), received.Order(StringComparer.Ordinal));

        // The end steps get the same exact environment (the shell adds only its own PWD, SHLVL and _).
        var endNames = File.ReadAllLines(endEnvironment).Select(line => line.Split('=')[0]).ToHashSet(StringComparer.Ordinal);
        Assert.DoesNotContain("ARCFORGES_TEST_MANAGER_EXTRA", endNames);
        Assert.DoesNotContain("JAVA_HOME_8_X64", endNames);
        Assert.DoesNotContain("INVOCATION_ID", endNames);
        Assert.Contains("A", endNames);
    }

    [Theory(Timeout = 120_000)]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(-1)]
    public void ACommandKilledByARealTimeSignalIsRecordedWithItAndItsEndStepsRun(int offset)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // RTMIN, RTMIN+3 and RTMAX (offset -1): systemd writes them as RTMIN+n in $EXIT_STATUS; they are success statuses of the unit
        // too, so ExecStop runs.
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var signal = offset < 0 ? Libc.SigRtMax : Libc.SigRtMin + offset;
        var ran = Path.Combine(harness.Root, "end-ran.txt");
        var handle = harness.Launch(["/bin/sh", "-c", "kill -" + signal.ToString(CultureInfo.InvariantCulture) + " $$; sleep 5"],
            endSteps: [LinuxHarness.Step("marker", 10_000, "/bin/sh", "-c", "echo ran > \"$1\"", "sh", ran)]);
        var exit = LinuxHarness.WaitExit(handle, Bound);
        Assert.Equal(("killed", signal), (exit.ExitCodeKind, exit.ExitStatus));
        Assert.True(File.Exists(ran), "The end step did not run.");
    }

    [Fact(Timeout = 120_000)]
    public void ALeftoverThatIgnoresSigtermIsKilledOnceLeftoverGraceEnds()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // 04 section 3: after leftover_grace the remaining processes are killed at once (the forced phase), not after TimeoutStopSec.
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var watch = Stopwatch.StartNew();
        var handle = harness.Launch(["/bin/sh", "-c", "(trap '' TERM; exec sleep 60) & sleep 0.2; exit 0"], leftoverGraceMs: 1_000);
        var exit = LinuxHarness.WaitExit(handle, Bound);
        Assert.Equal(("exited", 0), (exit.ExitCodeKind, exit.ExitStatus));
        Assert.Equal(["sleep"], exit.LeftoversTerminated);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(8), $"The attempt took {watch.Elapsed} (leftover_grace 1 s; TimeoutStopSec would be 16 s).");
    }

    // isolation=exclusive: a spawn into a frozen cgroup blocks the whole user manager, and every platform start releases stuck freezes machine-wide.
    [Fact(Timeout = 240_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task AFrozenUnitBlockingTheManagerIsThawedByAStartingPlatformAndByTheGuard()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // A node or guard that died between killing a frozen unit's processes and thawing it leaves the cgroup frozen while the manager
        // spawns ExecStop into it. Observed (L-24): systemd 257 forks a child named "systemd" (exe unreadable) into the cgroup and the
        // whole manager blocks until it is thawed; systemd 255.4 puts systemd-executor (named "9") there, keeps answering, and the unit
        // stays deactivating until the cgroup is thawed. Neither the platform's start nor the guard needs the manager to release it.
        // What the running systemd does is printed and asserted as observed.
        RequireUnits();
        using var harness = LinuxHarness.Start();

        var first = (LinuxAttemptHandle)harness.Launch(["sleep", "60"]);
        var firstFrozen = LeaveStuck(first);
        var restarted = harness.NewPlatform();
        if (firstFrozen)
        {
            Assert.Contains(first.CgroupDirectory!, restarted.ReleasedFreezes);
        }

        Assert.Equal("0", File.ReadAllText(Path.Combine(first.CgroupDirectory!, "cgroup.freeze")).Trim());
        var firstExit = LinuxHarness.WaitExit(first, Bound);
        Assert.Equal(("killed", 9), (firstExit.ExitCodeKind, firstExit.ExitStatus));

        var second = (LinuxAttemptHandle)harness.Launch(["sleep", "60"]);
        LeaveStuck(second);
        using var stop = new CancellationTokenSource();
        var guard = Task.Run(() => GuardRole.Run(new GuardOptions { DataRoot = harness.DataRoot, Stop = stop.Token }), Ct);
        try
        {
            LinuxHarness.WaitFor(() => File.ReadAllText(Path.Combine(second.CgroupDirectory!, "cgroup.freeze")).Trim() == "0", Bound, "the guard to thaw the cgroup");
            var secondExit = LinuxHarness.WaitExit(second, Bound);
            Assert.Equal(("killed", 9), (secondExit.ExitCodeKind, secondExit.ExitStatus));
        }
        finally
        {
            await stop.CancelAsync();
            Assert.Equal(0, await guard.WaitAsync(Bound, Ct));
        }

        // Returns whether the cgroup is still frozen once the manager reacted: then only its spawn (or nothing) may be left in it.
        static bool LeaveStuck(LinuxAttemptHandle handle)
        {
            LinuxHarness.WaitFor(() => handle.Root is not null && handle.CgroupDirectory is not null && handle.Processes().Count > 0, Bound, "the unit");
            var directory = handle.CgroupDirectory!;
            ProcFs.WriteControl(Path.Combine(directory, "cgroup.freeze"), "1");
            LinuxHarness.WaitFor(() => File.ReadAllText(Path.Combine(directory, "cgroup.events")).Contains("frozen 1", StringComparison.Ordinal), Bound, "the freeze");
            foreach (var pid in ProcFs.Procs(directory))
            {
                _ = Libc.Kill(pid, Libc.SigKill);
            }

            // A deliberate hold (the scenario): give the manager time to react to the dead main process (spawn ExecStop into the frozen
            // cgroup, or anything else; what it does depends on the systemd version, so there is no single event to await).
            Thread.Sleep(1_500);
            var manager = UnitControl.ManagerPid(UnitControl.ManagerCgroup());
            var observation = Observe(directory, handle.Unit, manager);
            TestContext.Current.TestOutputHelper?.WriteLine(observation);
            var settled = Stopwatch.StartNew();
            while (!(Frozen(directory) is false || UnitControl.OnlyManagerSpawns(directory, manager)))
            {
                Assert.True(settled.Elapsed < TimeSpan.FromSeconds(20),
                    "Processes other than the manager's spawn stay in the frozen cgroup: " + Observe(directory, handle.Unit, manager));
                Thread.Sleep(100);
            }

            return Frozen(directory) is true;
        }

        static bool? Frozen(string directory) => ProcFs.Text(Path.Combine(directory, "cgroup.freeze")) is { } value ? value == "1" : null;
    }

    // isolation=exclusive: it asserts that the machine-wide release of stuck freezes finds nothing.
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public void APausedAttemptStaysFrozenAcrossAPlatformStart()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // The release of stuck freezes never thaws a paused attempt: its own processes are still in the cgroup.
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var handle = (LinuxAttemptHandle)harness.Launch(["/bin/sh", "-c", "sleep 60 & sleep 60"]);
        LinuxHarness.WaitFor(() => handle.Processes().Count >= 3, Bound, "the tree");
        handle.Freeze();
        var directory = handle.CgroupDirectory!;
        LinuxHarness.WaitFor(() => File.ReadAllText(Path.Combine(directory, "cgroup.events")).Contains("frozen 1", StringComparison.Ordinal), Bound, "the freeze");
        var restarted = harness.NewPlatform();
        Assert.DoesNotContain(directory, restarted.ReleasedFreezes);
        Assert.Empty(UnitControl.ReleaseStuckFreezes());
        Assert.Contains("frozen 1", File.ReadAllText(Path.Combine(directory, "cgroup.events")), StringComparison.Ordinal);
        handle.Thaw();
        LinuxHarness.WaitFor(() => File.ReadAllText(Path.Combine(directory, "cgroup.events")).Contains("frozen 0", StringComparison.Ordinal), Bound, "the thaw");
        handle.Terminate();
        Assert.Equal(9, LinuxHarness.WaitExit(handle, Bound).ExitStatus);
    }

    /// <summary>What the frozen cgroup holds and whether the manager answers (bounded), for the test output and failure messages.</summary>
    private static string Observe(string directory, string unit, int manager)
    {
        var text = new System.Text.StringBuilder();
        text.Append(SystemdVersion()).Append("; manager pid ").Append(manager).Append("; ").Append(unit).Append(": ");
        text.Append(File.ReadAllText(Path.Combine(directory, "cgroup.events")).ReplaceLineEndings(" ").Trim()).Append("; processes:");
        foreach (var pid in ProcFs.Procs(directory))
        {
            var target = UnitControl.Executable(pid) ?? "(unreadable)";
            var stat = ProcFs.Stat(pid);
            text.Append(CultureInfo.InvariantCulture, $" [{pid} comm={ProcFs.Image(pid)} exe={target} ppid={stat?.ParentPid} state={stat?.State} spawn={UnitControl.IsManagerSpawn(pid, manager)}]");
        }

        text.Append("; manager answers: ").Append(ManagerAnswer(unit));
        return text.ToString();
    }

    private static string SystemdVersion()
    {
        var start = new ProcessStartInfo("systemctl", "--version") { RedirectStandardOutput = true, UseShellExecute = false };
        using var process = Process.Start(start)!;
        var line = process.StandardOutput.ReadLine() ?? "?";
        process.WaitForExit(5_000);
        return line;
    }

    /// <summary><c>systemctl --user show -P ActiveState</c> within 3 s, or "blocked" (the process is killed).</summary>
    private static string ManagerAnswer(string unit)
    {
        var start = new ProcessStartInfo("systemctl") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in (string[])["--user", "show", "-P", "ActiveState", unit])
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        if (!process.WaitForExit(3_000))
        {
            process.Kill();
            process.WaitForExit(5_000);
            return "no (blocked for 3 s)";
        }

        return "yes (" + output.Result.Trim() + ")";
    }

    [Fact(Timeout = 120_000)]
    public void FreezeAndThawStopAndResumeTheWholeTree()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // R-EXE-011: pause through FreezeUnit (cgroup.freeze); the platform reports pause SUPPORTED.
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var counter = Path.Combine(harness.Root, "count.txt");
        var child = Path.Combine(harness.Root, "child.txt");
        var handle = (LinuxAttemptHandle)harness.Launch(["/bin/sh", "-c",
            "(while :; do echo x >> \"$2\"; sleep 0.02; done) & while :; do echo y >> \"$1\"; sleep 0.02; done", "sh", counter, child]);
        // The handle learns its cgroup from the manager (Processes() asks for it); under load that answer can come after the first writes.
        LinuxHarness.WaitFor(() => File.Exists(counter) && File.Exists(child) && new FileInfo(child).Length > 20 && handle.Processes().Count >= 2
            && handle.CgroupDirectory is not null, Bound, "the tree to write");
        handle.Freeze();
        var events = Path.Combine(handle.CgroupDirectory!, "cgroup.events");
        Assert.Contains("frozen 1", File.ReadAllText(events), StringComparison.Ordinal);
        var (parent, descendant) = (new FileInfo(counter).Length, new FileInfo(child).Length);

        // A deliberate hold (no write can be awaited from a frozen tree): over 500 ms, 25 writes per process would have happened.
        Thread.Sleep(500);
        Assert.Equal(parent, new FileInfo(counter).Length);
        Assert.Equal(descendant, new FileInfo(child).Length);
        handle.Thaw();
        LinuxHarness.WaitFor(() => File.ReadAllText(events).Contains("frozen 0", StringComparison.Ordinal), Bound, "the thaw");
        LinuxHarness.WaitFor(() => new FileInfo(child).Length > descendant && new FileInfo(counter).Length > parent, Bound, "the tree to resume");
        handle.Terminate();
        Assert.Equal(9, LinuxHarness.WaitExit(handle, Bound).ExitStatus);
    }

    [Fact(Timeout = 120_000)]
    public async Task TheGracefulPhaseSignalsEveryProcessAndTheForcedPhaseKillsATreeThatIgnoresIt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        using var harness = LinuxHarness.Start();

        // A tree that ends on SIGTERM: KillUnit("all", SIGTERM) ends it, and the record says killed by TERM.
        var polite = harness.Launch(["/bin/sh", "-c", "sleep 60 & sleep 60"]);
        Assert.NotNull(await polite.Started.WaitAsync(Bound, Ct));
        var outcome = polite.RequestGracefulStop(null);
        Assert.True(outcome.ConsoleSignalled, outcome.Reason);
        var politeExit = LinuxHarness.WaitExit(polite, Bound);
        Assert.Equal(("killed", 15), (politeExit.ExitCodeKind, politeExit.ExitStatus));

        // A tree that ignores SIGTERM (and SIGINT, the task's stop_signal here) survives the graceful phase; the forced phase kills it whole.
        var stubborn = (LinuxAttemptHandle)harness.Launch(["/bin/sh", "-c", "trap '' TERM INT; sleep 60 & sleep 60"]);
        Assert.NotNull(await stubborn.Started.WaitAsync(Bound, Ct));
        LinuxHarness.WaitFor(() => stubborn.Processes().Count >= 3, Bound, "the tree");
        Assert.True(stubborn.RequestGracefulStop("SIGINT").ConsoleSignalled);

        // A deliberate hold: the tree that ignores the signal is still whole 700 ms later (its survival cannot be awaited).
        Thread.Sleep(700);
        Assert.Equal(3, stubborn.Processes().Count);
        var watch = Stopwatch.StartNew();
        stubborn.Terminate();
        var exit = LinuxHarness.WaitExit(stubborn, Bound);
        Assert.Equal(("killed", 9), (exit.ExitCodeKind, exit.ExitStatus));
        Assert.True(stubborn.LastLimitStop!.Frozen);
        Assert.Empty(exit.LeftoversTerminated);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"The forced phase took {watch.Elapsed}.");
        LinuxHarness.WaitFor(() => SystemdTestEnvironment.Property(stubborn.Unit, "LoadState") is "not-found" or "", Bound, "the unit to be collected");
    }

    [Fact(Timeout = 120_000)]
    public void ALimitStopFreezesTheUnitBeforeItKillsIt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // 04 section 6 step 4: limit stops skip the graceful phase; on Linux the unit is frozen at once and then killed.
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var handle = (LinuxAttemptHandle)harness.Launch([TestPrograms.TestLoad, "output", "--bytes", "4294967296", "--rate", "20000000"]);
        var attempt = Directory.EnumerateDirectories(Path.Combine(harness.DataRoot, "logs")).Single();
        var output = Path.Combine(attempt, AttemptFiles.Stdout);
        LinuxHarness.WaitFor(() => File.Exists(output) && new FileInfo(output).Length > 2_000_000, Bound, "the flood");
        var described = handle.StopAtLimit();
        var stop = handle.LastLimitStop!;
        Assert.True(stop.Frozen, described);
        Assert.True(stop.FrozenAt <= stop.KilledAt, described);
        Assert.True(stop.Killed >= 1);
        Assert.Contains("frozen at", described, StringComparison.Ordinal);
        var exit = LinuxHarness.WaitExit(handle, Bound);
        Assert.Equal(("killed", 9), (exit.ExitCodeKind, exit.ExitStatus));
        var size = new FileInfo(output).Length;

        // A deliberate hold: nothing writes the output any more 300 ms after the exit record (an absence cannot be awaited).
        Thread.Sleep(300);
        Assert.Equal(size, new FileInfo(output).Length);
    }

    [Fact(Timeout = 120_000)]
    public void LaunchStepsRunInsideTheUnitBeforeTheCommandWhichStaysTheMainProcess()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // 04 section 3 (L-13): ExecStart is exec-launch; the steps run in the unit's cgroup, then the command replaces it (execve).
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var stepFile = Path.Combine(harness.Root, "step.txt");
        var commandFile = Path.Combine(harness.Root, "command.txt");
        var handle = (LinuxAttemptHandle)harness.Launch(
            ["/bin/sh", "-c", "echo $$ > \"$1\"; cat /proc/self/cgroup >> \"$1\"; date +%s%N >> \"$1\"; exit 4", "sh", commandFile],
            launchSteps: [LinuxHarness.Step("prepare", 30_000, "/bin/sh", "-c", "cat /proc/self/cgroup > \"$1\"; date +%s%N >> \"$1\"; sleep 0.2", "sh", stepFile)]);
        var exit = LinuxHarness.WaitExit(handle, Bound);
        Assert.Equal(("exited", 4), (exit.ExitCodeKind, exit.ExitStatus));
        Assert.Null(handle.TryReadLaunchFailure());
        var step = File.ReadAllLines(stepFile);
        var command = File.ReadAllLines(commandFile);
        var unitCgroup = "0::" + handle.CgroupDirectory![ProcFs.CgroupRoot.Length..];
        Assert.Equal(unitCgroup, step[0]);
        Assert.Equal(unitCgroup, command[1]);
        Assert.True(long.Parse(step[1], CultureInfo.InvariantCulture) < long.Parse(command[2], CultureInfo.InvariantCulture), "The step ran after the command.");

        // The command kept the PID systemd started (exec-launch replaced itself), so it is the unit's main process and the root.
        Assert.Equal(handle.Root!.Pid.ToString(CultureInfo.InvariantCulture), command[0]);
    }

    [Fact(Timeout = 120_000)]
    public void AFailingLaunchStepIsRecordedAndTheCommandNeverRuns()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var marker = Path.Combine(harness.Root, "ran.txt");
        var handle = harness.Launch(["/bin/sh", "-c", "echo ran > \"$1\"", "sh", marker],
            launchSteps: [LinuxHarness.Step("compiler-server", 30_000, "/bin/sh", "-c", "exit 4")]);
        var exit = LinuxHarness.WaitExit(handle, Bound);
        var launch = handle.TryReadLaunchFailure();
        Assert.NotNull(launch);
        Assert.Equal("compiler-server", launch!.Step);
        Assert.Equal(4, launch.ExitCode);
        Assert.Contains("exited with code 4", launch.Error, StringComparison.Ordinal);
        Assert.Equal(ExecLaunchRole.LaunchFailed, exit.ExitStatus);
        Assert.False(File.Exists(marker));
    }

    [Fact(Timeout = 120_000)]
    public void EndStepsRunAsExecStopBeforeTheRemainingProcessesAreStopped()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var background = Path.Combine(harness.Root, "background.txt");
        var seen = Path.Combine(harness.Root, "seen.txt");
        var handle = harness.Launch(["/bin/sh", "-c", "sleep 60 & echo $! > \"$1\"; exit 5", "sh", background],
            endSteps: [LinuxHarness.Step("stats", 10_000, "/bin/sh", "-c", "cat /sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/cgroup.procs > \"$1\"", "sh", seen)],
            leftoverGraceMs: 1_000);
        var exit = LinuxHarness.WaitExit(handle, Bound);
        Assert.Equal(("exited", 5), (exit.ExitCodeKind, exit.ExitStatus));
        var sleeper = File.ReadAllText(background).Trim();

        // The end step saw the leftover still running in the unit; systemd stopped it afterwards, and the record lists it.
        Assert.Contains(sleeper, File.ReadAllLines(seen));
        Assert.Equal(["sleep"], exit.LeftoversTerminated);
        Assert.Null(ProcFs.StartOf(int.Parse(sleeper, CultureInfo.InvariantCulture)));
        var stop = StopRecord.TryRead(new AttemptFiles(harness.DataRoot, Path.GetFileName(Directory.EnumerateDirectories(Path.Combine(harness.DataRoot, "logs")).Single())).StopPath)!;
        Assert.Equal("exited", stop.EndSteps.Single().Outcome);
    }

    [Fact(Timeout = 120_000)]
    public void SlowAndFailingEndStepsNeverChangeTheResult()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var watch = Stopwatch.StartNew();
        var handle = harness.Launch(["/bin/sh", "-c", "exit 0"],
            endSteps:
            [
                LinuxHarness.Step("failing", 10_000, "/bin/sh", "-c", "exit 7"),
                LinuxHarness.Step("slow", 30_000, "/bin/sleep", "60"),
                LinuxHarness.Step("after-budget", 10_000, "/bin/true"),
            ]);
        var exit = LinuxHarness.WaitExit(handle, Bound);
        Assert.Equal(("exited", 0, "success"), (exit.ExitCodeKind, exit.ExitStatus, exit.ServiceResult));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(25), $"The end steps took {watch.Elapsed} (budget 10 s).");
        var stop = StopRecord.TryRead(new AttemptFiles(harness.DataRoot, Path.GetFileName(Directory.EnumerateDirectories(Path.Combine(harness.DataRoot, "logs")).Single())).StopPath)!;
        Assert.Equal(["failed", "timed_out", "skipped"], stop.EndSteps.Select(step => step.Outcome));
        Assert.Equal(7, stop.EndSteps[0].ExitCode);
    }

    [Fact(Timeout = 120_000)]
    public void AnOomKillIsRecordedFromTheFailedUnit()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // When OOMPolicy=kill ends a unit, systemd may skip ExecStopPost (seen when the kill races the unit's stop) or run it: either the
        // failed unit, kept by CollectMode=inactive, is recorded from its properties, or exit-record records it; the result is the same.
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var handle = (LinuxAttemptHandle)harness.Launch(["/bin/sh", "-c", "head -c 400M /dev/zero | tail > /dev/null"],
            new ContainerLimits { MemoryMaxBytes = 64L << 20, SwapMaxBytes = 0 });
        var exit = LinuxHarness.WaitExit(handle, Bound);
        TestContext.Current.TestOutputHelper?.WriteLine($"recorded by {exit.RecordedBy}");
        Assert.Equal("oom-kill", exit.ServiceResult);
        Assert.Contains(exit.RecordedBy, (string[])["unit", "exit-record"]);
        Assert.True(exit.OomKills >= 1, $"{exit.OomKills} OOM kills recorded.");
        Assert.InRange(exit.MemPeakBytes, 1, 64L << 20);
        Assert.Equal(0, exit.SwapPeakBytes);

        // Once the node recorded it, the failed unit is unloaded.
        handle.Acknowledge();
        LinuxHarness.WaitFor(() => SystemdTestEnvironment.Property(handle.Unit, "LoadState") is "not-found" or "", Bound, "the failed unit to be reset");
    }

    [Fact(Timeout = 120_000)]
    public async Task ARestartedPlatformReopensARunningUnitAndAFinishedOneLeavesItsRecord()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // 04 section 9 (F-L03 at the platform): the platform that started the units is gone; a new one finds them by name.
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var running = harness.Launch(["sleep", "60"]);
        var root = (await running.Started.WaitAsync(Bound, Ct))!;
        var finishedFiles = harness.Files(out _);
        var finished = harness.Launch(["/bin/sh", "-c", "exit 6"], files: finishedFiles);
        LinuxHarness.WaitExit(finished, Bound);
        var runningFiles = new AttemptFiles(harness.DataRoot, ((LinuxAttemptHandle)running).Files.AttemptName);
        harness.Platform.Dispose();

        var restarted = harness.NewPlatform();
        var reopened = restarted.Reopen(harness.NodeName, runningFiles, null);
        Assert.NotNull(reopened);
        Assert.Equal(root.Pid, reopened!.Root!.Pid);
        Assert.True(reopened.RootRunning);
        Assert.Null(restarted.Reopen(harness.NodeName, finishedFiles, null));
        Assert.Equal(6, ExitRecord.TryRead(finishedFiles.ExitPath)!.ExitStatus);
        reopened.Terminate();
        Assert.Equal(9, LinuxHarness.WaitExit(reopened, Bound).ExitStatus);
    }

    // isolation=exclusive: daemon-reexec restarts the user manager every other test uses.
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task AttemptsSurviveARestartOfTheUserManagerAndThePlatformKeepsControllingThem()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // F-L03 (risk mitigation: the user manager restarts): systemctl --user daemon-reexec serializes and restores the units; the
        // attempt keeps running in its unit, the platform keeps controlling it, and units started afterwards leave their records.
        RequireUnits();
        using var harness = LinuxHarness.Start();
        var running = harness.Launch(["sleep", "60"]);
        var root = (await running.Started.WaitAsync(Bound, Ct))!;
        var unit = ((LinuxAttemptHandle)running).Unit;

        var reexec = SystemdTestEnvironment.Systemctl("daemon-reexec");
        Assert.True(reexec.ExitCode == 0, reexec.Output);
        Assert.Equal("active", SystemdTestEnvironment.Property(unit, "ActiveState"));
        Assert.Equal(root.Pid.ToString(CultureInfo.InvariantCulture), SystemdTestEnvironment.Property(unit, "MainPID"));

        running.Refresh();
        Assert.True(running.RootRunning);
        Assert.Contains(root.Pid, running.Processes().Select(process => process.Pid));
        var after = harness.Launch(["/bin/sh", "-c", "exit 4"]);
        Assert.Equal(4, LinuxHarness.WaitExit(after, Bound).ExitStatus);
        running.Terminate();
        var exit = LinuxHarness.WaitExit(running, Bound);
        Assert.Equal(("killed", 9), (exit.ExitCodeKind, exit.ExitStatus));
        Assert.NotNull(ExitRecord.TryRead(((LinuxAttemptHandle)running).Files.ExitPath));
    }

    // isolation=exclusive: the heartbeat age (2-3 s) and the overshoot (rate over 500 ms) are timing bounds.
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task TheGuardFreezesAndKillsAFloodOnceTheHeartbeatIsStale()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // 06 section 5: arcforges node guard takes over after guard_takeover_ms without a heartbeat change and stops the flood at the limit.
        RequireUnits();
        using var harness = LinuxHarness.Start();
        const long Limit = 4L << 20;
        const long Rate = 2L << 20;
        var files = harness.Files(out var name);
        Directory.CreateDirectory(files.Directory);
        HelperFiles.WriteAtomically(files.GuardPath, new GuardSpec
        {
            AttemptId = name,
            OutputFiles = [files.StdoutPath, files.StderrPath],
            MaxOutputBytes = Limit,
            TakeoverMs = 2_000,
            HeartbeatPath = AttemptFiles.HeartbeatPath(harness.DataRoot),
        }.ToJson());
        var handle = harness.Launch([TestPrograms.TestLoad, "output", "--bytes", "268435456", "--rate", Rate.ToString(CultureInfo.InvariantCulture)], files: files);
        Assert.NotNull(await handle.Started.WaitAsync(Bound, Ct));
        using var stop = new CancellationTokenSource();
        var started = Stopwatch.StartNew();
        var guard = Task.Run(() => GuardRole.Run(new GuardOptions { DataRoot = harness.DataRoot, Stop = stop.Token }), Ct);
        try
        {
            var exit = LinuxHarness.WaitExit(handle, Bound);
            Assert.Equal(("killed", 9), (exit.ExitCodeKind, exit.ExitStatus));
            var events = GuardEvent.ReadAll(files.GuardEventsPath);
            Assert.Equal(GuardEventKinds.Takeover, events[0].Event);
            var terminate = events.Single(item => item.Event == GuardEventKinds.Terminate);
            Assert.Equal("OUTPUT_LIMIT", terminate.Reason);
            var output = new FileInfo(files.StdoutPath).Length;
            TestContext.Current.TestOutputHelper?.WriteLine($"stopped after {started.ElapsedMilliseconds} ms at {output} bytes (limit {Limit}, {Rate} B/s)");
            Assert.True(output - Limit <= Rate / 2, $"The overshoot {output - Limit} exceeds the rate over one interval plus the stop latency.");
            Assert.InRange(events[0].HeartbeatAgeMs!.Value, 2_000, 3_000);
        }
        finally
        {
            await stop.CancelAsync();
            Assert.Equal(0, await guard.WaitAsync(Bound, Ct));
        }
    }
}

/// <summary>The observe-only platform without a user manager (AD-0005 Linux section 4): attempts are plain child processes.</summary>
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class DirectPlatformTests
{
    [Fact(Timeout = 120_000)]
    public void WithoutAUserManagerAttemptsRunAsChildProcessesAndEverythingIsObserveOnly()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux child processes.");
        using var harness = LinuxHarness.Start(options: slice => new LinuxPlatformOptions { Slice = slice, ManagerAddress = "unix:path=/nonexistent/arcforges-test-bus" });
        var platform = harness.Platform;
        Assert.False(platform.UnitMode);
        Assert.Equal("linux-direct", platform.Name);
        var report = platform.Evaluate();
        Assert.Equal(CpuControl.ObserveOnly, report.Cpu);
        Assert.Equal(MemoryControl.ObserveOnly, report.Memory);
        Assert.Equal(ProcessCountControl.ObserveOnly, report.Pids);
        Assert.Contains("cannot be reached", report.CpuReason, StringComparison.Ordinal);
        Assert.Equal(KillTreeGuarantee.BestEffort, report.KillTree);
        Assert.False(report.RestartSurvival);

        var handle = harness.Launch(["/bin/sh", "-c", "printf hi; exit 2"]);
        var exit = LinuxHarness.WaitExit(handle, TimeSpan.FromSeconds(60));
        Assert.Equal(("exited", 2, "node"), (exit.ExitCodeKind, exit.ExitStatus, exit.RecordedBy));
        var attempt = Directory.EnumerateDirectories(Path.Combine(harness.DataRoot, "logs")).Single();
        Assert.Equal("hi", File.ReadAllText(Path.Combine(attempt, AttemptFiles.Stdout)));
        Assert.Null(platform.Reopen(harness.NodeName, new AttemptFiles(harness.DataRoot, Path.GetFileName(attempt)), null));

        // The exact environment here too, a caller's own variable named like the carrier included.
        List<string> environment = ["A=1", "PATH=/usr/bin:/bin", "my-var=x", ExecLaunchRole.CarrierVariable + "=the caller's own value"];
        var printed = harness.Launch(["/usr/bin/env", "-0"], environment: environment);
        Assert.Equal(0, LinuxHarness.WaitExit(printed, TimeSpan.FromSeconds(60)).ExitStatus);
        var printedDirectory = Directory.EnumerateDirectories(Path.Combine(harness.DataRoot, "logs")).Single(directory => directory != attempt);
        var received = File.ReadAllText(Path.Combine(printedDirectory, AttemptFiles.Stdout)).Split('\0', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(environment.Order(StringComparer.Ordinal), received.Order(StringComparer.Ordinal));

        var tree = harness.Launch(["/bin/sh", "-c", "sleep 60 & sleep 60"]);
        LinuxHarness.WaitFor(() => tree.Processes().Count >= 2, TimeSpan.FromSeconds(30), "the tree");
        tree.Terminate();
        var treeExit = LinuxHarness.WaitExit(tree, TimeSpan.FromSeconds(60));
        Assert.Equal(("killed", 9), (treeExit.ExitCodeKind, treeExit.ExitStatus));
        Assert.Empty(tree.Processes());
    }
}
