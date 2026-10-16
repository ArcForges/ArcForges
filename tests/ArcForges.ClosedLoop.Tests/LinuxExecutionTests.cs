// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Node.Platform;
using ArcForges.Tests;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// Linux execution end to end with real processes (loop=local, env=linux-real; AF-EXEC-02): the <c>arcforges</c> node and CLI over real
/// transient units of the user manager. Covers byte-identical output and exit codes against direct runs (R-EXE-003), each limit from the
/// node in the unit's and the slice's cgroup files (L-07, L-13; R-RES-007), survival with durable exit records across a node crash and a
/// <c>systemctl --user restart</c> of the node unit (F-L03; R-EXE-008, R-EXE-018), the observe-only and partial modes (R-RES-008), the
/// client-timeout hand-off and <c>ReleaseCallerBinding</c> (R-AI-010), the guard unit stopping an output flood with the node killed, with
/// the node unit failed after repeated crashes, and with the node restarting faster than <c>guard_takeover_ms</c> (R-STOR-009), and the
/// systemd watchdog restarting a node whose enforcement loop or cache-store probe hangs (13 section 3.4). The unit files are the shipped
/// ones of <c>packaging/linux</c>, installed per test in the runtime unit directory with this test's binary and environment.
/// </summary>
[Trait("loop", "local")]
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class LinuxExecutionTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(90);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RequireUnits() => Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);

    [Fact(Timeout = 300_000)]
    public async Task RunMirrorsTheStreamsByteExactlyAndExitsLikeTheDirectRun()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        string[] workload = [TestNode.TestLoad, "output", "--bytes", "8388608", "--line-bytes", "77", "--stream", "both", "--seed", "11"];
        var managed = await node.CliBytesAsync(Bound, ["run", "--", .. workload]);
        var direct = Direct(workload);
        Assert.Equal(direct.ExitCode, managed.ExitCode);
        Assert.Equal(SHA256.HashData(direct.Stdout), SHA256.HashData(managed.Stdout));
        Assert.Equal(SHA256.HashData(direct.Stderr), SHA256.HashData(managed.Stderr));

        // The argument vector arrives exactly: systemd's own $VAR, $$ and %-specifier expansion never touches it.
        string[] args = [TestNode.TestLoad, "args", "two words", "quote\"inside", "back\\\\\"slash", "unicode äöü 中文", "$$", "${HOME}", "$PATH", "%h", "%%", ""];
        var argsRun = await node.CliBytesAsync(Bound, ["run", "--", .. args]);
        Assert.Equal(Encoding.UTF8.GetString(Direct(args).Stdout).Replace(Environment.CurrentDirectory, "<cwd>", StringComparison.Ordinal),
            Encoding.UTF8.GetString(argsRun.Stdout).Replace(Environment.CurrentDirectory, "<cwd>", StringComparison.Ordinal));

        Assert.Equal(7, (await node.CliBytesAsync(Bound, "run", "--", "/bin/sh", "-c", "exit 7")).ExitCode);
        Assert.Equal(127, (await node.CliBytesAsync(Bound, "run", "--", "arcforges-no-such-program")).ExitCode);
        var notExecutable = Path.Combine(node.Root, "not-executable");
        File.WriteAllText(notExecutable, "#!/bin/sh\nexit 0\n");
        Assert.Equal(126, (await node.CliBytesAsync(Bound, "run", "--", notExecutable)).ExitCode);

        // A signal maps to 128 + n (04 section 5): the program's own, and the node's stop of a timed-out task (SIGTERM).
        var signalled = await node.CliBytesAsync(Bound, "run", "--", "/bin/sh", "-c", "kill -TERM $$");
        Assert.Equal(143, signalled.ExitCode);

        // Real-time signals too (RTMIN, RTMIN+3, RTMAX as the shell numbers them), exactly like the direct run.
        foreach (var signal in (int[])[34, 37, 64])
        {
            string[] killer = ["/bin/sh", "-c", $"kill -{signal.ToString(CultureInfo.InvariantCulture)} $$"];
            Assert.Equal(Direct(killer).ExitCode, (await node.CliBytesAsync(Bound, ["run", "--", .. killer])).ExitCode);
            Assert.Equal(128 + signal, Direct(killer).ExitCode);
        }
        var timedOut = await node.CliBytesAsync(Bound, "--timeout", "2s", "run", "--", "/bin/sleep", "60");
        Assert.Equal(143, timedOut.ExitCode);
        Assert.Contains("TIMED_OUT", Encoding.UTF8.GetString(timedOut.Stderr), StringComparison.Ordinal);
    }

    [Fact(Timeout = 300_000)]
    public async Task EachLimitFromTheNodeReachesTheUnitAndTheSlice()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        var detached = await node.CliBytesAsync(Bound, "run", "--detach", "--priority", "high", "--mem", "64MiB", "--mem-max", "128MiB", "--", "/bin/sleep", "60");
        Assert.Equal(0, detached.ExitCode);
        var id = Encoding.UTF8.GetString(detached.Stdout).Trim();
        var attempt = await RunningAttemptAsync(node, id);
        var unit = SystemdTestEnvironment.AttemptUnit(attempt);
        var cgroup = SystemdTestEnvironment.Property(unit, "ControlGroup");
        if (cgroup.Length == 0)
        {
            Assert.Fail($"ControlGroup of {unit} is empty: {SystemdTestEnvironment.Describe(unit)}; {await DiagnoseAsync(node, id)}");
        }

        var directory = "/sys/fs/cgroup" + cgroup;
        Assert.Contains("/" + node.Slice + "/", directory, StringComparison.Ordinal);

        // 03 section 5.2 from the node: CPUWeight by priority (HIGH 200), MemoryHigh = 1.25 x mem_expected, MemoryMax = mem_ceiling,
        // MemorySwapMax = swap_allowance (0), TasksMax 4096, OOMPolicy=kill (memory.oom.group).
        Assert.Equal("200", Read(directory, "cpu.weight"));
        Assert.Equal((80L << 20).ToString(CultureInfo.InvariantCulture), Read(directory, "memory.high"));
        Assert.Equal((128L << 20).ToString(CultureInfo.InvariantCulture), Read(directory, "memory.max"));
        Assert.Equal("0", Read(directory, "memory.swap.max"));
        Assert.Equal("4096", Read(directory, "pids.max"));
        Assert.Equal("1", Read(directory, "memory.oom.group"));

        // 03 section 5.1 on the slice: CPUQuota from B_cpu, MemoryHigh = B_mem, MemoryMax = C_mem - R_mem, MemorySwapMax 0, TasksMax 32768.
        var facts = Capabilities((await node.CliAsync("node", "capabilities", "--json")).Json());
        string Fact(string name) => facts.GetProperty("platformFacts").EnumerateArray().Single(fact => fact.GetProperty("name").GetString() == name).GetProperty("value").GetString()!;
        var slice = Path.GetDirectoryName(directory)!;
        var rate = long.Parse(Fact("root_cpu_rate"), CultureInfo.InvariantCulture);
        Assert.Equal((rate * Environment.ProcessorCount * 10).ToString(CultureInfo.InvariantCulture) + " 100000", Read(slice, "cpu.max"));
        var page = Environment.SystemPageSize;
        var hard = long.Parse(Fact("root_memory_max_bytes"), CultureInfo.InvariantCulture);
        Assert.Equal((hard - (hard % page)).ToString(CultureInfo.InvariantCulture), Read(slice, "memory.max"));
        var high = long.Parse(Fact("root_memory_high_bytes"), CultureInfo.InvariantCulture);
        Assert.Equal((high - (high % page)).ToString(CultureInfo.InvariantCulture), Read(slice, "memory.high"));
        Assert.Equal("0", Read(slice, "memory.swap.max"));
        Assert.Equal("32768", Read(slice, "pids.max"));
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", id)).ExitCode);
        Assert.Equal("TASK_STATE_CANCELLED", JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement.GetProperty("state").GetString());
    }

    [Fact(Timeout = 300_000)]
    public async Task TheNodeKilledMidRunRecoversItsAttemptsFromTheirUnitsAndExitRecords()
    {
        // F-L03: executions survive a node crash; one that finished meanwhile is recorded from its durable exit record.
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = TestNode.Create();
        var first = await node.StartNodeAsync();
        var pidFile = Path.Combine(node.Root, "long.pid");

        // Both attempts wait for the go file the test writes once the node is dead, so neither can finish before the kill however slowly
        // the test runs (fixed sleeps raced with it under load).
        var go = Path.Combine(node.Root, "go");
        var id = Encoding.UTF8.GetString((await node.CliBytesAsync(Bound, "run", "--detach", "--", "/bin/sh", "-c",
            "echo $$ > \"$1\"; echo before; while [ ! -e \"$2\" ]; do sleep 0.05; done; echo while-down; exec sleep 120", "sh", pidFile, go)).Stdout).Trim();
        var shortId = Encoding.UTF8.GetString((await node.CliBytesAsync(Bound, "run", "--detach", "--", "/bin/sh", "-c",
            "while [ ! -e \"$1\" ]; do sleep 0.05; done; echo done; exit 5", "sh", go)).Stdout).Trim();
        var longAttempt = await RunningAttemptAsync(node, id);
        var shortAttempt = await RunningAttemptAsync(node, shortId);
        await TestNode.WaitAsync(() => File.Exists(pidFile), Bound, "the long attempt");

        first.Kill();
        await first.WaitForExitAsync(Ct);
        File.WriteAllText(go, "go");
        var pid = int.Parse(File.ReadAllText(pidFile).Trim(), CultureInfo.InvariantCulture);
        var root = ProcessIdentity.Capture(pid)!.Value;
        await TestNode.WaitAsync(() => File.Exists(Path.Combine(node.DataRoot, "logs", shortAttempt, AttemptFiles.Exit)), Bound, "the short attempt's exit record");
        var record = ExitRecord.TryRead(Path.Combine(node.DataRoot, "logs", shortAttempt, AttemptFiles.Exit))!;
        Assert.Equal(("exited", 5, "exit-record"), (record.ExitCodeKind, record.ExitStatus, record.RecordedBy));

        // The long attempt keeps running while the node is down: it writes its next line into the captured output.
        await TestNode.WaitAsync(() => TestNode.ReadShared(Path.Combine(node.DataRoot, "logs", longAttempt, AttemptFiles.Stdout)).Contains("while-down", StringComparison.Ordinal),
            Bound, "the long attempt's output while the node is down");
        Assert.True(root.IsRunning(), "The attempt survived the node.");

        await node.StartNodeAsync();
        var shortTask = JsonDocument.Parse((await node.CliAsync("tasks", "wait", shortId, "--json")).Output).RootElement;
        Assert.Equal(5, shortTask.GetProperty("currentAttempt").GetProperty("result").GetProperty("exitCode").GetInt32());
        Assert.True(shortTask.GetProperty("currentAttempt").GetProperty("nodeGap").GetBoolean());
        var shown = JsonDocument.Parse((await node.CliAsync("tasks", "show", id, "--json")).Output).RootElement.GetProperty("task");
        Assert.Equal("TASK_STATE_RUNNING", shown.GetProperty("state").GetString());
        Assert.True(shown.GetProperty("currentAttempt").GetProperty("nodeGap").GetBoolean());
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", id)).ExitCode);
        var cancelled = JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement;
        Assert.Equal("TASK_STATE_CANCELLED", cancelled.GetProperty("state").GetString());
        Assert.True(long.Parse(cancelled.GetProperty("currentAttempt").GetProperty("usage").GetProperty("memPeakBytes").GetString()!, CultureInfo.InvariantCulture) > 0);
        Assert.False(root.IsRunning());
        var logs = await node.CliBytesAsync(Bound, "tasks", "logs", id);
        Assert.Equal("before\nwhile-down\n", Encoding.UTF8.GetString(logs.Stdout));
    }

    [Fact(Timeout = 300_000)]
    public async Task AttemptsSurviveARestartOfTheNodeUnitWithDurableExitRecords()
    {
        // F-L03: the node runs as its user unit (13 section 3.4); `systemctl --user restart` stops only the node's own cgroup.
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = TestNode.Create();
        var unit = InstallNodeUnit(node);
        Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", unit).ExitCode);
        await node.WaitReadyAsync();
        var pidFile = Path.Combine(node.Root, "long.pid");
        var id = Encoding.UTF8.GetString((await node.CliBytesAsync(Bound, "run", "--detach", "--", "/bin/sh", "-c", "echo $$ > \"$1\"; exec sleep 120", "sh", pidFile)).Stdout).Trim();
        // The short attempt runs until the test writes the go file just before the restart (a fixed sleep could end before the test saw
        // it running).
        var go = Path.Combine(node.Root, "go");
        var shortId = Encoding.UTF8.GetString((await node.CliBytesAsync(Bound, "run", "--detach", "--", "/bin/sh", "-c",
            "while [ ! -e \"$1\" ]; do sleep 0.05; done; exit 9", "sh", go)).Stdout).Trim();
        var attempt = await RunningAttemptAsync(node, id);
        await RunningAttemptAsync(node, shortId);
        await TestNode.WaitAsync(() => File.Exists(pidFile), Bound, "the long attempt");
        var pid = int.Parse(File.ReadAllText(pidFile).Trim(), CultureInfo.InvariantCulture);
        var root = ProcessIdentity.Capture(pid)!.Value;

        // The execution is not in the node unit's cgroup but in its own unit in the slice.
        var nodeCgroup = SystemdTestEnvironment.RequiredProperty(unit, "ControlGroup");
        var attemptCgroup = File.ReadAllText($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/cgroup").Trim();
        Assert.DoesNotContain(nodeCgroup, attemptCgroup, StringComparison.Ordinal);
        Assert.EndsWith("/" + node.Slice + "/" + SystemdTestEnvironment.AttemptUnit(attempt), attemptCgroup, StringComparison.Ordinal);

        var before = SystemdTestEnvironment.RequiredProperty(unit, "MainPID");
        File.WriteAllText(go, "go");
        Assert.Equal(0, SystemdTestEnvironment.Systemctl("restart", unit).ExitCode);
        await node.WaitReadyAsync();
        Assert.NotEqual(before, SystemdTestEnvironment.Property(unit, "MainPID"));
        Assert.True(root.IsRunning(), "The attempt survived the restart of the node unit.");
        var shortTask = JsonDocument.Parse((await node.CliAsync("tasks", "wait", shortId, "--json")).Output).RootElement;
        Assert.Equal(9, shortTask.GetProperty("currentAttempt").GetProperty("result").GetProperty("exitCode").GetInt32());
        Assert.Equal("TASK_STATE_RUNNING", JsonDocument.Parse((await node.CliAsync("tasks", "show", id, "--json")).Output).RootElement.GetProperty("task").GetProperty("state").GetString());
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", id)).ExitCode);
        Assert.Equal("TASK_STATE_CANCELLED", JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement.GetProperty("state").GetString());
        Assert.Equal(0, (await node.CliAsync("node", "stop")).ExitCode);
        await TestNode.WaitAsync(() => SystemdTestEnvironment.Property(unit, "ActiveState") is "inactive" or "failed", Bound, "the node unit to stop");
    }

    [Fact(Timeout = 300_000)]
    public async Task WithoutAUserManagerTheNodeIsDegradedRefusesEnforcementAndLabelsTasks()
    {
        // R-RES-008, simulated as the design allows: a user manager address where nothing listens.
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux.");
        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_SYSTEMD_ADDRESS"] = "unix:path=" + Path.Combine(node.Root, "absent-user-manager");
        await node.StartNodeAsync();
        var status = (await node.CliAsync("status", "--json")).Json();
        Assert.Equal("NODE_LIFECYCLE_STATE_DEGRADED", status.GetProperty("node").GetProperty("state").GetString());
        var capabilities = Capabilities((await node.CliAsync("node", "capabilities", "--json")).Json());
        Assert.Equal("CPU_CONTROL_OBSERVE_ONLY", capabilities.GetProperty("cpu").GetString());
        Assert.Contains("cannot be reached", capabilities.GetProperty("memoryReason").GetString(), StringComparison.Ordinal);

        var refused = await node.CliBytesAsync(Bound, "run", "--require-enforcement", "memory", "--", "/bin/true");
        Assert.Equal(125, refused.ExitCode);
        Assert.Contains("enforcement_unavailable", Encoding.UTF8.GetString(refused.Stderr), StringComparison.Ordinal);
        var labelled = await node.CliBytesAsync(Bound, "run", "--detach", "--", "/bin/sh", "-c", "exit 3");
        var id = Encoding.UTF8.GetString(labelled.Stdout).Trim();
        var task = JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement;
        Assert.Equal(3, task.GetProperty("currentAttempt").GetProperty("result").GetProperty("exitCode").GetInt32());
        Assert.True(task.GetProperty("currentAttempt").GetProperty("unenforced").GetBoolean());
    }

    [Fact(Timeout = 300_000)]
    public async Task WithoutMemoryDelegationTheNodeIsPartialAndRefusesTasksRequiringMemory()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_TEST_CONTROLLERS"] = "cpu pids";
        await node.StartNodeAsync();
        var capabilities = Capabilities((await node.CliAsync("node", "capabilities", "--json")).Json());
        Assert.Equal("CPU_CONTROL_ENFORCED_SHARE_AND_CAP", capabilities.GetProperty("cpu").GetString());
        Assert.Equal("MEMORY_CONTROL_OBSERVE_ONLY", capabilities.GetProperty("memory").GetString());
        Assert.Contains("no memory delegation", capabilities.GetProperty("memoryReason").GetString(), StringComparison.Ordinal);
        Assert.Equal(125, (await node.CliBytesAsync(Bound, "run", "--require-enforcement", "memory", "--", "/bin/true")).ExitCode);
        var cpu = await node.CliBytesAsync(Bound, "run", "--require-enforcement", "cpu", "--detach", "--", "/bin/true");
        var task = JsonDocument.Parse((await node.CliAsync("tasks", "wait", Encoding.UTF8.GetString(cpu.Stdout).Trim(), "--json")).Output).RootElement;
        Assert.Equal("TASK_STATE_SUCCEEDED", task.GetProperty("state").GetString());
        Assert.True(task.GetProperty("currentAttempt").GetProperty("unenforced").GetBoolean());
    }

    // isolation=exclusive: the caller-gone cancellation within 5 s (AD-0006 section 7) is a product timing contract.
    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task AClientTimeoutHandsOffWithExit124AndAnInterruptBeforeItCancels()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        var watch = Stopwatch.StartNew();
        var handoff = await node.CliBytesAsync(Bound, "run", "--client-timeout", "16s", "--", "/bin/sleep", "60");
        Assert.Equal(124, handoff.ExitCode);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"The hand-off took {watch.Elapsed}.");
        var message = Encoding.UTF8.GetString(handoff.Stderr);
        var handedOff = message.Split("arcforges tasks wait ")[1].Split('\n')[0].Trim();

        // A deliberate hold longer than the 5 s caller-gone window (AD-0006 section 7): the handed-off task is not cancelled.
        await Task.Delay(TimeSpan.FromSeconds(7), Ct);
        Assert.Contains("TASK_STATE_RUNNING", (await node.CliAsync("tasks", "show", handedOff, "--json")).Output, StringComparison.Ordinal);
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", handedOff)).ExitCode);

        // Interrupt before the hand-off: the killed client's bound task is cancelled within 5 s (AD-0006 section 7).
        var pidFile = Path.Combine(node.Root, "interrupted.pid");
        using var client = node.Start(TestNode.Host, ["--test-mode", "run", "--client-timeout", "10m", "--", "/bin/sh", "-c", "echo $$ > \"$1\"; exec sleep 60", "sh", pidFile]);
        await TestNode.WaitAsync(() => File.Exists(pidFile) && File.ReadAllText(pidFile).Trim().Length > 0, Bound, "the task to start");
        var root = ProcessIdentity.Capture(int.Parse(File.ReadAllText(pidFile).Trim(), CultureInfo.InvariantCulture))!.Value;
        client.Kill();
        await client.WaitForExitAsync(Ct);
        var interrupted = Stopwatch.StartNew();
        await TestNode.WaitAsync(() => TestNode.LogEvents(node.NodeLog, "execution.caller_gone").Count > 0, TimeSpan.FromSeconds(20), "the caller-gone cancellation");
        Assert.True(interrupted.Elapsed < TimeSpan.FromSeconds(5), $"Cancelled {interrupted.Elapsed} after the client ended.");
        await TestNode.WaitAsync(() => !root.IsRunning(), TimeSpan.FromSeconds(20), "the interrupted run's task to stop");
    }

    // isolation=exclusive: the takeover delay (takeover + 1 s) and the overshoot (rate over 500 ms) are timing bounds.
    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task TheGuardUnitStopsAFloodWhileTheNodeIsKilled()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        const long Limit = 8L << 20;
        const long Rate = 2L << 20;
        const int Takeover = 2_000;
        await using var node = TestNode.Create();
        SeedLimit(node, Limit, Takeover);
        var guard = InstallGuardUnit(node);
        var first = await node.StartNodeAsync();

        // The node starts the installed guard unit (13 section 3.4).
        await TestNode.WaitAsync(() => SystemdTestEnvironment.Property(guard, "ActiveState") == "active", Bound, "the node to start the guard unit");
        var id = Encoding.UTF8.GetString((await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "output", "--bytes", "268435456", "--rate", Rate.ToString(CultureInfo.InvariantCulture))).Stdout).Trim();
        var attempt = Path.Combine(node.DataRoot, "logs", await RunningAttemptAsync(node, id));
        first.Kill();
        await first.WaitForExitAsync(Ct);
        var killedAt = DateTimeOffset.UtcNow;
        var events = Path.Combine(attempt, AttemptFiles.GuardEvents);
        await TestNode.WaitAsync(() => GuardEvent.ReadAll(events).Any(item => item.Event == GuardEventKinds.Terminate), Bound, "the guard to stop the attempt");
        var all = GuardEvent.ReadAll(events);
        var takeoverDelay = DateTimeOffset.Parse(all.First(item => item.Event == GuardEventKinds.Takeover).At, CultureInfo.InvariantCulture) - killedAt;
        var output = new FileInfo(Path.Combine(attempt, AttemptFiles.Stdout)).Length;
        TestContext.Current.TestOutputHelper?.WriteLine($"takeover {takeoverDelay.TotalMilliseconds:0} ms after the kill; output {output} for a {Limit} limit at {Rate} B/s");
        Assert.True(takeoverDelay <= TimeSpan.FromMilliseconds(Takeover + 1_000), $"The guard took over {takeoverDelay.TotalMilliseconds:0} ms after the kill (15 section 2: takeover + 1 s).");
        Assert.True(output - Limit <= Rate / 2, $"The overshoot {output - Limit} exceeds the rate over one interval plus the stop latency.");

        await node.StartNodeAsync();
        var task = JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement;
        Assert.Equal("TERMINATION_REASON_OUTPUT_LIMIT", task.GetProperty("currentAttempt").GetProperty("result").GetProperty("terminationReason").GetString());
        Assert.Equal("GUARD", task.GetProperty("currentAttempt").GetProperty("limitEnforcedBy").GetString());
    }

    // isolation=exclusive: the overshoot (rate over 500 ms) is a timing bound.
    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task TheGuardUnitStopsAFloodWithTheNodeUnitFailedAfterRepeatedCrashes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        const long Limit = 16L << 20;
        const long Rate = 1L << 20;
        await using var node = TestNode.Create();
        SeedLimit(node, Limit, 2_000);
        InstallGuardUnit(node);

        // The shipped node unit with a shorter restart delay, so the start limit (StartLimitBurst=5) is reached quickly.
        var unit = InstallNodeUnit(node, content => content.Replace("RestartSec=2", "RestartSec=500ms", StringComparison.Ordinal));
        Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", unit).ExitCode);
        await node.WaitReadyAsync();
        var id = Encoding.UTF8.GetString((await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "output", "--bytes", "268435456", "--rate", Rate.ToString(CultureInfo.InvariantCulture))).Stdout).Trim();
        var attempt = Path.Combine(node.DataRoot, "logs", await RunningAttemptAsync(node, id));

        // Crash the node again and again until systemd gives up (start-limit-hit): the unit is failed and stays down.
        var crashes = 0;
        var watch = Stopwatch.StartNew();
        while (SystemdTestEnvironment.Property(unit, "ActiveState") != "failed" && watch.Elapsed < TimeSpan.FromSeconds(60))
        {
            if (int.TryParse(SystemdTestEnvironment.Property(unit, "MainPID"), CultureInfo.InvariantCulture, out var pid) && pid > 0)
            {
                SystemdTestEnvironment.Systemctl("kill", "--kill-whom=main", "--signal=KILL", unit);
                crashes++;
            }

            await Task.Delay(100, Ct);
        }

        Assert.Equal("failed", SystemdTestEnvironment.Property(unit, "ActiveState"));
        TestContext.Current.TestOutputHelper?.WriteLine($"{crashes} crashes; result {SystemdTestEnvironment.Property(unit, "Result")}");
        var events = Path.Combine(attempt, AttemptFiles.GuardEvents);
        await TestNode.WaitAsync(() => GuardEvent.ReadAll(events).Any(item => item.Event == GuardEventKinds.Terminate), Bound, "the guard to stop the attempt");
        var output = new FileInfo(Path.Combine(attempt, AttemptFiles.Stdout)).Length;
        Assert.True(output - Limit <= Rate / 2, $"The overshoot {output - Limit} exceeds the stated bound.");

        SystemdTestEnvironment.Systemctl("reset-failed", unit);
        await node.StartNodeAsync();
        var task = JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement;
        Assert.Equal("TERMINATION_REASON_OUTPUT_LIMIT", task.GetProperty("currentAttempt").GetProperty("result").GetProperty("terminationReason").GetString());
        Assert.Equal("GUARD", task.GetProperty("currentAttempt").GetProperty("limitEnforcedBy").GetString());
    }

    // isolation=exclusive: the overshoot bound depends on short node lifetimes and the guard's timing.
    [Theory(Timeout = 300_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [InlineData(300)]
    [InlineData(40)]
    public async Task TheGuardUnitStopsTheFloodWhileTheNodeRestartsFasterThanTheTakeover(int lifetimeMs)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        const long Limit = 4L << 20;
        const long Rate = 1L << 20;
        const int Takeover = 2_000;
        await using var node = TestNode.Create();
        SeedLimit(node, Limit, Takeover);
        InstallGuardUnit(node);
        var first = await node.StartNodeAsync();
        var id = Encoding.UTF8.GetString((await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "output", "--bytes", "268435456", "--rate", Rate.ToString(CultureInfo.InvariantCulture))).Stdout).Trim();
        var attempt = Path.Combine(node.DataRoot, "logs", await RunningAttemptAsync(node, id));
        first.Kill();
        await first.WaitForExitAsync(Ct);

        // The node is killed lifetimeMs after every start. At 300 ms whichever acts first stops the flood: the guard (no instance renews the
        // heartbeat) or an instance that completed recovery and enforced the limit before it was killed (a Native AOT start gets that far).
        // At 40 ms no instance reaches enforcement, so the guard must stop it although nodes keep starting. A heartbeat comes only from an
        // enforcing node.
        var events = Path.Combine(attempt, AttemptFiles.GuardEvents);
        var exit = Path.Combine(attempt, AttemptFiles.Exit);
        var restarts = 0;
        var watch = Stopwatch.StartNew();
        while (!File.Exists(exit) && watch.Elapsed < TimeSpan.FromSeconds(30))
        {
            using var restarted = node.Start(TestNode.Host, ["node", "run", "--test-mode"]);
            await Task.Delay(lifetimeMs, Ct);
            restarted.Kill();
            await restarted.WaitForExitAsync(Ct);
            restarts++;
        }

        var output = new FileInfo(Path.Combine(attempt, AttemptFiles.Stdout)).Length;
        var guardStop = GuardEvent.ReadAll(events).FirstOrDefault(item => item.Event == GuardEventKinds.Terminate);
        TestContext.Current.TestOutputHelper?.WriteLine($"{restarts} restarts; output {output} for a {Limit} limit at {Rate} B/s; stopped by {(guardStop is null ? "a node instance" : "the guard")}");
        Assert.True(File.Exists(exit), "The flood was not stopped within 30 s of restarts.");
        Assert.True(output - Limit <= Rate * (Takeover + 600) / 1000, $"The overshoot {output - Limit} exceeds the stated bound.");
        if (lifetimeMs < 100)
        {
            Assert.NotNull(guardStop);
        }

        await node.StartNodeAsync();
        var task = JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement;
        Assert.Equal("TERMINATION_REASON_OUTPUT_LIMIT", task.GetProperty("currentAttempt").GetProperty("result").GetProperty("terminationReason").GetString());
        Assert.Equal(guardStop is null ? "NODE" : "GUARD", task.GetProperty("currentAttempt").GetProperty("limitEnforcedBy").GetString());
    }

    [Theory(Timeout = 240_000)]
    [InlineData("hang-tailer-after")]
    [InlineData("hang-probe-after")]
    public async Task TheWatchdogRestartsANodeWhoseEnforcementLoopOrProbeHangs(string fault)
    {
        // 13 section 3.4: WatchdogSec=30, pinged with each heartbeat renewal; a hung enforcement loop, or three missed cache-store probes,
        // stop the pings and systemd restarts the node (Result watchdog). The fault fires once per data root. systemd sends SIGABRT at the
        // watchdog timeout; a .NET process that does not end on it is killed after the unit's TimeoutAbortSec (5 s), then RestartSec (2 s).
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_TEST_FAULT"] = fault + "=3";
        var unit = InstallNodeUnit(node);
        Assert.Equal(0, SystemdTestEnvironment.Systemctl("start", unit).ExitCode);
        await node.WaitReadyAsync();
        var first = SystemdTestEnvironment.Property(unit, "MainPID");
        var watch = Stopwatch.StartNew();
        await TestNode.WaitAsync(() => SystemdTestEnvironment.Property(unit, "NRestarts") is var restarts && restarts.Length > 0 && restarts != "0", TimeSpan.FromSeconds(120),
            "systemd to restart the hung node");
        var restarted = Stopwatch.StartNew();
        TestContext.Current.TestOutputHelper?.WriteLine($"restarted after {watch.Elapsed.TotalSeconds:0.0} s");
        // The fault (3 s), for the probe up to three missed probes (5 s timeout each, one a second), WatchdogSec (30 s),
        // TimeoutAbortSec (5 s), RestartSec (2 s) and a few seconds of slack for the restart.
        var bound = fault == "hang-probe-after" ? TimeSpan.FromSeconds(66) : TimeSpan.FromSeconds(45);
        Assert.InRange(watch.Elapsed, TimeSpan.FromSeconds(25), bound);
        Assert.NotEqual(first, SystemdTestEnvironment.Property(unit, "MainPID"));
        var journal = Journal(unit);
        Assert.Contains("Watchdog timeout (limit 30s)", journal, StringComparison.Ordinal);
        Assert.Contains("Failed with result 'watchdog'", journal, StringComparison.Ordinal);

        // The fault fires once per data root: the restarted node's heartbeat still changes after the moment the fault would have stopped it.
        await node.WaitReadyAsync();
        await node.WaitHeartbeatChangeAsync(restarted, TestNode.FaultHorizon(fault, 3));
        Assert.Equal("1", SystemdTestEnvironment.Property(unit, "NRestarts"));
        Assert.Equal(0, (await node.CliAsync("node", "stop")).ExitCode);
        await TestNode.WaitAsync(() => SystemdTestEnvironment.Property(unit, "ActiveState") is "inactive" or "failed", Bound, "the node unit to stop");
    }

    /// <summary>The shipped node unit (packaging/linux) for this test: this binary in test mode, this environment.</summary>
    private static string InstallNodeUnit(TestNode node, Func<string, string>? change = null)
    {
        var name = "arcforges-node-test-" + Guid.NewGuid().ToString("N")[..10] + ".service";
        var template = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Procedures", "packaging", "arcforges-node.service"));
        var content = template
            .Replace("ExecStart=%h/.local/share/arcforges/app/current/arcforges node run --systemd", $"ExecStart={TestNode.Host} node run --systemd {NodeLocations.TestModeOption}", StringComparison.Ordinal)
            .Replace("[Service]\n", "[Service]\n" + node.UnitEnvironment() + "\n", StringComparison.Ordinal);
        Assert.Contains(TestNode.Host, content, StringComparison.Ordinal);
        return node.InstallUnit(name, change?.Invoke(content) ?? content);
    }

    /// <summary>The shipped guard unit (packaging/linux) for this test's data root; the node starts it (ARCFORGES_GUARD_UNIT).</summary>
    private static string InstallGuardUnit(TestNode node)
    {
        var name = "arcforges-guard-test-" + Guid.NewGuid().ToString("N")[..10] + ".service";
        var template = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Procedures", "packaging", "arcforges-guard.service"));
        var content = template
            .Replace("ExecStart=%h/.local/share/arcforges/app/current/arcforges node guard", $"ExecStart={TestNode.Host} node guard {NodeLocations.TestModeOption}", StringComparison.Ordinal)
            .Replace("[Service]\n", "[Service]\n" + node.UnitEnvironment() + "\n", StringComparison.Ordinal);
        Assert.Contains(TestNode.Host, content, StringComparison.Ordinal);
        node.Environment["ARCFORGES_GUARD_UNIT"] = name;
        return node.InstallUnit(name, content);
    }

    private static void SeedLimit(TestNode node, long limit, int takeover) => node.SeedPolicy(policy =>
    {
        policy.Storage.MaxAttemptOutputBytes = (ulong)limit;
        policy.Storage.GuardTakeoverMs = (uint)takeover;
    });

    private static string Journal(string unit)
    {
        var start = new ProcessStartInfo("journalctl") { RedirectStandardOutput = true, UseShellExecute = false };
        foreach (var argument in (string[])["--user", "-u", unit, "--no-pager", "-o", "cat"])
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit(TimeSpan.FromSeconds(30));
        return output;
    }

    private static JsonElement Capabilities(JsonElement json) => json.TryGetProperty("capabilities", out var report) ? report : json;

    private static string Read(string directory, string file) => File.ReadAllText(Path.Combine(directory, file)).TrimEnd('\n');

    /// <summary>What the node says about a task and its enforcement, for a failure message.</summary>
    private static async Task<string> DiagnoseAsync(TestNode node, string id)
    {
        var task = (await node.CliAsync("tasks", "show", id, "--json")).Output.ReplaceLineEndings(" ");
        var capabilities = (await node.CliAsync("node", "capabilities", "--json")).Output.ReplaceLineEndings(" ");
        return $"task: {task}; capabilities: {capabilities}";
    }

    /// <summary>The attempt ID of a task's running attempt (waits until it runs).</summary>
    private static async Task<string> RunningAttemptAsync(TestNode node, string id)
    {
        var watch = Stopwatch.StartNew();
        while (true)
        {
            var shown = JsonDocument.Parse((await node.CliAsync("tasks", "show", id, "--json")).Output).RootElement.GetProperty("task");
            if (shown.TryGetProperty("currentAttempt", out var attempt) && attempt.GetProperty("state").GetString() == "ATTEMPT_STATE_RUNNING")
            {
                return attempt.GetProperty("attemptId").GetString()!;
            }

            Assert.True(watch.Elapsed < Bound, "The attempt did not start.");
            await Task.Delay(100, Ct);
        }
    }

    private static (int ExitCode, byte[] Stdout, byte[] Stderr) Direct(string[] argv)
    {
        var start = new ProcessStartInfo(argv[0])
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        foreach (var argument in argv.Skip(1))
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        process.StandardInput.Close();
        return TestNode.BytesAsync(process, TimeSpan.FromSeconds(60)).GetAwaiter().GetResult();
    }
}
