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
/// Execution end to end with real processes (loop=local, env=windows-real): the <c>arcforges run</c> and <c>tasks</c> commands against a
/// real node process with real holders. Covers byte-identical attached output and exit codes vs direct runs (R-EXE-003; cli.md section 3),
/// <c>tasks wait --output</c>, the client-timeout hand-off with exit 124 and the interrupt that still cancels (R-AI-010), the node killed
/// mid-run with recovery through the holders (F-W03, R-EXE-008), and the guard taking over the output limit while the node is down or
/// restarting faster than <c>guard_takeover_ms</c> (R-STOR-009).
/// </summary>
[Trait("loop", "local")]
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class ExecutionTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(90);

    private static string Supervisor => Path.Combine(Path.GetDirectoryName(TestNode.Host)!, "arcforges-supervisor.exe");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 300_000)]
    public async Task RunMirrorsTheStreamsByteExactlyAndExitsLikeTheDirectRun()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        string[] workload = [TestNode.TestLoad, "output", "--bytes", "8388608", "--line-bytes", "77", "--stream", "both", "--seed", "11"];
        var managed = await node.CliBytesAsync(Bound, ["run", "--", .. workload]);
        var direct = Direct(workload);
        Assert.Equal(direct.ExitCode, managed.ExitCode);
        Assert.Equal(SHA256.HashData(direct.Stdout), SHA256.HashData(managed.Stdout));
        Assert.Equal(SHA256.HashData(direct.Stderr), SHA256.HashData(managed.Stderr));

        string[] args = [TestNode.TestLoad, "args", "two words", "quote\"inside", "back\\\\\"slash", "unicode äöü 中文", "%PATH%", ""];
        var argsRun = await node.CliBytesAsync(Bound, ["run", "--", .. args]);
        Assert.Equal(Encoding.UTF8.GetString(Direct(args).Stdout).Replace(Environment.CurrentDirectory, "<cwd>", StringComparison.Ordinal),
            Encoding.UTF8.GetString(argsRun.Stdout).Replace(Environment.CurrentDirectory, "<cwd>", StringComparison.Ordinal));

        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        Assert.Equal(7, (await node.CliBytesAsync(Bound, "run", "--", cmd, "/d", "/c", "exit 7")).ExitCode);
        Assert.Equal(127, (await node.CliBytesAsync(Bound, "run", "--", "arcforges-no-such-program")).ExitCode);
        var script = Path.Combine(node.Root, "probe.cmd");
        File.WriteAllText(script, "@exit /b 0\r\n");
        var refused = await node.CliBytesAsync(Bound, "run", "--", script, "\"&calc");
        Assert.Equal(125, refused.ExitCode);
        Assert.Contains("unsafe_batch_argument", Encoding.UTF8.GetString(refused.Stderr), StringComparison.Ordinal);
        var notAProgram = Path.Combine(node.Root, "text.exe");
        File.WriteAllText(notAProgram, "not a program");
        Assert.Equal(126, (await node.CliBytesAsync(Bound, "run", "--", notAProgram)).ExitCode);

        // A termination on Windows exits 1 with a message on stderr (04 section 5).
        var timedOut = await node.CliBytesAsync(Bound, "--timeout", "2s", "run", "--", TestNode.TestLoad, "signal", "--hold-ms", "60000", "--marker", Path.Combine(node.Root, "m.txt"));
        Assert.Equal(1, timedOut.ExitCode);
        Assert.Contains("TIMED_OUT", Encoding.UTF8.GetString(timedOut.Stderr), StringComparison.Ordinal);
    }

    [Fact(Timeout = 300_000)]
    public async Task TasksWaitPrintsTheOutputAndExitsWithTheTaskCodeOrNine()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var detached = await node.CliBytesAsync(Bound, "run", "--detach", "--", cmd, "/d", "/c", "echo waited-output & exit 5");
        Assert.Equal(0, detached.ExitCode);
        var id = Encoding.UTF8.GetString(detached.Stdout).Trim();
        var wait = await node.CliBytesAsync(Bound, "tasks", "wait", id, "--output", "all");
        Assert.Equal(5, wait.ExitCode);
        Assert.Contains("waited-output", Encoding.UTF8.GetString(wait.Stdout), StringComparison.Ordinal);

        var running = await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "signal", "--hold-ms", "60000", "--marker", Path.Combine(node.Root, "w.txt"));
        var runningId = Encoding.UTF8.GetString(running.Stdout).Trim();
        var notReached = await node.CliBytesAsync(Bound, "--timeout", "1s", "tasks", "wait", runningId);
        Assert.Equal(9, notReached.ExitCode);
        Assert.Contains("the wait ended", Encoding.UTF8.GetString(notReached.Stderr), StringComparison.Ordinal);
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", runningId)).ExitCode);
        Assert.NotEqual(9, (await node.CliBytesAsync(Bound, "tasks", "wait", runningId, "--output", "none")).ExitCode);
    }

    // isolation=exclusive: the caller-gone cancellation within 5 s (AD-0006 section 7) is a product timing contract.
    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task AClientTimeoutHandsOffWithExit124AndAnInterruptBeforeItCancels()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        await using var node = TestNode.Create();
        await node.StartNodeAsync();

        // Hand-off: --client-timeout 16s with the 15 s margin hands off after about 1 s; the task keeps running and keeps its binding released.
        var watch = Stopwatch.StartNew();
        var handoff = await node.CliBytesAsync(Bound, "run", "--client-timeout", "16s", "--", TestNode.TestLoad, "signal", "--hold-ms", "60000", "--marker", Path.Combine(node.Root, "h.txt"));
        Assert.Equal(124, handoff.ExitCode);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"The hand-off took {watch.Elapsed}.");
        var message = Encoding.UTF8.GetString(handoff.Stderr);
        Assert.Contains("arcforges tasks wait ", message, StringComparison.Ordinal);
        Assert.Contains("arcforges tasks cancel ", message, StringComparison.Ordinal);
        var handedOff = message.Split("arcforges tasks wait ")[1].Split('\n')[0].Trim();

        // A deliberate hold longer than the 5 s caller-gone window (AD-0006 section 7): the handed-off task is not cancelled.
        await Task.Delay(TimeSpan.FromSeconds(7), Ct);
        Assert.Contains("TASK_STATE_RUNNING", (await node.CliAsync("tasks", "show", handedOff, "--json")).Output, StringComparison.Ordinal);
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", handedOff)).ExitCode);

        // A task that itself exits 124 prints no hand-off line.
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var own = await node.CliBytesAsync(Bound, "run", "--client-timeout", "60s", "--", cmd, "/d", "/c", "exit 124");
        Assert.Equal(124, own.ExitCode);
        Assert.DoesNotContain("tasks wait", Encoding.UTF8.GetString(own.Stderr), StringComparison.Ordinal);

        // Interrupt before the hand-off: the client process ends (killed), so its bound task is cancelled within 5 s (AD-0006 section 7);
        // the root's exit follows the stop sequence's graceful phase (CTRL_BREAK; the workload exits on it).
        var marker = Path.Combine(node.Root, "i.txt");
        using var client = node.Start(TestNode.Host, ["--test-mode", "run", "--client-timeout", "10m", "--", TestNode.TestLoad, "signal", "--hold-ms", "60000", "--marker", marker]);
        await TestNode.WaitAsync(() => Marker(marker).Count > 0, Bound, "the task to start");
        client.Kill();
        await client.WaitForExitAsync(Ct);
        var interrupted = Stopwatch.StartNew();
        var task = MarkerProcess(marker);
        await TestNode.WaitAsync(() => TestNode.LogEvents(node.NodeLog, "execution.caller_gone").Count > 0, TimeSpan.FromSeconds(20), "the caller-gone cancellation");
        var cancelledAfter = interrupted.Elapsed;
        await TestNode.WaitAsync(() => !task.IsRunning(), TimeSpan.FromSeconds(20), "the interrupted run's task to stop");
        TestContext.Current.TestOutputHelper?.WriteLine($"cancelled {cancelledAfter.TotalMilliseconds:0} ms after the client was killed; the root ended after {interrupted.Elapsed.TotalMilliseconds:0} ms");
        Assert.True(cancelledAfter < TimeSpan.FromSeconds(5), $"Cancelled {cancelledAfter} after the client ended (AD-0006 section 7: within 5 s).");
        var list = await node.CliAsync("tasks", "list", "--json");
        Assert.Contains("TASK_STATE_CANCELLED", list.Output, StringComparison.Ordinal);
    }

    [Fact(Timeout = 300_000)]
    public async Task TheNodeKilledMidRunRecoversTheAttemptThroughItsHolder()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        await using var node = TestNode.Create();
        var first = await node.StartNodeAsync();
        var marker = Path.Combine(node.Root, "f.txt");
        var detached = await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "signal", "--hold-ms", "120000", "--marker", marker);
        var id = Encoding.UTF8.GetString(detached.Stdout).Trim();

        // The short attempt runs until the test writes the go file once the node is dead, so it cannot finish before the kill however
        // slowly the test runs (a fixed 3 s hold raced with it under load).
        var go = Path.Combine(node.Root, "go");
        var shortRun = await node.CliBytesAsync(Bound, ["run", "--detach", "--", .. WaitForFile(go)]);
        var shortId = Encoding.UTF8.GetString(shortRun.Stdout).Trim();
        await TestNode.WaitAsync(() => Marker(marker).Count > 0, Bound, "the attempts to run");
        var shortAttempt = await AttemptDirectoryAsync(node, shortId);

        // The node is killed (not stopped): the attempts continue under their holders, and the short one's holder records its exit alone.
        first.Kill();
        await first.WaitForExitAsync(Ct);
        File.WriteAllText(go, "go");
        var attempt = MarkerProcess(marker);
        await TestNode.WaitAsync(() => File.Exists(Path.Combine(shortAttempt, "exit.json")), Bound, "the short attempt's exit record while the node is down");
        Assert.True(attempt.IsRunning(), "The attempt survived the node.");

        await node.StartNodeAsync();
        var shortTask = JsonDocument.Parse((await node.CliAsync("tasks", "wait", shortId, "--json")).Output).RootElement;
        Assert.Equal("TASK_STATE_SUCCEEDED", shortTask.GetProperty("state").GetString());
        Assert.True(shortTask.GetProperty("currentAttempt").GetProperty("nodeGap").GetBoolean());

        var shown = JsonDocument.Parse((await node.CliAsync("tasks", "show", id, "--json")).Output).RootElement.GetProperty("task");
        Assert.Equal("TASK_STATE_RUNNING", shown.GetProperty("state").GetString());
        Assert.True(shown.GetProperty("currentAttempt").GetProperty("nodeGap").GetBoolean());
        Assert.NotEmpty(TestNode.LogEvents(node.NodeLog, "execution.recovered"));

        // The recovered attempt is cancelled through the re-opened job and its accounting is read.
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", id)).ExitCode);
        var cancelled = JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement;
        Assert.Equal("TASK_STATE_CANCELLED", cancelled.GetProperty("state").GetString());
        var usage = cancelled.GetProperty("currentAttempt").GetProperty("usage");
        Assert.True(long.Parse(usage.GetProperty("memPeakBytes").GetString()!, CultureInfo.InvariantCulture) > 0);
        Assert.False(attempt.IsRunning());
    }

    /// <summary>
    /// 04 section 4 and 15 section 2 (node at most 150 MB private under load): 700 MiB written while the node is down are indexed in
    /// records of at most 1 MiB after the restart, and <c>tasks attach --from-start</c> replays them byte for byte while the node's private
    /// bytes stay bounded.
    /// </summary>
    [Fact(Timeout = 300_000)]
    public async Task AttachingAfterARestartReplaysTheBacklogInBoundedNodeMemory()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        const long Bytes = 700L << 20;
        await using var node = TestNode.Create();
        var first = await node.StartNodeAsync();
        var report = Path.Combine(node.Root, "report.json");
        var detached = await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "output", "--bytes", Bytes.ToString(CultureInfo.InvariantCulture),
            "--line-bytes", "4096", "--rate", "150000000", "--report", report);
        var id = Encoding.UTF8.GetString(detached.Stdout).Trim();
        var attempt = await AttemptDirectoryAsync(node, id);
        first.Kill();
        await first.WaitForExitAsync(Ct);
        await TestNode.WaitAsync(() => File.Exists(Path.Combine(attempt, "exit.json")), Bound, "the attempt to finish under its holder");

        await node.StartNodeAsync();
        var nodePid = node.NodePid();
        using var nodeProcess = Process.GetProcessById(nodePid);
        nodeProcess.Refresh();
        var baseline = nodeProcess.PrivateMemorySize64;
        long peak = baseline;
        using var sampling = new CancellationTokenSource();
        var sampler = Task.Run(async () =>
        {
            while (!sampling.IsCancellationRequested)
            {
                nodeProcess.Refresh();
                peak = Math.Max(peak, nodeProcess.PrivateMemorySize64);
                await Task.Delay(20, CancellationToken.None);
            }
        }, CancellationToken.None);

        using var attach = node.Start(TestNode.Host, [NodeLocations.TestModeOption, "tasks", "attach", id, "--from-start"]);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1 << 20];
        long received = 0;
        var output = attach.StandardOutput.BaseStream;
        var errors = attach.StandardError.ReadToEndAsync(Ct);
        int count;
        while ((count = await output.ReadAsync(buffer, Ct)) > 0)
        {
            hash.AppendData(buffer, 0, count);
            received += count;
        }

        await attach.WaitForExitAsync(Ct);
        await sampling.CancelAsync();
        await sampler;
        var records = new FileInfo(Path.Combine(attempt, "index.bin")).Length / OutputIndexRecord.Size;
        TestContext.Current.TestOutputHelper?.WriteLine(
            $"node private bytes {baseline} before the attach, peak {peak}; {received} bytes replayed; {records} index records");
        Assert.True(attach.ExitCode == 0, $"tasks attach exited {attach.ExitCode}: {await errors}");
        Assert.Equal(Bytes, received);
        var expected = JsonDocument.Parse(File.ReadAllBytes(report)).RootElement.GetProperty("streamDigests").GetProperty("stdout").GetString();
        Assert.Equal(expected, Convert.ToHexStringLower(hash.GetHashAndReset()));
        Assert.True(records >= Bytes / OutputIndexRecord.MaxLength, $"{records} index records for {Bytes} bytes: the records were not capped.");
        Assert.True(peak <= 150L << 20, $"The node peaked at {peak} private bytes while replaying the backlog (15 section 2: 150 MB).");
    }

    /// <summary>
    /// A node that dies between recording a finished attempt and acknowledging its exit record leaves the holder waiting; the next start
    /// acknowledges recorded attempts whose ack event still opens, so the holder releases the jobs and exits.
    /// </summary>
    [Fact(Timeout = 300_000)]
    public async Task AHolderLeftWaitingByACrashAfterTheRecordIsReleasedAtTheNextStart()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        await using var node = TestNode.Create();
        node.Environment[ExecutionFaultVariable] = "kill-before-ack=0";
        var first = await node.StartNodeAsync();
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var detached = await node.CliBytesAsync(Bound, "run", "--detach", "--", cmd, "/d", "/c", "exit 3");
        var id = Encoding.UTF8.GetString(detached.Stdout).Trim();
        Assert.True(first.WaitForExit(TimeSpan.FromSeconds(30)), "The node did not kill itself after recording the attempt.");
        var holders = node.LiveProcesses().Select(process => ProcessIdentity.Capture(process.Id)).OfType<ProcessIdentity>().ToList();
        Assert.Single(holders);

        // A deliberate hold (the absence of an exit cannot be awaited): the holder still waits for the acknowledgement 2 s later.
        await Task.Delay(TimeSpan.FromSeconds(2), Ct);
        Assert.True(holders[0].IsRunning(), "The holder waits for the acknowledgement.");

        await node.StartNodeAsync();
        await TestNode.WaitAsync(() => !holders[0].IsRunning(), TimeSpan.FromSeconds(15), "the holder to be released");
        Assert.NotEmpty(TestNode.LogEvents(node.NodeLog, "execution.recover.acknowledged"));
        var task = JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement;
        Assert.Equal(3, task.GetProperty("currentAttempt").GetProperty("result").GetProperty("exitCode").GetInt32());
    }

    private const string ExecutionFaultVariable = "ARCFORGES_TEST_FAULT";

    /// <summary>An unexpected exception in the finalization never leaves the attempt stuck: it is logged by type and retried.</summary>
    [Fact(Timeout = 120_000)]
    public async Task AnUnexpectedFinalizationFailureIsLoggedAndRetried()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        await using var node = TestNode.Create();
        node.Environment[ExecutionFaultVariable] = "finalize-throw=0";
        await node.StartNodeAsync();
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var run = await node.CliBytesAsync(Bound, "run", "--", cmd, "/d", "/c", "exit 4");
        Assert.Equal(4, run.ExitCode);
        var failures = TestNode.LogEvents(node.NodeLog, "execution.finalize.unexpected");
        var failure = Assert.Single(failures);
        Assert.Equal("NotSupportedException", failure.GetProperty("fields").GetProperty("errorType").GetString());
        Assert.Single(TestNode.LogEvents(node.NodeLog, "execution.finished"));
        Assert.Single(node.LiveProcesses());
    }

    // isolation=exclusive: the takeover delay (takeover + 1 s) and the overshoot (rate over 500 ms) are timing bounds.
    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task TheHolderTakesOverTheOutputLimitWhileTheNodeIsDown()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        const long Limit = 8L << 20;
        const long Rate = 2L << 20;
        const int Takeover = 2_000;
        await using var node = TestNode.Create();
        node.SeedPolicy(policy =>
        {
            policy.Storage.MaxAttemptOutputBytes = Limit;
            policy.Storage.GuardTakeoverMs = Takeover;
        });
        var first = await node.StartNodeAsync();
        var detached = await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "output", "--bytes", "268435456", "--rate", Rate.ToString(CultureInfo.InvariantCulture));
        var id = Encoding.UTF8.GetString(detached.Stdout).Trim();
        var attempt = await AttemptDirectoryAsync(node, id);

        first.Kill();
        await first.WaitForExitAsync(Ct);
        var killedAt = DateTimeOffset.UtcNow;
        var events = Path.Combine(attempt, "guard-events.jsonl");
        await TestNode.WaitAsync(() => GuardEvent.ReadAll(events).Any(item => item.Event == GuardEventKinds.Terminate), Bound, "the guard to stop the attempt");
        var all = GuardEvent.ReadAll(events);
        var takeover = all.First(item => item.Event == GuardEventKinds.Takeover);
        var stop = all.First(item => item.Event == GuardEventKinds.Terminate);
        var takeoverDelay = DateTimeOffset.Parse(takeover.At, CultureInfo.InvariantCulture) - killedAt;
        var output = new FileInfo(Path.Combine(attempt, "stdout.bin")).Length;
        TestContext.Current.TestOutputHelper?.WriteLine($"takeover {takeoverDelay.TotalMilliseconds:0} ms after the kill; output {output} for a {Limit} limit at {Rate} B/s");
        Assert.True(takeoverDelay <= TimeSpan.FromMilliseconds(Takeover + 1_000), $"The guard took over {takeoverDelay.TotalMilliseconds:0} ms after the kill.");
        Assert.Equal("OUTPUT_LIMIT", stop.Reason);
        Assert.True(output - Limit <= Rate / 2, $"The overshoot {output - Limit} exceeds the rate over one interval plus the stop latency ({Rate / 2}).");

        await node.StartNodeAsync();
        var task = JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement;
        Assert.Equal("TASK_STATE_FAILED", task.GetProperty("state").GetString());
        Assert.Equal("TERMINATION_REASON_OUTPUT_LIMIT", task.GetProperty("currentAttempt").GetProperty("result").GetProperty("terminationReason").GetString());
        Assert.Equal("GUARD", task.GetProperty("currentAttempt").GetProperty("limitEnforcedBy").GetString());
    }

    // isolation=exclusive: the overshoot bound depends on 300 ms node lifetimes and the guard's timing.
    [Fact(Timeout = 300_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task TheHolderStopsTheFloodWhileTheNodeRestartsFasterThanTheTakeover()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        const long Limit = 4L << 20;
        const long Rate = 1L << 20;
        const int Takeover = 2_000;
        await using var node = TestNode.Create();
        node.SeedPolicy(policy =>
        {
            policy.Storage.MaxAttemptOutputBytes = Limit;
            policy.Storage.GuardTakeoverMs = Takeover;
        });
        var first = await node.StartNodeAsync();
        var detached = await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "output", "--bytes", "268435456", "--rate", Rate.ToString(CultureInfo.InvariantCulture));
        var id = Encoding.UTF8.GetString(detached.Stdout).Trim();
        var attempt = await AttemptDirectoryAsync(node, id);
        first.Kill();
        await first.WaitForExitAsync(Ct);

        // The node is killed 300 ms after every start. Whichever acts first stops the flood: the guard, when no node instance renews the
        // heartbeat (a JIT node rarely gets that far), or a node instance that completed recovery and enforced the limit before it was
        // killed (a fast Native AOT start). A heartbeat comes only from an enforcing node, so the restarts never leave the attempt unguarded.
        var events = Path.Combine(attempt, "guard-events.jsonl");
        var exit = Path.Combine(attempt, "exit.json");
        var restarts = 0;
        var watch = Stopwatch.StartNew();
        while (!File.Exists(exit) && watch.Elapsed < TimeSpan.FromSeconds(30))
        {
            using var restarted = node.Start(TestNode.Host, ["node", "run", "--test-mode"]);
            await Task.Delay(300, Ct);
            restarted.Kill();
            await restarted.WaitForExitAsync(Ct);
            restarts++;
        }

        var output = new FileInfo(Path.Combine(attempt, "stdout.bin")).Length;
        var guardStop = GuardEvent.ReadAll(events).FirstOrDefault(item => item.Event == GuardEventKinds.Terminate);
        TestContext.Current.TestOutputHelper?.WriteLine($"{restarts} restarts; output {output} for a {Limit} limit at {Rate} B/s; stopped by {(guardStop is null ? "a node instance" : "the guard")}");
        Assert.True(File.Exists(exit), "The flood was not stopped within 30 s of restarts.");
        Assert.True(output - Limit <= Rate * (Takeover + 600) / 1000, $"The overshoot {output - Limit} exceeds the stated bound.");

        await node.StartNodeAsync();
        var task = JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement;
        Assert.Equal("TERMINATION_REASON_OUTPUT_LIMIT", task.GetProperty("currentAttempt").GetProperty("result").GetProperty("terminationReason").GetString());
        Assert.Equal(guardStop is null ? "NODE" : "GUARD", task.GetProperty("currentAttempt").GetProperty("limitEnforcedBy").GetString());

        // The guard's record agrees with the recorded enforcer. GUARD: the guard took over before it stopped the attempt. NODE: the guard never stopped it, and whenever it took over, the node's fresh heartbeat made it stand down
        // again before the node stopped the attempt (the guard is not in charge at the end).
        var log = GuardEvent.ReadAll(events);
        TestContext.Current.TestOutputHelper?.WriteLine("guard events: " + string.Join(", ", log.Select(item => item.Event)));
        var lastTakeover = log.FindLastIndex(item => item.Event == GuardEventKinds.Takeover);
        var lastStandDown = log.FindLastIndex(item => item.Event == GuardEventKinds.StandDown);
        if (guardStop is not null)
        {
            var stopIndex = log.FindIndex(item => item.Event == GuardEventKinds.Terminate);
            Assert.InRange(log.FindIndex(item => item.Event == GuardEventKinds.Takeover), 0, stopIndex - 1);
        }
        else
        {
            Assert.DoesNotContain(log, item => item.Event == GuardEventKinds.Terminate);
            Assert.True(lastTakeover < 0 || lastStandDown > lastTakeover, "The guard took over and never stood down, yet the node recorded NODE.");
        }
    }

    [Theory(Timeout = 240_000)]
    [InlineData("hang-tailer-after")]
    [InlineData("hang-probe-after")]
    public async Task TheSupervisorRestartsANodeWhoseHeartbeatStalls(string fault)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_TEST_FAULT"] = fault + "=3";
        using var supervisor = node.Start(Supervisor, [NodeLocations.TestModeOption]);
        await node.WaitReadyAsync();
        var first = node.NodePid();
        var watch = Stopwatch.StartNew();
        await TestNode.WaitAsync(() => node.Descriptor() is { } descriptor && descriptor.ProcessId != first && descriptor.ProcessIsAlive(),
            TimeSpan.FromSeconds(90), "the supervisor to restart the hung node");
        var restarted = Stopwatch.StartNew();
        var log = File.ReadAllText(node.SupervisorLog);
        TestContext.Current.TestOutputHelper?.WriteLine($"restarted after {watch.Elapsed.TotalSeconds:0.0} s");
        Assert.Contains("node.first_heartbeat", log, StringComparison.Ordinal);
        Assert.Contains("node.hung pid=" + first.ToString(CultureInfo.InvariantCulture), log, StringComparison.Ordinal);
        var stall = long.Parse(log.Split("stallMs=")[1].Split(' ', '\n', '\r')[0], CultureInfo.InvariantCulture);
        Assert.InRange(stall, 30_000, 33_000);

        // The fault fires once per data root: the restarted node's heartbeat still changes after the moment the fault would have stopped it.
        await node.WaitReadyAsync();
        await node.WaitHeartbeatChangeAsync(restarted, TestNode.FaultHorizon(fault, 3));
        Assert.Single(File.ReadAllText(node.SupervisorLog).Split("node.hung").Skip(1));
        await node.StopNodeAsync();
        Assert.True(supervisor.WaitForExit(TimeSpan.FromSeconds(15)));
        Assert.Equal(0, supervisor.ExitCode);
    }

    [Fact(Timeout = 240_000)]
    public async Task AStartupLongerThanTheStallIsNotMistakenForAHang()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (the Linux equivalents are LinuxExecutionTests).");
        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_TEST_FAULT"] = "slow-startup=35";
        using var supervisor = node.Start(Supervisor, [NodeLocations.TestModeOption]);
        var watch = Stopwatch.StartNew();
        await TestNode.WaitAsync(async () => (await node.CliAsync("node", "wait-ready", "--timeout", "20s")).ExitCode == 0, TimeSpan.FromSeconds(90), "the slow node");
        Assert.True(watch.Elapsed >= TimeSpan.FromSeconds(34), $"Ready after {watch.Elapsed}: the slow startup did not take effect.");
        var pid = node.NodePid();

        // A deliberate hold (the absence of a restart cannot be awaited): the supervisor keeps the node over the next 5 s of heartbeats.
        await Task.Delay(TimeSpan.FromSeconds(5), Ct);
        Assert.Equal(pid, node.NodePid());
        var log = File.ReadAllText(node.SupervisorLog);
        Assert.DoesNotContain("node.hung", log, StringComparison.Ordinal);
        Assert.DoesNotContain("node.crashed", log, StringComparison.Ordinal);
        Assert.Contains("node.first_heartbeat", log, StringComparison.Ordinal);
        await node.StopNodeAsync();
        Assert.True(supervisor.WaitForExit(TimeSpan.FromSeconds(15)));
        Assert.Equal(0, supervisor.ExitCode);
    }

    private static async Task<string> AttemptDirectoryAsync(TestNode node, string id)
    {
        var watch = Stopwatch.StartNew();
        while (true)
        {
            var shown = JsonDocument.Parse((await node.CliAsync("tasks", "show", id, "--json")).Output).RootElement.GetProperty("task");
            if (shown.TryGetProperty("currentAttempt", out var attempt) && attempt.GetProperty("state").GetString() == "ATTEMPT_STATE_RUNNING")
            {
                return Path.Combine(node.DataRoot, "logs", attempt.GetProperty("attemptId").GetString()!);
            }

            Assert.True(watch.Elapsed < Bound, "The attempt did not start.");
            await Task.Delay(100, Ct);
        }
    }

    /// <summary>A command that exits 0 once <paramref name="file"/> exists (checked every 50 ms): an attempt that ends when the test says so.</summary>
    internal static string[] WaitForFile(string file) =>
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
        "-NoProfile", "-NonInteractive", "-Command", $"while (-not (Test-Path -LiteralPath '{file}')) {{ Start-Sleep -Milliseconds 50 }}",
    ];

    private static (int ExitCode, byte[] Stdout, byte[] Stderr) Direct(string[] argv)
    {
        var start = new ProcessStartInfo(argv[0])
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true,
        };
        foreach (var argument in argv.Skip(1))
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        process.StandardInput.Close();
        var result = TestNode.BytesAsync(process, TimeSpan.FromSeconds(60)).GetAwaiter().GetResult();
        return result;
    }

    private static List<(string Event, int Pid, long At)> Marker(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return [.. new StreamReader(stream).ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Split(' '))
            .Where(parts => parts.Length == 3)
            .Select(parts => (parts[0], int.Parse(parts[1], CultureInfo.InvariantCulture), long.Parse(parts[2], CultureInfo.InvariantCulture)))];
    }

    /// <summary>The process that wrote the first line of a marker, identified by its ID and that line's time (never by its ID alone).</summary>
    private static ProcessIdentity MarkerProcess(string marker)
    {
        var first = Marker(marker)[0];
        return ProcessIdentity.CreatedNoLaterThan(first.Pid, first.At);
    }
}
