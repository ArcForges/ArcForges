// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Node.Platform;

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
[Collection(SerialProcessTests.Name)]
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
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (Linux execution is AF-EXEC-02; its node refuses submissions as enforcement_unavailable).");
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
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (Linux execution is AF-EXEC-02; its node refuses submissions as enforcement_unavailable).");
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

    [Fact(Timeout = 300_000)]
    public async Task AClientTimeoutHandsOffWithExit124AndAnInterruptBeforeItCancels()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (Linux execution is AF-EXEC-02; its node refuses submissions as enforcement_unavailable).");
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
        await Task.Delay(TimeSpan.FromSeconds(7), Ct);
        Assert.Contains("TASK_STATE_RUNNING", (await node.CliAsync("tasks", "show", handedOff, "--json")).Output, StringComparison.Ordinal);
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", handedOff)).ExitCode);

        // A task that itself exits 124 prints no hand-off line.
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var own = await node.CliBytesAsync(Bound, "run", "--client-timeout", "60s", "--", cmd, "/d", "/c", "exit 124");
        Assert.Equal(124, own.ExitCode);
        Assert.DoesNotContain("tasks wait", Encoding.UTF8.GetString(own.Stderr), StringComparison.Ordinal);

        // Interrupt before the hand-off: the client disappears (killed), so its bound task is cancelled within 5 s.
        var marker = Path.Combine(node.Root, "i.txt");
        using var client = node.Start(TestNode.Host, ["--test-mode", "run", "--client-timeout", "10m", "--", TestNode.TestLoad, "signal", "--hold-ms", "60000", "--marker", marker]);
        await TestNode.WaitAsync(() => Marker(marker).Count > 0, Bound, "the task to start");
        client.Kill();
        await client.WaitForExitAsync(Ct);
        var interrupted = Stopwatch.StartNew();
        var pid = Marker(marker)[0].Pid;
        await TestNode.WaitAsync(() => !IsRunning(pid), TimeSpan.FromSeconds(20), "the interrupted run's task to be cancelled");
        Assert.True(interrupted.Elapsed < TimeSpan.FromSeconds(15), $"Cancelled after {interrupted.Elapsed}.");
        var list = await node.CliAsync("tasks", "list", "--json");
        Assert.Contains("TASK_STATE_CANCELLED", list.Output, StringComparison.Ordinal);
    }

    [Fact(Timeout = 300_000)]
    public async Task TheNodeKilledMidRunRecoversTheAttemptThroughItsHolder()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (Linux execution is AF-EXEC-02; its node refuses submissions as enforcement_unavailable).");
        await using var node = TestNode.Create();
        var first = await node.StartNodeAsync();
        var marker = Path.Combine(node.Root, "f.txt");
        var shortMarker = Path.Combine(node.Root, "s.txt");
        var detached = await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "signal", "--hold-ms", "120000", "--marker", marker);
        var id = Encoding.UTF8.GetString(detached.Stdout).Trim();
        var shortRun = await node.CliBytesAsync(Bound, "run", "--detach", "--", TestNode.TestLoad, "signal", "--hold-ms", "3000", "--marker", shortMarker);
        var shortId = Encoding.UTF8.GetString(shortRun.Stdout).Trim();
        await TestNode.WaitAsync(() => Marker(marker).Count > 0 && Marker(shortMarker).Count > 0, Bound, "the attempts to run");

        // The node is killed (not stopped): the attempts continue under their holders.
        first.Kill();
        await first.WaitForExitAsync(Ct);
        var pid = Marker(marker)[0].Pid;
        await Task.Delay(TimeSpan.FromSeconds(4), Ct);
        Assert.True(IsRunning(pid), "The attempt survived the node.");
        Assert.False(IsRunning(Marker(shortMarker)[0].Pid), "The short attempt finished while the node was down.");

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
        Assert.False(IsRunning(pid));
    }

    [Fact(Timeout = 300_000)]
    public async Task TheHolderTakesOverTheOutputLimitWhileTheNodeIsDown()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (Linux execution is AF-EXEC-02; its node refuses submissions as enforcement_unavailable).");
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

    [Fact(Timeout = 300_000)]
    public async Task TheHolderStopsTheFloodWhileTheNodeRestartsFasterThanTheTakeover()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (Linux execution is AF-EXEC-02; its node refuses submissions as enforcement_unavailable).");
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
    }

    [Theory(Timeout = 240_000)]
    [InlineData("hang-tailer-after")]
    [InlineData("hang-probe-after")]
    public async Task TheSupervisorRestartsANodeWhoseHeartbeatStalls(string fault)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (Linux execution is AF-EXEC-02; its node refuses submissions as enforcement_unavailable).");
        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_TEST_FAULT"] = fault + "=3";
        using var supervisor = node.Start(Supervisor, [NodeLocations.TestModeOption]);
        await node.WaitReadyAsync();
        var first = node.NodePid();
        var watch = Stopwatch.StartNew();
        await TestNode.WaitAsync(() => node.Descriptor() is { } descriptor && descriptor.ProcessId != first && descriptor.ProcessIsAlive(),
            TimeSpan.FromSeconds(90), "the supervisor to restart the hung node");
        var log = File.ReadAllText(node.SupervisorLog);
        TestContext.Current.TestOutputHelper?.WriteLine($"restarted after {watch.Elapsed.TotalSeconds:0.0} s");
        Assert.Contains("node.first_heartbeat", log, StringComparison.Ordinal);
        Assert.Contains("node.hung pid=" + first.ToString(CultureInfo.InvariantCulture), log, StringComparison.Ordinal);
        var stall = long.Parse(log.Split("stallMs=")[1].Split(' ', '\n', '\r')[0], CultureInfo.InvariantCulture);
        Assert.InRange(stall, 30_000, 33_000);

        // The fault fires once per data root: the restarted node keeps its heartbeat.
        await node.WaitReadyAsync();
        await Task.Delay(TimeSpan.FromSeconds(3), Ct);
        Assert.Single(File.ReadAllText(node.SupervisorLog).Split("node.hung").Skip(1));
        Assert.Equal(0, (await node.CliAsync("node", "stop")).ExitCode);
        Assert.True(supervisor.WaitForExit(TimeSpan.FromSeconds(15)));
        Assert.Equal(0, supervisor.ExitCode);
    }

    [Fact(Timeout = 240_000)]
    public async Task AStartupLongerThanTheStallIsNotMistakenForAHang()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows execution (Linux execution is AF-EXEC-02; its node refuses submissions as enforcement_unavailable).");
        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_TEST_FAULT"] = "slow-startup=35";
        using var supervisor = node.Start(Supervisor, [NodeLocations.TestModeOption]);
        var watch = Stopwatch.StartNew();
        await TestNode.WaitAsync(async () => (await node.CliAsync("node", "wait-ready", "--timeout", "20s")).ExitCode == 0, TimeSpan.FromSeconds(90), "the slow node");
        Assert.True(watch.Elapsed >= TimeSpan.FromSeconds(34), $"Ready after {watch.Elapsed}: the slow startup did not take effect.");
        var pid = node.NodePid();
        await Task.Delay(TimeSpan.FromSeconds(5), Ct);
        Assert.Equal(pid, node.NodePid());
        var log = File.ReadAllText(node.SupervisorLog);
        Assert.DoesNotContain("node.hung", log, StringComparison.Ordinal);
        Assert.DoesNotContain("node.crashed", log, StringComparison.Ordinal);
        Assert.Contains("node.first_heartbeat", log, StringComparison.Ordinal);
        Assert.Equal(0, (await node.CliAsync("node", "stop")).ExitCode);
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

    private static List<(string Event, int Pid)> Marker(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return [.. new StreamReader(stream).ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Split(' '))
            .Where(parts => parts.Length == 3).Select(parts => (parts[0], int.Parse(parts[1], CultureInfo.InvariantCulture)))];
    }

    private static bool IsRunning(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }
}
