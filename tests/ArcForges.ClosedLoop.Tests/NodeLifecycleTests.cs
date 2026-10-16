// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.IO.Pipes;
using System.Net.Sockets;
using ArcForges.Client;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// The node and the CLI as real processes on both platforms (closed loop, local): auto-start and its refusals, single instance, stop,
/// crash recovery, stream resume and reset through <c>arcforges events</c>, a busy endpoint, and the CLI's output and exit codes.
/// </summary>
[Trait("loop", "local")]
public sealed class NodeLifecycleTests
{
    /// <summary>
    /// <c>node wait-ready</c> reports a node once it is READY or DEGRADED (02 section 2 step 9), not as soon as it listens (step 7): a node
    /// that answers hellos in RECOVERING for 3 s (<c>slow-ready</c> fault) is not ready yet, and a <c>node stop</c> sent then failed with
    /// INTERNAL (SM-NODE has no RECOVERING -> STOPPING). After wait-ready the node has logged <c>node.ready</c>, and the stop succeeds.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task WaitReadyReturnsOnlyOnceTheNodeIsReady()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_TEST_FAULT"] = "slow-ready=3";
        using var process = node.Start(TestNode.Host, ["node", "run", NodeLocations.TestModeOption]);
        var ready = await node.CliAsync("node", "wait-ready", "--timeout", "60s", "--json");
        Assert.True(ready.ExitCode == 0, ready + node.Diagnostics());
        Assert.NotEmpty(TestNode.LogEvents(node.NodeLog, "node.fault.slow_ready"));
        // The state wait-ready reports is the readiness contract; the node writes its node.ready log line after the transition,
        // so the log is not read here (it may trail the state by a moment).
        Assert.Contains(ready.Json().GetProperty("state").GetString(), (string[])["READY", "DEGRADED"]);
        Assert.True(node.Descriptor() is { } descriptor && descriptor.ProcessIsAlive(), "No endpoint descriptor after wait-ready.");
        await node.StopNodeAsync();
        Assert.True(process.WaitForExit(TimeSpan.FromSeconds(15)));
    }

    // isolation=exclusive: the CLI waits at most 5 s for an auto-started node to become ready (a JIT node under parallel load can take longer).
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task StatusAutoStartsTheNodeAndReportsIt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        if (OperatingSystem.IsWindows())
        {
            var sandbox = NodeAutoStart.WindowsSandboxReason(out _);
            Assert.SkipWhen(sandbox is not null,
                $"This test process runs in a job that does not allow breakaway ({sandbox}): auto-start is refused there by design (see StatusRefusesToAutoStartInASandboxJob).");
        }

        await using var node = TestNode.Create();
        if (!OperatingSystem.IsWindows())
        {
            // Without the user's unit installed, the test uses the setsid launch (the systemd path has its own Linux test).
            node.Environment[NodeLocations.AutostartVariable] = "setsid";
        }

        var watch = Stopwatch.StartNew();
        var first = await node.CliAsync("status", "--json");
        var elapsed = watch.Elapsed;
        Assert.True(first.ExitCode == 0, first.ToString());
        var json = first.Json();
        Assert.True(json.GetProperty("autoStarted").GetBoolean());
        Assert.Equal(OperatingSystem.IsWindows() || ArcForges.Tests.SystemdTestEnvironment.FullyEnforced ? "NODE_LIFECYCLE_STATE_READY" : "NODE_LIFECYCLE_STATE_DEGRADED",
            json.GetProperty("node").GetProperty("state").GetString());
        Assert.Equal(node.Endpoint, json.GetProperty("node").GetProperty("endpoint").GetString());
        Assert.True(elapsed < TimeSpan.FromSeconds(15), $"status took {elapsed}");

        var second = await node.CliAsync("status", "--json");
        Assert.False(second.Json().GetProperty("autoStarted").GetBoolean());
        Assert.Equal(NodeLocations.EndpointVariable, second.Json().GetProperty("endpointSource").GetString());
        var nodePid = node.NodePid();
        if (OperatingSystem.IsWindows())
        {
            // The supervisor started the node (02 section 3) and logged it.
            Assert.Contains($"node.started pid={nodePid}", File.ReadAllText(node.SupervisorLog), StringComparison.Ordinal);
        }

        var stop = await node.CliAsync("node", "stop");
        Assert.Equal(0, stop.ExitCode);
        await TestNode.WaitAsync(() => node.LiveProcesses().Count == 0, TimeSpan.FromSeconds(15), "the node (and its supervisor) to exit");
        if (OperatingSystem.IsWindows())
        {
            Assert.Contains("node.stopped", File.ReadAllText(node.SupervisorLog), StringComparison.Ordinal);
        }
    }

    [Fact(Timeout = 60_000)]
    public async Task StatusRefusesToAutoStartInACiJob()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        node.Environment["CI"] = "true";

        var run = await node.CliAsync("status");

        Assert.Equal(75, run.ExitCode);
        Assert.Equal("arcforges: node not running; start it with 'arcforges node run --background' or the Desktop", run.Error.Trim());
        Assert.Empty(node.LiveProcesses());
        var json = await node.CliAsync("status", "--json");
        Assert.Equal(75, json.ExitCode);
        Assert.Equal("node_not_running", json.Json().GetProperty("error").GetProperty("code").GetString());
    }

    [Fact(Timeout = 60_000)]
    public async Task StatusRefusesToAutoStartInASandboxJob()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows() && NodeAutoStart.WindowsSandboxReason(out _) is not null,
            "Needs a Windows job that does not allow breakaway (an AI-client sandbox or a CI job); this test process is not in one.");
        await using var node = TestNode.Create();

        var run = await node.CliAsync("status", "--verbose");

        Assert.Equal(75, run.ExitCode);
        Assert.StartsWith("arcforges: node not running; start it with 'arcforges node run --background' or the Desktop", run.Error, StringComparison.Ordinal);
        Assert.Contains("does not allow breakaway", run.Error, StringComparison.Ordinal);
        Assert.Empty(node.LiveProcesses());
    }

    [Fact(Timeout = 120_000)]
    public async Task ASecondNodeExitsWithThreeAndNamesTheEndpoint()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        await node.StartNodeAsync();

        using var second = node.Start(TestNode.Host, ["node", "run", NodeLocations.TestModeOption]);
        var run = await TestNode.CompleteAsync(second, TimeSpan.FromSeconds(30));

        Assert.Equal(3, run.ExitCode);
        Assert.Equal(node.Endpoint, run.Output.Trim());
        Assert.Contains("already running", run.Error, StringComparison.Ordinal);
        var background = await node.CliAsync("node", "run", "--background");
        Assert.Equal(3, background.ExitCode);
    }

    [Fact(Timeout = 120_000)]
    public async Task NodeStopEndsTheProcessCleanly()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        using var process = await node.StartNodeAsync();
        Assert.NotNull(node.Descriptor());

        var stop = await node.CliAsync("node", "stop", "--reason", "test");

        Assert.Equal(0, stop.ExitCode);
        Assert.True(process.WaitForExit(TimeSpan.FromSeconds(15)));
        Assert.Equal(0, process.ExitCode);
        Assert.Null(node.Descriptor());
        var stopped = TestNode.LogEvents(node.NodeLog, "node.stopped");
        Assert.Single(stopped);
        Assert.True(stopped[0].GetProperty("fields").GetProperty("shutdownMs").GetInt64() < 10_000);
        Assert.Equal("The node is not running.", (await node.CliAsync("node", "stop")).Output.Trim());
    }

    [Fact(Timeout = 180_000)]
    public async Task AKilledNodeIsRecoveredAndItsStreamsResetToANewGeneration()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        using var first = await node.StartNodeAsync();

        // A subscriber's cursor in the first generation, then events it misses.
        var cursor = await SnapshotCursorAsync(node);
        Assert.Equal(0, (await node.CliAsync("node", "rename", "before crash")).ExitCode);
        var resumed = await EventsAsync(node, cursor, frames: 1);
        Assert.Single(resumed);
        Assert.Equal("renamed", resumed[0].GetProperty("event").GetProperty("node").GetProperty("reason").GetString());
        Assert.False(resumed[0].GetProperty("event").TryGetProperty("fromSnapshot", out _));

        // Crash: the process is killed; its descriptor stays behind and the store is not closed.
        first.Kill(entireProcessTree: true);
        Assert.True(first.WaitForExit(TimeSpan.FromSeconds(10)));
        Assert.NotNull(node.Descriptor());

        using var second = await node.StartNodeAsync();
        var recovering = TestNode.LogEvents(node.NodeLog, "node.recovering");
        Assert.Equal(2, recovering.Count);
        Assert.True(recovering[1].GetProperty("fields").GetProperty("uncleanShutdown").GetBoolean());
        Assert.Equal(recovering[0].GetProperty("fields").GetProperty("generation").GetInt32() + 1, recovering[1].GetProperty("fields").GetProperty("generation").GetInt32());
        var health = (await node.CliAsync("node", "health", "--json")).Json();
        Assert.Contains(health.GetProperty("checks").EnumerateArray(), check => check.GetProperty("checkId").GetString() == "node.store"
            && check.GetProperty("status").GetString() == "CHECK_STATUS_PASS"
            && check.GetProperty("summary").GetString()!.Contains("integrity check", StringComparison.Ordinal));

        // The old cursor is from another generation: reset, then a fresh snapshot.
        var reset = await EventsAsync(node, cursor, until: frame => frame.TryGetProperty("snapshotComplete", out _));
        Assert.Equal("generation_changed", reset[0].GetProperty("reset").GetProperty("reason").GetString());
        Assert.True(reset[1].GetProperty("event").GetProperty("fromSnapshot").GetBoolean());
        Assert.Equal("before crash", (await node.CliAsync("node", "info", "--json")).Json().GetProperty("node").GetProperty("node").GetProperty("name").GetString());
    }

    [Fact(Timeout = 120_000)]
    public async Task TheCliReportsNodeErrorsWithTheirExitCodes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        await node.StartNodeAsync();

        var info = await node.CliAsync("node", "info", "--json");
        Assert.Equal(0, info.ExitCode);
        Assert.Matches("^[0-9a-hjkmnp-tv-z]{26}$", info.Json().GetProperty("node").GetProperty("node").GetProperty("nodeId").GetString());

        Assert.Equal(0, (await node.CliAsync("config", "set", "logLevel", "debug")).ExitCode);
        Assert.Equal("debug", (await node.CliAsync("config", "get", "logLevel")).Output.Trim());
        Assert.Equal("1", (await node.CliAsync("config", "get", "revision", "--quiet")).Output.Trim());
        Assert.Equal(2, (await node.CliAsync("config", "set", "dataRoot", "/elsewhere")).ExitCode);
        Assert.Equal(2, (await node.CliAsync("config", "set", "logLevel", "loud")).ExitCode);

        var missing = await node.CliAsync("jobs", "show", "01m4zrxnr8e7d81pn7xnwfqw14");
        Assert.Equal(4, missing.ExitCode);
        Assert.Matches(@"^error: not found: .*\(STATE/not_found, correlation [0-9a-z]{26}\)", missing.Error.Trim());
        var missingJson = await node.CliAsync("jobs", "show", "01m4zrxnr8e7d81pn7xnwfqw14", "--json");
        Assert.Equal(4, missingJson.ExitCode);
        Assert.Equal("not_found", missingJson.Json().GetProperty("error").GetProperty("code").GetString());
        Assert.Equal(string.Empty, missingJson.Error);
        Assert.Equal(2, (await node.CliAsync("node", "rename", new string('n', 65))).ExitCode);

        var version = await node.CliAsync("version", "--json");
        Assert.Equal(version.Json().GetProperty("client").GetProperty("version").GetString(), version.Json().GetProperty("node").GetProperty("version").GetString());
        Assert.Equal(0, (await node.CliAsync("node", "capabilities", "--reevaluate")).ExitCode);
        Assert.Contains("No jobs.", (await node.CliAsync("jobs", "list")).Output, StringComparison.Ordinal);
    }

    [Fact(Timeout = 120_000)]
    public async Task ABusyEndpointIsRetriedAndNeverAutoStarted()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // Design follow-up of AF-DP-01: connects beyond the backlog get EAGAIN on Linux (a Windows client waits for a pipe instance).
        // The client retries with bounded backoff and never reads that as "not running", so no second node is started.
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        var nodePid = node.NodePid();
        var held = new List<IDisposable>();
        try
        {
            // 64 connection slots, then the backlog (16) or the waiting pipe clients: hold everything until a connect is refused.
            var refused = string.Empty;
            for (var i = 0; i < 300 && refused.Length == 0; i++)
            {
                refused = TryHold(node.Endpoint, held);
            }

            // Windows: the 64 instances are taken and the next client waits; Linux: a burst fills the accept backlog first (EAGAIN).
            Assert.True(refused.Length > 0 && held.Count >= (OperatingSystem.IsWindows() ? 64 : 1), $"held {held.Count} connections; refusal: '{refused}'");
            var run = await node.CliAsync("status", "--json");

            // Either the bounded retries got through (the backlog drains as the node accepts) or the client reports the node busy
            // (exit 75); it never reads the refusal as "not running", so no second node is started.
            Assert.True(run.ExitCode == 0 ? !run.Json().GetProperty("autoStarted").GetBoolean() : run.ExitCode == 75 && run.Json().GetProperty("error").GetProperty("code").GetString() == "overloaded"
                    && run.Error.Contains("busy", StringComparison.Ordinal),
                $"held {held.Count} connections (then '{refused}'); status: {run}");
            Assert.Equal(nodePid, node.NodePid());
            Assert.Single(node.LiveProcesses(), process => process.ProcessName == "arcforges");
        }
        finally
        {
            held.ForEach(item => item.Dispose());
        }

        // Once the held connections are gone the node answers again.
        var after = await node.CliAsync("status", "--json");
        Assert.True(after.ExitCode == 0, after.ToString());
        Assert.False(after.Json().GetProperty("autoStarted").GetBoolean());
    }

    /// <summary>Opens one more connection that never speaks; returns why it was refused, or an empty string when it is held.</summary>
    private static string TryHold(string endpoint, List<IDisposable> held)
    {
        if (OperatingSystem.IsWindows())
        {
            var pipe = new NamedPipeClientStream(".", endpoint, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                pipe.Connect(200);
                held.Add(pipe);
                return string.Empty;
            }
            catch (TimeoutException)
            {
                pipe.Dispose();
                return "no free pipe instance within 200 ms";
            }
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified) { Blocking = false };
        try
        {
            socket.Connect(new UnixDomainSocketEndPoint(endpoint));
            held.Add(socket);
            return string.Empty;
        }
        catch (SocketException exception)
        {
            socket.Dispose();
            return exception.SocketErrorCode.ToString();
        }
    }

    private static async Task<string> SnapshotCursorAsync(TestNode node)
    {
        var frames = await EventsAsync(node, null, until: frame => frame.TryGetProperty("snapshotComplete", out _));
        return frames[^1].GetProperty("position").GetProperty("cursor").GetString()!;
    }

    /// <summary>Runs <c>arcforges events</c> and reads JSON Lines frames until enough arrived, then ends the CLI.</summary>
    private static async Task<List<System.Text.Json.JsonElement>> EventsAsync(TestNode node, string? since, int frames = int.MaxValue,
        Func<System.Text.Json.JsonElement, bool>? until = null)
    {
        List<string> arguments = ["events", "--topic", "node", "--topic", "jobs", "--topic", "notifications", NodeLocations.TestModeOption];
        if (since is not null)
        {
            arguments.AddRange(["--since", since]);
        }

        using var process = node.Start(TestNode.Host, arguments);
        var read = new List<System.Text.Json.JsonElement>();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            while (read.Count < frames && await process.StandardOutput.ReadLineAsync(timeout.Token) is { } line)
            {
                var frame = System.Text.Json.JsonDocument.Parse(line).RootElement.Clone();
                read.Add(frame);
                if (until?.Invoke(frame) == true)
                {
                    break;
                }
            }
        }
        finally
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit(TimeSpan.FromSeconds(10));
        }

        return read;
    }
}

/// <summary>Linux platform probes shared by the tests.</summary>
internal static class Linux
{
    public static bool UserManagerAvailable() => !OperatingSystem.IsWindows() && NodeAutoStart.UserManagerAvailable();
}
