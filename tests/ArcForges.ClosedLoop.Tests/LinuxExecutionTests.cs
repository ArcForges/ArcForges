// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Tests;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Linux Node capability reporting, retired Task admission and the shipped user-unit watchdog.</summary>
/// <remarks>
/// The original Linux V1 CLI launch, attempt-scope and guard-unit effect scenarios remain executable at
/// eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a (blob f248aa69e5ce27e33db32bf926e51c02e142ff26).
/// Current installed Sandbox, Run and resource qualification uses the official MXC package fixtures.
/// </remarks>
[Trait("loop", "local")]
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class LinuxExecutionTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(90);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RequireUnits() => Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);

    [Fact(Timeout = 300_000)]
    public async Task WithoutAUserManagerTheNodeIsDegradedAndRefusesLegacyTaskAdmission()
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

        await AssertLegacyAdmissionRefusedAsync(node, EnforcedResource.Memory);
        await AssertLegacyAdmissionRefusedAsync(node);
    }

    [Fact(Timeout = 300_000)]
    public async Task WithoutMemoryDelegationTheNodeIsPartialAndRefusesLegacyTaskAdmission()
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
        await AssertLegacyAdmissionRefusedAsync(node, EnforcedResource.Memory);
        await AssertLegacyAdmissionRefusedAsync(node, EnforcedResource.Cpu);
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
    private static string InstallNodeUnit(TestNode node)
    {
        var name = "arcforges-node-test-" + Guid.NewGuid().ToString("N")[..10] + ".service";
        var template = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Procedures", "packaging", "arcforges-node.service"));
        var content = template
            .Replace("ExecStart=%h/.local/share/arcforges/app/current/arcforges node run --systemd", $"ExecStart={TestNode.Host} node run --systemd {NodeLocations.TestModeOption}", StringComparison.Ordinal)
            .Replace("[Service]\n", "[Service]\n" + node.UnitEnvironment() + "\n", StringComparison.Ordinal);
        Assert.Contains(TestNode.Host, content, StringComparison.Ordinal);
        return node.InstallUnit(name, content);
    }

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

    private static async Task AssertLegacyAdmissionRefusedAsync(TestNode node, EnforcedResource? required = null)
    {
        await using var channel = await node.HumanChannelAsync();
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { Path.Combine(node.Root, "missing-legacy-task-fixture") } } },
            WorkingDirectory = node.Root,
        };
        if (required is { } resource)
        {
            spec.Resources = new ResourceSpec();
            spec.Resources.RequireEnforcement.Add(resource);
        }

        var meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };
        var refused = await channel.Tasks.SubmitTaskAsync(new TaskServiceSubmitTaskRequest { Meta = meta, Spec = spec }, cancellationToken: Ct);
        Assert.Null(refused.Value);
        Assert.Equal("operation_failed", refused.Error.Code);
        Assert.Equal("LEGACY_DRAIN", refused.Error.Details.State.State);
        Assert.Equal("legacy_task_outcome_unavailable", refused.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, refused.Error.Effect);
        Assert.Equal(RetryMode.Never, refused.Error.Retry.Mode);
        Assert.Equal(meta.CorrelationId, refused.Error.CorrelationId);

        var listed = await channel.Tasks.ListTasksAsync(new TaskServiceListTasksRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
        }, cancellationToken: Ct);
        Assert.Null(listed.Error);
        Assert.Empty(listed.Value.Tasks);
    }
}
