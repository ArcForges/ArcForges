// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Tests;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// The scheduler through the CLI against the real node (loop=local; AF-SCHED-01; cli.md <c>run</c>, <c>queue</c>, <c>policy</c>):
/// <c>run --exclusive/--depends-on/--kind service --ready-file</c>, <c>queue show/explain/pools/pool/pause/resume/parallelism</c> and
/// <c>policy show/defaults/validate/apply/revisions/restore</c>. Each test runs on the OS its env trait names and skips elsewhere.
/// </summary>
[Trait("loop", "local")]
public sealed class SchedulingCliTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(90);

    [Fact(Timeout = 300_000)]
    [Trait("env", "windows-real")]
    public async Task TheSchedulerIsDrivenThroughTheCliOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job platform test.");
        await CliAsync();
    }

    [Fact(Timeout = 300_000)]
    [Trait("env", "linux-real")]
    public async Task TheSchedulerIsDrivenThroughTheCliOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        await CliAsync();
    }

    private static async Task CliAsync()
    {
        await using var node = TestNode.Create();
        await node.StartNodeAsync();
        async Task<string> RunAsync(params string[] args)
        {
            var run = await node.CliBytesAsync(Bound, ["run", "--detach", "--cwd", node.Root, .. args]);
            Assert.True(run.ExitCode == 0, $"run {string.Join(' ', args)}: exit {run.ExitCode}; {Encoding.UTF8.GetString(run.Stderr)}");
            return Encoding.UTF8.GetString(run.Stdout).Trim();
        }

        async Task<string> StateAsync(string id) =>
            JsonDocument.Parse((await node.CliAsync("tasks", "wait", id, "--json")).Output).RootElement.GetProperty("state").GetString()!;

        async Task<JsonElement> ExplainedAsync(string id, string reason)
        {
            var watch = Stopwatch.StartNew();
            while (true)
            {
                var explain = await node.CliAsync("queue", "explain", id, "--json");
                Assert.True(explain.ExitCode == 0, explain.ToString());
                var json = explain.Json();
                if (json.TryGetProperty("blockingReason", out var value) && value.GetString() == reason)
                {
                    return json;
                }

                Assert.True(watch.Elapsed < Bound, $"queue explain {id}: {reason} not reached ({explain.Output})");
                await Task.Delay(200, TestContext.Current.CancellationToken);
            }
        }

        string Hold(string name) => Path.Combine(node.Root, name + ".txt");

        // A key holder, a writer of the same key and a dependent.
        var holder = await RunAsync("--exclusive", "name:db", "--", TestNode.TestLoad, "hold", "--hold-ms", "120000", "--marker", Hold("holder"));
        var writer = await RunAsync("--exclusive", "name:db", "--", TestNode.TestLoad, "hold", "--hold-ms", "100", "--marker", Hold("writer"));
        var dependent = await RunAsync("--depends-on", holder + ":finished", "--", TestNode.TestLoad, "hold", "--hold-ms", "100", "--marker", Hold("dependent"));
        var explained = await ExplainedAsync(writer, "exclusive_key");
        Assert.Contains("name:db", explained.GetProperty("blockingKeys").EnumerateArray().Select(key => key.GetString()));
        var text = await node.CliAsync("queue", "explain", writer);
        Assert.True(text.ExitCode == 0, text.ToString());
        Assert.Contains("name:db", text.Output, StringComparison.Ordinal);
        await ExplainedAsync(dependent, "dependency");
        var show = await node.CliAsync("queue", "show");
        Assert.True(show.ExitCode == 0, show.ToString());
        Assert.Contains("budget", show.Output, StringComparison.Ordinal);
        Assert.Equal(0, (await node.CliAsync("queue", "show", "--json")).ExitCode);

        // Pools and parallelism.
        var pools = await node.CliAsync("queue", "pools");
        Assert.True(pools.ExitCode == 0, pools.ToString());
        Assert.Contains("default", pools.Output, StringComparison.Ordinal);
        // The CLI here is a SCRIPT caller (no terminal): pausing a pool and changing a task's priority are allowed; pool, parallelism and
        // policy changes need an approval (11 section 1): the CLI prints the approval and exits 6 (cli.md section 5).
        async Task NeedsApprovalAsync(params string[] args)
        {
            var pending = await node.CliAsync(args);
            Assert.True(pending.ExitCode == 6 && pending.Error.Contains("Waiting for approval", StringComparison.Ordinal), $"{string.Join(' ', args)}: {pending}");
        }

        Assert.Equal(0, (await node.CliAsync("tasks", "priority", writer, "low")).ExitCode);
        Assert.Contains("PRIORITY_LOW", (await node.CliAsync("tasks", "show", writer, "--json")).Output, StringComparison.Ordinal);
        Assert.Equal(2, (await node.CliAsync("tasks", "priority", writer)).ExitCode);
        Assert.Equal(0, (await node.CliAsync("queue", "pause", "background")).ExitCode);
        Assert.Contains("paused", (await node.CliAsync("queue", "pools")).Output, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, (await node.CliAsync("queue", "resume", "background")).ExitCode);
        await NeedsApprovalAsync("queue", "pool", "create", "builds", "--weight", "2", "--max", "off");
        await NeedsApprovalAsync("queue", "parallelism", "global", "4");

        // With --wait-approval the CLI waits for a HUMAN's decision and then receives the executed outcome under its own command ID.
        await using (var human = await node.HumanChannelAsync())
        {
            var listed = await node.CliAsync("approvals", "list", "--state", "pending", "--json");
            Assert.True(listed.ExitCode == 0, listed.ToString());
            Assert.Equal(2, listed.Json().GetProperty("approvals").GetArrayLength());
            foreach (var approval in listed.Json().GetProperty("approvals").EnumerateArray())
            {
                // The requester (this SCRIPT CLI) withdraws its own requests.
                Assert.Equal(0, (await node.CliAsync("approvals", "withdraw", approval.GetProperty("approvalId").GetString()!)).ExitCode);
            }

            var waiting = node.CliAsync("queue", "parallelism", "global", "3", "--wait-approval", "60s");
            var approved = await TestNode.ApproveNextAsync(human, Bound);
            Assert.Equal("QueueService.SetParallelism", approved.Operation);
            var set = await waiting;
            Assert.True(set.ExitCode == 0, set.ToString());
            var shown = await node.CliAsync("approvals", "show", IdText.Format(approved.ApprovalId)[..20]);
            Assert.True(shown.ExitCode == 0 && shown.Output.Contains("EXECUTED", StringComparison.Ordinal), shown.ToString());

            // A SCRIPT caller never decides.
            var decide = await node.CliAsync("approvals", "approve", IdText.Format(approved.ApprovalId));
            Assert.Equal(5, decide.ExitCode);
        }

        Assert.NotEqual(0, (await node.CliAsync("queue", "pool", "delete", "default")).ExitCode);
        Assert.Equal(2, (await node.CliAsync("queue", "parallelism", "everywhere", "off")).ExitCode);

        // The holder ends (cancelled): the writer gets the key and the FINISHED dependent starts.
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", holder)).ExitCode);
        Assert.Equal("TASK_STATE_SUCCEEDED", await StateAsync(writer));
        Assert.Equal("TASK_STATE_SUCCEEDED", await StateAsync(dependent));
        Assert.True(TestNode.ReadShared(Hold("dependent")).Length > 0);

        // A service with file readiness and a READY dependent.
        var flag = Path.Combine(node.Root, "ready.flag");
        var service = await RunAsync("--kind", "service", "--ready-file", flag, "--ready-timeout", "60s", "--", TestNode.TestLoad, "hold", "--hold-ms", "60000",
            "--ready-after-ms", "1000", "--file", flag, "--marker", Hold("service"));
        var afterReady = await RunAsync("--depends-on", service + ":ready", "--", TestNode.TestLoad, "hold", "--hold-ms", "100", "--marker", Hold("after-ready"));
        Assert.Equal("TASK_STATE_SUCCEEDED", await StateAsync(afterReady));
        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", service)).ExitCode);
        await StateAsync(service);

        // The policy.
        var policy = await node.CliAsync("policy", "show", "--section", "resources", "--json");
        Assert.True(policy.ExitCode == 0, policy.ToString());
        Assert.Equal(0, (await node.CliAsync("policy", "defaults", "--json")).ExitCode);
        var invalid = Path.Combine(node.Root, "invalid.json");
        File.WriteAllText(invalid, "{ \"resources\": { \"overcommitCpu\": 9 } }");
        var validated = await node.CliAsync("policy", "validate", invalid);
        Assert.Equal(1, validated.ExitCode);
        Assert.Contains("overcommit_cpu", validated.Output + validated.Error, StringComparison.Ordinal);
        var current = Path.Combine(node.Root, "current.json");
        File.WriteAllText(current, (await node.CliAsync("policy", "show", "--json")).Json().GetProperty("document").GetRawText());
        Assert.Equal(0, (await node.CliAsync("policy", "validate", current)).ExitCode);
        var revisions = await node.CliAsync("policy", "revisions");
        Assert.True(revisions.ExitCode == 0, revisions.ToString());
        await NeedsApprovalAsync("policy", "restore", "1", "--comment", "back to the defaults");
    }
}
