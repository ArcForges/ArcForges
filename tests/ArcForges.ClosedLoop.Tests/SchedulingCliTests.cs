// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using ArcForges.Tests;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// The legacy queue and policy CLI reads persisted Tasks, applies authorized changes and reports actual approvals.
/// Task admission, dependencies and service readiness are exercised by the original tests at 8496f155213d0c215396d1093f866f39b4678f43.
/// </summary>
[Trait("loop", "local")]
public sealed class SchedulingCliTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(90);

    [Fact(Timeout = 300_000)]
    [Trait("env", "windows-real")]
    public async Task RetainedQueueAndPolicyControlsWorkThroughTheCliOnWindows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job platform test.");
        await CliAsync();
    }

    [Fact(Timeout = 300_000)]
    [Trait("env", "linux-real")]
    public async Task RetainedQueueAndPolicyControlsWorkThroughTheCliOnLinux()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux transient units.");
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        await CliAsync();
    }

    private static async Task CliAsync()
    {
        await using var node = TestNode.Create();
        var writer = SeedQueuedTask(node);
        await node.StartNodeAsync();
        var explain = await node.CliAsync("queue", "explain", writer, "--json");
        Assert.True(explain.ExitCode == 0, explain.ToString());
        Assert.Equal("TASK_STATE_QUEUED", explain.Json().GetProperty("state").GetString());
        var text = await node.CliAsync("queue", "explain", writer);
        Assert.True(text.ExitCode == 0, text.ToString());
        Assert.Contains(writer, text.Output, StringComparison.Ordinal);
        var show = await node.CliAsync("queue", "show");
        Assert.True(show.ExitCode == 0, show.ToString());
        Assert.Contains("budget", show.Output, StringComparison.Ordinal);
        var showJson = await node.CliAsync("queue", "show", "--json");
        Assert.True(showJson.ExitCode == 0, showJson.ToString());
        var queued = Assert.Single(showJson.Json().GetProperty("entries").EnumerateArray());
        var recordedQueue = queued.GetProperty("queue");
        Assert.Equal("legacy_admission_retired", recordedQueue.GetProperty("blockingReason").GetString());
        Assert.False(recordedQueue.TryGetProperty("position", out _));

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

        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", writer)).ExitCode);
        Assert.Contains("TASK_STATE_CANCELLED", (await node.CliAsync("tasks", "show", writer, "--json")).Output, StringComparison.Ordinal);

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

    private static string SeedQueuedTask(TestNode node)
    {
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = BootIdentity.Read() });
        var task = StoreIds.NewUuid7(TimeProvider.System);
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "fixture-never-starts" } } },
        }.ToByteArray();
        store.Write(transaction => transaction.Execute(
            """
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                              pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                              command_digest, created_at, queued_at, rev)
            VALUES ($id, $queued, 1, 'retained CLI fixture', 'retained CLI fixture', $spec, $digest, $owner, $origin,
                    'default', 3, 3, 4, 1, 'retained-cli-fixture', $digest, $now, $now, 0);
            """,
            ("$id", task), ("$queued", (int)TaskState.Queued), ("$spec", spec), ("$digest", SHA256.HashData(spec)),
            ("$owner", new ActorRef { Origin = Origin.Script, ClientKind = ClientKind.Cli }.ToByteArray()),
            ("$origin", (int)Origin.Script), ("$now", transaction.NowMicroseconds)), CommitDurability.Full);
        return IdText.Format(task);
    }
}
