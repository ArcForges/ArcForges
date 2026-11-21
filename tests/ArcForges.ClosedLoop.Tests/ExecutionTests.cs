// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using OutputIndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Retained Windows Task CLI and Node supervisor controls against the real local Host.</summary>
/// <remarks>
/// The fresh V1 CLI, Windows holder and output guard scenarios are kept at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
/// Their holder acknowledgement, guard takeover and backlog measurements apply to that executor.
/// The current installed MXC fixture separately exercises the V2 CLI, terminal and original-Run recovery.
/// </remarks>
[Trait("loop", "local")]
[Trait("env", "windows-real")]
[SupportedOSPlatform("windows")]
public sealed class ExecutionTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(90);

    private static string Supervisor => Path.Combine(Path.GetDirectoryName(TestNode.Host)!, "arcforges-supervisor.exe");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 120_000)]
    public async Task TasksWaitPrintsTheRetainedOutputAndExitsWithTheTaskCodeOrNine()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows Task CLI.");
        await using var node = TestNode.Create();
        var completed = RetainedClosedLoopTask.Seed(node, exitCode: 5, output: "waited-output");
        var queued = RetainedClosedLoopTask.Seed(node);
        using var process = await node.StartNodeAsync();

        var wait = await node.CliBytesAsync(Bound, "tasks", "wait", completed, "--output", "all");
        Assert.Equal(5, wait.ExitCode);
        Assert.Contains("waited-output", Encoding.UTF8.GetString(wait.Stdout), StringComparison.Ordinal);

        var notReached = await node.CliBytesAsync(Bound, "--timeout", "1s", "tasks", "wait", queued);
        Assert.Equal(9, notReached.ExitCode);
        Assert.Contains("the wait ended", Encoding.UTF8.GetString(notReached.Stderr), StringComparison.Ordinal);

        Assert.Equal(0, (await node.CliBytesAsync(Bound, "tasks", "cancel", queued)).ExitCode);
        var cancelled = await node.CliAsync("tasks", "wait", queued, "--output", "none", "--json");
        Assert.NotEqual(9, cancelled.ExitCode);
        using var result = JsonDocument.Parse(cancelled.Output);
        Assert.Equal("TASK_STATE_CANCELLED", result.RootElement.GetProperty("state").GetString());
        Assert.Single(node.LiveProcesses());
    }

    [Fact(Timeout = 120_000)]
    public async Task AnUnexpectedFinalizationFailureOfARetainedAttemptIsLoggedAndRetried()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows Task recovery.");
        await using var node = TestNode.Create();
        var task = RetainedClosedLoopTask.Seed(node, exitCode: 4, finalizing: true);
        node.Environment["ARCFORGES_TEST_FAULT"] = "finalize-throw=0";
        using var process = await node.StartNodeAsync();

        var wait = await node.CliBytesAsync(Bound, "tasks", "wait", task);
        Assert.Equal(4, wait.ExitCode);
        await TestNode.WaitAsync(() => TestNode.LogEvents(node.NodeLog, "execution.finished").Count != 0,
            Bound, "the recovered attempt to finish logging");
        var failure = Assert.Single(TestNode.LogEvents(node.NodeLog, "execution.finalize.unexpected"));
        Assert.Equal("NotSupportedException", failure.GetProperty("fields").GetProperty("errorType").GetString());
        Assert.Single(TestNode.LogEvents(node.NodeLog, "execution.finished"));
        Assert.Single(node.LiveProcesses());
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

}

/// <summary>Pre-cutover Task and Attempt state in a fixture store before the current Node opens it.</summary>
internal static class RetainedClosedLoopTask
{
    internal static string Seed(TestNode node, int? exitCode = null, string? output = null, bool finalizing = false)
    {
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = BootIdentity.Read() });
        var task = StoreIds.NewUuid7(TimeProvider.System);
        var attempt = exitCode.HasValue ? StoreIds.NewUuid7(TimeProvider.System) : null;
        var state = exitCode switch
        {
            null => TaskState.Queued,
            _ when finalizing => TaskState.Running,
            0 => TaskState.Succeeded,
            _ => TaskState.Failed,
        };
        const string label = "retained-task-fixture";
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { label } } },
            WorkingDirectory = node.Root,
        }.ToByteArray();
        var owner = new ActorRef { Origin = Origin.Script, ClientKind = ClientKind.Cli }.ToByteArray();
        store.Write(transaction =>
        {
            var now = transaction.NowMicroseconds;
            transaction.Execute(
                """
                INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                                  pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                                  command_digest, created_at, queued_at, started_at, finished_at, current_attempt_id, attempt_count, rev)
                VALUES ($task, $state, $kind, $label, $label, $spec, $digest, $owner, $origin,
                        'default', 3, 3, 4, 1, $label, $digest, $now, $now, $started, $finished, $attempt, $count, 0);
                """,
                ("$task", task), ("$state", (int)state), ("$kind", (int)TaskKind.Command), ("$label", label),
                ("$spec", spec), ("$digest", SHA256.HashData(spec)), ("$owner", owner), ("$origin", (int)Origin.Script),
                ("$now", now), ("$started", attempt is null ? null : now), ("$finished", attempt is not null && !finalizing ? now : null),
                ("$attempt", attempt), ("$count", attempt is null ? 0 : 1));
            if (attempt is not null)
            {
                transaction.Execute(
                    """
                    INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, boot_identity,
                                         request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source,
                                         accounted_mem_bytes, created_at, started_at, finished_at, exit_code, termination_reason, effect, rev)
                    VALUES ($attempt, $task, 1, 1, $state, $node, $boot, 100, 67108864, 67108864, 1,
                            67108864, $now, $now, $finished, $exit, $cause, $effect, 0);
                    """,
                    ("$attempt", attempt), ("$task", task), ("$state", (int)(finalizing ? AttemptState.Finalizing : AttemptState.Finished)),
                    ("$node", store.Metadata.NodeId.ToArray()), ("$boot", store.Metadata.BootIdentity), ("$now", now),
                    ("$finished", finalizing ? null : now), ("$exit", finalizing ? null : exitCode),
                    ("$cause", finalizing ? null : (int)TerminationReason.Exited),
                    ("$effect", finalizing ? null : (int)EffectCertainty.Happened));
            }
        }, CommitDurability.Full);

        if (attempt is not null)
        {
            var files = new AttemptFiles(node.DataRoot, IdText.Format(attempt));
            Directory.CreateDirectory(files.Directory);
            if (output is not null)
            {
                var body = Encoding.UTF8.GetBytes(output);
                File.WriteAllBytes(files.StdoutPath, body);
                var index = new byte[OutputIndexRecord.Size];
                new OutputIndexRecord(OutputStreamKind.Stdout, 0, (uint)body.Length, 1, OutputChunkMarks.None).Write(index);
                File.WriteAllBytes(files.IndexPath, index);
            }

            if (finalizing)
            {
                HelperFiles.WriteAtomically(files.ExitPath, new ExitRecord
                {
                    AttemptId = files.AttemptName,
                    ExitStatus = exitCode!.Value,
                    ServiceResult = "exit-code",
                    RecordedAt = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                }.ToJson());
            }
        }

        return IdText.Format(task);
    }
}
