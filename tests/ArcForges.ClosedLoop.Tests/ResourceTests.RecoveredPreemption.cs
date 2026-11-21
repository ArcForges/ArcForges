// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink.Tests;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

public sealed class RetainedResourceRecoveryTests
{
    [Theory(Timeout = 30_000)]
    [InlineData(true, false, true)]
    [InlineData(false, false, true)]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    public async Task RetainedPreemptionKeepsTheOriginalStopAndRetryDecision(bool critical, bool legacy, bool retryable)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = CloudNode.Create(centerUrl: null);
        var clock = new RecoveryClock();
        const string boot = "retained-preemption-fixture-boot";
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = boot, Clock = clock });
        var detail = legacy ? null : critical ? "preempted at critical memory pressure" : "requeued at memory pressure";
        var (task, attempt) = SeedStoppingAttempt(store, boot, detail, retryable);
        var attemptName = IdText.Format(attempt);
        var files = new AttemptFiles(fixture.DataRoot, attemptName);
        Directory.CreateDirectory(files.Directory);

        // This synthetic holder receipt is scoped to the original attempt. No node endpoint or process is started.
        var exit = new ExitRecord
        {
            AttemptId = attemptName,
            ExitStatus = 137,
            ServiceResult = "exit-code",
            RecordedAt = clock.GetUtcNow().ToString("O", CultureInfo.InvariantCulture),
        };
        HelperFiles.WriteAtomically(files.ExitPath, exit.ToJson());
        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, clock);
        using var heartbeat = new NodeHeartbeatWriter(fixture.DataRoot, log, clock);
        await using var processor = new CommandProcessor(store, EventJournal.Open(store), new StreamHub());
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = clock,
            DataRoot = fixture.DataRoot,
            Heartbeat = heartbeat,
        });
        await execution.RecoverAsync(new RecoveryReport(true, false, null, store.Opening), processor, ct);
        execution.Start();

        ManagedTask ReadTask() => store.Read(reader => TaskRecords.GetTask(reader, task, full: false))!;
        await TestNode.WaitAsync(() => ReadTask().CurrentAttempt.State == AttemptState.Finished, TimeSpan.FromSeconds(10),
            "the retained attempt to finalize from its receipt");
        var recovered = ReadTask();
        Assert.Equal(attemptName, IdText.Format(recovered.CurrentAttempt.AttemptId));
        Assert.True(recovered.CurrentAttempt.NodeGap);
        Assert.Equal(legacy ? TerminationReason.Cancelled : TerminationReason.Preempted, recovered.CurrentAttempt.Result.TerminationReason);
        Assert.Equal(EffectCertainty.Happened, recovered.CurrentAttempt.Result.Effect);
        Assert.Equal(137, recovered.CurrentAttempt.Result.ExitCode);
        if (detail is not null)
        {
            Assert.Equal(detail, recovered.CurrentAttempt.Result.Detail);
        }

        var scheduled = !legacy && retryable;
        Assert.Equal(legacy ? TaskState.Cancelled : scheduled ? TaskState.RetryWait : TaskState.Failed, recovered.State);
        Assert.Equal(1u, recovered.AttemptCount);
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
        var retryAt = store.Read(reader => reader.Scalar("SELECT retry_at FROM task WHERE task_id = $id;", ("$id", task)));
        if (scheduled)
        {
            var finishedAt = store.Read(reader => reader.Scalar("SELECT finished_at FROM attempt WHERE attempt_id = $id;", ("$id", attempt)));
            Assert.Equal(Assert.IsType<long>(finishedAt) + 200_000L, Assert.IsType<long>(retryAt));
        }
        else
        {
            Assert.Null(retryAt);
        }
    }

    private sealed class RecoveryClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddDays(1);
    }

    private static (byte[] Task, byte[] Attempt) SeedStoppingAttempt(NodeStore store, string boot, string? detail, bool retryable)
    {
        const string command = "fixture-never-starts";
        var sideEffect = retryable ? SideEffectClass.Idempotent : SideEffectClass.Unknown;
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { command } } },
            Priority = Priority.Background,
            Resources = new ResourceSpec { Preemptible = true, CancelGraceMs = 0 },
            Retry = new RetrySpec { MaxAttempts = 2, InitialBackoffMs = 200, MaxBackoffMs = 400 },
            SideEffect = sideEffect,
        }.ToByteArray();
        var owner = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli }.ToByteArray();
        return store.Write(transaction =>
        {
            var task = StoreIds.NewUuid7(transaction.Clock);
            var attempt = StoreIds.NewUuid7(transaction.Clock);
            var digest = SHA256.HashData(spec);
            var now = transaction.NowMicroseconds;
            transaction.Execute(
                """
                INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                                  pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                                  command_digest, created_at, started_at, current_attempt_id, attempt_count, rev)
                VALUES ($task, $state, 1, $command, $command, $spec, $digest, $owner, $origin,
                        'default', $priority, $priority, $sideEffect, $source, $command, $digest, $now, $now, $attempt, 1, 0);
                """,
                ("$task", task), ("$state", (int)TaskState.Running), ("$command", command), ("$spec", spec), ("$digest", digest),
                ("$owner", owner), ("$origin", (int)Origin.Human), ("$priority", (int)Priority.Background),
                ("$sideEffect", (int)sideEffect), ("$source", (int)SideEffectSource.Caller), ("$now", now), ("$attempt", attempt));
            transaction.Execute(
                """
                INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, boot_identity,
                                     request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source,
                                     accounted_mem_bytes, created_at, started_at, termination_reason, detail, rev)
                VALUES ($attempt, $task, 1, 1, $state, $node, $boot, 100, 67108864, 67108864, 1, 67108864, $now, $now,
                        $reason, $detail, 0);
                """,
                ("$attempt", attempt), ("$task", task), ("$state", (int)AttemptState.Stopping), ("$node", store.Metadata.NodeId.ToArray()),
                ("$boot", boot), ("$now", now), ("$reason", detail is null ? null : (int)TerminationReason.Preempted), ("$detail", detail));
            return (task, attempt);
        }, CommitDurability.Full);
    }
}
