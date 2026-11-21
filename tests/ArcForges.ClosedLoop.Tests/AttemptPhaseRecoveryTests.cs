// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.Tests;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Restarts the current Node with pre-existing legacy Attempt rows and a simulated durable exit record.</summary>
/// <remarks>
/// Historical commit 8496f155213d0c215396d1093f866f39b4678f43 retains
/// <c>CommittedAttemptPhasesSurviveANodeCrashOnWindows</c>, <c>CommittedAttemptPhasesSurviveANodeCrashOnLinux</c>
/// and <c>ACancelReplyWaitsUntilTheCommittedStopHasBegun</c>. Those cases use legacy admission to create the
/// live Job or unit. This fixture covers recovery after a durable exit is already available.
/// </remarks>
[Trait("loop", "local")]
[Trait("env", "windows-real")]
[Trait("env", "linux-real")]
public sealed class AttemptPhaseRecoveryTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory(Timeout = 120_000)]
    [InlineData(AttemptState.Stopping, TerminationReason.TimedOut)]
    [InlineData(AttemptState.Finalizing, TerminationReason.TimedOut)]
    [InlineData(AttemptState.Finalizing, null)]
    [InlineData(AttemptState.Stopping, TerminationReason.Cancelled)]
    public async Task ARecordedLegacyAttemptSettlesWithItsOriginalIdentityAndStopCause(AttemptState phase, TerminationReason? stop)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = TestNode.Create();
        var (taskId, attemptId) = SeedPriorAttempt(node, phase, stop);
        Assert.Equal(((long)phase, (long?)stop, 1L), StoredPhase(node, attemptId));

        using var first = await node.StartNodeAsync();
        ManagedTask settled = new();
        await using (var channel = await node.HumanChannelAsync())
        {
            await TestNode.WaitAsync(async () =>
            {
                settled = await ReadTaskAsync(channel, taskId);
                return settled.CurrentAttempt.State == AttemptState.Finished;
            }, TimeSpan.FromSeconds(30), "the retained attempt's final record");
        }

        var cause = stop ?? TerminationReason.Exited;
        var state = stop switch
        {
            TerminationReason.TimedOut => TaskState.Failed,
            TerminationReason.Cancelled => TaskState.Cancelled,
            _ => TaskState.Succeeded,
        };
        Assert.Equal(attemptId, settled.CurrentAttempt.AttemptId);
        Assert.True(settled.CurrentAttempt.NodeGap);
        Assert.Equal(1u, settled.AttemptCount);
        Assert.Equal(state, settled.State);
        Assert.NotNull(settled.CurrentAttempt.Result);
        Assert.Equal(cause, settled.CurrentAttempt.Result.TerminationReason);
        Assert.Equal(EffectCertainty.Happened, settled.CurrentAttempt.Result.Effect);
        Assert.Equal(stop is null ? 0 : 1, settled.CurrentAttempt.Result.ExitCode);
        Assert.Equal(((long)AttemptState.Finished, (long?)cause, 1L), StoredPhase(node, attemptId));

        await node.StopNodeAsync();
        using var reopened = await node.StartNodeAsync();
        await using var after = await node.HumanChannelAsync();
        var retained = await ReadTaskAsync(after, taskId);
        Assert.Equal(settled.CurrentAttempt.Result, retained.CurrentAttempt.Result);
        Assert.Equal(attemptId, retained.CurrentAttempt.AttemptId);
        Assert.Equal(1u, retained.AttemptCount);
        Assert.Equal(((long)AttemptState.Finished, (long?)cause, 1L), StoredPhase(node, attemptId));
    }

    private static (Id TaskId, Id AttemptId) SeedPriorAttempt(TestNode node, AttemptState phase, TerminationReason? stop)
    {
        var boot = BootIdentity.Read();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = boot });
        var task = StoreIds.NewUuid7(TimeProvider.System);
        var attempt = StoreIds.NewUuid7(TimeProvider.System);
        var attemptName = IdText.Format(attempt);
        const string command = "fixture-already-exited";
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { command } } },
            WorkingDirectory = node.Root,
        }.ToByteArray();
        store.Write(transaction =>
        {
            transaction.Execute(
                """
                INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                                  pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                                  command_digest, created_at, started_at, current_attempt_id, attempt_count, rev)
                VALUES ($task, $state, $kind, $command, $command, $spec, $digest, $owner, $origin,
                        'default', 3, 3, 4, 1, $command, $digest, $now, $now, $attempt, 1, 0);
                """,
                ("$task", task), ("$state", (int)TaskState.Running), ("$kind", (int)TaskKind.Command), ("$command", command),
                ("$spec", spec), ("$digest", SHA256.HashData(spec)), ("$owner", new ActorRef { Origin = Origin.Human }.ToByteArray()),
                ("$origin", (int)Origin.Human), ("$attempt", attempt), ("$now", transaction.NowMicroseconds));
            transaction.Execute(
                """
                INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, boot_identity,
                                     request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source,
                                     accounted_mem_bytes, created_at, started_at, termination_reason, rev)
                VALUES ($attempt, $task, 1, 1, $phase, $node, $boot, 100, 67108864, 67108864, 1, 67108864, $now, $now, $stop, 0);
                """,
                ("$attempt", attempt), ("$task", task), ("$phase", (int)phase), ("$node", store.Metadata.NodeId.ToArray()),
                ("$boot", boot), ("$now", transaction.NowMicroseconds), ("$stop", (int?)stop));
        });

        var files = new AttemptFiles(node.DataRoot, attemptName);
        Directory.CreateDirectory(files.Directory);
        HelperFiles.WriteAtomically(files.ExitPath, new ExitRecord
        {
            AttemptId = attemptName,
            ExitStatus = stop is null ? 0 : 1,
            ServiceResult = stop is null ? "success" : "exit-code",
            RecordedAt = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
        }.ToJson());
        return (new Id { Value = ByteString.CopyFrom(task) }, new Id { Value = ByteString.CopyFrom(attempt) });
    }

    private static async Task<ManagedTask> ReadTaskAsync(NodeChannel channel, Id id)
    {
        var response = await channel.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest { Meta = new RequestMeta(), TaskId = id },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
        Assert.Null(response.Error);
        return response.Value.Task;
    }

    private static (long State, long? Cause, long Count) StoredPhase(TestNode node, Id id)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(node.DataRoot),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT state, termination_reason, (SELECT count(*) FROM attempt AS related WHERE related.task_id = attempt.task_id)
            FROM attempt WHERE attempt_id = $id;
            """;
        command.Parameters.AddWithValue("$id", id.Value.ToByteArray());
        using var reader = command.ExecuteReader();
        Assert.True(reader.Read());
        return (reader.GetInt64(0), reader.IsDBNull(1) ? null : reader.GetInt64(1), reader.GetInt64(2));
    }
}
