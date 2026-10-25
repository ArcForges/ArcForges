// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using ArcForges.Tests;
using Microsoft.Data.Sqlite;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Real node crashes at committed attempt phases, with real holders/jobs or user units and isolated secret stores.</summary>
[Trait("loop", "local")]
public sealed class AttemptPhaseRecoveryTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(60);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory(Timeout = 180_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CommittedAttemptPhasesSurviveANodeCrashOnWindows(bool timeout, bool finalizing)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows holders and jobs.");
        await CrashAtPhaseAsync(timeout, finalizing);
    }

    [Theory(Timeout = 180_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CommittedAttemptPhasesSurviveANodeCrashOnLinux(bool timeout, bool finalizing)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux user units.");
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        await CrashAtPhaseAsync(timeout, finalizing);
    }

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task ACancelReplyWaitsUntilTheCommittedStopHasBegun()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        if (OperatingSystem.IsLinux())
        {
            Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        }

        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_TEST_FAULT"] = "hold-stop-before-stop=60";
        await node.StartNodeAsync();
        var release = Path.Combine(node.DataRoot, "run", "fault-hold-stop-before-stop.release");
        try
        {
            await using var channel = await node.HumanChannelAsync();
            var marker = Path.Combine(node.Root, "cancel-reply-root.txt");
            var argv = new ArgvCommand();
            argv.Argv.Add([TestNode.TestLoad, "hold", "--hold-ms", "180000", "--marker", marker]);
            var submitted = await channel.Tasks.SubmitTaskAsync(new TaskServiceSubmitTaskRequest
            {
                Meta = Meta(),
                Spec = new TaskSpec
                {
                    Command = new CommandSpec { Argv = argv },
                    WorkingDirectory = node.Root,
                    Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
                    Resources = new ResourceSpec { CancelGraceMs = 0 },
                },
            }, cancellationToken: Ct);
            Assert.Null(submitted.Error);
            await TestNode.WaitAsync(() => TestNode.ReadShared(marker).Split('\n').Any(line => line.StartsWith("start ", StringComparison.Ordinal)),
                Bound, "the actual command before cancellation");
            var cancelled = channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest
            {
                Meta = Meta(),
                TaskId = submitted.Value.TaskId,
                GraceMs = 0,
            }, cancellationToken: Ct).ResponseAsync;
            await TestNode.WaitAsync(() => File.Exists(Path.Combine(node.DataRoot, "run", "fault-hold-stop-before-stop.done")),
                Bound, "the committed stop before platform action");
            Assert.False(cancelled.IsCompleted, "CancelTask replied before the durable stop's platform phase began.");
            var pending = await TaskAsync(channel, submitted.Value.TaskId);
            Assert.Equal(AttemptState.Stopping, pending.CurrentAttempt.State);
            Assert.Null(pending.CurrentAttempt.Result);
            await File.WriteAllTextAsync(release, "release", Ct);
            Assert.Null((await cancelled.WaitAsync(Bound, Ct)).Error);
            ManagedTask ended = new();
            await TestNode.WaitAsync(async () =>
            {
                ended = await TaskAsync(channel, submitted.Value.TaskId);
                return ended.State == TaskState.Cancelled;
            }, Bound, "the acknowledged stop to finish");
            Assert.Equal(TerminationReason.Cancelled, ended.CurrentAttempt.Result.TerminationReason);
            Assert.Equal(EffectCertainty.Happened, ended.CurrentAttempt.Result.Effect);
        }
        finally
        {
            await File.WriteAllTextAsync(release, "release", CancellationToken.None);
        }
    }

    private static async Task CrashAtPhaseAsync(bool timeout, bool finalizing)
    {
        // A normal exit uses FINALIZING; timeout covers both the pre-stop barrier and the pre-result barrier.
        finalizing |= !timeout;
        var fault = finalizing ? "hold-finalizing" : "hold-stop-before-stop";
        await using var node = TestNode.Create();
        node.Environment["ARCFORGES_TEST_FAULT"] = fault + "=60";
        var first = await node.StartNodeAsync();
        System.Diagnostics.Process? restarted = null;
        Id? id = null;
        try
        {
            await using var channel = await node.HumanChannelAsync();
            var marker = Path.Combine(node.Root, "phase-root.txt");
            var argv = new ArgvCommand();
            argv.Argv.Add([TestNode.TestLoad, "hold", "--hold-ms", timeout ? "180000" : "2000", "--marker", marker]);
            var spec = new TaskSpec
            {
                Command = new CommandSpec { Argv = argv },
                WorkingDirectory = node.Root,
                Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
                Resources = new ResourceSpec { CancelGraceMs = 0 },
            };
            if (timeout)
            {
                spec.TimeoutMs = 1_000;
            }

            var submitted = await channel.Tasks.SubmitTaskAsync(new TaskServiceSubmitTaskRequest { Meta = Meta(), Spec = spec }, cancellationToken: Ct);
            Assert.Null(submitted.Error);
            id = submitted.Value.TaskId;
            ManagedTask task = new();
            var phase = finalizing ? AttemptState.Finalizing : AttemptState.Stopping;
            var held = Path.Combine(node.DataRoot, "run", "fault-" + fault + ".done");
            await TestNode.WaitAsync(async () =>
            {
                task = await TaskAsync(channel, id);
                return File.Exists(held) && task.CurrentAttempt?.State == phase;
            }, Bound, "the committed attempt phase and its crash barrier");
            var attemptId = task.CurrentAttempt.AttemptId;
            Assert.Null(task.CurrentAttempt.Result);
            Assert.Equal((long)phase, StoredPhase(node, attemptId).State);
            Assert.Equal(timeout ? (long?)TerminationReason.TimedOut : null, StoredPhase(node, attemptId).Cause);
            var starts = TestNode.ReadShared(marker).Split('\n').Where(line => line.StartsWith("start ", StringComparison.Ordinal)).ToArray();
            var start = Assert.Single(starts);
            var pid = int.Parse(start.Split(' ')[1], CultureInfo.InvariantCulture);
            var root = ArcForges.Tests.ProcessIdentity.Capture(pid);
            if (!finalizing)
            {
                var live = Assert.IsType<ArcForges.Tests.ProcessIdentity>(root);
                Assert.True(live.IsRunning(), "The timeout must commit before the real command is stopped.");
            }

            first.Kill();
            await first.WaitForExitAsync(Ct);
            if (!finalizing)
            {
                var live = Assert.IsType<ArcForges.Tests.ProcessIdentity>(root);
                Assert.True(live.IsRunning(), "The actual command must survive this test node's crash.");
            }

            node.Environment["ARCFORGES_TEST_FAULT"] = null;
            restarted = await node.StartNodeAsync();
            await using var after = await node.HumanChannelAsync();
            await TestNode.WaitAsync(async () =>
            {
                task = await TaskAsync(after, id);
                return task.CurrentAttempt.State == AttemptState.Finished;
            }, Bound, "the same attempt's recovered final record");
            Assert.Equal(IdText.Format(attemptId), IdText.Format(task.CurrentAttempt.AttemptId));
            Assert.True(task.CurrentAttempt.NodeGap);
            Assert.Equal(timeout ? TaskState.Failed : TaskState.Succeeded, task.State);
            var result = task.CurrentAttempt.Result;
            Assert.NotNull(result);
            Assert.Equal(timeout ? TerminationReason.TimedOut : TerminationReason.Exited, result.TerminationReason);
            Assert.Equal(EffectCertainty.Happened, result.Effect);
            Assert.Equal(1u, task.AttemptCount);
            Assert.Equal(1, TestNode.ReadShared(marker).Split('\n').Count(line => line.StartsWith("start ", StringComparison.Ordinal)));
            Assert.Equal((long)AttemptState.Finished, StoredPhase(node, attemptId).State);
            if (root is { } exited)
            {
                Assert.False(exited.IsRunning());
            }
        }
        finally
        {
            node.Environment["ARCFORGES_TEST_FAULT"] = null;
            if (!first.HasExited && File.Exists(Path.Combine(node.DataRoot, "run", "fault-" + fault + ".done")))
            {
                first.Kill();
                await first.WaitForExitAsync(Ct);
            }

            if (id is not null)
            {
                if (first.HasExited && (restarted is null || restarted.HasExited))
                {
                    restarted = await node.StartNodeAsync();
                }

                await using var cleanup = await node.HumanChannelAsync();
                Assert.Null((await cleanup.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Meta(), TaskId = id, GraceMs = 0 }, cancellationToken: Ct)).Error);
                await TestNode.WaitAsync(async () => (await TaskAsync(cleanup, id)).State is TaskState.Succeeded or TaskState.Failed or TaskState.Cancelled or TaskState.Lost,
                    Bound, "the fixture's task cleanup");
            }
        }
    }

    private static RequestMeta Meta() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };

    private static async Task<ManagedTask> TaskAsync(NodeChannel channel, Id id) =>
        (await channel.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest { Meta = new RequestMeta(), TaskId = id },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct)).Value.Task;

    private static (long State, long? Cause) StoredPhase(TestNode node, Id id)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(node.DataRoot),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT state, termination_reason FROM attempt WHERE attempt_id = $id;";
        command.Parameters.AddWithValue("$id", id.Value.ToByteArray());
        using var reader = command.ExecuteReader();
        Assert.True(reader.Read());
        return (reader.GetInt64(0), reader.IsDBNull(1) ? null : reader.GetInt64(1));
    }
}
