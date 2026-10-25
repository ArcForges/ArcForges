// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using ArcForges.Tests;
using Microsoft.Data.Sqlite;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class ResourceTests
{
    [Theory(Timeout = 240_000, DisableParallelization = true)]
    [Trait("env", "windows-real")]
    [Trait("isolation", "exclusive")]
    [InlineData(true, false, true)]
    [InlineData(false, false, true)]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    public async Task APreemptedAttemptKeepsItsCauseAndRetryRulesAfterACrashOnWindows(bool critical, bool legacy, bool retryable)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows pressure requeue and critical preemption.");
        await RecoveredPreemptionAsync(critical, legacy, retryable);
    }

    [Theory(Timeout = 240_000, DisableParallelization = true)]
    [Trait("env", "linux-real")]
    [Trait("isolation", "exclusive")]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task APreemptedAttemptKeepsItsCauseAndRetryRulesAfterACrashOnLinux(bool legacy, bool retryable)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux critical preemption.");
        Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);
        await RecoveredPreemptionAsync(critical: true, legacy, retryable);
    }

    // A real sampler crosses only this node's changed policy thresholds; no fake sampler or allocator/global pressure is needed.
    // The test-mode hold keeps the actual root alive after STOPPING commits; killing the real node then exercises durable recovery.
    private static async Task RecoveredPreemptionAsync(bool critical, bool legacy, bool retryable)
    {
        await using var node = TestNode.Create();
        node.LiveMachine = true;
        node.Environment["ARCFORGES_TEST_FAULT"] = "hold-preempt-before-stop=60";
        var first = await node.StartNodeAsync();
        System.Diagnostics.Process? restarted = null;
        Id? taskId = null;
        try
        {
            await using var human = await node.HumanChannelAsync();
            var current = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Meta() }, cancellationToken: Ct);
            Assert.Null(current.Error);
            var originalPressure = current.Value.Document.Resources.Pressure.Clone();
            var argv = new ArgvCommand();
            var marker = Path.Combine(node.Root, "preempt-root.txt");
            argv.Argv.Add([TestNode.TestLoad, "hold", "--hold-ms", "180000", "--marker", marker]);
            var spec = new TaskSpec
            {
                Command = new CommandSpec { Argv = argv },
                WorkingDirectory = node.Root,
                Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
                Priority = Priority.Background,
                Resources = new ResourceSpec { Preemptible = true, CancelGraceMs = 0 },
                Retry = new RetrySpec { MaxAttempts = 2, InitialBackoffMs = 200, MaxBackoffMs = 400 },
            };
            if (retryable)
            {
                spec.SideEffect = SideEffectClass.Idempotent;
            }

            var submitted = await human.Tasks.SubmitTaskAsync(new TaskServiceSubmitTaskRequest { Meta = Meta(), Spec = spec }, cancellationToken: Ct);
            Assert.Null(submitted.Error);
            taskId = submitted.Value.TaskId;
            var attemptId = await RunningAttemptAsync(human, taskId);
            await TestNode.WaitAsync(() => File.Exists(marker) && File.ReadAllLines(marker).Any(line => line.StartsWith("start ", StringComparison.Ordinal)), Bound, "the actual root marker");
            var rootPid = int.Parse(File.ReadAllLines(marker).First(line => line.StartsWith("start ", StringComparison.Ordinal)).Split(' ')[1], CultureInfo.InvariantCulture);
            var root = Assert.IsType<ArcForges.Tests.ProcessIdentity>(ArcForges.Tests.ProcessIdentity.Capture(rootPid));

            await PreemptionPolicyAsync(human, document => document.Resources.Pressure = new PressureThresholds
            {
                TightAvailableFraction = 0.999,
                PressureAvailableFraction = 0.998,
                CriticalAvailableFraction = critical ? 0.997 : 0.001,
                MemoryPsiSomeAvg10 = 99,
                FreezeOnPressure = true,
                CancelOnCritical = true,
            });
            var held = Path.Combine(node.DataRoot, "run", "fault-hold-preempt-before-stop.done");
            await TestNode.WaitAsync(async () => File.Exists(held) && (await AttemptAsync(human, attemptId)).State == AttemptState.Stopping,
                Bound, "the preemption hold and committed STOPPING");
            Assert.True(root.IsRunning(), "The root must survive the node crash; this is not recovery of an already finished attempt.");
            Assert.Null((await AttemptAsync(human, attemptId)).Result);
            var pending = StoredStopCause(node, attemptId, clear: legacy);

            // Restore this node's real policy before the crash, so an allowed retry may execute at Normal.
            await PreemptionPolicyAsync(human, document => document.Resources.Pressure = originalPressure);
            first.Kill();
            await first.WaitForExitAsync(Ct);
            Assert.True(root.IsRunning(), "Killing this test node must leave its holder/unit and actual command running.");
            node.Environment["ARCFORGES_TEST_FAULT"] = null;
            restarted = await node.StartNodeAsync();
            await using var after = await node.HumanChannelAsync();
            Attempt finished = new();
            await TestNode.WaitAsync(async () => (finished = await AttemptAsync(after, attemptId)).State == AttemptState.Finished, Bound, "the recovered stop to finish");
            Assert.Equal(legacy ? TerminationReason.Cancelled : TerminationReason.Preempted, finished.Result.TerminationReason);
            Assert.Equal(EffectCertainty.Happened, finished.Result.Effect);
            Assert.True(finished.NodeGap);
            Assert.False(root.IsRunning());
            if (!legacy)
            {
                Assert.Equal((long)TerminationReason.Preempted, pending);
                Assert.Contains(critical ? "critical memory pressure" : "requeued at memory pressure", finished.Result.Detail, StringComparison.Ordinal);
            }

            ManagedTask task = new();
            if (!legacy && retryable)
            {
                await TestNode.WaitAsync(async () =>
                {
                    task = await TaskAsync(after, taskId);
                    return task.State == TaskState.Running && task.AttemptCount == 2 && task.CurrentAttempt.State == AttemptState.Running;
                }, Bound, "the permitted retry's second real attempt to run");
                Assert.NotEqual(IdText.Format(attemptId), IdText.Format(task.CurrentAttempt.AttemptId));
                await TestNode.WaitAsync(() => File.ReadAllLines(marker).Count(line => line.StartsWith("start ", StringComparison.Ordinal)) == 2,
                    Bound, "both actual command starts in the workload marker");
                Assert.Contains(TestNode.LogEvents(node.NodeLog, "execution.retry.scheduled"), entry =>
                    entry.GetProperty("fields").GetProperty("task").GetString() == IdText.Format(taskId));
            }
            else
            {
                await TestNode.WaitAsync(async () => (task = await TaskAsync(after, taskId)).State == (legacy ? TaskState.Cancelled : TaskState.Failed), Bound, "the terminal task without retry permission");
                Assert.DoesNotContain(TestNode.LogEvents(node.NodeLog, "execution.retry.scheduled"), entry =>
                    entry.GetProperty("fields").GetProperty("task").GetString() == IdText.Format(taskId));
            }

            Assert.Equal(!legacy && retryable ? 2u : 1u, task.AttemptCount);
        }
        finally
        {
            node.Environment["ARCFORGES_TEST_FAULT"] = null;
            if (!first.HasExited && File.Exists(Path.Combine(node.DataRoot, "run", "fault-hold-preempt-before-stop.done")))
            {
                first.Kill();
                await first.WaitForExitAsync(Ct);
            }

            if (taskId is not null)
            {
                if (first.HasExited && (restarted is null || restarted.HasExited))
                {
                    restarted = await node.StartNodeAsync();
                }

                await using var cleanup = await node.HumanChannelAsync();
                Assert.Null((await cleanup.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Meta(), TaskId = taskId, GraceMs = 0 }, cancellationToken: Ct)).Error);
                await TestNode.WaitAsync(async () => (await TaskAsync(cleanup, taskId)).State is TaskState.Cancelled or TaskState.Failed or TaskState.Succeeded or TaskState.Lost,
                    Bound, "the test task cleanup");
            }
        }
    }

    private static async Task PreemptionPolicyAsync(NodeChannel human, Action<PolicyDocument> change)
    {
        var current = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = Meta() }, cancellationToken: Ct);
        Assert.Null(current.Error);
        var document = current.Value.Document.Clone();
        change(document);
        var meta = Meta();
        meta.ExpectedRev = current.Value.Revision.Revision;
        var updated = await human.Policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = meta, Document = document, Comment = "isolated preemption recovery fault test" }, cancellationToken: Ct);
        Assert.Null(updated.Error);
    }

    // Only this fixture's temporary database: clearing the cause injects a legacy row without changing a schema/version.
    private static long? StoredStopCause(TestNode node, Id attempt, bool clear)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = StorePaths.Database(node.DataRoot),
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.Parameters.AddWithValue("$id", attempt.Value.ToByteArray());
        if (clear)
        {
            command.CommandText = "UPDATE attempt SET termination_reason = NULL WHERE attempt_id = $id AND state = 7;";
            Assert.Equal(1, command.ExecuteNonQuery());
        }

        command.CommandText = "SELECT termination_reason FROM attempt WHERE attempt_id = $id;";
        return command.ExecuteScalar() as long?;
    }
}
