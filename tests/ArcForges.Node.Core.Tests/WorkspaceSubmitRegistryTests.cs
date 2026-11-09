// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Scheduling;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real local TaskService, registered roots and SQLite transaction ordering; the callback only coordinates the actual race.</summary>
[Trait("feature", "workspace-submit-registry")]
public sealed class WorkspaceSubmitRegistryTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnregisterBeforeRealSubmitTransactionUsesOnlyCurrentWorkspaceAndPolicy(bool registerChild)
    {
        var cancellation = TestContext.Current.CancellationToken;
        cancellation.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.NotNull(node.Runtime.Execution?.Platform);
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: cancellation)).Error);

        var parent = Directory.CreateDirectory(Path.Combine(node.Root, "workspace")).FullName;
        var child = Directory.CreateDirectory(Path.Combine(parent, "child")).FullName;
        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var old = manager.RegisterFromVerifiedHuman(parent, cancellationToken: cancellation);
        var selectedBefore = node.Runtime.Store.Read(reader => ExecutionSupervisor.WorkspaceOf(reader, child));
        Assert.Equal(old.Id, selectedBefore);

        // The old root has a rule that must not be applied to the later, different workspace selection.
        var policy = await Sched.ChangePolicyAsync(human, document =>
        {
            document.RetrySafety ??= new RetrySafetyPolicy();
            document.RetrySafety.Rules.Add(new RetrySafetyRule
            {
                Pattern = ".*hold.*",
                WorkspaceId = new Id { Value = ByteString.CopyFrom(old.Id) },
                SideEffect = SideEffectClass.Idempotent,
            });
        });
        Assert.Null(policy.Error);
        Assert.Equal(SideEffectClass.Idempotent,
            PolicyRules.RetrySafety(node.Runtime.Execution!.Settings.RetrySafetyRules, "hold", old.Id));

        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var execution = node.Runtime.Execution!;
        execution.BeforeSubmitTransactionForTests = async token =>
        {
            entered.TrySetResult();
            await resume.Task.WaitAsync(token).ConfigureAwait(false);
        };
        var request = new TaskServiceSubmitTaskRequest
        {
            Meta = Tasks.Meta(),
            Spec = Tasks.Argv(child, Tasks.TestLoad, "hold", "--hold-ms", "60000"),
        };
        var pending = script.Tasks.SubmitTaskAsync(request, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: cancellation).ResponseAsync;
        RegisteredWorkspace? current = null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellation);
            manager.UnregisterFromVerifiedHuman(old.Id, cancellation);
            if (registerChild)
            {
                current = manager.RegisterFromVerifiedHuman(child, cancellationToken: cancellation);
                node.Runtime.Store.Write(transaction => transaction.Execute(
                    "UPDATE workspace SET concurrency_mode = $mode WHERE workspace_id = $id;",
                    ("$mode", (int)WorkspaceConcurrency.Serial), ("$id", current.Id)));
            }

            var currentBeforeCommit = node.Runtime.Store.Read(reader => ExecutionSupervisor.WorkspaceOf(reader, child));
            Assert.Equal(current?.Id, currentBeforeCommit);
        }
        finally
        {
            resume.TrySetResult();
        }

        var response = await pending.WaitAsync(TimeSpan.FromSeconds(15), cancellation);
        execution.BeforeSubmitTransactionForTests = null;
        Assert.Null(response.Error);
        Assert.Equal(EffectCertainty.Happened, response.Value.Receipt.Effect);
        var taskId = response.Value.TaskId.Value.ToByteArray();
        var actual = node.Runtime.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("SELECT workspace_id, state, side_effect, side_effect_source FROM task WHERE task_id=$id;");
            command.Parameters.AddWithValue("$id", taskId);
            using var rows = command.ExecuteReader();
            Assert.True(rows.Read());
            return (Workspace: rows.IsDBNull(0) ? null : (byte[])rows.GetValue(0), State: rows.GetInt32(1),
                SideEffect: rows.GetInt32(2), Source: rows.GetInt32(3));
        });
        Assert.Equal(current?.Id, actual.Workspace);
        Assert.NotEqual(Convert.ToHexString(old.Id), actual.Workspace is null ? string.Empty : Convert.ToHexString(actual.Workspace));
        Assert.Equal((int)TaskState.Queued, actual.State);
        Assert.Equal((int)SideEffectClass.Unknown, actual.SideEffect);
        Assert.Equal((int)SideEffectSource.Default, actual.Source);
        if (current is not null)
        {
            Assert.Equal("workspace_in_use", Assert.Throws<RegisteredWorkspaceException>(
                () => manager.UnregisterFromVerifiedHuman(current.Id, cancellation)).Reason);
        }

        var cancelled = await script.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest
        {
            Meta = Tasks.Meta(),
            TaskId = response.Value.TaskId,
        }, cancellationToken: cancellation);
        Assert.Null(cancelled.Error);
        Assert.Equal(TaskState.Cancelled, cancelled.Value.State);
        if (current is not null)
        {
            manager.UnregisterFromVerifiedHuman(current.Id, cancellation);
        }

        // The real command receipt replays without inserting the task a second time, even after unregistration.
        var replay = await script.Tasks.SubmitTaskAsync(request, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: cancellation);
        Assert.Null(replay.Error);
        Assert.Equal(response.Value.TaskId, replay.Value.TaskId);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE task_id=$id;", ("$id", taskId))));
    }
}
