// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Independent review: a real StopNode lifecycle transition must win over already-admitted routed effects.</summary>
public sealed class RoutedStopReviewTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 180_000)]
    public async Task StopQueueWaitDoesNotMistakeUnrelatedQueuedWorkForStopNode()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var meta = Tasks.Meta();
        var stopQueued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        node.Runtime.Processor.EnqueuedForTests = new Dictionary<string, TaskCompletionSource>(StringComparer.Ordinal)
        {
            [Convert.ToHexString(meta.CommandId.Value.Span)] = stopQueued,
        };
        using var releaseWriter = new ManualResetEventSlim(false);
        using var releaseStop = new ManualResetEventSlim(false);
        using var stopRegistration = node.Runtime.Stopping.Register(() => releaseStop.Wait(TimeSpan.FromSeconds(60)));
        var writerEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocker = node.Runtime.Processor.ExecuteAsync(_ =>
        {
            writerEntered.TrySetResult();
            releaseWriter.Wait(TimeSpan.FromSeconds(60));
            return 0;
        });
        Task<int>? unrelated = null;
        try
        {
            await writerEntered.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            unrelated = node.Runtime.Processor.ExecuteAsync(_ => 0);
            Assert.True(node.Runtime.Processor.Queued >= 1);
            var waitingForStop = WaitForStopQueuedAsync(stopQueued.Task);
            Assert.False(waitingForStop.IsCompleted, "unrelated queued work does not mean that StopNode is queued");
            var stopping = human.Node.StopNodeAsync(new NodeServiceStopNodeRequest { Meta = meta }, cancellationToken: Ct).ResponseAsync;
            await waitingForStop;
            Assert.True(stopQueued.Task.IsCompletedSuccessfully);
            releaseWriter.Set();
            await Tasks.WaitForAsync(() => node.Runtime.Lifecycle.IsStopping, TimeSpan.FromSeconds(15), "the real StopNode transition");
            releaseStop.Set();
            await stopping.WaitAsync(TimeSpan.FromSeconds(20), Ct);
        }
        finally
        {
            releaseWriter.Set();
            releaseStop.Set();
            await blocker;
            if (unrelated is not null)
            {
                await unrelated;
            }
        }
    }

    // The signal is set only after this StopNode command ID was successfully added to the real writer queue.
    private static Task WaitForStopQueuedAsync(Task stopQueued) => stopQueued.WaitAsync(TimeSpan.FromSeconds(15), Ct);

    [Theory(Timeout = 180_000)]
    [InlineData("submit")]
    [InlineData("cancel")]
    [InlineData("approval")]
    public async Task RealStopNodeBeforeAnAdmittedEffectPreventsTheEffect(string kind)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var caller = routed.Relay(Origin.Script);
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
        Id? taskId = null;
        if (kind == "cancel")
        {
            var initial = (await routed.SubmitAsync(caller, new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec })).Response!;
            Assert.Null(initial.Error);
            taskId = initial.Value.TaskId;
        }
        else if (kind == "approval")
        {
            taskId = await Tasks.SubmitAsync(human, spec);
        }

        var submit = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec };
        var cancel = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId };
        var method = kind == "submit" ? RoutedMethod.SubmitNodeTask : RoutedMethod.CancelNodeTask;
        var payload = kind == "submit" ? submit.ToByteArray() : cancel.ToByteArray();
        var command = kind == "submit" ? submit.Meta.CommandId : cancel.Meta.CommandId;
        var stopMeta = Tasks.Meta();
        var stopQueued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var effectQueued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        node.Runtime.Processor.EnqueuedForTests = new Dictionary<string, TaskCompletionSource>(StringComparer.Ordinal)
        {
            [Convert.ToHexString(stopMeta.CommandId.Value.Span)] = stopQueued,
            [Convert.ToHexString(command.Value.Span)] = effectQueued,
        };
        using var releaseWriter = new ManualResetEventSlim(false);
        using var releaseStop = new ManualResetEventSlim(false);
        using var stopRegistration = node.Runtime.Stopping.Register(() => releaseStop.Wait(TimeSpan.FromSeconds(60)));
        var writerEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocker = node.Runtime.Processor.ExecuteAsync(_ =>
        {
            writerEntered.TrySetResult();
            releaseWriter.Wait(TimeSpan.FromSeconds(60));
            return 0;
        });
        Task<int>? unrelated = null;
        try
        {
            await writerEntered.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            unrelated = node.Runtime.Processor.ExecuteAsync(_ => 0);
            Assert.True(node.Runtime.Processor.Queued >= 1);
            Assert.False(stopQueued.Task.IsCompleted, "the unrelated command is not StopNode");
            var stopping = human.Node.StopNodeAsync(new NodeServiceStopNodeRequest { Meta = stopMeta }, cancellationToken: Ct).ResponseAsync;
            await WaitForStopQueuedAsync(stopQueued.Task);
            var pending = routed.CallAsync(caller, method, payload, command, record: false);
            await effectQueued.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            releaseWriter.Set();
            var (answer, _) = await pending.WaitAsync(TimeSpan.FromSeconds(30), Ct);
            Assert.True(node.Runtime.Lifecycle.IsStopping, "the real StopNode transaction changed lifecycle first");
            Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
            var error = kind == "submit"
                ? TaskServiceSubmitTaskResponse.Parser.ParseFrom(answer.Response).Error
                : TaskServiceCancelTaskResponse.Parser.ParseFrom(answer.Response).Error;
            Assert.Equal(("node_stopping", EffectCertainty.DidNotHappen, RetryMode.AfterTime), (error?.Code, error?.Effect, error?.Retry?.Mode));
            if (kind == "submit")
            {
                Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;", ("$id", command.Value.ToByteArray()))));
            }
            else if (kind == "approval")
            {
                Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM approval WHERE command_id = $id;", ("$id", command.Value.ToByteArray()))));
            }
            else
            {
                Assert.NotEqual((long)TaskState.Cancelled, node.Runtime.Store.Read(reader => reader.Scalar("SELECT state FROM task WHERE task_id = $id;", ("$id", taskId!.Value.ToByteArray()))));
            }

            releaseStop.Set();
            await stopping.WaitAsync(TimeSpan.FromSeconds(20), Ct);
        }
        finally
        {
            releaseWriter.Set();
            releaseStop.Set();
            await blocker;
            if (unrelated is not null)
            {
                await unrelated;
            }
        }
    }
}
