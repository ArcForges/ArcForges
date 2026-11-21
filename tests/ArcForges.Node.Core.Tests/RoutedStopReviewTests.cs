// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
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
    [InlineData("submit-replay")]
    [InlineData("cancel")]
    [InlineData("approval")]
    public async Task RealStopNodeWinsBeforeAnAdmittedEffectOrAnUnsentHistoricalReplay(string kind)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var routed = new RoutedCalls(node);
        var caller = routed.Relay(Origin.Script);
        var reconcile = kind == "submit-replay";
        var owner = kind == "approval" ? new ActorRef { Origin = Origin.Human } :
            new ActorRef { Origin = Origin.Remote, CenterCaller = caller };
        var taskId = node.Runtime.Store.Write(tx => LegacyTaskHistoryFixture.SeedQueued(tx, owner), CommitDurability.Full);
        var spec = node.Runtime.Store.Read(reader => TaskSpec.Parser.ParseFrom(Assert.IsType<byte[]>(
            reader.Scalar("SELECT spec FROM task WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray())))));
        var submit = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec };
        var receipt = reconcile ? SeedSubmitReceipt(node, caller, submit, taskId) : null;
        var cancel = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = taskId };
        var stopMeta = Tasks.Meta();
        var stopQueued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var effectQueued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        node.Runtime.Processor.EnqueuedForTests = new Dictionary<string, TaskCompletionSource>(StringComparer.Ordinal)
        {
            [Convert.ToHexString(stopMeta.CommandId.Value.Span)] = stopQueued,
            [Convert.ToHexString(cancel.Meta.CommandId.Value.Span)] = effectQueued,
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
        Task<RoutedAnswer?>? pending = null;
        var queued = new List<Task<int>>();
        using var replayLink = new HeldReplayLink();
        try
        {
            await writerEntered.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            unrelated = node.Runtime.Processor.ExecuteAsync(_ => 0);
            Assert.True(node.Runtime.Processor.Queued >= 1);
            Assert.False(stopQueued.Task.IsCompleted, "the unrelated command is not StopNode");
            var stopping = human.Node.StopNodeAsync(new NodeServiceStopNodeRequest { Meta = stopMeta }, cancellationToken: Ct).ResponseAsync;
            await WaitForStopQueuedAsync(stopQueued.Task);
            if (reconcile)
            {
                while (node.Runtime.Processor.Queued < CommandProcessor.Capacity)
                {
                    try
                    {
                        queued.Add(node.Runtime.Processor.ExecuteAsync(_ => 0));
                    }
                    catch (CommandQueueFullException)
                    {
                        break;
                    }
                }

                Assert.Equal(CommandProcessor.Capacity, node.Runtime.Processor.Queued);
                var overloaded = Assert.IsType<RoutedAnswer>(await RequestCancelAsync().WaitAsync(TimeSpan.FromSeconds(15), Ct));
                Assert.Equal(RoutedOutcome.Executed, overloaded.Outcome);
                Assert.Null(overloaded.Error);
                var refused = TaskServiceCancelTaskResponse.Parser.ParseFrom(overloaded.Response);
                Assert.Null(refused.Value);
                Assert.Equal(("overloaded", EffectCertainty.DidNotHappen, RetryMode.AfterTime),
                    (refused.Error?.Code, refused.Error?.Effect, refused.Error?.Retry?.Mode));
                Assert.False(effectQueued.Task.IsCompleted, "the full queue did not admit the cancel command");

                var (cached, _) = await routed.CallAsync(caller, RoutedMethod.SubmitNodeTask, submit.ToByteArray(),
                    submit.Meta.CommandId, record: false).WaitAsync(TimeSpan.FromSeconds(15), Ct);
                Assert.Equal(RoutedOutcome.Executed, cached!.Outcome);
                Assert.Null(cached.Error);
                Assert.Equal(receipt, cached.Response!.ToByteArray());
                Assert.Equal(CommandProcessor.Capacity, node.Runtime.Processor.Queued);

                var call = VerifiedSubmit(node, caller, submit);
                pending = Task.Run(() => routed.Dispatcher.DispatchAsync(call, replayLink, Ct), Ct);
                await replayLink.AtReplyCheck.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            }
            else
            {
                pending = RequestCancelAsync();
                await effectQueued.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            }

            releaseWriter.Set();
            await Tasks.WaitForAsync(() => node.Runtime.Lifecycle.IsStopping, TimeSpan.FromSeconds(15), "the real StopNode transition");
            replayLink.Release.Set();
            var answer = Assert.IsType<RoutedAnswer>(await pending.WaitAsync(TimeSpan.FromSeconds(30), Ct));
            Assert.True(node.Runtime.Lifecycle.IsStopping, "the real StopNode transaction changed lifecycle first");
            Assert.Equal(RoutedOutcome.Executed, answer.Outcome);
            Assert.Null(answer.Error);
            ArcError? error;
            if (reconcile)
            {
                var response = TaskServiceSubmitTaskResponse.Parser.ParseFrom(answer.Response);
                Assert.Null(response.Value);
                error = response.Error;
                Assert.Equal(receipt, Assert.IsType<byte[]>(node.Runtime.Store.Read(reader => reader.Scalar(
                    "SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", submit.Meta.CommandId.Value.ToByteArray())))));
            }
            else
            {
                var response = TaskServiceCancelTaskResponse.Parser.ParseFrom(answer.Response);
                Assert.Null(response.Value);
                error = response.Error;
            }

            Assert.Equal(("node_stopping", EffectCertainty.DidNotHappen, RetryMode.AfterTime), (error?.Code, error?.Effect, error?.Retry?.Mode));
            node.Runtime.Store.Read(reader =>
            {
                Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM task;"));
                Assert.Equal((long)TaskState.Queued, reader.Scalar("SELECT state FROM task WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray())));
                Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM attempt;"));
                var id = cancel.Meta.CommandId.Value.ToByteArray();
                Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", id)));
                Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM approval WHERE command_id = $id;", ("$id", id)));
                return 0;
            });

            releaseStop.Set();
            var stopped = await stopping.WaitAsync(TimeSpan.FromSeconds(20), Ct);
            Assert.Null(stopped.Error);
            Assert.Equal(stopMeta.CommandId, stopped.Value.Receipt.CommandId);
        }
        finally
        {
            releaseWriter.Set();
            releaseStop.Set();
            replayLink.Release.Set();
            await blocker;
            await Task.WhenAll(queued);
            if (unrelated is not null)
            {
                await unrelated;
            }

            if (pending is not null)
            {
                await pending;
            }
        }

        async Task<RoutedAnswer?> RequestCancelAsync() =>
            (await routed.CallAsync(caller, RoutedMethod.CancelNodeTask, cancel.ToByteArray(), cancel.Meta.CommandId, record: false)).Answer;
    }

    private static byte[] SeedSubmitReceipt(InProcessNode node, CenterCaller owner, TaskServiceSubmitTaskRequest request, Id taskId)
    {
        var id = request.Meta.CommandId;
        var response = new TaskServiceSubmitTaskResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new TaskServiceSubmitTaskValue
            {
                TaskId = taskId,
                State = TaskState.Queued,
                Receipt = new Receipt { CommandId = id, Effect = EffectCertainty.Happened },
            },
        }.ToByteArray();
        node.Runtime.Store.Write(tx =>
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, id.Value.Span, "arcforges.node.v1.TaskService/SubmitTask",
                PayloadDigest.Compute(request.ToByteArray()), Origin.Remote).Status);
            CommandDeduplication.Complete(tx, id.Value.Span, response);
            RoutedCommandOwnership.Record(tx, id.Value.Span, new ActorRef { Origin = Origin.Remote, CenterCaller = owner, RemoteCommandId = id });
        }, CommitDurability.Full);
        return response;
    }

    private static VerifiedCall VerifiedSubmit(InProcessNode node, CenterCaller owner, TaskServiceSubmitTaskRequest request)
    {
        var payload = request.ToByteArray();
        var now = node.Runtime.Clock.GetUtcNow();
        return new VerifiedCall(new CallHeader
        {
            CallId = CommandIds.New(),
            Kid = "retained-stop-fixture",
            AccountId = owner.AccountId.Clone(),
            TargetNodeId = new Id { Value = ByteString.CopyFrom(node.Runtime.NodeId.Span) },
            Caller = owner.Clone(),
            CommandId = request.Meta.CommandId.Clone(),
            Method = RoutedMethod.SubmitNodeTask,
            RequestSha256 = ByteString.CopyFrom(SHA256.HashData(payload)),
            RequestSize = (uint)payload.Length,
            IssuedAt = ProtoTime.ToInstant(now.AddSeconds(-1)),
            ExpiresAt = ProtoTime.ToInstant(now.AddMinutes(1)),
            Deadline = ProtoTime.ToInstant(now.AddSeconds(10)),
        }, ByteString.CopyFrom(payload), 0);
    }

    private sealed class HeldReplayLink : IRoutedLink, IDisposable
    {
        private int _checks;

        public TaskCompletionSource AtReplyCheck { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ManualResetEventSlim Release { get; } = new(false);
        public bool Usable => true;

        public bool Stopping
        {
            get
            {
                // The second check is after the exact retained lookup on this route.
                if (Interlocked.Increment(ref _checks) == 2)
                {
                    AtReplyCheck.TrySetResult();
                    if (!Release.Wait(TimeSpan.FromSeconds(30), Ct))
                    {
                        throw new TimeoutException("The retained reply checkpoint was not released.");
                    }
                }

                return false;
            }
        }

        public void Dispose() => Release.Dispose();
    }
}
