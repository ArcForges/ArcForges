// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Independent review: routed waits consume monotonic time from receipt, including verification and in-flight admission.</summary>
public sealed class RoutedReceiptBudgetReviewTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [InlineData(false, false, 0)]
    [InlineData(false, true, 8)]
    [InlineData(false, true, 12)]
    [InlineData(true, false, 0)]
    [InlineData(true, true, 8)]
    [InlineData(true, true, 12)]
    public async Task WaitAndReadChargeTimeBeforeDispatch(bool readOutput, bool delay, int elapsedSeconds)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var center = await FakeCenter.StartAsync();
        var clock = new AdvanceableClock();
        var hold = new HeldDispatcher();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        node.Clock = clock;
        node.WrapRoutedDispatcher = inner => new HeldDispatcherWrapper(inner, hold);
        center.Channel.Limits.MaxInFlightCalls = 1;
        await node.StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        // The issued credential includes the initial key; a later unknown call key triggers refresh.
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        var connection = await center.Channel.ProvedAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        var argv = new ArgvCommand();
        argv.Argv.Add([CloudNode.TestLoad, "hold", "--hold-ms", "45000"]);
        var submitted = await human.Tasks.SubmitTaskAsync(new TaskServiceSubmitTaskRequest
        {
            Meta = CloudNode.Command(),
            Spec = new TaskSpec { Command = new CommandSpec { Argv = argv }, WorkingDirectory = node.Root, Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node } },
        }, cancellationToken: Ct);
        Assert.Null(submitted.Error);
        await using var taskCleanup = new TaskCleanup(human, submitted.Value.TaskId);
        await AllowRemoteOutputAsync(human);
        var started = await human.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest
        {
            Meta = CloudNode.Command(),
            TaskId = submitted.Value.TaskId,
            Target = WaitTarget.Started,
            WaitMs = 20_000,
        }, cancellationToken: Ct);
        Assert.Null(started.Error);
        Assert.True(started.Value.Reached);
        Assert.Equal(TaskState.Running, started.Value.Task.State);

        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
            LocalOrigin = Origin.Script,
            LocalSessionId = CommandIds.New(),
        };
        var method = readOutput ? RoutedMethod.ReadNodeTaskOutput : RoutedMethod.WaitNodeTask;
        IMessage request = readOutput
            ? new TaskServiceReadTaskOutputRequest { Meta = CloudNode.Command(), AttemptId = started.Value.Task.CurrentAttempt.AttemptId, FromOffset = 1_000_000, WaitMs = 4_000 }
            : new TaskServiceWaitTaskRequest { Meta = CloudNode.Command(), TaskId = submitted.Value.TaskId, Target = WaitTarget.Terminal, WaitMs = 4_000 };

        // One real channel call occupies the sole in-flight slot. The next frame must be received before the monotonic jump.
        var (first, _) = center.Channel.BuildCall(connection, new FakeCallSpec { Method = RoutedMethod.GetNodeTask, Caller = caller });
        hold.Arm(first.CallId);
        await connection.SendCallAsync(first);
        await hold.Entered.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
        try
        {
            var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec { Method = method, Payload = request.ToByteArray(), Caller = caller });
            clock.ObserveNextFrame();
            await connection.SendCallAsync(call);
            await clock.FrameReceived.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            if (delay)
            {
                clock.Advance(TimeSpan.FromSeconds(elapsedSeconds));
            }

            hold.Release.TrySetResult();
            var result = connection.ResultOfAsync(call.CallId);
            var early = await Task.WhenAny(result, Task.Delay(delay ? TimeSpan.FromSeconds(2) : TimeSpan.FromMilliseconds(500), Ct)) == result;
            var received = await result.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(verified => verified.Header.CallId.Equals(call.CallId)), "the routed result is signed and verified");
            var header = connection.VerifiedResults.Single(verified => verified.Header.CallId.Equals(call.CallId)).Header;
            Assert.True(header.Outcome == RoutedOutcome.Executed, $"unexpected routed outcome {header.Outcome}: {header.Error?.Code}/{header.Error?.Details?.State?.Reason}");
            if (readOutput)
            {
                Assert.Null(TaskServiceReadTaskOutputResponse.Parser.ParseFrom(received.Payload).Error);
            }
            else
            {
                var waited = TaskServiceWaitTaskResponse.Parser.ParseFrom(received.Payload);
                Assert.Null(waited.Error);
                Assert.False(waited.Value.Reached);
            }

            Assert.Equal(delay, early);
        }
        finally
        {
            hold.Release.TrySetResult();
        }
    }

    [Theory(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WaitAndReadChargeAnUnknownKeyRefresh(bool readOutput)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var center = await FakeCenter.StartAsync();
        var clock = new AdvanceableClock();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        node.Clock = clock;
        await node.StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        // The issued credential includes the initial key; a later unknown call key triggers refresh.
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        var connection = await center.Channel.ProvedAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        var argv = new ArgvCommand();
        argv.Argv.Add([CloudNode.TestLoad, "hold", "--hold-ms", "45000"]);
        var submitted = await human.Tasks.SubmitTaskAsync(new TaskServiceSubmitTaskRequest
        {
            Meta = CloudNode.Command(),
            Spec = new TaskSpec { Command = new CommandSpec { Argv = argv }, WorkingDirectory = node.Root, Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node } },
        }, cancellationToken: Ct);
        Assert.Null(submitted.Error);
        await using var taskCleanup = new TaskCleanup(human, submitted.Value.TaskId);
        await AllowRemoteOutputAsync(human);
        var started = await human.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest
        {
            Meta = CloudNode.Command(),
            TaskId = submitted.Value.TaskId,
            Target = WaitTarget.Started,
            WaitMs = 20_000,
        }, cancellationToken: Ct);
        Assert.Null(started.Error);
        Assert.True(started.Value.Reached);
        Assert.Equal(TaskState.Running, started.Value.Task.State);
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
            LocalOrigin = Origin.Script,
            LocalSessionId = CommandIds.New(),
        };
        IMessage request = readOutput
            ? new TaskServiceReadTaskOutputRequest { Meta = CloudNode.Command(), AttemptId = started.Value.Task.CurrentAttempt.AttemptId, FromOffset = 1_000_000, WaitMs = 4_000 }
            : new TaskServiceWaitTaskRequest { Meta = CloudNode.Command(), TaskId = submitted.Value.TaskId, Target = WaitTarget.Terminal, WaitMs = 4_000 };
        var rotated = center.Channel.CommandPublicKey;
        rotated.Kid = "cmd-review-refresh";
        center.CommandKeys.Add(rotated);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        center.Script("RefreshNodeSession", new FakeFault.Hold(release));
        try
        {
            var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = readOutput ? RoutedMethod.ReadNodeTaskOutput : RoutedMethod.WaitNodeTask,
                Payload = request.ToByteArray(),
                Caller = caller,
                FrameKid = rotated.Kid,
                HeaderKid = rotated.Kid,
            });
            await connection.SendCallAsync(call);
            await Eventually.TrueAsync(() => center.CallsOf("RefreshNodeSession").Count == 1, "call is held during unknown-key refresh");
            clock.Advance(TimeSpan.FromSeconds(12));
            release.TrySetResult();
            var result = connection.ResultOfAsync(call.CallId);
            var early = await Task.WhenAny(result, Task.Delay(TimeSpan.FromSeconds(2), Ct)) == result;
            var received = await result.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(verified => verified.Header.CallId.Equals(call.CallId)), "the routed result is signed and verified");
            var header = connection.VerifiedResults.Single(verified => verified.Header.CallId.Equals(call.CallId)).Header;
            Assert.True(header.Outcome == RoutedOutcome.Executed, $"unexpected routed outcome {header.Outcome}: {header.Error?.Code}/{header.Error?.Details?.State?.Reason}");
            Assert.Null(readOutput
                ? TaskServiceReadTaskOutputResponse.Parser.ParseFrom(received.Payload).Error
                : TaskServiceWaitTaskResponse.Parser.ParseFrom(received.Payload).Error);
            Assert.True(early, "verification time must be charged before the handler starts its wait");
        }
        finally
        {
            release.TrySetResult();
        }
    }

    private static async Task AllowRemoteOutputAsync(NodeChannel human)
    {
        var current = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = CloudNode.Command() }, cancellationToken: Ct);
        Assert.Null(current.Error);
        var document = current.Value.Document.Clone();
        (document.Privacy ??= new PrivacyPolicy()).RemoteOutputTail = true;
        var meta = CloudNode.Command();
        meta.ExpectedRev = current.Value.Revision.Revision;
        var changed = await human.Policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = meta, Document = document }, cancellationToken: Ct);
        Assert.Null(changed.Error);
    }

    private sealed class TaskCleanup(NodeChannel human, Id task) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            var cancel = await human.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = CloudNode.Command(), TaskId = task },
                deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: CancellationToken.None);
            Assert.Null(cancel.Error);
            var ended = await human.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest
            {
                Meta = CloudNode.Command(),
                TaskId = task,
                Target = WaitTarget.Terminal,
                WaitMs = 20_000,
            }, deadline: DateTime.UtcNow.AddSeconds(30), cancellationToken: CancellationToken.None);
            Assert.Null(ended.Error);
            Assert.True(ended.Value.Reached);
        }
    }

    private sealed class HeldDispatcher
    {
        private Id? _call;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Arm(Id id) => _call = id;
        public bool Matches(VerifiedCall call) => _call is not null && _call.Equals(call.Header.CallId);
    }

    private sealed class HeldDispatcherWrapper(IRoutedDispatcher inner, HeldDispatcher held) : IRoutedDispatcher
    {
        public async Task<RoutedAnswer?> DispatchAsync(VerifiedCall call, IRoutedLink link, CancellationToken cancellationToken)
        {
            if (held.Matches(call))
            {
                held.Entered.TrySetResult();
                await held.Release.Task.WaitAsync(cancellationToken);
            }

            return await inner.DispatchAsync(call, link, cancellationToken);
        }
    }

    private sealed class AdvanceableClock : TimeProvider
    {
        private long _offset;
        private int _observe;
        public TaskCompletionSource FrameReceived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override long TimestampFrequency => TimeProvider.System.TimestampFrequency;
        public override DateTimeOffset GetUtcNow() => TimeProvider.System.GetUtcNow();

        public override long GetTimestamp()
        {
            var timestamp = TimeProvider.System.GetTimestamp() + Interlocked.Read(ref _offset);
            if (Volatile.Read(ref _observe) != 0 && new StackTrace().GetFrames().Any(frame =>
                frame.GetMethod()?.DeclaringType?.FullName?.Contains("ChannelLoop+<ServeAsync>", StringComparison.Ordinal) == true))
            {
                Interlocked.Exchange(ref _observe, 0);
                FrameReceived.TrySetResult();
            }

            return timestamp;
        }

        public void ObserveNextFrame() => Volatile.Write(ref _observe, 1);
        public void Advance(TimeSpan by) => Interlocked.Add(ref _offset, checked((long)(by.TotalSeconds * TimestampFrequency)));
    }
}
