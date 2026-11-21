// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.Tests;

namespace ArcForges.Node.Core.Tests;

/// <summary>Controls on retained legacy Tasks after fresh Task admission was removed.</summary>
public sealed partial class LaunchFaultTests
{
    // The fresh Task launch and late-start process races remain executable at Windows historical anchor
    // eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a using this project's LaunchFaultTests on the original test profile.
    // The current V2 Run recovery cases are in RecoveryPreparedMxcRunServiceTests, RecoveryNativeDispatchMxcRunServiceTests
    // and RecoveryMxcRunServiceTests. Retained platform re-open checks still have their own JobTests and UnitPlatformTests.

    [Fact(Timeout = 30_000)]
    public async Task ConcurrentCancelsSettleAndReplayEveryRetainedQueuedTaskWithoutStartingAnAttempt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions
        {
            DataRoot = fixture.DataRoot,
            BootIdentity = BootIdentity.Read(),
            Clock = fixture.Clock,
        });
        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, fixture.Clock);
        using var heartbeat = new NodeHeartbeatWriter(fixture.DataRoot, log, fixture.Clock);
        using var keys = new NodeDataKeyRing(store, fixture.Secrets.Selection);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        var recovery = new RecoveryReport(false, false, null, store.Opening);
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = fixture.Clock,
            DataRoot = fixture.DataRoot,
            Secrets = new TaskSecrets(store, keys),
            Heartbeat = heartbeat,
        });
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(fixture.ConfigPath, fixture.DataRoot, log), fixture.DataRoot, "offline-fixture", fixture.Clock,
            recovery, new CapabilityReport())
        {
            Execution = execution,
        };

        const int count = 24;
        var owner = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
        var taskIds = store.Write(transaction => Enumerable.Range(0, count)
            .Select(_ => LegacyTaskHistoryFixture.SeedQueued(transaction, owner)).ToArray(), CommitDurability.Full);
        await runtime.TransitionAsync(NodeLifecycleState.Recovering, "fixture").WaitAsync(ct);
        await execution.RecoverAsync(recovery, processor, ct);
        await runtime.TransitionAsync(NodeLifecycleState.Ready, "fixture").WaitAsync(ct);

        var handler = new TaskServiceHandler(runtime, new ClientSessions());
        var human = new Caller(Origin.Human, ClientKind.Cli, null);
        var requests = taskIds.Select(id => new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "migration" }).ToArray();
        Assert.Equal((long)count, store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE state=$state;",
            ("$state", (int)TaskState.Queued))));
        var original = await Task.WhenAll(requests.Select(request => handler.CancelTask(human, request, ct)));
        var replay = await Task.WhenAll(requests.Select(request => handler.CancelTask(human, request, ct)));
        for (var index = 0; index < requests.Length; index++)
        {
            Assert.Null(original[index].Error);
            Assert.Equal(TaskState.Cancelled, original[index].Value.State);
            Assert.Equal(requests[index].Meta.CommandId, original[index].Value.Receipt.CommandId);
            Assert.Equal(EffectCertainty.Happened, original[index].Value.Receipt.Effect);
            Assert.Null(replay[index].Error);
            Assert.Equal(original[index].Value, replay[index].Value);
        }

        Assert.Equal((long)count, store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE state=$state;",
            ("$state", (int)TaskState.Cancelled))));
        Assert.Empty(execution.RunningAttempts);
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
    }
}
