// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Retired Submit admission and retained replay through real handlers and an offline SQLite fixture.</summary>
[Trait("feature", "workspace-submit-safety")]
public sealed class WorkspaceSubmitSafetyTests
{
    [Fact(Timeout = 30_000)]
    public Task RetainedSubmitReplaysWhileAnUnrelatedWriteIsUncommitted() =>
        WithOfflineHandlersAsync(async (node, handler) =>
        {
            var ct = TestContext.Current.CancellationToken;
            var request = SubmitRequest();
            var caller = new Caller(Origin.Human, ClientKind.Cli, null);
            var original = node.Store.Write(transaction =>
            {
                var task = LegacyTaskHistoryFixture.SeedQueued(transaction, caller.Actor);
                var response = new TaskServiceSubmitTaskResponse
                {
                    Meta = new() { CorrelationId = request.Meta.CorrelationId },
                    Value = new()
                    {
                        TaskId = task, State = TaskState.Queued,
                        Receipt = new() { CommandId = request.Meta.CommandId, Effect = EffectCertainty.Happened },
                    },
                };
                Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, request.Meta.CommandId.Value.Span,
                    "arcforges.node.v1.TaskService/SubmitTask", PayloadDigest.Compute(request), Origin.Human).Status);
                CommandDeduplication.Complete(transaction, request.Meta.CommandId.Value.Span, response.ToByteArray());
                return response;
            }, CommitDurability.Full);

            using var release = new ManualResetEventSlim();
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var writer = Task.Run(() => node.Store.Write(transaction =>
            {
                var rows = transaction.Execute("""
                    INSERT INTO node_setting (name, value_json, updated_at, rev)
                    VALUES ('retained-submit-probe', 'true', $now, 0);
                    """, ("$now", transaction.NowMicroseconds));
                entered.SetResult();
                Assert.True(release.Wait(TimeSpan.FromSeconds(10), ct));
                return rows;
            }, CommitDurability.Full), ct);

            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(8), ct);
                Assert.Equal(original, await Task.Run(() => handler.SubmitTask(caller, request, ct), ct)
                    .WaitAsync(TimeSpan.FromSeconds(8), ct));
            }
            finally
            {
                release.Set();
                Assert.Equal(1, await writer);
            }

            var fresh = SubmitRequest();
            AssertRetired((await handler.SubmitTask(caller, fresh, ct)).Error);
            AssertNoNewSubmitState(node.Store, retained: 1);
        });

    [Theory(Timeout = 30_000)]
    [InlineData(false)]
    [InlineData(true)]
    public Task FreshRoutedSubmitPreservesExpiryAndLinkRefusalWithoutCreatingTaskOrReceipt(bool expire) =>
        WithOfflineHandlersAsync(async (node, handler) =>
        {
            var ct = TestContext.Current.CancellationToken;
            using var dispatcher = new RoutedDispatcher(node);
            dispatcher.Bind(handler, new WorkspaceServiceHandler(node), new FileServiceHandler(node));
            var link = new RoutedCalls.TestLink();
            if (!expire)
            {
                link.Reset(usableFor: 0);
            }

            var now = node.Clock.GetUtcNow();
            var refused = await dispatcher.DispatchAsync(VerifiedSubmit(node, SubmitRequest(), expire ? now.AddMinutes(-4) : now), link, ct);
            if (expire)
            {
                Assert.NotNull(refused);
                Assert.Equal(RoutedOutcome.Expired, refused.Outcome);
                Assert.Equal("expired", refused.Error?.Code);
                Assert.Equal(EffectCertainty.DidNotHappen, refused.Error?.Effect);
            }
            else
            {
                Assert.Null(refused);
            }

            AssertNoNewSubmitState(node.Store, retained: 0);
            link.Reset();
            var usable = await dispatcher.DispatchAsync(VerifiedSubmit(node, SubmitRequest(), now), link, ct);
            Assert.NotNull(usable);
            Assert.Equal(RoutedOutcome.Executed, usable.Outcome);
            var response = TaskServiceSubmitTaskResponse.Parser.ParseFrom(Assert.IsType<ByteString>(usable.Response));
            AssertRetired(response.Error);
            AssertNoNewSubmitState(node.Store, retained: 0);
        });

    private static TaskServiceSubmitTaskRequest SubmitRequest()
    {
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "fixture-never-starts" } } },
            Environment = new EnvironmentSpec { Set = { ["VISIBLE_NAME"] = "test value" } },
        };
        return new() { Meta = Tasks.Meta(), Spec = spec };
    }

    private static VerifiedCall VerifiedSubmit(NodeRuntime node, TaskServiceSubmitTaskRequest request, DateTimeOffset when) =>
        new(new CallHeader
        {
            CallId = CommandIds.New(),
            Caller = RoutedCalls.Session(),
            CommandId = request.Meta.CommandId,
            Method = RoutedMethod.SubmitNodeTask,
            IssuedAt = ProtoTime.ToInstant(when.AddSeconds(-1)),
            ExpiresAt = ProtoTime.ToInstant(when.AddSeconds(60)),
            Deadline = ProtoTime.ToInstant(when.AddSeconds(10)),
            TargetNodeId = new Id { Value = ByteString.CopyFrom(node.NodeId.Span) },
            AccountId = RoutedCalls.Account.Clone(),
        }, request.ToByteString(), LogId: 0);

    private static async Task WithOfflineHandlersAsync(Func<NodeRuntime, TaskServiceHandler, Task> exercise)
    {
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "workspace-submit-fixture" });
        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, fixture.Clock);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(fixture.ConfigPath, fixture.DataRoot, log), fixture.DataRoot, "offline-fixture", fixture.Clock,
            new RecoveryReport(false, false, null, store.Opening), new CapabilityReport());
        var handler = new TaskServiceHandler(runtime, new ClientSessions(), new ApprovalExecutors());
        await exercise(runtime, handler);
    }

    private static void AssertRetired(ArcError error)
    {
        Assert.Equal("operation_failed", error.Code);
        Assert.Equal("legacy_task_outcome_unavailable", error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
    }

    private static void AssertNoNewSubmitState(NodeStore store, long retained)
    {
        Assert.Equal(retained, store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        Assert.Equal(retained, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM env_snapshot;")));
    }
}
