// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using OutputIndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.Node.Core.Tests;

/// <summary>Independent review: Wait keeps its task result while denying an unauthorized optional output tail.</summary>
public sealed class RoutedWaitTailReviewTests
{
    private static readonly TimeSpan SignedWaitLifetime = TimeSpan.FromSeconds(30);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory(Timeout = 30_000)]
    [InlineData(Origin.Unspecified, true, Origin.Remote)]
    [InlineData(Origin.Script, true, Origin.Script)]
    [InlineData(Origin.Agent, true, Origin.Agent)]
    [InlineData(Origin.Unspecified, false, Origin.Remote)]
    [InlineData(Origin.Script, false, Origin.Script)]
    [InlineData(Origin.Agent, false, Origin.Agent)]
    public async Task WaitOmitsTailWhenTheOutputPermissionIsNarrowed(Origin relayOrigin, bool own, Origin deniedOrigin)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var files = InProcessNode.Create();
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(files, AttemptState.Finished);
        var output = SeedOutput(files, attemptId);
        await WithFixtureAsync(files, async fixture =>
        {
            var caller = fixture.Caller(relayOrigin);
            if (own)
            {
                var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller };
                fixture.Store.Write(transaction => transaction.Execute("UPDATE task SET owner = $owner, owner_origin = $origin WHERE task_id = $id;",
                    ("$owner", actor.ToByteArray()), ("$origin", (int)actor.Origin), ("$id", taskId.Value.ToByteArray())), CommitDurability.Full);
            }

            async Task<TaskServiceWaitTaskValue> Wait(uint bytes, CenterCaller? requester = null)
            {
                var request = Request(taskId, bytes);
                var response = ReadResponse(await fixture.WaitAsync(requester ?? caller, request));
                Assert.Equal(request.Meta.CorrelationId, response.Meta.CorrelationId);
                Assert.Null(response.Error);
                var value = response.Value;
                Assert.True(value.Reached);
                Assert.Equal(taskId, value.Task.TaskId);
                Assert.Equal(TaskState.Succeeded, value.Task.State);
                Assert.Equal(attemptId, value.Task.CurrentAttempt.AttemptId);
                Assert.Equal(AttemptState.Finished, value.Task.CurrentAttempt.State);
                return value;
            }

            if (!own)
            {
                AssertNoTail(await Wait(20));
                fixture.ChangePolicy(policy => (policy.Privacy ??= new PrivacyPolicy()).RemoteOutputTail = true);
            }
            else if (relayOrigin == Origin.Unspecified)
            {
                // Replay ownership by user does not transfer output ownership to a different session.
                AssertNoTail(await Wait(20, RoutedCalls.Session()));
            }

            var allowed = await Wait(20);
            Assert.True(allowed.HasTail);
            Assert.Equal(output[^20..], allowed.Tail.ToByteArray());
            Assert.True(allowed.HasTailTruncated);
            Assert.True(allowed.TailTruncated);
            var full = await Wait(65_536);
            Assert.True(full.HasTail);
            Assert.Equal(output, full.Tail.ToByteArray());
            Assert.True(full.HasTailTruncated);
            Assert.False(full.TailTruncated);
            AssertNoTail(await Wait(0));

            fixture.ChangePolicy(policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.TaskReadOutput,
                Origin = deniedOrigin,
                Decision = PermissionDecision.Deny,
            }));
            AssertNoTail(await Wait(20));
            AssertNoTail(await Wait(0));
            Assert.Equal(1L, fixture.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
            Assert.Equal(1L, fixture.Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
            Assert.Equal(0L, fixture.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        });
    }

    [Fact(Timeout = 15_000)]
    public async Task WaitObservesTheReceivedDeadlineAndRefusesOversizedRequestsWithoutAnEffect()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var files = InProcessNode.Create();
        await WithFixtureAsync(files, async fixture =>
        {
            var taskId = fixture.Store.Write(transaction => LegacyTaskHistoryFixture.SeedQueued(transaction, new ActorRef { Origin = Origin.Human }),
                CommitDurability.Full);
            var caller = fixture.Caller(Origin.Unspecified);
            var request = Request(taskId, 20);
            request.WaitMs = 55_000;
            // The call remains valid, but its wait budget elapsed before dispatch. Ignoring receipt age would wait beyond the test timeout.
            var reply = ReadResponse(await fixture.WaitAsync(caller, request, age: SignedWaitLifetime + TimeSpan.FromSeconds(5)));
            Assert.Null(reply.Error);
            Assert.Equal(request.Meta.CorrelationId, reply.Meta.CorrelationId);
            Assert.Equal(taskId, reply.Value.Task.TaskId);
            Assert.Equal(TaskState.Queued, reply.Value.Task.State);
            Assert.False(reply.Value.Reached);
            AssertNoTail(reply.Value);

            var expired = await fixture.WaitAsync(caller, request, expired: true);
            Assert.Equal(RoutedOutcome.Expired, expired.Outcome);
            Assert.Null(expired.Response);
            Assert.Equal(EffectCertainty.DidNotHappen, expired.Error?.Effect);
            Assert.Equal("expired_before_effect", expired.Error?.Details.State.Reason);

            var tooLong = request.Clone();
            tooLong.WaitMs++;
            Assert.Equal("invalid_argument", ReadResponse(await fixture.WaitAsync(caller, tooLong)).Error?.Code);
            var tooWide = request.Clone();
            tooWide.TailBytes = 65_537;
            Assert.Equal("invalid_argument", ReadResponse(await fixture.WaitAsync(caller, tooWide)).Error?.Code);
            Assert.Equal(1L, fixture.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
            Assert.Equal(0L, fixture.Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
            Assert.Equal(0L, fixture.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        });
    }

    private static TaskServiceWaitTaskRequest Request(Id taskId, uint bytes) => new()
    {
        Meta = new RequestMeta { CorrelationId = CommandIds.New() },
        TaskId = taskId,
        TailBytes = bytes,
    };

    private static void AssertNoTail(TaskServiceWaitTaskValue value)
    {
        Assert.False(value.HasTail);
        Assert.False(value.HasTailTruncated);
    }

    private static TaskServiceWaitTaskResponse ReadResponse(RoutedAnswer answer)
    {
        Assert.Equal(RoutedOutcome.Executed, answer.Outcome);
        Assert.Null(answer.Error);
        return TaskServiceWaitTaskResponse.Parser.ParseFrom(Assert.IsType<ByteString>(answer.Response));
    }

    private static byte[] SeedOutput(InProcessNode node, Id attemptId)
    {
        var files = Tasks.Files(node, attemptId);
        var data = Enumerable.Range(0, 512).Select(index => (byte)(index % 251)).ToArray();
        Directory.CreateDirectory(files.Directory);
        File.WriteAllBytes(files.StdoutPath, data);
        var index = new byte[OutputIndexRecord.Size];
        new OutputIndexRecord(OutputStreamKind.Stdout, 0, (uint)data.Length, 1_700_000_000_000_000_000, OutputChunkMarks.None).Write(index);
        File.WriteAllBytes(files.IndexPath, index);
        return data;
    }

    private static async Task WithFixtureAsync(InProcessNode files, Func<WaitFixture, Task> verify)
    {
        var clock = files.Clock;
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = files.DataRoot, BootIdentity = "wait-tail-fixture", Clock = clock });
        using var log = new NodeLog(Path.Combine(files.DataRoot, "logs", "node"), LogLevel.Info, clock);
        using var heartbeat = new NodeHeartbeatWriter(files.DataRoot, log, clock);
        using var keys = new NodeDataKeyRing(store, files.Secrets.Selection);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        // Wait reads the existing supervisor's task pulse and bookkeeping. No platform is supplied and no execution loop is started.
        await using var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = clock,
            DataRoot = files.DataRoot,
            Secrets = new TaskSecrets(store, keys),
            Heartbeat = heartbeat,
        });
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(files.ConfigPath, files.DataRoot, log), files.DataRoot, "offline-fixture", clock,
            new RecoveryReport(false, false, null, store.Opening), new CapabilityReport())
        { Execution = execution };
        using var dispatcher = new RoutedDispatcher(runtime);
        dispatcher.Bind(new TaskServiceHandler(runtime, new ClientSessions()), new WorkspaceServiceHandler(runtime), new FileServiceHandler(runtime));
        await verify(new WaitFixture(store, runtime, dispatcher));
        Assert.Null(execution.Platform);
        Assert.Empty(execution.RunningAttempts);
    }

    private sealed record WaitFixture(NodeStore Store, NodeRuntime Runtime, RoutedDispatcher Dispatcher)
    {
        private Id NodeId => new() { Value = ByteString.CopyFrom(Runtime.NodeId.Span) };

        public CenterCaller Caller(Origin origin) => origin == Origin.Unspecified ? RoutedCalls.Session() : new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = RoutedCalls.Account.Clone(),
            RelayingNodeId = NodeId,
            LocalOrigin = origin,
            LocalSessionId = CommandIds.New(),
        };

        public void ChangePolicy(Action<PolicyDocument> change) => Store.Write(transaction =>
        {
            var document = PolicyRules.Current(transaction).Document;
            change(document);
            PolicyRules.Write(transaction, document, new ActorRef { Origin = Origin.Human }, "historical wait fixture policy");
        }, CommitDurability.Full);

        public async Task<RoutedAnswer> WaitAsync(CenterCaller caller, TaskServiceWaitTaskRequest request, TimeSpan? age = null, bool expired = false)
        {
            var raw = request.ToByteString();
            var clock = Runtime.Clock;
            var received = clock.GetTimestamp();
            if (age is { } elapsed)
            {
                received -= (long)(elapsed.TotalSeconds * clock.TimestampFrequency);
            }

            var now = clock.GetUtcNow();
            var issued = expired ? now - CallVerifier.Skew - TimeSpan.FromMinutes(2) : now - (age ?? TimeSpan.Zero) - TimeSpan.FromSeconds(1);
            var header = new CallHeader
            {
                CallId = CommandIds.New(),
                Kid = "wait-tail-fixture",
                AccountId = caller.AccountId.Clone(),
                TargetNodeId = NodeId,
                Caller = caller.Clone(),
                Method = RoutedMethod.WaitNodeTask,
                RequestSha256 = ByteString.CopyFrom(SHA256.HashData(raw.Span)),
                RequestSize = (uint)raw.Length,
                IssuedAt = ProtoTime.ToInstant(issued),
                ExpiresAt = ProtoTime.ToInstant(issued.AddMinutes(1)),
                Deadline = ProtoTime.ToInstant(issued + SignedWaitLifetime),
            };
            return Assert.IsType<RoutedAnswer>(await Dispatcher.DispatchAsync(new VerifiedCall(header, raw, 0, received), new RoutedCalls.TestLink(), Ct));
        }
    }
}
