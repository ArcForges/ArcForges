// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// AF-CTR-05 part N2a (CTR5-NODE-08, the refactor half; plan G.2 N2-15): the TaskService operations take a <see cref="Caller"/>, and each gRPC
/// method is a thin wrapper that builds it from the connection exactly as before. Pinned here: the mapping from a connection's session to its
/// caller (origin, client kind, the session itself; SCRIPT without a kind or session for a connection that sent no hello), the fields each
/// wrapper's operation reads on real nodes through the real client (the retained task owner and receipt, <c>command_dedup.origin</c> of
/// current idempotent mutations, and the audited actor of a purge), and the center-caller slot that a
/// local connection's caller can never carry. <c>ArcForges.Repository.Tests</c> (<c>TaskServiceCallerPolicyTests</c>) pins that every unary
/// wrapper builds its caller with <c>CallerOf(context)</c> and nothing else in the service reads the connection's session.
/// </summary>
public sealed class CallerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>The sessions a hello can open: each kind with the origins the node can assign it.</summary>
    public static TheoryData<ClientKind, Origin> Sessions => new()
    {
        { ClientKind.Cli, Origin.Human },
        { ClientKind.Cli, Origin.Script },
        { ClientKind.Cli, Origin.Agent },
        { ClientKind.Desktop, Origin.Human },
        { ClientKind.Desktop, Origin.Script },
        { ClientKind.McpAdapter, Origin.Agent },
        { ClientKind.Hook, Origin.Agent },
        { ClientKind.Supervisor, Origin.Script },
    };

    [Theory]
    [MemberData(nameof(Sessions))]
    public void AConnectionsCallerHasItsSessionsOriginKindAndSession(ClientKind kind, Origin origin)
    {
        var session = new ClientSession(Peer(), kind, origin);
        var caller = Caller.OfConnection(session);
        Assert.Equal(origin, caller.Origin);
        Assert.Equal(kind, caller.Kind);
        Assert.Same(session, caller.Session);
        Assert.Null(caller.CenterCaller);
        Assert.Null(caller.ApprovalId);
        Assert.False(caller.Approved);
        Assert.Equal(new ActorRef { Origin = origin, ClientKind = kind }, caller.Actor);
    }

    [Fact]
    public void AConnectionWithoutAHelloIsAScriptCallerWithoutAKindOrSession()
    {
        var caller = Caller.OfConnection(null);
        Assert.Equal(Origin.Script, caller.Origin);
        Assert.Equal(ClientKind.Unspecified, caller.Kind);
        Assert.Null(caller.Session);
        Assert.Null(caller.CenterCaller);
        Assert.False(caller.Approved);
        Assert.Equal(new ActorRef { Origin = Origin.Script, ClientKind = ClientKind.Unspecified }, caller.Actor);

        // An approval's requester executes without a session and without a center caller, as before.
        var approved = Caller.OfApproval(new ActorRef { Origin = Origin.Agent, ClientKind = ClientKind.McpAdapter }, [1, 2, 3]);
        Assert.Equal((Origin.Agent, ClientKind.McpAdapter), (approved.Origin, approved.Kind));
        Assert.Null(approved.Session);
        Assert.Null(approved.CenterCaller);
        Assert.True(approved.Approved);
    }

    [Fact]
    public void ACenterCallerCannotBeBuiltFromALocalConnection()
    {
        var center = new CenterCaller { Kind = CenterCallerKind.AccountSession, AccountId = CommandIds.New(), UserId = CommandIds.New(), SessionId = CommandIds.New() };
        var session = new ClientSession(Peer(), ClientKind.Cli, Origin.Human);

        // The slot exists for the routed path of part N2b: origin REMOTE, no kind, no local session.
        var routed = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: center);
        Assert.Same(center, routed.CenterCaller);
        Assert.Null(routed.Session);

        // A local connection's caller never carries one: not built with its session, not copied onto it, not with a local origin.
        Assert.Throws<ArgumentException>(() => new Caller(Origin.Human, ClientKind.Cli, session, centerCaller: center));
        Assert.Throws<ArgumentException>(() => new Caller(Origin.Remote, ClientKind.Unspecified, session, centerCaller: center));
        Assert.Throws<ArgumentException>(() => Caller.OfConnection(session) with { CenterCaller = center });
        Assert.Throws<ArgumentException>(() => Caller.OfConnection(null) with { CenterCaller = center });
        foreach (var origin in (Origin[])[Origin.Human, Origin.Script, Origin.Agent, Origin.Unspecified])
        {
            Assert.Throws<ArgumentException>(() => new Caller(origin, ClientKind.Cli, null, centerCaller: center));
        }

        // Nor does a routed caller take a local session or a local origin afterwards; the refusal names the assignment that failed (N2a N-4).
        Assert.Equal(nameof(Caller.Session), Assert.Throws<ArgumentException>(() => routed with { Session = session }).ParamName);
        Assert.Equal(nameof(Caller.Origin), Assert.Throws<ArgumentException>(() => routed with { Origin = Origin.Human }).ParamName);
        Assert.Equal(nameof(Caller.CenterCaller), Assert.Throws<ArgumentException>(() => Caller.OfConnection(session) with { CenterCaller = center }).ParamName);

        // A routed caller's actor names its center caller and its command ID (CTR5-NODE-10).
        var command = CommandIds.New();
        Assert.Equal(new ActorRef { Origin = Origin.Remote, ClientKind = ClientKind.Unspecified, CenterCaller = center, RemoteCommandId = command },
            (routed with { RemoteCommandId = command }).Actor);
    }

    /// <summary>
    /// Each wrapper's operation sees the caller of its connection: four connections (an interactive CLI: HUMAN; a CLI without a terminal:
    /// SCRIPT; the MCP adapter: AGENT; a connection that sent no hello: SCRIPT without a kind or session) reconcile historical Submit and
    /// Retry. Cancel, reprioritize, pause, resume and pin retain the actual dedup origin; purge retains the actual audited actor.
    /// Fresh Submit's caller-gone binding and owner assignment checks remain in eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task EachWrapperGivesItsOperationTheCallerOfItsConnection()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        await using var agent = await node.ChannelAsync(kind: ClientKind.McpAdapter);
        await using var bare = NodeChannel.Create(node.Endpoint);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);

        Origin DedupOrigin(RequestMeta meta) => (Origin)Convert.ToInt32(node.Runtime.Store.Read(reader =>
            reader.Scalar("SELECT origin FROM command_dedup WHERE command_id = $id;", ("$id", meta.CommandId.Value.ToByteArray()))), CultureInfo.InvariantCulture);

        var store = node.Runtime.Store;
        foreach (var (channel, origin, kind) in (ValueTuple<NodeChannel, Origin, ClientKind>[])
            [(human, Origin.Human, ClientKind.Cli), (script, Origin.Script, ClientKind.Cli), (agent, Origin.Agent, ClientKind.McpAdapter),
             (bare, Origin.Script, ClientKind.Unspecified)])
        {
            var label = $"{origin}/{kind}";
            var owner = new ActorRef { Origin = origin, ClientKind = kind };
            var submit = new TaskServiceSubmitTaskRequest
            {
                Meta = Tasks.Meta(),
                Spec = Tasks.Argv(node.Root, "fixture-never-starts"),
                CancelWhenCallerGone = true,
            };
            var submitted = await channel.Tasks.SubmitTaskAsync(submit, cancellationToken: Ct);
            if (origin == Origin.Agent)
            {
                Assert.Equal(("permission_denied", "task.submit", "local_submission_human_only"),
                    (submitted.Error?.Code, submitted.Error?.Details.State.State, submitted.Error?.Details.State.Reason));
            }
            else
            {
                Assert.Equal("operation_failed", submitted.Error.Code);
                Assert.Equal("legacy_task_outcome_unavailable", submitted.Error.Details.State.Reason);
                Assert.Equal(EffectCertainty.Unknown, submitted.Error.Effect);
                var previous = submit.Clone();
                previous.Meta = Tasks.Meta();
                var original = store.Write(transaction =>
                {
                    var taskId = LegacyTaskHistoryFixture.SeedQueued(transaction, owner);
                    transaction.Execute("UPDATE task SET local_diagnostic = 1 WHERE task_id = $id;", ("$id", taskId.Value.ToByteArray()));
                    var response = new TaskServiceSubmitTaskResponse
                    {
                        Meta = new ResponseMeta { CorrelationId = previous.Meta.CorrelationId },
                        Value = new TaskServiceSubmitTaskValue
                        {
                            TaskId = taskId, State = TaskState.Queued,
                            Receipt = new Receipt { CommandId = previous.Meta.CommandId, Effect = EffectCertainty.Happened },
                        },
                    };
                    RecordPrior(transaction, "SubmitTask", previous.Meta, previous, response, origin);
                    return response;
                }, CommitDurability.Full);
                Assert.Equal(original, await channel.Tasks.SubmitTaskAsync(previous, cancellationToken: Ct));
                var task = await Tasks.GetAsync(channel, original.Value.TaskId);
                Assert.Equal(owner, task.Owner);
                Assert.True(task.LocalDiagnostic, $"{label}: the retained task was a local diagnostic submission");
                Assert.Null(node.Runtime.Execution!.BindingOf(task.TaskId.Value.Span));
            }
            Assert.Null(store.Read(reader => reader.Scalar("SELECT 1 FROM command_dedup WHERE command_id = $id;",
                ("$id", submit.Meta.CommandId.Value.ToByteArray()))));

            // Retained Retry reproduces the old handler's error. A new ID is ambiguous and creates no receipt.
            var missing = CommandIds.New();
            var retry = new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = missing };
            var oldRetry = new TaskServiceRetryTaskResponse
            {
                Meta = new ResponseMeta { CorrelationId = retry.Meta.CorrelationId },
                Error = NodeErrors.NotFound("task", missing.Value.Span),
            };
            store.Write(transaction => RecordPrior(transaction, "RetryTask", retry.Meta, retry, oldRetry, origin), CommitDurability.Full);
            var replay = retry.Clone();
            replay.Meta.CorrelationId = CommandIds.New();
            var replayedRetry = await channel.Tasks.RetryTaskAsync(replay, cancellationToken: Ct);
            Assert.Equal(oldRetry.ToByteArray(), replayedRetry.ToByteArray());
            var freshRetry = retry.Clone();
            freshRetry.Meta = Tasks.Meta();
            var unknownRetry = await channel.Tasks.RetryTaskAsync(freshRetry, cancellationToken: Ct);
            Assert.Equal("legacy_task_outcome_unavailable", unknownRetry.Error.Details.State.Reason);
            Assert.Equal(EffectCertainty.Unknown, unknownRetry.Error.Effect);
            Assert.Null(store.Read(reader => reader.Scalar("SELECT 1 FROM command_dedup WHERE command_id = $id;",
                ("$id", freshRetry.Meta.CommandId.Value.ToByteArray()))));

            // The current idempotent mutations record the caller's origin with their command ID.
            var cancel = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = missing };
            Assert.Equal("not_found", (await channel.Tasks.CancelTaskAsync(cancel, cancellationToken: Ct)).Error?.Code);
            var priority = new TaskServiceSetTaskPriorityRequest { Meta = Tasks.Meta(), TaskId = missing, Priority = Priority.Low };
            Assert.NotNull((await channel.Tasks.SetTaskPriorityAsync(priority, cancellationToken: Ct)).Error);
            var pause = new TaskServicePauseTaskRequest { Meta = Tasks.Meta(), TaskId = missing };
            Assert.NotNull((await channel.Tasks.PauseTaskAsync(pause, cancellationToken: Ct)).Error);
            var resume = new TaskServiceResumeTaskRequest { Meta = Tasks.Meta(), TaskId = missing };
            Assert.NotNull((await channel.Tasks.ResumeTaskAsync(resume, cancellationToken: Ct)).Error);
            var pin = new TaskServicePinTaskRequest { Meta = Tasks.Meta(), TaskId = missing, Pinned = true };
            Assert.NotNull((await channel.Tasks.PinTaskAsync(pin, cancellationToken: Ct)).Error);
            foreach (var (method, meta) in (ValueTuple<string, RequestMeta>[])
                [("CancelTask", cancel.Meta), ("SetTaskPriority", priority.Meta), ("PauseTask", pause.Meta), ("ResumeTask", resume.Meta),
                 ("PinTask", pin.Meta)])
            {
                Assert.True(DedupOrigin(meta) == origin, $"{label}: {method} recorded {DedupOrigin(meta)}");
            }

            // PurgeTaskRecord: HUMAN A, SCRIPT and AGENT D; either way the audit entry carries the caller's origin and kind.
            var purge = new TaskServicePurgeTaskRecordRequest { Meta = Tasks.Meta(), TaskId = missing };
            var purged = await channel.Tasks.PurgeTaskRecordAsync(purge, cancellationToken: Ct);
            Assert.Equal(origin == Origin.Human ? "not_found" : "permission_denied", purged.Error?.Code);
            var audited = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Single(entry => entry.Operation == PermissionMatrix.TaskPurge + " TaskService.PurgeTaskRecord"
                && entry.TargetId is { } target && target.AsSpan().SequenceEqual(missing.Value.Span));
            Assert.Equal(new ActorRef { Origin = origin, ClientKind = kind }, audited.Actor);
        }

        var inconsistent = new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = CommandIds.New() };
        var otherTask = new TaskServiceRetryTaskResponse
        {
            Meta = new ResponseMeta { CorrelationId = inconsistent.Meta.CorrelationId },
            Error = NodeErrors.NotFound("task", CommandIds.New().Value.Span),
        };
        store.Write(transaction => RecordPrior(transaction, "RetryTask", inconsistent.Meta, inconsistent, otherTask, Origin.Human),
            CommitDurability.Full);
        var refusal = await human.Tasks.RetryTaskAsync(inconsistent, cancellationToken: Ct);
        Assert.Equal(EffectCertainty.Unknown, refusal.Error.Effect);
        Assert.Equal("legacy_task_outcome_unavailable", refusal.Error.Details.State.Reason);
        Assert.Equal(otherTask.ToByteArray(), store.Read(reader => reader.Scalar(
            "SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", inconsistent.Meta.CommandId.Value.ToByteArray()))) as byte[]);

        var afterPurge = new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = CommandIds.New() };
        var purgeTime = StoreTime.ToMicroseconds(new DateTimeOffset(2026, 11, 21, 8, 30, 0, TimeSpan.Zero));
        var previousPurgeRefusal = new TaskServiceRetryTaskResponse
        {
            Meta = new ResponseMeta { CorrelationId = afterPurge.Meta.CorrelationId },
            Error = StoreErrors.SecretsUnavailable(purgeTime),
        };
        store.Write(transaction => RecordPrior(transaction, "RetryTask", afterPurge.Meta, afterPurge, previousPurgeRefusal, Origin.Human),
            CommitDurability.Full);
        var purgeReplay = afterPurge.Clone();
        purgeReplay.Meta.CorrelationId = CommandIds.New();
        var recordedPurgeRefusal = await human.Tasks.RetryTaskAsync(purgeReplay, cancellationToken: Ct);
        Assert.Equal(EffectCertainty.DidNotHappen, recordedPurgeRefusal.Error.Effect);
        Assert.Equal(previousPurgeRefusal.ToByteArray(), recordedPurgeRefusal.ToByteArray());

        var malformed = afterPurge.Clone();
        malformed.Meta = Tasks.Meta();
        var malformedRefusal = previousPurgeRefusal.Clone();
        malformedRefusal.Meta.CorrelationId = malformed.Meta.CorrelationId;
        malformedRefusal.Error.Details.State.Reason = "2026-11-21T08:30:00Z";
        store.Write(transaction => RecordPrior(transaction, "RetryTask", malformed.Meta, malformed, malformedRefusal, Origin.Human),
            CommitDurability.Full);
        Assert.Equal(EffectCertainty.Unknown, (await human.Tasks.RetryTaskAsync(malformed, cancellationToken: Ct)).Error.Effect);
    }

    private static void RecordPrior(StoreTransaction transaction, string method, RequestMeta meta, IMessage request, IMessage response, Origin origin)
    {
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, meta.CommandId.Value.Span,
            "arcforges.node.v1.TaskService/" + method, PayloadDigest.Compute(request), origin).Status);
        CommandDeduplication.Complete(transaction, meta.CommandId.Value.Span, response.ToByteArray());
    }

    private static LocalRpcPeer Peer() => new(Environment.ProcessId, DateTimeOffset.UtcNow, null, null, null);
}
