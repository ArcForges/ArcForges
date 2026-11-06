// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Security;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// AF-CTR-05 part N2a (CTR5-NODE-08, the refactor half; plan G.2 N2-15): the TaskService operations take a <see cref="Caller"/>, and each gRPC
/// method is a thin wrapper that builds it from the connection exactly as before. Pinned here: the mapping from a connection's session to its
/// caller (origin, client kind, the session itself; SCRIPT without a kind or session for a connection that sent no hello), the fields each
/// wrapper's operation reads on real nodes through the real client (the task owner and the <c>cancel_when_caller_gone</c> binding of a
/// submission, the <c>command_dedup.origin</c> of every idempotent mutation, the audited actor of a purge), and the center-caller slot that a
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

        // Nor does a routed caller take a local session or a local origin afterwards.
        Assert.Throws<ArgumentException>(() => routed with { Session = session });
        Assert.Throws<ArgumentException>(() => routed with { Origin = Origin.Human });
    }

    /// <summary>
    /// Each wrapper's operation sees the caller of its connection: four connections (an interactive CLI: HUMAN; a CLI without a terminal:
    /// SCRIPT; the MCP adapter: AGENT; a connection that sent no hello: SCRIPT without a kind or session) submit (owner, binding, dedup origin),
    /// cancel, retry, reprioritize, pause, resume and pin (dedup origin) and purge (audited actor). Nothing runs: the pools are paused and
    /// the mutations name a task that does not exist, so each is answered by its idempotent command.
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

        foreach (var (channel, origin, kind, session) in (ValueTuple<NodeChannel, Origin, ClientKind, bool>[])
            [(human, Origin.Human, ClientKind.Cli, true), (script, Origin.Script, ClientKind.Cli, true), (agent, Origin.Agent, ClientKind.McpAdapter, true),
             (bare, Origin.Script, ClientKind.Unspecified, false)])
        {
            var label = $"{origin}/{kind}";

            // SubmitTask: the owner is the caller's origin and kind; the binding is to the session's process (none without a session).
            var submit = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100"), CancelWhenCallerGone = true };
            var submitted = await channel.Tasks.SubmitTaskAsync(submit, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: Ct);
            Assert.True(submitted.Error is null, $"{label}: SubmitTask failed: {submitted.Error?.Category}/{submitted.Error?.Code}");
            var task = await Tasks.GetAsync(channel, submitted.Value.TaskId);
            Assert.Equal(new ActorRef { Origin = origin, ClientKind = kind }, task.Owner);
            Assert.Equal(origin, DedupOrigin(submit.Meta));
            var binding = node.Runtime.Execution!.BindingOf(submitted.Value.TaskId.Value.Span);
            Assert.Equal(session ? (int?)Environment.ProcessId : null, binding?.ProcessId);

            // The idempotent mutations record the caller's origin with their command ID.
            var missing = CommandIds.New();
            var cancel = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = missing };
            Assert.Equal("not_found", (await channel.Tasks.CancelTaskAsync(cancel, cancellationToken: Ct)).Error?.Code);
            var retry = new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = missing };
            Assert.Equal("not_found", (await channel.Tasks.RetryTaskAsync(retry, cancellationToken: Ct)).Error?.Code);
            var priority = new TaskServiceSetTaskPriorityRequest { Meta = Tasks.Meta(), TaskId = missing, Priority = Priority.Low };
            Assert.NotNull((await channel.Tasks.SetTaskPriorityAsync(priority, cancellationToken: Ct)).Error);
            var pause = new TaskServicePauseTaskRequest { Meta = Tasks.Meta(), TaskId = missing };
            Assert.NotNull((await channel.Tasks.PauseTaskAsync(pause, cancellationToken: Ct)).Error);
            var resume = new TaskServiceResumeTaskRequest { Meta = Tasks.Meta(), TaskId = missing };
            Assert.NotNull((await channel.Tasks.ResumeTaskAsync(resume, cancellationToken: Ct)).Error);
            var pin = new TaskServicePinTaskRequest { Meta = Tasks.Meta(), TaskId = missing, Pinned = true };
            Assert.NotNull((await channel.Tasks.PinTaskAsync(pin, cancellationToken: Ct)).Error);
            foreach (var (method, meta) in (ValueTuple<string, RequestMeta>[])
                [("CancelTask", cancel.Meta), ("RetryTask", retry.Meta), ("SetTaskPriority", priority.Meta), ("PauseTask", pause.Meta), ("ResumeTask", resume.Meta),
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
    }

    private static LocalRpcPeer Peer() => new(Environment.ProcessId, DateTimeOffset.UtcNow, null, null, null);
}
