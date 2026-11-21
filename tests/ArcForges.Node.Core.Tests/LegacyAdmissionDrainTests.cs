// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed class LegacyAdmissionDrainTests
{
    private const string TaskService = "arcforges.node.v1.TaskService/";
    private const string ResourceService = "arcforges.node.v1.ResourceService/";

    [Fact(Timeout = 30_000)]
    public async Task SubmitAndRetryRefuseNewWorkAndReconcileOnlyOriginalCommands()
    {
        var ct = TestContext.Current.CancellationToken;
        var taskId = StoreIds.NewUuid7(TimeProvider.System);
        var id = new Id { Value = ByteString.CopyFrom(taskId) };
        var submit = new TaskServiceSubmitTaskRequest
        {
            Meta = Tasks.Meta(),
            Spec = new TaskSpec { Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "legacy-fixture-missing-program" } } } },
        };
        var retry = new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = id };
        var unresolved = retry.Clone();
        unresolved.Meta = Tasks.Meta();
        var incompleteOutcome = retry.Clone();
        incompleteOutcome.Meta = Tasks.Meta();
        var originalSubmit = new TaskServiceSubmitTaskResponse
        {
            Meta = new() { CorrelationId = submit.Meta.CorrelationId },
            Value = new() { Receipt = OriginalReceipt(submit.Meta.CommandId), TaskId = id, State = TaskState.Queued },
        };
        var originalRetry = new TaskServiceRetryTaskResponse
        {
            Meta = new() { CorrelationId = retry.Meta.CorrelationId },
            Value = new() { Receipt = OriginalReceipt(retry.Meta.CommandId), State = TaskState.Queued },
        };

        await using var node = InProcessNode.Create();
        using (var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "legacy-fixture" }))
        {
            store.Write(transaction =>
            {
                SeedQueuedTask(transaction, taskId);
                SeedCommand(transaction, TaskService + "SubmitTask", submit.Meta.CommandId, submit, originalSubmit);
                SeedCommand(transaction, TaskService + "RetryTask", retry.Meta.CommandId, retry, originalRetry);
                SeedCommand(transaction, TaskService + "RetryTask", unresolved.Meta.CommandId, unresolved, null);
                SeedCommand(transaction, TaskService + "RetryTask", incompleteOutcome.Meta.CommandId, incompleteOutcome, new TaskServiceRetryTaskResponse());
            }, CommitDurability.Full);
        }

        await node.StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        Assert.Equal(originalSubmit, await channel.Tasks.SubmitTaskAsync(submit, cancellationToken: ct));
        Assert.Equal(originalRetry, await channel.Tasks.RetryTaskAsync(retry, cancellationToken: ct));

        var changed = submit.Clone();
        changed.Spec.Title = "different payload under the original command";
        Assert.Equal("command_id_reused", (await channel.Tasks.SubmitTaskAsync(changed, cancellationToken: ct)).Error.Code);

        var pending = await channel.Tasks.RetryTaskAsync(unresolved, cancellationToken: ct);
        Assert.Equal(EffectCertainty.Unknown, pending.Error.Effect);
        Assert.Equal("command_in_progress", pending.Error.Details.State.Reason);
        Assert.Equal(RetryMode.SameCommand, pending.Error.Retry.Mode);
        AssertLegacyTaskUnknown((await channel.Tasks.RetryTaskAsync(incompleteOutcome, cancellationToken: ct)).Error);

        var freshSubmit = submit.Clone();
        freshSubmit.Meta = Tasks.Meta();
        var freshRetry = retry.Clone();
        freshRetry.Meta = Tasks.Meta();
        AssertLegacyTaskUnknown((await channel.Tasks.SubmitTaskAsync(freshSubmit, cancellationToken: ct)).Error);
        AssertLegacyTaskUnknown((await channel.Tasks.RetryTaskAsync(freshRetry, cancellationToken: ct)).Error);

        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM task;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM attempt;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM approval;"));
            Assert.Equal(4L, reader.Scalar("SELECT count(*) FROM command_dedup;"));
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM command_dedup WHERE outcome IS NULL;"));
            return 0;
        });

        var originalSubmitId = submit.Meta.CommandId.Value.ToByteArray();
        var originalRetryId = retry.Meta.CommandId.Value.ToByteArray();
        node.Runtime.Store.Write(transaction => Assert.Equal(2, transaction.Execute("""
            UPDATE command_dedup SET created_at = created_at - $age, expires_at = expires_at - $age
            WHERE command_id IN ($submit, $retry);
            """, ("$age", 2 * CommandDeduplication.Window.Ticks / TimeSpan.TicksPerMicrosecond), ("$submit", originalSubmitId), ("$retry", originalRetryId))),
            CommitDurability.Full);

        AssertLegacyTaskUnknown((await channel.Tasks.SubmitTaskAsync(submit, cancellationToken: ct)).Error);
        AssertLegacyTaskUnknown((await channel.Tasks.RetryTaskAsync(retry, cancellationToken: ct)).Error);
        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(originalSubmit.ToByteArray(), (byte[]?)reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", originalSubmitId)));
            Assert.Equal(originalRetry.ToByteArray(), (byte[]?)reader.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", originalRetryId)));
            return 0;
        });
        Assert.Equal(2, node.Runtime.Store.Commands.PurgeExpired());
        AssertLegacyTaskUnknown((await channel.Tasks.SubmitTaskAsync(submit, cancellationToken: ct)).Error);
        AssertLegacyTaskUnknown((await channel.Tasks.RetryTaskAsync(retry, cancellationToken: ct)).Error);
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, id)).State);
        Assert.Equal(2L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
    }

    [Fact(Timeout = 30_000)]
    public async Task AdoptUsesOnlyPriorReceiptsAndPreservesAnUnresolvedApprovedRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "legacy-adoption-fixture" });
        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, fixture.Clock);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(fixture.ConfigPath, fixture.DataRoot, log), fixture.DataRoot, "offline-fixture", fixture.Clock,
            new RecoveryReport(false, false, null, store.Opening), new CapabilityReport());
        // The real handlers and writer are composed without any native platform or service listener.
        Assert.Null(runtime.Execution);
        var sessions = new ClientSessions();
        var executors = new ApprovalExecutors();
        var resources = new ResourceServiceHandler(runtime, sessions, executors);
        _ = new TaskServiceHandler(runtime, sessions, executors);
        var approvals = new ApprovalServiceHandler(runtime, sessions, executors);
        var caller = new Caller(Origin.Human, ClientKind.Cli, null);

        ResourceServiceAdoptProcessRequest Request() => new()
        {
            Meta = Tasks.Meta(),
            Process = new() { Pid = int.MaxValue, StartTime = ProtoTime.ToInstant(DateTimeOffset.UnixEpoch) },
        };
        Task<ResourceServiceAdoptProcessResponse> Reconcile(ResourceServiceAdoptProcessRequest request, Caller? requester = null) =>
            resources.AdoptProcess(request, requester ?? caller).WaitAsync(ct);

        var prior = Request();
        var pending = Request();
        var approved = Request();
        var original = new ResourceServiceAdoptProcessResponse
        {
            Meta = new() { CorrelationId = prior.Meta.CorrelationId },
            Value = new() { Receipt = OriginalReceipt(prior.Meta.CommandId), TaskId = CommandIds.New(), AdoptedChildren = 2 },
        };
        byte[] Approve(CommandContext command, Id commandId, IMessage request, string method = "ResourceService.AdoptProcess",
            string permission = PermissionMatrix.ProcessAdopt, byte[]? captured = null, ActorRef? requester = null)
        {
            var (approval, created, error) = Approvals.Raise(command, new ApprovalCapture
            {
                Operation = method,
                MatrixOperation = permission,
                Summary = "historical approval fixture",
                Risk = PermissionMatrix.Find(permission)!.Risk,
                Requester = requester ?? caller.Actor,
                CommandId = commandId.Value.ToByteArray(),
                Request = captured ?? request.ToByteArray(),
                RequestDigest = PayloadDigest.Compute(request),
            }, Approvals.DefaultTtl);
            Assert.True(created);
            Assert.Null(error);
            Assert.NotNull(approval);
            return Approvals.Decide(command, approval.Id, approve: true, caller.Actor, null).Id;
        }

        var malformed = Request();
        var wrongReceipt = Request();
        var typedRefusal = Request();
        var executorFailure = Request();
        // A Human could configure a Script approval gate for adoption. The old executor saved its raw response in approval.outcome.
        var script = new Caller(Origin.Script, ClientKind.Cli, null);
        var refusalResponse = new ResourceServiceAdoptProcessResponse
        {
            Meta = new() { CorrelationId = typedRefusal.Meta.CorrelationId },
            Error = NodeErrors.ProcessNotFound("the requested process no longer exists"),
        };
        var genericFailure = new ResourceServiceAdoptProcessResponse { Error = NodeErrors.Internal(fixture.Clock.GetUtcNow()) };
        var expiredRetry = new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = original.Value.TaskId };
        var retryReceipt = new TaskServiceRetryTaskResponse
        {
            Value = new() { Receipt = OriginalReceipt(expiredRetry.Meta.CommandId), State = TaskState.Queued },
        };
        var approvalIds = await processor.ExecuteAsync(command =>
        {
            SeedCommand(command.Transaction, ResourceService + "AdoptProcess", prior.Meta.CommandId, prior, original);
            SeedCommand(command.Transaction, ResourceService + "AdoptProcess", pending.Meta.CommandId, pending, null);
            SeedCommand(command.Transaction, ResourceService + "AdoptProcess", wrongReceipt.Meta.CommandId, wrongReceipt, original);
            SeedCommand(command.Transaction, TaskService + "RetryTask", expiredRetry.Meta.CommandId, expiredRetry, retryReceipt);
            command.Transaction.Execute("UPDATE command_dedup SET created_at = created_at - $age, expires_at = expires_at - $age WHERE command_id = $id;",
                ("$id", expiredRetry.Meta.CommandId.Value.ToByteArray()), ("$age", 2 * CommandDeduplication.Window.Ticks / TimeSpan.TicksPerMicrosecond));
            var typedId = Approve(command, typedRefusal.Meta.CommandId, typedRefusal, requester: script.Actor);
            var genericId = Approve(command, executorFailure.Meta.CommandId, executorFailure, requester: script.Actor);
            Approvals.Executed(command, typedId, refusalResponse.ToByteArray(), refusalResponse.Error, PermissionMatrix.ProcessAdopt);
            Approvals.Executed(command, genericId, genericFailure.ToByteArray(), genericFailure.Error, PermissionMatrix.ProcessAdopt);
            return (TypedFailure: typedId, GenericFailure: genericId,
                Unresolved: Approve(command, approved.Meta.CommandId, approved), Known: Approve(command, prior.Meta.CommandId, prior),
                Malformed: Approve(command, malformed.Meta.CommandId, malformed, captured: [0x80]),
                WrongReceipt: Approve(command, wrongReceipt.Meta.CommandId, wrongReceipt),
                ExpiredRetry: Approve(command, expiredRetry.Meta.CommandId, expiredRetry, "TaskService.RetryTask", PermissionMatrix.TaskRetry));
        }, CommitDurability.Full).WaitAsync(ct);

        Assert.Equal(original, await Reconcile(prior));
        var otherAuthority = new Caller(Origin.Remote, ClientKind.Unspecified, null, centerCaller: RoutedCalls.Session())
        {
            RawRequest = prior.ToByteArray(),
        };
        Assert.Equal("command_id_reused", (await Reconcile(prior, otherAuthority)).Error.Code);
        var changed = prior.Clone();
        changed.Title = "different payload with the original command";
        Assert.Equal("command_id_reused", (await Reconcile(changed)).Error.Code);

        var unresolved = await Reconcile(pending);
        Assert.Equal("command_in_progress", unresolved.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, unresolved.Error.Effect);
        Assert.Equal(RetryMode.SameCommand, unresolved.Error.Retry.Mode);
        AssertAdoptionUnknown((await Reconcile(Request())).Error);
        AssertAdoptionUnknown((await Reconcile(approved)).Error);
        AssertAdoptionUnknown((await Reconcile(wrongReceipt)).Error);
        var refusalReplay = typedRefusal.Clone();
        refusalReplay.Meta.CorrelationId = CommandIds.New();
        var refusal = await Reconcile(refusalReplay, script);
        Assert.Equal(refusalResponse, refusal);
        Assert.Null(refusal.Error.CorrelationId);
        AssertAdoptionUnknown((await Reconcile(executorFailure, script)).Error);

        await approvals.ResumeAsync().WaitAsync(ct);
        store.Read(reader =>
        {
            var retained = Approvals.Get(reader, approvalIds.Unresolved);
            Assert.NotNull(retained);
            Assert.Equal(ApprovalState.Approved, retained.State);
            Assert.Equal(caller.Actor, retained.View.Requester);
            Assert.Equal(approved.Meta.CommandId, retained.View.CommandId);
            Assert.Null(retained.Outcome);
            Assert.Equal(ApprovalState.Approved, Approvals.Get(reader, approvalIds.Malformed)?.State);
            Assert.Null(Approvals.Get(reader, approvalIds.Malformed)?.Outcome);
            Assert.Equal(ApprovalState.Approved, Approvals.Get(reader, approvalIds.WrongReceipt)?.State);
            Assert.Null(Approvals.Get(reader, approvalIds.WrongReceipt)?.Outcome);
            var known = Approvals.Get(reader, approvalIds.Known);
            Assert.NotNull(known);
            Assert.Equal(ApprovalState.Executed, known.State);
            Assert.Equal(original.ToByteArray(), known.Outcome);
            var historicalRefusal = Approvals.Get(reader, approvalIds.TypedFailure);
            Assert.NotNull(historicalRefusal);
            Assert.Equal(ApprovalState.Failed, historicalRefusal.State);
            Assert.Equal(refusalResponse.ToByteArray(), historicalRefusal.Outcome);
            var historicalFailure = Approvals.Get(reader, approvalIds.GenericFailure);
            Assert.NotNull(historicalFailure);
            Assert.Equal(ApprovalState.Failed, historicalFailure.State);
            Assert.Equal(genericFailure.ToByteArray(), historicalFailure.Outcome);
            Assert.Equal(ApprovalState.Approved, Approvals.Get(reader, approvalIds.ExpiredRetry)?.State);
            Assert.Null(Approvals.Get(reader, approvalIds.ExpiredRetry)?.Outcome);
            Assert.Equal(4L, reader.Scalar("SELECT count(*) FROM command_dedup;"));
            Assert.Equal(1L, reader.Scalar("SELECT count(*) FROM command_dedup WHERE outcome IS NULL;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM task;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM attempt;"));
            return 0;
        });

        var blockedOnStop = Request();
        var stoppedReceipt = original.Clone();
        stoppedReceipt.Meta.CorrelationId = blockedOnStop.Meta.CorrelationId;
        stoppedReceipt.Value.Receipt.CommandId = blockedOnStop.Meta.CommandId;
        var stopApproval = await processor.ExecuteAsync(command =>
        {
            SeedCommand(command.Transaction, ResourceService + "AdoptProcess", blockedOnStop.Meta.CommandId, blockedOnStop, stoppedReceipt);
            return Approve(command, blockedOnStop.Meta.CommandId, blockedOnStop);
        }, CommitDurability.Full).WaitAsync(ct);
        await runtime.TransitionAsync(NodeLifecycleState.Recovering, "fixture").WaitAsync(ct);
        await runtime.TransitionAsync(NodeLifecycleState.Ready, "fixture").WaitAsync(ct);
        await runtime.TransitionAsync(NodeLifecycleState.Stopping, "fixture").WaitAsync(ct);
        Assert.Equal("node_stopping", (await Reconcile(blockedOnStop)).Error.Code);
        await approvals.ResumeAsync().WaitAsync(ct);
        var stillApproved = store.Read(reader => Approvals.Get(reader, stopApproval));
        Assert.NotNull(stillApproved);
        Assert.Equal(ApprovalState.Approved, stillApproved.State);
        Assert.Null(stillApproved.Outcome);
    }

    [Fact(Timeout = 30_000)]
    public async Task RecoveredQueueDoesNotAdmitAnAttemptAndTheOwnerCanCancelIt()
    {
        var ct = TestContext.Current.CancellationToken;
        var taskId = StoreIds.NewUuid7(TimeProvider.System);
        var id = new Id { Value = ByteString.CopyFrom(taskId) };

        await using var node = await InProcessNode.Create(seed: transaction => SeedQueuedTask(transaction, taskId)).StartAsync();
        var execution = Assert.IsType<Execution.ExecutionSupervisor>(node.Runtime.Execution);
        Assert.SkipWhen(execution.Platform is null, "Legacy platform unavailable for the scheduler regression check.");
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, id)).State);

        // Keep the task queued past the former admission loop's two-second polling interval.
        await Task.Delay(TimeSpan.FromSeconds(3), ct);
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, id)).State);
        AssertNoAttemptEffects();

        var request = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id };
        var cancel = await channel.Tasks.CancelTaskAsync(request, cancellationToken: ct);
        Assert.Null(cancel.Error);
        Assert.Equal(TaskState.Cancelled, cancel.Value.State);
        Assert.Equal(request.Meta.CommandId, cancel.Value.Receipt.CommandId);
        Assert.Equal(EffectCertainty.Happened, cancel.Value.Receipt.Effect);

        var replay = await channel.Tasks.CancelTaskAsync(request, cancellationToken: ct);
        Assert.Null(replay.Error);
        Assert.Equal(cancel.Value, replay.Value);
        Assert.Equal(TaskState.Cancelled, (await Tasks.GetAsync(channel, id)).State);
        AssertNoAttemptEffects();

        void AssertNoAttemptEffects()
        {
            Assert.Empty(execution.RunningAttempts);
            Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
            Assert.Equal("node", Path.GetFileName(Assert.Single(Directory.EnumerateDirectories(Path.Combine(node.DataRoot, "logs")))));
            var temp = Path.Combine(node.DataRoot, "tmp");
            if (Directory.Exists(temp))
            {
                Assert.Empty(Directory.EnumerateFileSystemEntries(temp));
            }
        }
    }

    private static void SeedQueuedTask(StoreTransaction transaction, byte[] id)
    {
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "migration-fixture-never-starts" } } },
        }.ToByteArray();
        transaction.Execute("""
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                              pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                              command_digest, created_at, queued_at, rev)
            VALUES ($id, $queued, $kind, 'legacy queue fixture', 'legacy queue fixture', $spec, $digest, $owner, $origin,
                    'default', 3, 3, 4, 1, 'legacy-drain-fixture', $digest, $now, $now, 0);
            """, ("$id", id), ("$queued", (int)TaskState.Queued), ("$kind", (int)TaskKind.Command), ("$spec", spec),
            ("$digest", SHA256.HashData(spec)), ("$owner", new ActorRef { Origin = Origin.Human }.ToByteArray()),
            ("$origin", (int)Origin.Human), ("$now", transaction.NowMicroseconds));
    }

    private static Receipt OriginalReceipt(Id commandId) => new() { CommandId = commandId, Effect = EffectCertainty.Happened };

    private static void SeedCommand(StoreTransaction transaction, string method, Id commandId, IMessage request, IMessage? outcome)
    {
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, commandId.Value.Span,
            method, PayloadDigest.Compute(request), Origin.Human).Status);
        if (outcome is not null)
        {
            CommandDeduplication.Complete(transaction, commandId.Value.Span, outcome.ToByteArray());
        }
    }

    private static void AssertLegacyTaskUnknown(ArcError error)
    {
        Assert.Equal("operation_failed", error.Code);
        Assert.Equal("LEGACY_DRAIN", error.Details.State.State);
        Assert.Equal("legacy_task_outcome_unavailable", error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
    }

    private static void AssertAdoptionUnknown(ArcError error)
    {
        Assert.Equal(ErrorCategory.Execution, error.Category);
        Assert.Equal("operation_failed", error.Code);
        Assert.Equal("legacy_adoption_outcome_unavailable", error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
    }
}
