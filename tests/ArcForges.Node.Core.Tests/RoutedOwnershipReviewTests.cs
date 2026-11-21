// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
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

public sealed class RoutedOwnershipReviewTests
{
    private const string Submit = "arcforges.node.v1.TaskService/SubmitTask";
    private const string Cancel = "arcforges.node.v1.TaskService/CancelTask";
    private const string CancelApproval = "TaskService.CancelTask";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 30_000)]
    public async Task RecordedErrorsAndApprovalsBelongToTheRequesterAcrossStoreReopen()
    {
        await using var files = InProcessNode.Create();
        var owner = RoutedCalls.Session();
        var foreign = OtherUser();
        var submit = PriorSubmit(Tasks.Meta());
        var submitBytes = WithUnknownPrefix(submit);
        var submitError = WithUnknownPrefix(new TaskServiceSubmitTaskResponse
        {
            Meta = new() { CorrelationId = submit.Meta.CorrelationId },
            Error = NodeErrors.InvalidArgument("historical request"),
        });
        var missing = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = CommandIds.New() };
        var missingError = WithUnknownPrefix(new TaskServiceCancelTaskResponse
        {
            Meta = new() { CorrelationId = missing.Meta.CorrelationId },
            Error = NodeErrors.NotFound("task", missing.TaskId.Value.ToByteArray()),
        });
        var cancelled = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = CommandIds.New() };
        var cancelledBytes = WithUnknownPrefix(cancelled);
        var approved = WithUnknownPrefix(new TaskServiceCancelTaskResponse
        {
            Meta = new() { CorrelationId = cancelled.Meta.CorrelationId },
            Value = new() { State = TaskState.Cancelled, Receipt = ReceiptOf(cancelled.Meta.CommandId) },
        });
        Assert.False(submitError.AsSpan().SequenceEqual(TaskServiceSubmitTaskResponse.Parser.ParseFrom(submitError).ToByteArray()));
        Assert.False(missingError.AsSpan().SequenceEqual(TaskServiceCancelTaskResponse.Parser.ParseFrom(missingError).ToByteArray()));
        Assert.False(approved.AsSpan().SequenceEqual(TaskServiceCancelTaskResponse.Parser.ParseFrom(approved).ToByteArray()));

        byte[] approvalId;
        await using (var node = new HistoricalNode(files))
        {
            node.Store.Write(tx =>
            {
                SeedHistoricalTask(tx, cancelled.TaskId, TaskState.Cancelled);
                RecordPrior(tx, owner, submit.Meta.CommandId, Submit, submitBytes, submitError);
                RecordPrior(tx, owner, missing.Meta.CommandId, Cancel, missing.ToByteArray(), missingError);
            }, CommitDurability.Full);
            approvalId = await node.Processor.ExecuteAsync(command =>
            {
                var approval = CaptureCancel(command, owner, cancelled, cancelledBytes);
                Approvals.Decide(command, approval.Id, approve: true, new ActorRef { Origin = Origin.Human }, comment: null);
                RecordPrior(command.Transaction, owner, cancelled.Meta.CommandId, Cancel, cancelledBytes, approved);
                Assert.Equal(ApprovalState.Executed, Approvals.Executed(command, approval.Id, approved,
                    error: null, matrixOperation: PermissionMatrix.TaskCancelOthers)?.State);
                return approval.Id;
            }, CommitDurability.Full).WaitAsync(Ct);
            await AssertReplays(node);
        }

        await using var reopened = new HistoricalNode(files);
        await AssertReplays(reopened);
        var marker = reopened.Store.Read(reader => AuditLog.Recent(reader).Single(entry => entry.TargetKind == RoutedCommandOwnership.TargetKind
            && entry.Actor.RemoteCommandId?.Equals(cancelled.Meta.CommandId) == true));
        Assert.Equal(Actor(owner, cancelled.Meta.CommandId), marker.Actor);
        Assert.Equal("routed command outcome recorded", marker.Outcome);
        Assert.Equal(PermissionDecision.Unspecified, marker.Decision);
        var approvalRecord = reopened.Store.Read(reader => Approvals.Get(reader, approvalId));
        Assert.NotNull(approvalRecord);
        Assert.Equal(Actor(owner, cancelled.Meta.CommandId), approvalRecord.View.Requester);
        Assert.Equal(PayloadDigest.Compute(cancelledBytes), approvalRecord.RequestDigest);
        Assert.Equal(cancelledBytes, approvalRecord.Request);
        Assert.Equal(approved, approvalRecord.Outcome);
        reopened.Store.Write(tx => tx.Execute("UPDATE command_dedup SET expires_at = $expired WHERE command_id = $id;",
            ("$expired", tx.NowMicroseconds - 1), ("$id", cancelled.Meta.CommandId.Value.ToByteArray())), CommitDurability.Full);
        Assert.Equal(approved, ReplayBytes(await reopened.CancelAsync(RoutedCalls.Session(), cancelled, cancelledBytes)));
        AssertConflict(await reopened.CancelErrorAsync(foreign, cancelled, cancelledBytes));
        AssertHistoricalRows(reopened.Store, receipts: 3, approvals: 1, taskId: cancelled.TaskId, state: TaskState.Cancelled, revision: 1);

        async Task AssertReplays(HistoricalNode node)
        {
            var renewed = RoutedCalls.Session();
            Assert.NotEqual(owner.SessionId, renewed.SessionId);
            var newSubmit = submit.Clone();
            newSubmit.Meta.CorrelationId = CommandIds.New();
            var newCancel = cancelled.Clone();
            newCancel.Meta.CorrelationId = CommandIds.New();
            var retainedSubmit = ReplayBytes(await node.SubmitAsync(renewed, newSubmit, WithUnknownPrefix(newSubmit)));
            Assert.Equal(submitError, retainedSubmit);
            Assert.Equal(submit.Meta.CorrelationId, TaskServiceSubmitTaskResponse.Parser.ParseFrom(retainedSubmit).Meta.CorrelationId);
            Assert.Equal(missingError, ReplayBytes(await node.CancelAsync(renewed, missing)));
            var retainedCancel = ReplayBytes(await node.CancelAsync(renewed, newCancel, WithUnknownPrefix(newCancel)));
            Assert.Equal(approved, retainedCancel);
            Assert.Equal(cancelled.Meta.CorrelationId, TaskServiceCancelTaskResponse.Parser.ParseFrom(retainedCancel).Meta.CorrelationId);
            var reordered = TaskServiceCancelTaskRequest.Parser.ParseFrom(cancelledBytes).ToByteArray();
            AssertConflict(await node.CancelErrorAsync(renewed, cancelled, reordered));
            foreach (var different in new[] { foreign, node.Relay(Origin.Script) })
            {
                AssertConflict(await node.SubmitErrorAsync(different, submit, submitBytes));
                AssertConflict(await node.CancelErrorAsync(different, missing));
                AssertConflict(await node.CancelErrorAsync(different, cancelled, cancelledBytes));
            }

            AssertHistoricalRows(node.Store, receipts: 3, approvals: 1, taskId: cancelled.TaskId, state: TaskState.Cancelled, revision: 1);
        }
    }

    [Fact(Timeout = 30_000)]
    public async Task MissingOwnershipAndDigestMismatchRefuseAndExpiryDoesNotAdmitAReplacement()
    {
        await using var files = InProcessNode.Create();
        await using var node = new HistoricalNode(files);
        var owner = RoutedCalls.Session();
        var foreign = OtherUser();
        var request = PriorSubmit(Tasks.Meta());
        var raw = WithUnknownPrefix(request);
        var parsed = TaskServiceSubmitTaskRequest.Parser.ParseFrom(raw);
        var reordered = parsed.ToByteArray();
        Assert.Equal(parsed, TaskServiceSubmitTaskRequest.Parser.ParseFrom(reordered));
        Assert.False(PayloadDigest.Compute(raw).AsSpan().SequenceEqual(PayloadDigest.Compute(reordered)));
        var original = WithUnknownPrefix(SubmitOutcome(request));
        var id = request.Meta.CommandId.Value.ToByteArray();
        node.Store.Write(tx => RecordPrior(tx, owner, request.Meta.CommandId, Submit, raw, original), CommitDurability.Full);
        Assert.Equal(original, ReplayBytes(await node.SubmitAsync(RoutedCalls.Session(), request, raw)));
        AssertConflict(await node.SubmitErrorAsync(owner, request, reordered));
        var changed = request.Clone();
        changed.Spec.Title = "different payload, same command";
        AssertConflict(await node.SubmitErrorAsync(owner, changed, WithUnknownPrefix(changed)));

        node.Store.Write(tx => tx.Execute("DELETE FROM audit_log WHERE target_kind = $kind AND remote_command_id = $id;",
            ("$kind", RoutedCommandOwnership.TargetKind), ("$id", id)), CommitDurability.Full);
        AssertConflict(await node.SubmitErrorAsync(RoutedCalls.Session(), request, raw));
        AssertConflict(await node.SubmitErrorAsync(foreign, request, raw));

        node.Store.Write(tx =>
        {
            RoutedCommandOwnership.Record(tx, id, Actor(owner, request.Meta.CommandId));
            tx.Execute("UPDATE command_dedup SET expires_at = $expired WHERE command_id = $id;",
                ("$expired", tx.NowMicroseconds - 1), ("$id", id));
        }, CommitDurability.Full);
        AssertUnknown(await node.SubmitErrorAsync(RoutedCalls.Session(), request, raw));
        AssertUnknown(await node.SubmitErrorAsync(foreign, request, raw));
        Assert.Equal(original, Assert.IsType<byte[]>(node.Store.Read(reader => reader.Scalar(
            "SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", id)))));
        Assert.Single(node.Store.Read(reader => AuditLog.Recent(reader).Where(entry => entry.TargetKind == RoutedCommandOwnership.TargetKind)));
        AssertHistoricalRows(node.Store, receipts: 1, approvals: 0);
    }

    [Fact(Timeout = 30_000)]
    public async Task CapturedPendingApprovalCannotBeReusedForAnotherMethodPayloadOrRequester()
    {
        await using var files = InProcessNode.Create();
        await using var node = new HistoricalNode(files);
        var owner = RoutedCalls.Session();
        var cancel = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = CommandIds.New() };
        var raw = WithUnknownPrefix(cancel);
        var original = await node.Processor.ExecuteAsync(command =>
        {
            SeedHistoricalTask(command.Transaction, cancel.TaskId, TaskState.Queued);
            return CaptureCancel(command, owner, cancel, raw);
        }, CommitDurability.Full).WaitAsync(Ct);
        var gated = await node.CancelAsync(RoutedCalls.Session(), cancel, raw);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, gated.Outcome);
        var error = Assert.IsType<ArcError>(gated.Error);
        Assert.Equal("approval_required", error.Code);
        Assert.Equal(PermissionMatrix.TaskCancelOthers, error.Details.State.State);
        Assert.Equal(original.View.ApprovalId, error.Details.State.Resource.Id);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
        AssertConflict(await node.CancelErrorAsync(OtherUser(), cancel, raw));
        AssertConflict(await node.CancelErrorAsync(node.Relay(Origin.Script), cancel, raw));
        AssertConflict(await node.SubmitErrorAsync(owner, PriorSubmit(cancel.Meta)));
        var changed = cancel.Clone();
        changed.TaskId = CommandIds.New();
        AssertConflict(await node.CancelErrorAsync(owner, changed, WithUnknownPrefix(changed)));

        var pending = node.Store.Read(reader => Approvals.Get(reader, original.Id));
        Assert.NotNull(pending);
        Assert.Equal(ApprovalState.Pending, pending.State);
        Assert.Equal(Actor(owner, cancel.Meta.CommandId), pending.View.Requester);
        Assert.Equal(CancelApproval, pending.View.Operation);
        Assert.Equal(raw, pending.Request);
        Assert.Equal(PayloadDigest.Compute(raw), pending.RequestDigest);
        Assert.Null(pending.Outcome);
        await node.Processor.ExecuteAsync(command => Approvals.Decide(command, original.Id, approve: true,
            new ActorRef { Origin = Origin.Human }, comment: null), CommitDurability.Full).WaitAsync(Ct);
        var inProgress = await node.CancelErrorAsync(RoutedCalls.Session(), cancel, raw);
        Assert.Equal("operation_failed", inProgress.Code);
        Assert.Equal("command_in_progress", inProgress.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, inProgress.Effect);
        Assert.Equal(RetryMode.SameCommand, inProgress.Retry.Mode);
        AssertConflict(await node.CancelErrorAsync(OtherUser(), cancel, raw));
        var approved = node.Store.Read(reader => Approvals.Get(reader, original.Id));
        Assert.NotNull(approved);
        Assert.Equal(ApprovalState.Approved, approved.State);
        Assert.Equal(pending.Request, approved.Request);
        Assert.Equal(pending.View.Requester, approved.View.Requester);
        Assert.Null(approved.Outcome);
        AssertHistoricalRows(node.Store, receipts: 0, approvals: 1, taskId: cancel.TaskId);
    }

    [Fact(Timeout = 30_000)]
    public async Task OwnershipSharesTheOutcomeTransactionAndRetentionProtectsLiveRows()
    {
        await using var files = InProcessNode.Create();
        await using var node = new HistoricalNode(files);
        var owner = RoutedCalls.Session();
        var request = PriorSubmit(Tasks.Meta());
        var outcome = SubmitOutcome(request).ToByteArray();
        var id = request.Meta.CommandId.Value.ToByteArray();
        node.Store.Write(tx => RecordPrior(tx, owner, request.Meta.CommandId, Submit, request.ToByteArray(), outcome), CommitDurability.Full);
        node.Store.Write(tx =>
        {
            var old = tx.NowMicroseconds - (366L * 24 * 60 * 60 * 1_000_000);
            tx.Execute("UPDATE command_dedup SET created_at = $old WHERE command_id = $id;", ("$old", old), ("$id", id));
            tx.Execute("UPDATE audit_log SET at = $old WHERE target_kind = $kind AND remote_command_id = $id;",
                ("$old", old), ("$kind", RoutedCommandOwnership.TargetKind), ("$id", id));
            AuditLog.Prune(tx);
        }, CommitDurability.Full);
        Assert.Equal(outcome, ReplayBytes(await node.SubmitAsync(RoutedCalls.Session(), request)));
        var plan = node.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("EXPLAIN QUERY PLAN SELECT actor FROM audit_log WHERE at = $at AND target_kind = $kind AND remote_command_id = $id ORDER BY seq DESC LIMIT 1;");
            command.Parameters.AddWithValue("$at", 0L);
            command.Parameters.AddWithValue("$kind", RoutedCommandOwnership.TargetKind);
            command.Parameters.AddWithValue("$id", id);
            using var rows = command.ExecuteReader();
            var details = new List<string>();
            while (rows.Read())
            {
                details.Add(rows.GetString(3));
            }

            return details;
        });
        Assert.Contains(plan, detail => detail.Contains("ix_audit_log__at", StringComparison.Ordinal));

        var rolledBack = PriorSubmit(Tasks.Meta());
        var rolledBackId = rolledBack.Meta.CommandId;
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => node.Processor.ExecuteIdempotentAsync(rolledBackId.Value.Memory,
            Submit, PayloadDigest.Compute(rolledBack.ToByteArray()), Origin.Remote, _ => SubmitOutcome(rolledBack).ToByteArray(), afterComplete: command =>
            {
                RoutedCommandOwnership.Record(command.Transaction, rolledBackId.Value.Span, Actor(owner, rolledBackId));
                throw new InvalidOperationException("rollback after writing the ownership marker");
            }).WaitAsync(Ct));
        Assert.Equal("rollback after writing the ownership marker", failure.Message);
        var rolledBackBytes = rolledBackId.Value.ToByteArray();
        Assert.Equal(0L, node.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", rolledBackBytes))));
        Assert.Equal(0L, node.Store.Read(reader => reader.Scalar("SELECT count(*) FROM audit_log WHERE target_kind = $kind AND remote_command_id = $id;",
            ("$kind", RoutedCommandOwnership.TargetKind), ("$id", rolledBackBytes))));
        AssertUnknown(await node.SubmitErrorAsync(owner, rolledBack));
        AssertHistoricalRows(node.Store, receipts: 1, approvals: 0);
        Assert.Single(node.Store.Read(reader => AuditLog.Recent(reader).Where(entry => entry.TargetKind == RoutedCommandOwnership.TargetKind)));
    }

    private static void RecordPrior(StoreTransaction tx, CenterCaller owner, Id id, string method, byte[] request, byte[] outcome)
    {
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, id.Value.Span, method,
            PayloadDigest.Compute(request), Origin.Remote).Status);
        CommandDeduplication.Complete(tx, id.Value.Span, outcome);
        RoutedCommandOwnership.Record(tx, id.Value.Span, Actor(owner, id));
    }

    private static StoredApproval CaptureCancel(CommandContext command, CenterCaller owner, TaskServiceCancelTaskRequest request, byte[] raw)
    {
        var (approval, created, error) = Approvals.Raise(command, new ApprovalCapture
        {
            Operation = CancelApproval,
            MatrixOperation = PermissionMatrix.TaskCancelOthers,
            Summary = "historical cancel fixture",
            Risk = PermissionMatrix.Find(PermissionMatrix.TaskCancelOthers)!.Risk,
            Requester = Actor(owner, request.Meta.CommandId),
            CommandId = request.Meta.CommandId.Value.ToByteArray(),
            Request = raw,
            RequestDigest = PayloadDigest.Compute(raw),
            TargetKind = "task",
            TargetId = request.TaskId.Value.ToByteArray(),
        }, Approvals.DefaultTtl);
        Assert.True(created);
        Assert.Null(error);
        return Assert.IsType<StoredApproval>(approval);
    }

    private static TaskServiceSubmitTaskRequest PriorSubmit(RequestMeta meta) => new()
    {
        Meta = meta,
        Spec = FixtureSpec(),
    };

    private static TaskSpec FixtureSpec() => new()
    {
        Kind = TaskKind.Command,
        Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "historical-fixture-no-launch" } } },
    };

    private static void SeedHistoricalTask(StoreTransaction tx, Id taskId, TaskState state)
    {
        var spec = FixtureSpec().ToByteArray();
        tx.Execute("""
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                              pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                              command_digest, created_at, queued_at, finished_at, rev)
            VALUES ($id, $state, $kind, 'historical cancel fixture', 'historical cancel fixture', $spec, $digest, $owner, $origin,
                    'default', 3, 3, 4, 1, 'historical-cancel-fixture', $digest, $now, $now, $finished, $rev);
            """, ("$id", taskId.Value.ToByteArray()), ("$state", (int)state), ("$kind", (int)TaskKind.Command),
            ("$spec", spec), ("$digest", SHA256.HashData(spec)), ("$owner", new ActorRef { Origin = Origin.Human }.ToByteArray()),
            ("$origin", (int)Origin.Human), ("$now", tx.NowMicroseconds),
            ("$finished", state == TaskState.Cancelled ? tx.NowMicroseconds : (long?)null), ("$rev", state == TaskState.Cancelled ? 1 : 0));
    }

    private static TaskServiceSubmitTaskResponse SubmitOutcome(TaskServiceSubmitTaskRequest request) => new()
    {
        Meta = new() { CorrelationId = request.Meta.CorrelationId },
        Value = new() { TaskId = CommandIds.New(), State = TaskState.Queued, Receipt = ReceiptOf(request.Meta.CommandId) },
    };

    private static Receipt ReceiptOf(Id commandId) => new() { CommandId = commandId, Effect = EffectCertainty.Happened };

    // Protobuf field 100 (varint 1) is legal and is reserialized after the known fields.
    private static byte[] WithUnknownPrefix(IMessage message) => [0xa0, 0x06, 1, .. message.ToByteArray()];

    private static byte[] ReplayBytes(RoutedAnswer answer)
    {
        Assert.Equal(RoutedOutcome.Executed, answer.Outcome);
        Assert.Null(answer.Error);
        return Assert.IsType<ByteString>(answer.Response).ToByteArray();
    }

    private static CenterCaller OtherUser()
    {
        var caller = RoutedCalls.Session();
        caller.UserId = CommandIds.New();
        return caller;
    }

    private static ActorRef Actor(CenterCaller center, Id id) => new() { Origin = Origin.Remote, CenterCaller = center, RemoteCommandId = id };

    private static void AssertConflict(ArcError error)
    {
        Assert.Equal("command_id_reused", error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
    }

    private static void AssertUnknown(ArcError error)
    {
        Assert.Equal("operation_failed", error.Code);
        Assert.Equal("LEGACY_DRAIN", error.Details.State.State);
        Assert.Equal("legacy_task_outcome_unavailable", error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
    }

    private static void AssertHistoricalRows(NodeStore store, long receipts, long approvals,
        Id? taskId = null, TaskState state = TaskState.Queued, long revision = 0)
    {
        Assert.Equal(receipts, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        Assert.Equal(approvals, store.Read(reader => reader.Scalar("SELECT count(*) FROM approval;")));
        Assert.Equal(taskId is null ? 0L : 1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        if (taskId is not null)
        {
            Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE task_id = $id AND state = $state AND rev = $rev;",
                ("$id", taskId.Value.ToByteArray()), ("$state", (int)state), ("$rev", revision))));
        }

        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
    }

    // Real legacy handlers and SQLite with no listener, native execution supervisor or payload.
    private sealed class HistoricalNode : IAsyncDisposable
    {
        private readonly NodeLog _log;
        private readonly NodeRuntime _runtime;
        private readonly RoutedDispatcher _dispatcher;
        private readonly Id _nodeId;

        public HistoricalNode(InProcessNode files)
        {
            Store = NodeStore.Open(new NodeStoreOptions { DataRoot = files.DataRoot, BootIdentity = "routed-receipt-fixture", Clock = files.Clock });
            _log = new NodeLog(Path.Combine(files.DataRoot, "logs", "node"), LogLevel.Info, files.Clock);
            var journal = EventJournal.Open(Store);
            var hub = new StreamHub();
            Processor = new CommandProcessor(Store, journal, hub);
            _runtime = new NodeRuntime(Store, journal, hub, Processor, _log,
                new NodeSettingsManager(files.ConfigPath, files.DataRoot, _log), files.DataRoot, "offline-fixture", files.Clock,
                new RecoveryReport(false, false, null, Store.Opening), new CapabilityReport());
            Assert.Null(_runtime.Execution);
            _nodeId = new Id { Value = ByteString.CopyFrom(_runtime.NodeId.Span) };
            _dispatcher = new RoutedDispatcher(_runtime);
            _dispatcher.Bind(new TaskServiceHandler(_runtime, new ClientSessions()), new WorkspaceServiceHandler(_runtime), new FileServiceHandler(_runtime));
        }

        public NodeStore Store { get; }
        public CommandProcessor Processor { get; }

        public CenterCaller Relay(Origin origin) => new()
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = RoutedCalls.Account.Clone(),
            RelayingNodeId = _nodeId.Clone(),
            LocalOrigin = origin,
            LocalSessionId = CommandIds.New(),
        };

        public Task<RoutedAnswer> SubmitAsync(CenterCaller center, TaskServiceSubmitTaskRequest request, byte[]? raw = null) =>
            DispatchAsync(center, RoutedMethod.SubmitNodeTask, request.Meta, raw ?? request.ToByteArray());

        public Task<RoutedAnswer> CancelAsync(CenterCaller center, TaskServiceCancelTaskRequest request, byte[]? raw = null) =>
            DispatchAsync(center, RoutedMethod.CancelNodeTask, request.Meta, raw ?? request.ToByteArray());

        public async Task<ArcError> SubmitErrorAsync(CenterCaller center, TaskServiceSubmitTaskRequest request, byte[]? raw = null)
        {
            var answer = await SubmitAsync(center, request, raw);
            return Assert.IsType<ArcError>(answer.Error ?? TaskServiceSubmitTaskResponse.Parser.ParseFrom(ReplayBytes(answer)).Error);
        }

        public async Task<ArcError> CancelErrorAsync(CenterCaller center, TaskServiceCancelTaskRequest request, byte[]? raw = null)
        {
            var answer = await CancelAsync(center, request, raw);
            return Assert.IsType<ArcError>(answer.Error ?? TaskServiceCancelTaskResponse.Parser.ParseFrom(ReplayBytes(answer)).Error);
        }

        private async Task<RoutedAnswer> DispatchAsync(CenterCaller center, RoutedMethod method, RequestMeta meta, byte[] raw)
        {
            var now = _runtime.Clock.GetUtcNow();
            var header = new CallHeader
            {
                CallId = CommandIds.New(),
                Kid = "routed-receipt-fixture",
                AccountId = center.AccountId.Clone(),
                TargetNodeId = _nodeId.Clone(),
                Caller = center.Clone(),
                CommandId = meta.CommandId.Clone(),
                Method = method,
                RequestSha256 = ByteString.CopyFrom(SHA256.HashData(raw)),
                RequestSize = (uint)raw.Length,
                IssuedAt = ProtoTime.ToInstant(now.AddSeconds(-1)),
                ExpiresAt = ProtoTime.ToInstant(now.AddMinutes(1)),
                Deadline = ProtoTime.ToInstant(now.AddSeconds(9)),
            };
            var answer = await _dispatcher.DispatchAsync(new VerifiedCall(header, ByteString.CopyFrom(raw), 0), new RoutedCalls.TestLink(), Ct);
            return Assert.IsType<RoutedAnswer>(answer);
        }

        public async ValueTask DisposeAsync()
        {
            _dispatcher.Dispose();
            _runtime.Dispose();
            await Processor.DisposeAsync();
            _log.Dispose();
            Store.Dispose();
        }
    }
}
