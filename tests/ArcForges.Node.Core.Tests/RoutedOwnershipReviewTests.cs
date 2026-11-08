// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed class RoutedOwnershipReviewTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 180_000)]
    public async Task RecordedErrorsAndApprovalsBelongToTheRequesterAndSurviveRestart()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var owner = RoutedCalls.Session();
        var foreign = routed.Relay(Origin.Script);
        var absentTask = CommandIds.New();
        var errorMeta = Tasks.Meta();
        var firstError = (await routed.CancelAsync(owner, absentTask, errorMeta)).Response!;
        Assert.Equal("not_found", firstError.Error?.Code);
        Assert.Equal(firstError.ToByteArray(), (await routed.CancelAsync(RoutedCalls.Session(), absentTask, errorMeta)).Response!.ToByteArray());
        Assert.Equal("command_id_reused", (await routed.CancelAsync(foreign, absentTask, errorMeta)).Response!.Error?.Code);

        var task = await Tasks.SubmitAsync(human, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100"));
        var approvalMeta = Tasks.Meta();
        var raised = (await routed.CancelAsync(owner, task, approvalMeta)).Answer!;
        Assert.Equal("approval_required", raised.Error?.Code);
        var decision = await human.Approvals.DecideApprovalAsync(new ApprovalServiceDecideApprovalRequest
        {
            Meta = Tasks.Meta(),
            ApprovalId = raised.Error!.Details.State.Resource.Id,
            Decision = ApprovalDecisionKind.Approve,
        }, cancellationToken: Ct);
        Assert.Null(decision.Error);
        Assert.Equal(ApprovalState.Executed, decision.Value.Approval.State);
        var marker = node.Runtime.Store.Read(reader => AuditLog.Recent(reader).Single(entry => entry.TargetKind == RoutedCommandOwnership.TargetKind
            && entry.Actor.RemoteCommandId?.Equals(approvalMeta.CommandId) == true));
        Assert.Equal(Origin.Remote, marker.Actor.Origin);
        Assert.Equal(owner, marker.Actor.CenterCaller);
        Assert.Equal("routed command outcome recorded", marker.Outcome);
        Assert.Equal(PermissionDecision.Unspecified, marker.Decision);
        var accepted = (await routed.CancelAsync(RoutedCalls.Session(), task, approvalMeta)).Response!;
        Assert.Null(accepted.Error);
        Assert.Equal("command_id_reused", (await routed.CancelAsync(foreign, task, approvalMeta)).Response!.Error?.Code);

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var restarted = new RoutedCalls(node);
        Assert.Equal(firstError.ToByteArray(), (await restarted.CancelAsync(RoutedCalls.Session(), absentTask, errorMeta)).Response!.ToByteArray());
        Assert.Equal(accepted.ToByteArray(), (await restarted.CancelAsync(RoutedCalls.Session(), task, approvalMeta)).Response!.ToByteArray());
        Assert.Equal("command_id_reused", (await restarted.CancelAsync(foreign, task, approvalMeta)).Response!.Error?.Code);
    }

    [Fact(Timeout = 180_000)]
    public async Task MissingOwnershipFailsClosedAndExpiredIdCanStartANewGeneration()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var owner = RoutedCalls.Session();
        var foreign = routed.Relay(Origin.Script);
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100") };
        var original = (await routed.SubmitAsync(owner, request)).Response!;
        Assert.Null(original.Error);
        var id = request.Meta.CommandId.Value.ToByteArray();
        await node.Runtime.Processor.ExecuteAsync(context => context.Transaction.Execute(
            "DELETE FROM audit_log WHERE target_kind = $kind AND remote_command_id = $id;", ("$kind", RoutedCommandOwnership.TargetKind), ("$id", id)));
        Assert.Equal("command_id_reused", (await routed.SubmitAsync(RoutedCalls.Session(), request)).Response!.Error?.Code);
        Assert.Equal("command_id_reused", (await routed.SubmitAsync(foreign, request)).Response!.Error?.Code);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;", ("$id", id))));

        // Restore the original marker in this isolated fixture so the expired generation remains in audit retention.
        await node.Runtime.Processor.ExecuteAsync(context =>
        {
            RoutedCommandOwnership.Record(context.Transaction, id, new ActorRef { Origin = Origin.Remote, CenterCaller = owner, RemoteCommandId = request.Meta.CommandId });
            context.Transaction.Execute("UPDATE command_dedup SET expires_at = $expired WHERE command_id = $id;",
                ("$expired", context.Transaction.NowMicroseconds - 1), ("$id", id));
            return 0;
        });
        var replacement = (await routed.SubmitAsync(foreign, request)).Response!;
        Assert.Null(replacement.Error);
        Assert.NotEqual(original.Value.TaskId, replacement.Value.TaskId);
        Assert.Equal(replacement.ToByteArray(), (await routed.SubmitAsync(routed.Relay(Origin.Script), request)).Response!.ToByteArray());
        Assert.Equal("command_id_reused", (await routed.SubmitAsync(owner, request)).Response!.Error?.Code);
        Assert.Equal(2L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;", ("$id", id))));
        Assert.Equal(2L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(DISTINCT at) FROM audit_log WHERE target_kind = $kind AND remote_command_id = $id;", ("$kind", RoutedCommandOwnership.TargetKind), ("$id", id))));
    }

    [Fact(Timeout = 180_000)]
    public async Task PendingApprovalCannotBeReusedForAnotherMethodByTheSameCaller()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var task = await Tasks.SubmitAsync(human, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100"));
        var routed = new RoutedCalls(node);
        var owner = RoutedCalls.Session();
        var meta = Tasks.Meta();
        Assert.Equal("approval_required", (await routed.CancelAsync(owner, task, meta)).Answer!.Error?.Code);
        var submit = new TaskServiceSubmitTaskRequest { Meta = meta, Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100") };
        Assert.Equal("command_id_reused", (await routed.SubmitAsync(owner, submit)).Response!.Error?.Code);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;",
            ("$id", meta.CommandId.Value.ToByteArray()))));
    }

    [Fact(Timeout = 180_000)]
    public async Task OwnershipSharesTheOutcomeTransactionAndRetentionProtectsLiveRows()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var owner = RoutedCalls.Session();
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100") };
        var response = (await routed.SubmitAsync(owner, request)).Response!;
        Assert.Null(response.Error);
        var id = request.Meta.CommandId.Value.ToByteArray();
        await node.Runtime.Processor.ExecuteAsync(context =>
        {
            var old = context.Transaction.NowMicroseconds - (366L * 24 * 60 * 60 * 1_000_000);
            context.Transaction.Execute("UPDATE command_dedup SET created_at = $old WHERE command_id = $id;", ("$old", old), ("$id", id));
            context.Transaction.Execute("UPDATE audit_log SET at = $old WHERE target_kind = $kind AND remote_command_id = $id;",
                ("$old", old), ("$kind", RoutedCommandOwnership.TargetKind), ("$id", id));
            AuditLog.Prune(context.Transaction);
            return 0;
        });
        Assert.Equal(response.ToByteArray(), (await routed.SubmitAsync(RoutedCalls.Session(), request)).Response!.ToByteArray());
        var plan = node.Runtime.Store.Read(reader =>
        {
            using var command = reader.CreateCommand("EXPLAIN QUERY PLAN SELECT actor FROM audit_log WHERE at = $at AND target_kind = $kind AND remote_command_id = $id ORDER BY seq DESC LIMIT 1;");
            command.Parameters.AddWithValue("$at", 0L);
            command.Parameters.AddWithValue("$kind", RoutedCommandOwnership.TargetKind);
            command.Parameters.AddWithValue("$id", id);
            using var rows = command.ExecuteReader();
            var details = new List<string>();
            while (rows.Read()) details.Add(rows.GetString(3));
            return details;
        });
        Assert.Contains(plan, detail => detail.Contains("ix_audit_log__at", StringComparison.Ordinal));

        var rolledBack = CommandIds.New();
        var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = owner, RemoteCommandId = rolledBack };
        var synthetic = new TaskServiceCancelTaskResponse { Error = NodeErrors.InvalidArgument("recorded error") }.ToByteArray();
        await Assert.ThrowsAsync<InvalidOperationException>(() => node.Runtime.Processor.ExecuteIdempotentAsync(rolledBack.Value.Memory,
            "arcforges.node.v1.TaskService/CancelTask", new byte[32], Origin.Remote, _ => synthetic, afterComplete: context =>
            {
                RoutedCommandOwnership.Record(context.Transaction, rolledBack.Value.Span, actor);
                throw new InvalidOperationException("rollback test");
            }));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", rolledBack.Value.ToByteArray()))));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM audit_log WHERE at >= 0 AND target_kind = $kind AND remote_command_id = $id;",
            ("$kind", RoutedCommandOwnership.TargetKind), ("$id", rolledBack.Value.ToByteArray()))));
    }
}
