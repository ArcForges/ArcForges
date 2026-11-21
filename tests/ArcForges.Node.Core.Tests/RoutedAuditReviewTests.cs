// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using OutputIndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.Node.Core.Tests;

/// <summary>Independent review: a routed refusal is auditable exactly once, or it fails closed if the audit cannot be written.</summary>
public sealed class RoutedAuditReviewTests
{
    private const string CommandName = "routed-audit-fixture-command";
    private const string PrivateMarker = "audit-sensitive-marker";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory(Timeout = 180_000)]
    [InlineData("malformed", CenterRouting.Incomplete)]
    [InlineData("relay", CenterRouting.OwnNodeOnly)]
    [InlineData("privacy", "remote_output_tail_off")]
    [InlineData("matrix", "permission_override")]
    public async Task EachRefusalHasExactlyOneClosedRemoteAudit(string kind, string reason)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var attemptId = kind == "privacy" ? SeedPrivateOutput(node) : null;
        await node.StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var routed = new RoutedCalls(node);
        var caller = routed.Relay(Origin.Script, ownNode: kind != "relay");
        if (kind == "matrix")
        {
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.TaskSubmit,
                Origin = Origin.Remote,
                Decision = PermissionDecision.Deny,
            }))).Error);
        }

        var before = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Select(entry => entry.Seq).DefaultIfEmpty().Max();
        Id? commandId = null;
        RoutedAnswer? answer;
        var expectedOperation = kind == "privacy" ? PermissionMatrix.TaskReadOutput : PermissionMatrix.TaskSubmit;
        if (attemptId is not null)
        {
            var request = ReadOutput(attemptId);
            var local = await human.Tasks.ReadTaskOutputAsync(request, cancellationToken: Ct);
            Assert.Null(local.Error);
            Assert.Equal(PrivateMarker, local.Value.Data.ToStringUtf8());
            (answer, _) = await routed.CallAsync(caller, RoutedMethod.ReadNodeTaskOutput, request.ToByteArray());
        }
        else
        {
            if (kind == "malformed")
            {
                caller.LocalSessionId = null;
            }

            var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, CommandName, PrivateMarker) };
            commandId = request.Meta.CommandId;
            (answer, _) = await routed.CallAsync(caller, RoutedMethod.SubmitNodeTask, request.ToByteArray(), commandId);
        }

        Assert.Equal(RoutedOutcome.RefusedByPolicy, answer!.Outcome);
        Assert.Null(answer.Response);
        Assert.Equal(("permission_denied", reason), (answer.Error?.Code, answer.Error?.Details.State.Reason));
        var rows = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Where(entry => entry.Seq > before && entry.Decision == PermissionDecision.Deny).ToList();
        var audit = Assert.Single(rows);
        Assert.Equal(Origin.Remote, audit.Actor.Origin);
        Assert.Equal(caller, audit.Actor.CenterCaller);
        Assert.Equal(commandId, audit.Actor.RemoteCommandId);
        Assert.StartsWith(expectedOperation + " ", audit.Operation, StringComparison.Ordinal);
        Assert.Equal("denied: " + reason, audit.Outcome);
        Assert.DoesNotContain(CommandName, audit.Outcome, StringComparison.Ordinal);
        Assert.DoesNotContain(PrivateMarker, audit.Outcome, StringComparison.Ordinal);
        var storedCommand = node.Runtime.Store.Read(reader => reader.Scalar("SELECT remote_command_id FROM audit_log WHERE seq = $seq;", ("$seq", audit.Seq)));
        Assert.Equal(commandId?.Value.ToByteArray(), storedCommand as byte[]);
    }

    [Fact(Timeout = 180_000)]
    public async Task NewAndRepeatedApprovalsAndAgentDenialsEachHaveOneAudit()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var routed = new RoutedCalls(node);
        var task = SeedQueuedTask(node);
        var caller = routed.Relay(Origin.Script);
        var meta = Tasks.Meta();
        Id? approvalId = null;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var before = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Select(entry => entry.Seq).DefaultIfEmpty().Max();
            var answer = (await routed.CancelAsync(caller, task, meta)).Answer!;
            Assert.Equal((RoutedOutcome.RefusedByPolicy, "approval_required"), (answer.Outcome, answer.Error?.Code));
            var entries = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Where(entry => entry.Seq > before
                && entry.Actor.RemoteCommandId?.Equals(meta.CommandId) == true
                && entry.Decision is PermissionDecision.Approval or PermissionDecision.Deny).ToList();
            var audit = Assert.Single(entries);
            Assert.Equal(PermissionDecision.Approval, audit.Decision);
            Assert.Equal("denied: approval_required", audit.Outcome);
            Assert.Equal(Origin.Remote, audit.Actor.Origin);
            Assert.Equal(caller, audit.Actor.CenterCaller);
            var current = answer.Error!.Details.State.Resource.Id;
            approvalId ??= current;
            Assert.Equal(approvalId, current);
            Assert.Equal(current.Value.ToByteArray(), audit.ApprovalId);
        }

        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM approval;")));
        Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(human, task)).State);

        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.TaskSubmit,
            Origin = Origin.Agent,
            Decision = PermissionDecision.Deny,
        }))).Error);
        var agent = routed.Relay(Origin.Agent);
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, CommandName, PrivateMarker) };
        var prior = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Select(entry => entry.Seq).DefaultIfEmpty().Max();
        var denied = (await routed.SubmitAsync(agent, request)).Answer!;
        Assert.Equal((RoutedOutcome.RefusedByPolicy, "permission_denied", "permission_override"),
            (denied.Outcome, denied.Error?.Code, denied.Error?.Details.State.Reason));
        var agentAudit = Assert.Single(node.Runtime.Store.Read(reader => AuditLog.Recent(reader)), entry => entry.Seq > prior
            && entry.Actor.RemoteCommandId?.Equals(request.Meta.CommandId) == true && entry.Decision == PermissionDecision.Deny);
        Assert.Equal(Origin.Remote, agentAudit.Actor.Origin);
        Assert.Equal(agent, agentAudit.Actor.CenterCaller);
        Assert.Equal("denied: permission_override", agentAudit.Outcome);
        Assert.DoesNotContain(PrivateMarker, agentAudit.Outcome, StringComparison.Ordinal);
        Assert.DoesNotContain(CommandName, agentAudit.Outcome, StringComparison.Ordinal);
    }

    [Theory(Timeout = 180_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AFullWriterQueueCannotDropTheAuditOfABodyRefusal(bool privacy)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var attemptId = privacy ? SeedPrivateOutput(node) : null;
        await node.StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var routed = new RoutedCalls(node);
        var caller = routed.Relay(Origin.Script);
        TaskServiceCancelTaskRequest? cancel = null;
        if (!privacy)
        {
            var queued = SeedQueuedTask(node);
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.TaskCancelOthers,
                Origin = Origin.Remote,
                Decision = PermissionDecision.Deny,
            }))).Error);

            cancel = new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = queued };
            var originalCommandId = cancel.Meta.CommandId;
            var (normal, _) = await routed.CallAsync(caller, RoutedMethod.CancelNodeTask, cancel.ToByteArray(), originalCommandId);
            Assert.NotNull(normal);
            Assert.Equal((RoutedOutcome.RefusedByPolicy, "permission_denied", PermissionMatrix.TaskCancelOthers, "permission_override"),
                (normal.Outcome, normal.Error?.Code, normal.Error?.Details.State.State, normal.Error?.Details.State.Reason));
            Assert.Null(normal.Response);
            var audit = Assert.Single(node.Runtime.Store.Read(reader => AuditLog.Recent(reader)),
                entry => entry.Actor.RemoteCommandId?.Equals(originalCommandId) == true);
            Assert.Equal(PermissionDecision.Deny, audit.Decision);
            Assert.Equal(PermissionMatrix.TaskCancelOthers + " TaskService.CancelTask", audit.Operation);
            Assert.Equal("denied: permission_override", audit.Outcome);
            Assert.Equal("task", audit.TargetKind);
            Assert.Equal(queued.Value.ToByteArray(), audit.TargetId);
            Assert.Equal(Origin.Remote, audit.Actor.Origin);
            Assert.Equal(caller, audit.Actor.CenterCaller);
            Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(human, queued)).State);

            cancel.Meta = Tasks.Meta();
            Assert.NotEqual(originalCommandId, cancel.Meta.CommandId);
        }

        var before = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Select(entry => entry.Seq).DefaultIfEmpty().Max();
        using var release = new ManualResetEventSlim(false);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocker = node.Runtime.Processor.ExecuteAsync(_ => { entered.TrySetResult(); release.Wait(TimeSpan.FromSeconds(60)); return 0; });
        var pending = new List<Task<int>>();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            for (var n = 0; n < CommandProcessor.Capacity; n++) pending.Add(node.Runtime.Processor.ExecuteAsync(_ => 0));
            Assert.Equal(CommandProcessor.Capacity, node.Runtime.Processor.Queued);
            if (attemptId is not null)
            {
                var request = ReadOutput(attemptId);
                var (answer, _) = await routed.CallAsync(caller, RoutedMethod.ReadNodeTaskOutput, request.ToByteArray(), record: false);
                Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
                var response = TaskServiceReadTaskOutputResponse.Parser.ParseFrom(answer.Response);
                Assert.Null(response.Value);
                var error = response.Error;
                Assert.Equal(("overloaded", EffectCertainty.DidNotHappen, RetryMode.AfterTime), (error.Code, error.Effect, error.Retry.Mode));
            }
            else
            {
                Assert.NotNull(cancel);
                var (answer, _) = await routed.CallAsync(caller, RoutedMethod.CancelNodeTask, cancel.ToByteArray(), cancel.Meta.CommandId, record: false);
                Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
                var response = TaskServiceCancelTaskResponse.Parser.ParseFrom(answer.Response);
                Assert.Equal(("overloaded", EffectCertainty.DidNotHappen, RetryMode.AfterTime),
                    (response.Error?.Code, response.Error?.Effect, response.Error?.Retry.Mode));
                Assert.Null(response.Value);
            }
        }
        finally
        {
            release.Set();
            await blocker;
            await Task.WhenAll(pending);
        }

        Assert.DoesNotContain(node.Runtime.Store.Read(reader => AuditLog.Recent(reader)), entry => entry.Seq > before
            && entry.Actor.CenterCaller?.Equals(caller) == true);
        if (cancel is not null)
        {
            Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(human, cancel.TaskId)).State);
        }
    }

    [Fact(Timeout = 180_000)]
    public async Task AFullWriterQueueDoesNotReturnAnUnauditedPolicyRefusal()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => (policy.CenterRouted ??= new CenterRoutedPolicy()).Enabled = false)).Error);
        var routed = new RoutedCalls(node);
        using var release = new ManualResetEventSlim(false);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocker = node.Runtime.Processor.ExecuteAsync(_ =>
        {
            entered.TrySetResult();
            release.Wait(TimeSpan.FromSeconds(60));
            return 0;
        });
        var pending = new List<Task<int>>();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            for (var n = 0; n < CommandProcessor.Capacity; n++)
            {
                pending.Add(node.Runtime.Processor.ExecuteAsync(_ => 0));
            }

            Assert.Equal(CommandProcessor.Capacity, node.Runtime.Processor.Queued);
            var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, CommandName, PrivateMarker) };
            var (answer, response) = await routed.SubmitAsync(routed.Relay(Origin.Script), request, record: false);
            Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
            Assert.Equal(("overloaded", EffectCertainty.DidNotHappen, RetryMode.AfterTime),
                (response!.Error?.Code, response.Error?.Effect, response.Error?.Retry?.Mode));
        }
        finally
        {
            release.Set();
            await blocker;
            await Task.WhenAll(pending);
        }
    }

    private static Id SeedQueuedTask(InProcessNode node) => node.Runtime.Store.Write(transaction =>
        LegacyTaskHistoryFixture.SeedQueued(transaction, new ActorRef { Origin = Origin.Human }), CommitDurability.Full);

    private static Id SeedPrivateOutput(InProcessNode node)
    {
        var (_, attemptId) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished);
        var files = Tasks.Files(node, attemptId);
        var data = ByteString.CopyFromUtf8(PrivateMarker).ToByteArray();
        Directory.CreateDirectory(files.Directory);
        File.WriteAllBytes(files.StdoutPath, data);
        var index = new byte[OutputIndexRecord.Size];
        new OutputIndexRecord(OutputStreamKind.Stdout, 0, (uint)data.Length, 1_700_000_000_000_000_000, OutputChunkMarks.None).Write(index);
        File.WriteAllBytes(files.IndexPath, index);
        return attemptId;
    }

    private static TaskServiceReadTaskOutputRequest ReadOutput(Id attemptId) => new()
    {
        Meta = Tasks.Meta(),
        AttemptId = attemptId,
        MaxBytes = (uint)PrivateMarker.Length,
    };
}
