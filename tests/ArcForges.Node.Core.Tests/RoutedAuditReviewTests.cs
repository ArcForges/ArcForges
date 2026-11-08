// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Security;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Independent review: a routed refusal is auditable exactly once, or it fails closed if the audit cannot be written.</summary>
public sealed class RoutedAuditReviewTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory(Timeout = 180_000)]
    [InlineData("malformed")]
    [InlineData("interactive")]
    [InlineData("privacy")]
    [InlineData("matrix")]
    public async Task EachRefusalHasExactlyOneClosedRemoteAudit(string kind)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var routed = new RoutedCalls(node);
        var caller = routed.Relay(Origin.Script);
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "output", "--bytes", "64");
        var taskId = await Tasks.SubmitAsync(human, spec);
        var task = await Tasks.WaitAsync(human, taskId);
        Assert.Equal(TaskState.Succeeded, task.State);
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
        if (kind == "privacy")
        {
            var request = new TaskServiceReadTaskOutputRequest { Meta = Tasks.Meta(), AttemptId = task.CurrentAttempt.AttemptId, MaxBytes = 10 };
            (answer, _) = await routed.CallAsync(caller, RoutedMethod.ReadNodeTaskOutput, request.ToByteArray());
        }
        else
        {
            if (kind == "malformed")
            {
                caller.LocalSessionId = null;
            }

            if (kind == "interactive")
            {
                spec.Priority = Priority.Interactive;
            }

            var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec };
            commandId = request.Meta.CommandId;
            (answer, _) = await routed.CallAsync(caller, RoutedMethod.SubmitNodeTask, request.ToByteArray(), commandId);
        }

        Assert.Equal(RoutedOutcome.RefusedByPolicy, answer!.Outcome);
        var rows = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Where(entry => entry.Seq > before && entry.Decision == PermissionDecision.Deny).ToList();
        var audit = Assert.Single(rows);
        Assert.Equal(Origin.Remote, audit.Actor.Origin);
        Assert.Equal(caller, audit.Actor.CenterCaller);
        Assert.Equal(commandId, audit.Actor.RemoteCommandId);
        Assert.StartsWith(expectedOperation + " ", audit.Operation, StringComparison.Ordinal);
        Assert.Equal("denied: " + answer.Error!.Details.State.Reason, audit.Outcome);
        Assert.DoesNotContain(Tasks.TestLoad, audit.Outcome, StringComparison.Ordinal);
        var storedCommand = node.Runtime.Store.Read(reader => reader.Scalar("SELECT remote_command_id FROM audit_log WHERE seq = $seq;", ("$seq", audit.Seq)));
        Assert.Equal(commandId?.Value.ToByteArray(), storedCommand as byte[]);
    }

    [Fact(Timeout = 180_000)]
    public async Task NewAndRepeatedApprovalsAndAgentDenialsEachHaveOneAudit()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var task = await Tasks.SubmitAsync(human, Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100"));
        var caller = routed.Relay(Origin.Script);
        var meta = Tasks.Meta();
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
            Assert.Equal(answer.Error!.Details.State.Resource.Id.Value.ToByteArray(), audit.ApprovalId);
        }

        Assert.Null((await Sched.ChangePolicyAsync(human, policy =>
        {
            policy.Agents.AllowedCommandPatterns.Clear();
            policy.Agents.AllowedCommandPatterns.Add("^no-such-command$");
        })).Error);
        await Tasks.WaitForAsync(() => !node.Runtime.Execution!.Settings.AgentCommandAllowed("audit-sensitive-marker"), TimeSpan.FromSeconds(30),
            "the restrictive agent pattern to be applied");
        var agent = routed.Relay(Origin.Agent);
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "audit-sensitive-marker") };
        var prior = node.Runtime.Store.Read(reader => AuditLog.Recent(reader)).Select(entry => entry.Seq).DefaultIfEmpty().Max();
        var denied = (await routed.SubmitAsync(agent, request)).Answer!;
        Assert.Equal((RoutedOutcome.RefusedByPolicy, "command_pattern_denied"), (denied.Outcome, denied.Error?.Code));
        var agentAudit = Assert.Single(node.Runtime.Store.Read(reader => AuditLog.Recent(reader)), entry => entry.Seq > prior
            && entry.Actor.RemoteCommandId?.Equals(request.Meta.CommandId) == true && entry.Decision == PermissionDecision.Deny);
        Assert.Equal("denied: " + denied.Error!.Details.State.Reason, agentAudit.Outcome);
        Assert.DoesNotContain("audit-sensitive-marker", agentAudit.Outcome, StringComparison.Ordinal);
        Assert.DoesNotContain(Tasks.TestLoad, agentAudit.Outcome, StringComparison.Ordinal);
    }

    [Theory(Timeout = 180_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AFullWriterQueueCannotDropTheAuditOfABodyRefusal(bool privacy)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var taskId = await Tasks.SubmitAsync(human, Tasks.Argv(node.Root, Tasks.TestLoad, "output", "--bytes", "10"));
        var task = await Tasks.WaitAsync(human, taskId);
        var routed = new RoutedCalls(node);
        var caller = routed.Relay(Origin.Script);
        using var release = new ManualResetEventSlim(false);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocker = node.Runtime.Processor.ExecuteAsync(_ => { entered.TrySetResult(); release.Wait(TimeSpan.FromSeconds(60)); return 0; });
        var pending = new List<Task<int>>();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            for (var n = 0; n < CommandProcessor.Capacity; n++) pending.Add(node.Runtime.Processor.ExecuteAsync(_ => 0));
            Assert.Equal(CommandProcessor.Capacity, node.Runtime.Processor.Queued);
            if (privacy)
            {
                var request = new TaskServiceReadTaskOutputRequest { Meta = Tasks.Meta(), AttemptId = task.CurrentAttempt.AttemptId, MaxBytes = 10 };
                var (answer, _) = await routed.CallAsync(caller, RoutedMethod.ReadNodeTaskOutput, request.ToByteArray(), record: false);
                Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
                var error = TaskServiceReadTaskOutputResponse.Parser.ParseFrom(answer.Response).Error;
                Assert.Equal(("overloaded", EffectCertainty.DidNotHappen, RetryMode.AfterTime), (error.Code, error.Effect, error.Retry.Mode));
            }
            else
            {
                var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100");
                spec.Priority = Priority.Interactive;
                var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec };
                var (answer, response) = await routed.SubmitAsync(caller, request, record: false);
                Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
                Assert.Equal(("overloaded", EffectCertainty.DidNotHappen, RetryMode.AfterTime),
                    (response!.Error?.Code, response.Error?.Effect, response.Error?.Retry.Mode));
            }
        }
        finally
        {
            release.Set();
            await blocker;
            await Task.WhenAll(pending);
        }
    }

    [Fact(Timeout = 180_000)]
    public async Task AFullWriterQueueDoesNotReturnAnUnauditedPolicyRefusal()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
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
            var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100") };
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
}
