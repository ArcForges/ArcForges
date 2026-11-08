// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Security;

namespace ArcForges.Node.Core.Tests;

/// <summary>Independent review: Wait keeps its task result while denying an unauthorized optional output tail.</summary>
public sealed class RoutedWaitTailReviewTests
{
    [Theory(Timeout = 180_000)]
    [InlineData(Origin.Unspecified, true, Origin.Remote)]
    [InlineData(Origin.Script, true, Origin.Script)]
    [InlineData(Origin.Agent, true, Origin.Agent)]
    [InlineData(Origin.Unspecified, false, Origin.Remote)]
    [InlineData(Origin.Script, false, Origin.Script)]
    [InlineData(Origin.Agent, false, Origin.Agent)]
    public async Task WaitOmitsTailWhenTheOutputPermissionIsNarrowed(Origin relayOrigin, bool own, Origin deniedOrigin)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.SkipWhen(node.Runtime.Execution is null, "The node has no execution supervisor.");
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var routed = new RoutedCalls(node);
        var caller = relayOrigin == Origin.Unspecified ? RoutedCalls.Session() : routed.Relay(relayOrigin);
        var spec = Tasks.Argv(node.Root, Tasks.TestLoad, "output", "--bytes", "512");
        Id taskId;
        if (own)
        {
            var submitted = (await routed.SubmitAsync(caller, new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = spec })).Response!;
            Assert.Null(submitted.Error);
            taskId = submitted.Value.TaskId;
        }
        else
        {
            taskId = await Tasks.SubmitAsync(human, spec);
        }

        Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(human, taskId)).State);

        async Task<TaskServiceWaitTaskValue> Wait(uint bytes)
        {
            var request = new TaskServiceWaitTaskRequest { Meta = Tasks.Meta(), TaskId = taskId, TailBytes = bytes };
            var (answer, response) = await routed.ReadAsync(caller, RoutedMethod.WaitNodeTask, request, TaskServiceWaitTaskResponse.Parser);
            Assert.Equal(RoutedOutcome.Executed, answer!.Outcome);
            Assert.Null(response!.Error);
            return response.Value;
        }

        if (!own)
        {
            Assert.False((await Wait(20)).HasTail);
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => (policy.Privacy ??= new PrivacyPolicy()).RemoteOutputTail = true)).Error);
        }

        var allowed = await Wait(20);
        Assert.True(allowed.HasTail);
        Assert.Equal(20, allowed.Tail.Length);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.TaskReadOutput,
            Origin = deniedOrigin,
            Decision = PermissionDecision.Deny,
        }))).Error);

        var denied = await Wait(20);
        Assert.Equal(taskId, denied.Task.TaskId);
        Assert.True(denied.Reached);
        Assert.False(denied.HasTail);
        Assert.False(denied.HasTailTruncated);
        var noTail = await Wait(0);
        Assert.Equal(taskId, noTail.Task.TaskId);
        Assert.False(noTail.HasTail);
        Assert.False(noTail.HasTailTruncated);
    }
}
