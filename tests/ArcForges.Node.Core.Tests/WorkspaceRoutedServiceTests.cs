// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real node, SQLite and filesystem through the internal routed seam; no signature or real-center E2E is claimed.</summary>
public sealed class WorkspaceRoutedServiceTests
{
    private static readonly Origin[] RefusedOrigins = [Origin.Script, Origin.Agent];

    [Fact(Timeout = 120_000)]
    public async Task RoutedHumanRegistrationReadReplayAndUnregisterAreRealAndAgentCannotRegister()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var path = Directory.CreateDirectory(Path.Combine(node.Root, "registered-root")).FullName;
        var marker = Path.Combine(path, "marker");
        File.WriteAllText(marker, "unchanged");
        var meta = Tasks.Meta();
        var request = new WorkspaceServiceRegisterWorkspaceRequest { Meta = meta.Clone(), Path = path, Name = "demo" };

        foreach (var origin in RefusedOrigins)
        {
            var deniedRequest = request.Clone();
            deniedRequest.Meta = Tasks.Meta();
            var denied = await calls.CallAsync(calls.Relay(origin), RoutedMethod.RegisterNodeWorkspace,
                deniedRequest.ToByteArray(), deniedRequest.Meta.CommandId);
            Assert.Equal(RoutedOutcome.RefusedByPolicy, denied.Answer!.Outcome);
            Assert.Equal("permission_denied", denied.Answer.Error!.Code);
        }

        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        var human = calls.Relay(Origin.Human);
        await using var humanChannel = await node.ChannelAsync(helloAsHuman: true);
        var handler = calls.Dispatcher.WorkspaceHandlerForTests!;
        handler.AfterPrepareForTests = async _ =>
        {
            var changedPolicy = await Sched.ChangePolicyAsync(humanChannel, policy => (policy.CenterRouted ??= new CenterRoutedPolicy()).Enabled = false);
            Assert.Null(changedPolicy.Error);
        };
        var stalePolicyRequest = request.Clone();
        stalePolicyRequest.Meta = Tasks.Meta();
        var stalePolicy = await calls.CallAsync(human, RoutedMethod.RegisterNodeWorkspace,
            stalePolicyRequest.ToByteArray(), stalePolicyRequest.Meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, stalePolicy.Answer!.Outcome);
        Assert.Equal("center_routed_disabled", stalePolicy.Answer.Error!.Details.State.Reason);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id=$id;", ("$id", stalePolicyRequest.Meta.CommandId.Value.ToByteArray()))));
        handler.AfterPrepareForTests = null;
        Assert.Null((await Sched.ChangePolicyAsync(humanChannel, policy => policy.CenterRouted.Enabled = true)).Error);

        var droppedRequest = request.Clone();
        droppedRequest.Meta = Tasks.Meta();
        // The real dispatcher and writer run; this seam switches the link off on the final pre-effect recheck.
        calls.Link.Reset(usableFor: 5);
        var dropped = await calls.CallAsync(human, RoutedMethod.RegisterNodeWorkspace,
            droppedRequest.ToByteArray(), droppedRequest.Meta.CommandId);
        Assert.Null(dropped.Answer);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id=$id;", ("$id", droppedRequest.Meta.CommandId.Value.ToByteArray()))));
        calls.Link.Reset();
        var first = await calls.CallAsync(human, RoutedMethod.RegisterNodeWorkspace, request.ToByteArray(), meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, first.Answer!.Outcome);
        var registered = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(first.Answer.Response);
        Assert.Null(registered.Error);
        Assert.NotNull(registered.Value.Workspace);
        Assert.Equal(path, registered.Value.Workspace.RootPath);
        Assert.Equal("demo", registered.Value.Workspace.Name);
        Assert.NotNull(registered.Audit);
        var id = registered.Value.Workspace.WorkspaceId;
        Assert.Equal(id.Value.ToByteArray(), first.Answer.WorkspaceId);
        foreach (var origin in RefusedOrigins)
        {
            var deniedRemove = new WorkspaceServiceUnregisterWorkspaceRequest { Meta = Tasks.Meta(), WorkspaceId = id };
            var denied = await calls.CallAsync(calls.Relay(origin), RoutedMethod.UnregisterNodeWorkspace,
                deniedRemove.ToByteArray(), deniedRemove.Meta.CommandId);
            Assert.Equal(RoutedOutcome.RefusedByPolicy, denied.Answer!.Outcome);
            Assert.Equal("permission_denied", denied.Answer.Error!.Code);
        }

        var foreignRequest = request.Clone();
        foreignRequest.Meta = Tasks.Meta();
        var foreign = await calls.CallAsync(calls.Relay(Origin.Human, ownNode: false), RoutedMethod.RegisterNodeWorkspace,
            foreignRequest.ToByteArray(), foreignRequest.Meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, foreign.Answer!.Outcome);
        Assert.Equal("relay_own_node_only", foreign.Answer.Error!.Details.State.Reason);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));

        var replay = await calls.CallAsync(human, RoutedMethod.RegisterNodeWorkspace, request.ToByteArray(), meta.CommandId);
        Assert.Equal(first.Answer.Response, replay.Answer!.Response);

        var foreignReplay = await calls.CallAsync(RoutedCalls.Session(), RoutedMethod.RegisterNodeWorkspace, request.ToByteArray(), meta.CommandId);
        Assert.Equal("command_id_reused", WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(foreignReplay.Answer!.Response).Error.Code);

        var changed = request.Clone();
        changed.Name = "other";
        var conflict = await calls.CallAsync(human, RoutedMethod.RegisterNodeWorkspace, changed.ToByteArray(), meta.CommandId);
        Assert.Equal("command_id_reused", WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(conflict.Answer!.Response).Error.Code);

        var getRequest = new WorkspaceServiceGetWorkspaceRequest { WorkspaceId = id };
        var get = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.GetNodeWorkspace, getRequest.ToByteArray());
        var got = WorkspaceServiceGetWorkspaceResponse.Parser.ParseFrom(get.Answer!.Response);
        Assert.Null(got.Error);
        Assert.Equal(id, got.Value.Workspace.WorkspaceId);
        Assert.Equal(WorkspaceAuditMetadata.ForRecords([got.Value.Workspace]), got.Audit);

        // RequestMeta is generic context, not an authority to redirect the explicit operation target.
        var unrelatedId = CommandIds.New();
        var scopedGet = new WorkspaceServiceGetWorkspaceRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New(), WorkspaceId = unrelatedId },
            WorkspaceId = id,
        };
        var scoped = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.GetNodeWorkspace, scopedGet.ToByteArray());
        Assert.Equal(id, WorkspaceServiceGetWorkspaceResponse.Parser.ParseFrom(scoped.Answer!.Response).Value.Workspace.WorkspaceId);
        Assert.Equal(id.Value.ToByteArray(), scoped.Answer.WorkspaceId);

        // The published policy has operation/origin overrides, not a per-workspace permission field.
        // Its narrower AGENT deny must block both Get and the entire List, irrespective of metadata.
        Assert.Null((await Sched.ChangePolicyAsync(humanChannel, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.WorkspaceRead,
            Origin = Origin.Agent,
            Decision = PermissionDecision.Deny,
        }))).Error);
        var deniedGet = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.GetNodeWorkspace, scopedGet.ToByteArray());
        Assert.Equal(RoutedOutcome.RefusedByPolicy, deniedGet.Answer!.Outcome);
        Assert.Equal(id.Value.ToByteArray(), deniedGet.Answer.WorkspaceId);
        Assert.Equal("permission_denied", deniedGet.Answer.Error!.Code);
        var deniedList = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.ListNodeWorkspaces,
            new WorkspaceServiceListWorkspacesRequest { Meta = new RequestMeta { CorrelationId = CommandIds.New(), WorkspaceId = unrelatedId } }.ToByteArray());
        Assert.Equal(RoutedOutcome.RefusedByPolicy, deniedList.Answer!.Outcome);
        Assert.Equal("permission_denied", deniedList.Answer.Error!.Code);
        Assert.Null((await Sched.ChangePolicyAsync(humanChannel, policy => policy.Permissions.Clear())).Error);

        // Change actual policy after the first read authorization. The workspace's transactional last-used update
        // must not occur when the current policy is denied; this is not a simulated target or center result.
        var revisionBefore = node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT rev FROM workspace WHERE workspace_id=$id;", ("$id", id.Value.ToByteArray())));
        handler.BeforeReadUseForTests = async _ =>
        {
            var result = await Sched.ChangePolicyAsync(humanChannel, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.WorkspaceRead,
                Origin = Origin.Agent,
                Decision = PermissionDecision.Deny,
            }));
            Assert.Null(result.Error);
        };
        var revoked = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.GetNodeWorkspace, scopedGet.ToByteArray());
        Assert.Equal(RoutedOutcome.RefusedByPolicy, revoked.Answer!.Outcome);
        Assert.Equal(revisionBefore, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT rev FROM workspace WHERE workspace_id=$id;", ("$id", id.Value.ToByteArray()))));
        handler.BeforeReadUseForTests = null;
        Assert.Null((await Sched.ChangePolicyAsync(humanChannel, policy => policy.Permissions.Clear())).Error);

        var invalidRead = new WorkspaceServiceGetWorkspaceRequest { Meta = Tasks.Meta(), WorkspaceId = id };
        var invalid = await calls.CallAsync(human, RoutedMethod.GetNodeWorkspace, invalidRead.ToByteArray());
        Assert.Equal("invalid_argument", WorkspaceServiceGetWorkspaceResponse.Parser.ParseFrom(invalid.Answer!.Response).Error.Code);
        Assert.Equal(id.Value.ToByteArray(), invalid.Answer.WorkspaceId);

        var listRequest = new WorkspaceServiceListWorkspacesRequest { Meta = new RequestMeta { CorrelationId = CommandIds.New() } };
        var listed = await calls.CallAsync(human, RoutedMethod.ListNodeWorkspaces, listRequest.ToByteArray());
        var list = WorkspaceServiceListWorkspacesResponse.Parser.ParseFrom(listed.Answer!.Response);
        Assert.Null(list.Error);
        Assert.Equal(id, Assert.Single(list.Value.Workspaces).WorkspaceId);
        Assert.Equal(WorkspaceAuditMetadata.ForRecords(list.Value.Workspaces), list.Audit);

        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        using var use = manager.OpenForUse(id.Value.Span, ct);
        var removeMeta = Tasks.Meta();
        removeMeta.WorkspaceId = unrelatedId;
        var remove = new WorkspaceServiceUnregisterWorkspaceRequest { Meta = removeMeta, WorkspaceId = id };
        var inUse = await calls.CallAsync(human, RoutedMethod.UnregisterNodeWorkspace, remove.ToByteArray(), removeMeta.CommandId);
        Assert.Equal("in_use", WorkspaceServiceUnregisterWorkspaceResponse.Parser.ParseFrom(inUse.Answer!.Response).Error.Code);
        Assert.Equal("unchanged", File.ReadAllText(marker));
        use.Dispose();
        remove.Meta = Tasks.Meta();
        remove.Meta.WorkspaceId = unrelatedId;
        var removed = await calls.CallAsync(human, RoutedMethod.UnregisterNodeWorkspace, remove.ToByteArray(), remove.Meta.CommandId);
        var receipt = WorkspaceServiceUnregisterWorkspaceResponse.Parser.ParseFrom(removed.Answer!.Response);
        Assert.Null(receipt.Error);
        Assert.Equal(EffectCertainty.Happened, receipt.Value.Receipt.Effect);
        Assert.Equal("unchanged", File.ReadAllText(marker));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NULL;")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE removed_at IS NOT NULL;")));
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_workspace_audit;"))! >= 6);
    }
}
