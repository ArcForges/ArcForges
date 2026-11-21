// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real node, SQLite and filesystem through the internal routed seam; no signature or real-center E2E is claimed.</summary>
public sealed class WorkspaceRoutedServiceTests
{
    private static readonly Origin[] RefusedOrigins = [Origin.Script, Origin.Agent];

    [Fact(Timeout = 120_000)]
    public async Task RegistrationReplaysTheHistoricalReceiptAndExistingWorkspaceControlsStillWork()
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
        var fresh = request.Clone();
        fresh.Meta = Tasks.Meta();
        fresh.Path = Path.Combine(node.Root, "missing-registration-root");
        calls.Link.Reset(usableFor: 0);
        var dropped = await calls.CallAsync(human, RoutedMethod.RegisterNodeWorkspace, fresh.ToByteArray(), fresh.Meta.CommandId);
        Assert.Null(dropped.Answer);
        calls.Link.Reset();
        var refused = await calls.CallAsync(human, RoutedMethod.RegisterNodeWorkspace, fresh.ToByteArray(), fresh.Meta.CommandId);
        AssertUnknown(WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(refused.Answer!.Response).Error);
        Assert.False(Directory.Exists(fresh.Path));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));

        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var originalPending = request.Clone();
        originalPending.Meta = Tasks.Meta();
        WorkspaceServiceRegisterWorkspaceResponse originalReceipt;
        using (var prepared = manager.PrepareRegistration(path, "demo", cancellationToken: ct))
        {
            originalReceipt = node.Runtime.Store.Write(transaction =>
            {
                var workspace = manager.RegisterPreparedFromVerifiedHuman(transaction, prepared, cancellationToken: ct);
                var view = new Workspace
                {
                    WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) },
                    Kind = WorkspaceKind.Registered,
                    State = WorkspaceState.Active,
                    Name = workspace.Name,
                    RootPath = workspace.RootPath,
                    CreatedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(workspace.CreatedAt)),
                    LastUsedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(workspace.LastUsedAt)),
                };
                var response = new WorkspaceServiceRegisterWorkspaceResponse
                {
                    Meta = new() { CorrelationId = request.Meta.CorrelationId },
                    Value = new() { Workspace = view },
                    Audit = WorkspaceAuditMetadata.ForRecords([view]),
                };
                SeedRegistration(transaction, human, request, response.ToByteArray());
                SeedRegistration(transaction, human, originalPending, null);
                return response;
            }, CommitDurability.Full);
        }

        Assert.Null((await Sched.ChangePolicyAsync(humanChannel, policy => (policy.CenterRouted ??= new CenterRoutedPolicy()).Enabled = false)).Error);
        var first = await calls.CallAsync(human, RoutedMethod.RegisterNodeWorkspace, request.ToByteArray(), meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, first.Answer!.Outcome);
        Assert.NotNull(first.Answer.Response);
        Assert.Equal(originalReceipt.ToByteArray(), first.Answer.Response.ToByteArray());
        var id = originalReceipt.Value.Workspace.WorkspaceId;
        Assert.Equal(id.Value.ToByteArray(), first.Answer.WorkspaceId);
        var stillPending = await calls.CallAsync(human, RoutedMethod.RegisterNodeWorkspace, originalPending.ToByteArray(), originalPending.Meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, stillPending.Answer!.Outcome);
        AssertPending(WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(stillPending.Answer.Response).Error);
        var closedPolicy = await calls.CallAsync(human, RoutedMethod.RegisterNodeWorkspace, fresh.ToByteArray(), fresh.Meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, closedPolicy.Answer!.Outcome);
        Assert.Equal("center_routed_disabled", closedPolicy.Answer.Error!.Details.State.Reason);
        Assert.Null((await Sched.ChangePolicyAsync(humanChannel, policy => policy.CenterRouted.Enabled = true)).Error);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM audit_log a JOIN routed_file_audit_retention h ON h.audit_seq = a.seq
            WHERE a.target_kind = 'routed_command_owner' AND a.remote_command_id = $id
              AND length(h.process_epoch) = 16 AND h.monotonic_start IS NOT NULL AND h.delete_permitted = 0;
            """, ("$id", meta.CommandId.Value.ToByteArray()))));
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

    [Fact(Timeout = 30_000)]
    public async Task OnlyTheOriginalCallerCanReadTheHeldBytesAndUnreadableOrMissingResultsStayUnknown()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var missingPath = Path.Combine(node.Root, "nonexistent-reconcile-root");
        WorkspaceServiceRegisterWorkspaceRequest Request() => new() { Meta = Tasks.Meta(), Path = missingPath, Name = "historical" };
        Task<(RoutedAnswer? Answer, long LogId)> Route(WorkspaceServiceRegisterWorkspaceRequest request, CenterCaller? owner = null, byte[]? payload = null) =>
            calls.CallAsync(owner ?? caller, RoutedMethod.RegisterNodeWorkspace, payload ?? request.ToByteArray(), request.Meta.CommandId).WaitAsync(ct);

        var prior = Request();
        var corrupt = Request();
        var empty = Request();
        var incomplete = Request();
        var oversized = Request();
        var pending = Request();
        var workspace = new Workspace { WorkspaceId = CommandIds.New(), Kind = WorkspaceKind.Registered, State = WorkspaceState.Active, Name = prior.Name, RootPath = prior.Path };
        var registered = new WorkspaceServiceRegisterWorkspaceResponse
        {
            Meta = new() { CorrelationId = prior.Meta.CorrelationId },
            Value = new() { Workspace = workspace },
            Audit = WorkspaceAuditMetadata.ForRecords([workspace]),
        };
        byte[] retainedBytes = [0x98, 0x06, 0x01, .. registered.ToByteArray()];
        node.Runtime.Store.Write(transaction =>
        {
            SeedRegistration(transaction, caller, prior, retainedBytes, wallExpired: true);
            SeedRegistration(transaction, caller, corrupt, [0x80]);
            SeedRegistration(transaction, caller, empty, []);
            var incompleteOutcome = registered.Clone();
            incompleteOutcome.Meta.CorrelationId = incomplete.Meta.CorrelationId;
            incompleteOutcome.Value.Workspace = new Workspace { WorkspaceId = CommandIds.New() };
            SeedRegistration(transaction, caller, incomplete, incompleteOutcome.ToByteArray());
            var oversizedOutcome = registered.Clone();
            oversizedOutcome.Meta.CorrelationId = oversized.Meta.CorrelationId;
            oversizedOutcome.Meta.Warnings.Add(new string('x', 131_072));
            SeedRegistration(transaction, caller, oversized, oversizedOutcome.ToByteArray());
            SeedRegistration(transaction, caller, pending, null);
            Assert.True(RoutedFileRetention.IsHeld(transaction, prior.Meta.CommandId.Value.Span));
        }, CommitDurability.Full);

        var retry = prior.Clone();
        retry.Meta.CorrelationId = CommandIds.New();
        var concurrent = await Task.WhenAll(Route(retry), Route(retry, RoutedCalls.Session()),
            Route(retry, payload: [.. retry.ToByteArray(), 0x98, 0x06, 0x01]));
        var known = concurrent[0].Answer;
        Assert.NotNull(known);
        Assert.NotNull(known.Response);
        Assert.Equal(retainedBytes, known.Response.ToByteArray());
        Assert.Equal(prior.Meta.CorrelationId, WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(known.Response).Meta.CorrelationId);
        Assert.Equal(workspace.WorkspaceId.Value.ToByteArray(), known.WorkspaceId);

        var other = concurrent[1].Answer!;
        Assert.Equal("command_id_reused", WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(other.Response).Error.Code);
        var changedWire = concurrent[2].Answer!;
        Assert.Equal("command_id_reused", WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(changedWire.Response).Error.Code);

        foreach (var request in new[] { corrupt, empty, incomplete, oversized, Request() })
        {
            var unknown = (await Route(request)).Answer!;
            AssertUnknown(WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(unknown.Response).Error);
        }

        var inProgress = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom((await Route(pending)).Answer!.Response).Error;
        AssertPending(inProgress);

        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id = $id AND expires_at <= $now;",
            ("$id", prior.Meta.CommandId.Value.ToByteArray()), ("$now", reader.NowMicroseconds))));

        Assert.False(Directory.Exists(missingPath));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace;")));
        Assert.Equal(6L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE outcome IS NULL;")));
    }

    internal static void SeedRegistration(StoreTransaction transaction, CenterCaller caller, WorkspaceServiceRegisterWorkspaceRequest request,
        byte[]? outcome, bool wallExpired = false)
    {
        var id = request.Meta.CommandId.Value.Span;
        const string method = "arcforges.node.v1.WorkspaceService/RegisterWorkspace";
        var digest = PayloadDigest.Compute(request.ToByteArray());
        if (wallExpired)
        {
            // Seed an older generation before the retention trigger guards its original timestamps.
            var day = (long)TimeSpan.FromDays(1).TotalMicroseconds;
            var now = transaction.NowMicroseconds;
            transaction.Execute("""
                INSERT INTO command_dedup (command_id, method, payload_digest, origin, outcome, created_at, expires_at)
                VALUES ($id, $method, $digest, $origin, NULL, $created, $expires);
                """, ("$id", id.ToArray()), ("$method", method), ("$digest", digest), ("$origin", (int)Origin.Remote),
                ("$created", now - 2 * day), ("$expires", now - day));
        }
        else
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id, method, digest, Origin.Remote).Status);
        }

        if (outcome is not null)
        {
            CommandDeduplication.Complete(transaction, id, outcome);
        }

        RoutedCommandOwnership.Record(transaction, id, new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId });
    }

    private static void AssertUnknown(ArcError error)
    {
        Assert.Equal(ErrorCategory.Internal, error.Category);
        Assert.Equal("internal", error.Code);
        Assert.Equal("legacy_workspace_registration_outcome_unavailable", error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
    }

    private static void AssertPending(ArcError error)
    {
        Assert.Equal("internal", error.Code);
        Assert.Equal("command_in_progress", error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
    }
}
