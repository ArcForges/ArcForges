// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real dispatcher, native workspace and SQLite; the test seam does not claim a signed channel or real Center.</summary>
public sealed class FileRemovalPlanRoutedTests
{
    [Fact(Timeout = 120_000)]
    public async Task RealPlanAndReceiptCommitTogetherReplayAndBindTheRelaySession()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var manager = new RegisteredWorkspaces(node.Runtime.Store);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "removal-plan-root")).FullName;
        var tree = Directory.CreateDirectory(Path.Combine(root, "tree")).FullName;
        const string body = "owned-fixture-plan-body-must-never-be-persisted-8196";
        File.WriteAllText(Path.Combine(tree, "content.txt"), body);
        var workspace = manager.RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "tree" },
        };
        var caller = calls.Relay(Origin.Agent);
        var bytes = request.ToByteArray();
        var first = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, bytes, request.Meta.CommandId);
        Assert.NotNull(first.Answer);
        Assert.Equal(RoutedOutcome.Executed, first.Answer.Outcome);
        var firstBytes = first.Answer.Response ?? throw new InvalidOperationException("The plan response is missing.");
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(firstBytes);
        Assert.Null(response.Error);
        Assert.True(NodeShapes.IsValid(response));
        var plan = response.Value.Plan;
        Assert.Equal(request.WorkspacePath, plan.WorkspacePath);
        Assert.Equal(2, plan.Items.Count);
        Assert.Equal((ulong)Encoding.UTF8.GetByteCount(body), plan.TotalBytes);
        Assert.True(plan.RequiresApproval);
        Assert.False(plan.QuarantineAvailable);
        Assert.NotEqual(RiskClass.Low, plan.Risk);
        Assert.All(plan.Items, item => Assert.False(item.OwnerVerified));
        Assert.Equal(body, File.ReadAllText(Path.Combine(tree, "content.txt")));

        var commandId = request.Meta.CommandId.Value.ToByteArray();
        var expectedSha = SHA256.HashData(bytes);
        node.Runtime.Store.Read(reader =>
        {
            using var sql = reader.CreateCommand("""
                SELECT p.request_sha256, p.workspace_id, p.workspace_path, p.caller, d.outcome,
                       (SELECT count(*) FROM file_removal_plan_item i WHERE i.plan_id = p.plan_id)
                FROM file_removal_plan p JOIN command_dedup d ON d.command_id = p.command_id WHERE p.command_id = $id;
                """);
            sql.Parameters.AddWithValue("$id", commandId);
            using var row = sql.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(expectedSha, (byte[])row.GetValue(0));
            Assert.Equal(workspace.Id, (byte[])row.GetValue(1));
            Assert.Equal("tree", row.GetString(2));
            Assert.Equal(caller, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(3)));
            Assert.Equal(firstBytes.ToByteArray(), (byte[])row.GetValue(4));
            Assert.Equal(2L, row.GetInt64(5));
            Assert.False(row.Read());
            return 0;
        });

        var replay = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, bytes, request.Meta.CommandId);
        Assert.Equal(firstBytes, replay.Answer!.Response);
        var otherSession = caller.Clone();
        otherSession.LocalSessionId = CommandIds.New();
        var foreign = await calls.CallAsync(otherSession, RoutedMethod.PlanNodeRemoval, bytes, request.Meta.CommandId);
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(foreign.Answer!.Response).Error.Code);
        var changed = request.Clone();
        changed.Meta.CorrelationId = CommandIds.New();
        var mismatch = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, changed.ToByteArray(), request.Meta.CommandId);
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(mismatch.Answer!.Response).Error.Code);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(body, File.ReadAllText(Path.Combine(tree, "content.txt")));

        var accountRequest = request.Clone();
        accountRequest.Meta = Tasks.Meta();
        var account = RoutedCalls.Session();
        var accountFirst = await calls.CallAsync(account, RoutedMethod.PlanNodeRemoval, accountRequest.ToByteArray(), accountRequest.Meta.CommandId);
        Assert.NotNull(accountFirst.Answer?.Response);
        var nextSession = RoutedCalls.Session();
        nextSession.UserId = CommandIds.New();
        var accountReplay = await calls.CallAsync(nextSession, RoutedMethod.PlanNodeRemoval, accountRequest.ToByteArray(), accountRequest.Meta.CommandId);
        Assert.Equal(accountFirst.Answer!.Response, accountReplay.Answer!.Response);

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var afterRestart = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, bytes, request.Meta.CommandId);
        Assert.Equal(firstBytes, afterRestart.Answer!.Response);
        Assert.Equal(2L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));

        foreach (var db in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(db)) continue;
            using var stream = new FileStream(db, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var data = new MemoryStream();
            stream.CopyTo(data);
            Assert.False(data.ToArray().AsSpan().IndexOf(Encoding.UTF8.GetBytes(body)) >= 0);
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task PlanningPermissionAndUnknownWorkspaceReturnActualAuditedRefusals()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = CommandIds.New(), Path = "missing" },
        };
        var missing = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.Equal("not_found", FileServicePlanRemovalResponse.Parser.ParseFrom(missing.Answer!.Response).Error.Code);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        var unknownAttempt = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = CommandIds.New() };
        var attempt = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, unknownAttempt.ToByteArray(), unknownAttempt.Meta.CommandId);
        Assert.Equal("not_found", FileServicePlanRemovalResponse.Parser.ParseFrom(attempt.Answer!.Response).Error.Code);

        string reason;
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.CleanupPlan,
                Origin = Origin.Agent,
                Decision = PermissionDecision.Deny,
            }))).Error);
            request.Meta = Tasks.Meta();
            var denied = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
            Assert.Equal(RoutedOutcome.RefusedByPolicy, denied.Answer!.Outcome);
            Assert.Equal("permission_denied", denied.Answer.Error!.Code);
            reason = denied.Answer.Error.Details.State.Reason;
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Clear())).Error);
        }

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var replay = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, replay.Answer!.Outcome);
        Assert.Equal(reason, replay.Answer.Error!.Details.State.Reason);
        Assert.Equal(reason, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT policy_reason FROM file_removal_command_owner WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM file_workspace_audit f JOIN audit_log a ON a.seq = f.audit_seq WHERE a.operation LIKE '%PlanRemoval%';"))! >= 3);
    }
    [Fact(Timeout = 120_000)]
    public async Task AnExceptionAfterActualPlanInsertsRollsBackPlanAndCommandReceipt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "rollback-root")).FullName;
        File.WriteAllText(Path.Combine(root, "kept"), "owned rollback marker");
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        using var workspace = WorkspacePath.OpenRoot(root);
        var snapshot = WorkspaceRemovalPlan.Capture(workspace, "kept", ct);
        var id = Tasks.Meta().CommandId.Value.ToByteArray();
        var raw = SHA256.HashData("exact test command"u8);
        var caller = calls.Relay(Origin.Human);
        var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller.Clone() };
        var target = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(registered.Id) }, Path = "kept" };

        Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write<int>(transaction =>
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id,
                "arcforges.node.v1.FileService/PlanRemoval", raw, Origin.Remote).Status);
            var prepared = FileRemovalPlans.PrepareWorkspace(transaction, id, raw, caller, actor, target, root, snapshot, transaction.NowMicroseconds);
            FileRemovalPlans.RecordWorkspace(transaction, prepared);
            throw new InvalidOperationException("test-owned rollback");
        }, CommitDurability.Full));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", id))));
        Assert.Equal("owned rollback marker", File.ReadAllText(Path.Combine(root, "kept")));
    }

    [Fact(Timeout = 120_000)]
    public async Task OversizedRealTreePersistsAndReplaysRefusalWithoutAPlanEvenAfterUncertainCommit()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "large-response-root")).FullName;
        var selected = Directory.CreateDirectory(Path.Combine(root, "tree")).FullName;
        var deep = selected;
        for (var depth = 0; depth < 5; depth++)
            deep = Directory.CreateDirectory(Path.Combine(deep, new string((char)('a' + depth), 210))).FullName;
        for (var index = 0; index < 980; index++)
            File.WriteAllBytes(Path.Combine(deep, "f" + index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);
        const string privateBody = "plan-budget-fixture-content-never-persisted-3752";
        File.WriteAllText(Path.Combine(deep, "f0000"), privateBody);
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        using var workspace = WorkspacePath.OpenRoot(root);
        var snapshot = WorkspaceRemovalPlan.Capture(workspace, "tree", ct);
        Assert.Equal(986, snapshot.Entries.Count);
        var caller = calls.Relay(Origin.Agent);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(registered.Id) }, Path = "tree" },
        };
        var raw = SHA256.HashData(request.ToByteArray());
        var id = request.Meta.CommandId.Value.ToByteArray();
        var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller.Clone() };
        var encodedSize = 0;
        var shapeAccepted = false;
        var planShapeAccepted = false;
        var invalidItemCount = 0;
        var firstInvalidPathBytes = 0;
        Assert.Throws<InvalidOperationException>(() => node.Runtime.Store.Write<int>(transaction =>
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id,
                "arcforges.node.v1.FileService/PlanRemoval", raw, Origin.Remote).Status);
            var prepared = FileRemovalPlans.PrepareWorkspace(transaction, id, raw, caller, actor, request.WorkspacePath, root,
                snapshot, transaction.NowMicroseconds);
            FileRemovalPlans.RecordWorkspace(transaction, prepared);
            var plan = prepared.Plan;
            var response = new FileServicePlanRemovalResponse
            {
                Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
                Value = new FileServicePlanRemovalValue { Plan = plan },
            };
            encodedSize = response.CalculateSize();
            shapeAccepted = NodeShapes.IsValid(response);
            planShapeAccepted = NodeShapes.IsValid(plan);
            foreach (var item in plan.Items)
            {
                if (NodeShapes.IsValid(item)) continue;
                invalidItemCount++;
                if (firstInvalidPathBytes == 0) firstInvalidPathBytes = Encoding.UTF8.GetByteCount(item.Path);
            }
            throw new InvalidOperationException("test-owned size measurement rollback");
        }, CommitDurability.Full));
        // The actual 450.1 response validator enforces the encoded-size ceiling even though the plan and all items fit.
        Assert.True(planShapeAccepted);
        Assert.Equal(0, invalidItemCount);
        Assert.Equal(0, firstInvalidPathBytes);
        Assert.True(encodedSize > 1_040_384, $"Actual encoded response was {encodedSize} bytes.");
        Assert.False(shapeAccepted);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", id))));

        var requestBytes = request.ToByteArray();
        var handler = calls.Dispatcher.FileHandlerForTests!;
        handler.AfterRemovalSizeRefusalForTests = transaction =>
        {
            Assert.Equal(CommitDurability.Full, transaction.Durability);
            Assert.Equal(2L, transaction.Scalar("PRAGMA synchronous;"));
            throw new InvalidOperationException("test-owned pre-commit fault");
        };
        await Assert.ThrowsAsync<InvalidOperationException>(() => calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval,
            requestBytes, request.Meta.CommandId));
        handler.AfterRemovalSizeRefusalForTests = null;
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", id))));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM audit_log WHERE operation = 'cleanup.plan FileService.PlanRemoval';")));

        // The real SQLite FULL commit succeeds; an injected failure at its return makes its caller's outcome uncertain.
        var observedFullBeforeCommit = false;
        handler.AfterRemovalSizeRefusalForTests = transaction =>
        {
            Assert.Equal(CommitDurability.Full, transaction.Durability);
            Assert.Equal(2L, transaction.Scalar("PRAGMA synchronous;"));
            observedFullBeforeCommit = true;
        };
        handler.AfterRemovalSizeCommitForTests = () => throw new SqliteException("test-owned commit return fault", 10);
        var uncertain = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, requestBytes, request.Meta.CommandId);
        handler.AfterRemovalSizeRefusalForTests = null;
        handler.AfterRemovalSizeCommitForTests = null;
        Assert.True(observedFullBeforeCommit);
        var unknown = FileServicePlanRemovalResponse.Parser.ParseFrom(uncertain.Answer!.Response);
        Assert.True(NodeShapes.IsValid(unknown));
        Assert.Equal("internal", unknown.Error.Code);
        Assert.Equal(ErrorCategory.Internal, unknown.Error.Category);
        Assert.Equal(EffectCertainty.Unknown, unknown.Error.Effect);
        Assert.Equal(RetryMode.Never, unknown.Error.Retry.Mode);
        Assert.Null(unknown.Value);
        var receipt = node.Runtime.Store.Read(reader =>
        {
            using var sql = reader.CreateCommand("""
                SELECT d.payload_digest, d.outcome, o.caller FROM command_dedup d
                JOIN file_removal_command_owner o ON o.command_id = d.command_id WHERE d.command_id = $id;
                """);
            sql.Parameters.AddWithValue("$id", id);
            using var row = sql.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(SHA256.HashData(requestBytes), (byte[])row.GetValue(0));
            Assert.Equal(caller, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2)));
            return (byte[])row.GetValue(1);
        });
        var committed = FileServicePlanRemovalResponse.Parser.ParseFrom(receipt);
        Assert.True(NodeShapes.IsValid(committed));
        Assert.Equal(ErrorCategory.Resource, committed.Error.Category);
        Assert.Equal("too_large", committed.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, committed.Error.Effect);
        Assert.Equal(RetryMode.Never, committed.Error.Retry.Mode);
        Assert.Equal("removal_plan_response_bytes", committed.Error.Details.Limit.LimitName);
        Assert.Equal("1040384", committed.Error.Details.Limit.Maximum.Value);
        Assert.Null(committed.Value);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM audit_log WHERE operation = 'cleanup.plan FileService.PlanRemoval' AND outcome_summary = 'refused: too_large';")));

        // A second account session of the same account may replay the first account session's exact refusal.
        var account = RoutedCalls.Session();
        var accountRequest = request.Clone();
        accountRequest.Meta = Tasks.Meta();
        var accountBytes = accountRequest.ToByteArray();
        var accountFirst = await calls.CallAsync(account, RoutedMethod.PlanNodeRemoval, accountBytes, accountRequest.Meta.CommandId);
        var accountResult = FileServicePlanRemovalResponse.Parser.ParseFrom(accountFirst.Answer!.Response);
        Assert.Equal("removal_plan_response_bytes", accountResult.Error.Details.Limit.LimitName);
        var anotherAccountSession = RoutedCalls.Session();
        Assert.NotEqual(account.SessionId, anotherAccountSession.SessionId);
        var accountReplay = await calls.CallAsync(anotherAccountSession, RoutedMethod.PlanNodeRemoval, accountBytes, accountRequest.Meta.CommandId);
        Assert.Equal(accountFirst.Answer.Response, accountReplay.Answer!.Response);

        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.CleanupPlan,
                Origin = Origin.Agent,
                Decision = PermissionDecision.Deny,
            }))).Error);
        }
        // Re-enumerating now would hit the different 1000-descendant bound, so the original result proves receipt replay.
        for (var index = 980; index < 996; index++)
            File.WriteAllBytes(Path.Combine(deep, "f" + index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);
        var replay = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, requestBytes, request.Meta.CommandId);
        Assert.Equal(receipt, replay.Answer!.Response!.ToByteArray());
        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var denied = await calls.CallAsync(foreign, RoutedMethod.PlanNodeRemoval, requestBytes, request.Meta.CommandId);
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(denied.Answer!.Response).Error.Code);
        var differentRawBytes = requestBytes.Concat(new byte[] { 0x98, 0x06, 0x01 }).ToArray();
        var mismatch = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, differentRawBytes, request.Meta.CommandId);
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(mismatch.Answer!.Response).Error.Code);
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var restarted = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, requestBytes, request.Meta.CommandId);
        Assert.Equal(receipt, restarted.Answer!.Response!.ToByteArray());
        var restartedAccount = await calls.CallAsync(anotherAccountSession, RoutedMethod.PlanNodeRemoval, accountBytes, accountRequest.Meta.CommandId);
        Assert.Equal(accountFirst.Answer.Response, restartedAccount.Answer!.Response);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
        Assert.Equal(privateBody, File.ReadAllText(Path.Combine(deep, "f0000")));
        foreach (var db in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(db)) continue;
            using var stream = new FileStream(db, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var data = new MemoryStream();
            stream.CopyTo(data);
            Assert.True(data.ToArray().AsSpan().IndexOf(Encoding.UTF8.GetBytes(privateBody)) < 0);
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task DispatcherFailureAfterPlanInsertsRollsBackBeforeTheSameCommandIsRetried()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "injected-rollback-root")).FullName;
        File.WriteAllText(Path.Combine(root, "target"), "unchanged");
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var caller = calls.Relay(Origin.Agent);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(registered.Id) }, Path = "target" },
        };
        var handler = calls.Dispatcher.FileHandlerForTests!;
        handler.AfterRemovalPlanInsertForTests = () => throw new ArgumentException("test-owned post-insert failure");
        await Assert.ThrowsAsync<ArgumentException>(() => calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval,
            request.ToByteArray(), request.Meta.CommandId));
        handler.AfterRemovalPlanInsertForTests = null;
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id=$id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        Assert.Equal("unchanged", File.ReadAllText(Path.Combine(root, "target")));

        handler.AfterRemovalPlanInsertForTests = () => calls.Link.Reset(usableFor: 0);
        var dropped = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        handler.AfterRemovalPlanInsertForTests = null;
        calls.Link.Reset();
        Assert.Null(dropped.Answer);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id=$id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));

        var retry = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(retry.Answer!.Response);
        Assert.Null(response.Error);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
    }

    [Fact(Timeout = 120_000)]
    public async Task AThousandRealDescendantsFitAndTheCompletePlanSurvivesThePublishedConsumer()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "bounded-routed-root")).FullName;
        var tree = Directory.CreateDirectory(Path.Combine(root, "tree")).FullName;
        for (var index = 0; index < 1000; index++)
            File.WriteAllBytes(Path.Combine(tree, index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(registered.Id) }, Path = "tree" },
        };
        var answer = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.PlanNodeRemoval,
            request.ToByteArray(), request.Meta.CommandId);
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(answer.Answer!.Response);
        Assert.Null(response.Error);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Equal(1001, response.Value.Plan.Items.Count);
        Assert.True(response.CalculateSize() <= 1_040_384);
        var target = CommandIds.New();
        var fleetResponse = new FleetServicePlanNodeRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target.Clone(), Response = response.ToByteString() },
        };
        Assert.True(RoutedFileResponseValidation.PlanRemoval(fleetResponse, target, request));
        Assert.Equal(1001L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan_item;")));
        Assert.True(File.Exists(Path.Combine(tree, "0000")));

        File.WriteAllBytes(Path.Combine(tree, "extra"), []);
        request.Meta = Tasks.Meta();
        var tooMany = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.PlanNodeRemoval,
            request.ToByteArray(), request.Meta.CommandId);
        var refused = FileServicePlanRemovalResponse.Parser.ParseFrom(tooMany.Answer!.Response);
        Assert.True(NodeShapes.IsValid(refused));
        Assert.Equal("too_large", refused.Error.Code);
        Assert.Equal("removal_descendants", refused.Error.Details.Limit.LimitName);
        Assert.Equal("1000", refused.Error.Details.Limit.Maximum.Value);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.True(File.Exists(Path.Combine(tree, "extra")));
    }

    [Fact(Timeout = 120_000)]
    public async Task RealSizeAndInputPathBoundsReturnCanonicalRefusalsWithoutChangingTheFile()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "plan-bound-root")).FullName;
        var file = Path.Combine(root, "large");
        using (var stream = File.Create(file)) stream.SetLength(67_108_865);
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(registered.Id) }, Path = "large" },
        };
        var caller = calls.Relay(Origin.Agent);
        var tooLarge = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        var refused = FileServicePlanRemovalResponse.Parser.ParseFrom(tooLarge.Answer!.Response);
        Assert.True(NodeShapes.IsValid(refused));
        Assert.Equal("too_large", refused.Error.Code);
        Assert.Equal("removal_total_bytes", refused.Error.Details.Limit.LimitName);
        Assert.Equal("67108864", refused.Error.Details.Limit.Maximum.Value);
        Assert.Equal(67_108_865, new FileInfo(file).Length);

        request.Meta = Tasks.Meta();
        request.WorkspacePath.Path = new string('x', 4097);
        var pathTooLarge = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        var pathRefused = FileServicePlanRemovalResponse.Parser.ParseFrom(pathTooLarge.Answer!.Response);
        Assert.True(NodeShapes.IsValid(pathRefused));
        Assert.Equal("too_large", pathRefused.Error.Code);
        Assert.Equal("path_bytes", pathRefused.Error.Details.Limit.LimitName);
        Assert.Equal("4096", pathRefused.Error.Details.Limit.Maximum.Value);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
    }

    [Fact(Timeout = 120_000)]
    [Trait("env", "linux-real")]
    public async Task NonportableChildIsAFileAccessRefusalForAValidSelectedPath()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "This fixture uses a Linux filename containing a backslash.");
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "nonportable-plan-root")).FullName;
        var tree = Directory.CreateDirectory(Path.Combine(root, "tree")).FullName;
        var child = Path.Combine(tree, "nonportable\\name");
        File.WriteAllText(child, "unchanged");
        var registered = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(registered.Id) }, Path = "tree" },
        };
        var call = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.PlanNodeRemoval,
            request.ToByteArray(), request.Meta.CommandId);
        var refusal = FileServicePlanRemovalResponse.Parser.ParseFrom(call.Answer!.Response);
        Assert.True(NodeShapes.IsValid(refusal));
        Assert.Equal("file_access_denied", refusal.Error.Code);
        Assert.Equal("path_enforcement_unavailable", refusal.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
        Assert.Equal("unchanged", File.ReadAllText(child));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
    }

}
