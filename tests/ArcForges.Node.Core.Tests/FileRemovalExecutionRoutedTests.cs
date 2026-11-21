// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Tests;

/// <summary>Tests removal receipt replay using real SQLite and the in-process route with synthetic callers.</summary>
/// <remarks>The fresh V1 preflight and effect-commit cases are executable in this class at
/// eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.</remarks>
public sealed class FileRemovalExecutionRoutedTests
{
    [Fact(Timeout = 120_000)]
    public async Task RetainedDenialReplaysExactBytesAcrossRestartOnlyForTheOriginalCommand()
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var (target, plan) = SeedPlan(node, caller, token);
        var request = RetainedRemovalFixture.Execution(plan);
        request.DeleteWithoutQuarantine = true;
        var raw = request.ToByteArray();
        var refusal = HistoricalRefusal(request, ErrorCategory.Resource, "enforcement_unavailable", "strict_cleanup_guard_unavailable");
        byte[] recorded = [0x98, 0x06, 1, .. refusal.ToByteArray()];
        node.Runtime.Store.Write(tx =>
        {
            RetainedRemovalFixture.ReserveExecution(tx, caller, request, raw);
            CommandDeduplication.Complete(tx, request.Meta.CommandId.Value.Span, recorded);
        }, CommitDurability.Full);

        var first = await InvokeBytes(calls, caller, request);
        Assert.Equal(recorded, first.ToByteArray());
        byte[] changedRaw = [.. raw, 0x98, 0x06, 1];
        var mismatch = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, changedRaw, request.Meta.CommandId);
        Assert.Equal("command_id_reused", Parse(mismatch.Answer).Error.Code);
        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        Assert.Equal("command_id_reused", (await Invoke(calls, foreign, request)).Error.Code);

        File.WriteAllText(target, "later replacement bytes");
        Assert.Equal(0, await node.StopAsync().WaitAsync(token));
        await node.StartAsync();
        calls = new RoutedCalls(node);
        Assert.Equal(recorded, (await InvokeBytes(calls, caller, request)).ToByteArray());
        var fresh = await Invoke(calls, caller, RetainedRemovalFixture.Execution(plan));
        AssertUnknown(fresh.Error);
        Assert.Equal("later replacement bytes", File.ReadAllText(target));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE method = 'arcforges.node.v1.FileService/ExecuteRemoval';")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }

    [Fact(Timeout = 120_000)]
    public async Task RetiredExecutionChecksPlanOwnerAndDigestWithoutAdmittingExpiredOrTerminalWork()
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var (target, plan) = SeedPlan(node, caller, token);
        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var request = RetainedRemovalFixture.Execution(plan);
        Assert.Equal("not_found", (await Invoke(calls, foreign, request)).Error.Code);
        request.PlanDigest = ByteString.CopyFrom(SHA256.HashData("different plan"u8));
        Assert.Equal("digest_mismatch", (await Invoke(calls, caller, request)).Error.Code);
        request.PlanId = CommandIds.New();
        Assert.Equal("not_found", (await Invoke(calls, caller, request)).Error.Code);

        var id = plan.PlanId.Value.ToByteArray();
        var expiry = node.Runtime.Store.Write(tx =>
        {
            var before = tx.NowMicroseconds - 1;
            Assert.Equal(1, tx.Execute("UPDATE cleanup_plan SET expires_at = $time WHERE plan_id = $id;",
                ("$time", before), ("$id", id)));
            return before;
        }, CommitDurability.Full);
        AssertUnknown((await Invoke(calls, caller, RetainedRemovalFixture.Execution(plan))).Error);
        node.Runtime.Store.Write(tx => tx.Execute("UPDATE cleanup_plan SET state = 4 WHERE plan_id = $id;", ("$id", id)),
            CommitDurability.Full);
        AssertUnknown((await Invoke(calls, caller, RetainedRemovalFixture.Execution(plan))).Error);
        Assert.Equal(expiry, node.Runtime.Store.Read(reader => reader.Scalar("SELECT expires_at FROM cleanup_plan;")));
        Assert.Equal(4L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE method = 'arcforges.node.v1.FileService/ExecuteRemoval';")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal("fixture stays", File.ReadAllText(target));
    }

    [Theory(Timeout = 120_000)]
    [InlineData(Origin.Agent, PermissionMatrix.FileRemove, false)]
    [InlineData(Origin.Script, PermissionMatrix.CleanupExecute, true)]
    public async Task RetainedPolicyDenialSurvivesPolicyChangeWithoutEnablingFreshRemoval(
        Origin origin, string operation, bool explicitDenial)
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var actor = calls.Relay(origin);
        var (target, plan) = SeedPlan(node, actor, token);
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        if (explicitDenial)
        {
            Assert.Null((await Sched.ChangePolicyAsync(human, policy =>
            {
                policy.Permissions.Add(new PermissionOverride
                {
                    Operation = PermissionMatrix.FileRemove, Origin = origin, Decision = PermissionDecision.Allow,
                });
                policy.Permissions.Add(new PermissionOverride { Operation = operation, Origin = origin, Decision = PermissionDecision.Deny });
            })).Error);
        }

        var fresh = RetainedRemovalFixture.Execution(plan);
        var initial = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, fresh.ToByteArray(), fresh.Meta.CommandId, cancellationToken: token);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, initial.Answer?.Outcome);
        Assert.Equal("permission_denied", initial.Answer!.Error?.Code);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE method = 'arcforges.node.v1.FileService/ExecuteRemoval';")));

        var request = RetainedRemovalFixture.Execution(plan);
        var raw = request.ToByteArray();
        var denial = HistoricalRefusal(request, ErrorCategory.Authorization, "permission_denied", operation);
        var recorded = denial.ToByteArray();
        node.Runtime.Store.Write(tx =>
        {
            RetainedRemovalFixture.ReserveExecution(tx, actor, request, raw, policyReason: "denied");
            CommandDeduplication.Complete(tx, request.Meta.CommandId.Value.Span, recorded);
        }, CommitDurability.Full);

        Assert.Null((await Sched.ChangePolicyAsync(human, policy =>
        {
            if (explicitDenial)
                policy.Permissions.Single(item => item.Operation == operation && item.Origin == origin).Decision = PermissionDecision.Allow;
            else
            {
                policy.Permissions.Add(new PermissionOverride { Operation = operation, Origin = origin, Decision = PermissionDecision.Allow });
                policy.Permissions.Add(new PermissionOverride
                {
                    Operation = PermissionMatrix.CleanupExecute, Origin = origin, Decision = PermissionDecision.Allow,
                });
            }
        })).Error);
        var replay = await calls.CallAsync(actor, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId, cancellationToken: token);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, replay.Answer?.Outcome);
        Assert.Equal("permission_denied", replay.Answer!.Error?.Code);
        Assert.Equal(recorded, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        AssertUnknown((await Invoke(calls, actor, fresh)).Error);
        Assert.Equal("fixture stays", File.ReadAllText(target));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM approval;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }

    [Fact(Timeout = 120_000)]
    public async Task AnUnansweredFullCommitKeepsTheRecoveredUnknownReceiptAndItsHold()
    {
        var token = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var (target, plan) = SeedPlan(node, caller, token);
        var snapshot = RetainedRemovalFixture.Capture(Path.GetDirectoryName(target)!, "selected", token);
        var destination = Path.Combine(node.Root, "unresolved-custody");
        var (request, approval) = await RetainedRemovalFixture.SeedInterruptedAsync(node.Runtime.Processor, caller, plan, snapshot, destination, token);
        var id = request.Meta.CommandId.Value.ToByteArray();
        Assert.Throws<SqliteException>(() => node.Runtime.Store.Write(tx =>
        {
            Assert.Equal(1, FileMutationJournal.RecoverInterrupted(tx));
            tx.AfterCommitForTests = () => throw new SqliteException("test-owned commit return fault", 10);
        }, CommitDurability.Full));

        var recorded = Assert.IsType<byte[]>(node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", id))));
        var replay = await Invoke(calls, caller, request);
        Assert.Equal(recorded, replay.ToByteArray());
        AssertUnknown(replay.Error);
        var operation = node.Runtime.Store.Read(reader => FileMutationJournal.GetForCaller(reader, id, caller));
        Assert.Equal(FileOperationState.Unknown, operation?.State);
        Assert.True(operation!.Held);
        var decision = node.Runtime.Store.Read(reader => Approvals.Get(reader, approval));
        Assert.Equal(ApprovalState.Approved, decision?.State);
        Assert.Null(decision!.Outcome);
        Assert.Equal(destination, node.Runtime.Store.Read(reader => FileMutationJournal.RemovalRecoveryLocation(reader, id)));
        Assert.False(Path.Exists(destination));
        Assert.Equal("fixture stays", File.ReadAllText(target));
    }

    private static (string Target, FileRemovalPlan Plan) SeedPlan(InProcessNode node, CenterCaller caller, CancellationToken token)
    {
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "retained-removal")).FullName;
        var target = Path.Combine(root, "selected");
        File.WriteAllText(target, "fixture stays");
        var snapshot = RetainedRemovalFixture.Capture(root, "selected", token);
        return (target, RetainedRemovalFixture.SeedPlan(node.Runtime.Store, caller, root, "selected", snapshot, token));
    }

    private static async Task<FileServiceExecuteRemovalResponse> Invoke(
        RoutedCalls calls, CenterCaller caller, FileServiceExecuteRemovalRequest request) =>
        FileServiceExecuteRemovalResponse.Parser.ParseFrom(await InvokeBytes(calls, caller, request));

    private static async Task<ByteString> InvokeBytes(RoutedCalls calls, CenterCaller caller, FileServiceExecuteRemovalRequest request) =>
        ResponseBytes((await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId)).Answer);

    private static FileServiceExecuteRemovalResponse Parse(RoutedAnswer? answer) =>
        FileServiceExecuteRemovalResponse.Parser.ParseFrom(ResponseBytes(answer));

    private static ByteString ResponseBytes(RoutedAnswer? answer)
    {
        Assert.NotNull(answer);
        Assert.Equal(RoutedOutcome.Executed, answer.Outcome);
        return Assert.IsType<ByteString>(answer.Response);
    }

    private static FileServiceExecuteRemovalResponse HistoricalRefusal(
        FileServiceExecuteRemovalRequest request, ErrorCategory category, string code, string reason)
    {
        var response = new FileServiceExecuteRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Error = new ArcError
            {
                Category = category,
                Code = code,
                MessageKey = $"error.{category.ToString().ToLowerInvariant()}.{code}",
                CorrelationId = request.Meta.CorrelationId.Clone(),
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = reason } },
            },
        };
        Assert.True(RoutedFileResponseValidation.RemovalExecutionOutcome(response, request));
        return response;
    }

    private static void AssertUnknown(ArcError error)
    {
        Assert.Equal(ErrorCategory.Execution, error.Category);
        Assert.Equal("operation_failed", error.Code);
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
        Assert.Equal("file_outcome_unknown", error.Details.State.Reason);
    }
}

internal static class RetainedRemovalFixture
{
    internal static WorkspaceRemovalSnapshot Capture(string root, string selected, CancellationToken token)
    {
        using var heldRoot = WorkspacePath.OpenRoot(root);
        return WorkspaceRemovalPlan.Capture(heldRoot, selected, token);
    }

    internal static FileRemovalPlan SeedPlan(
        NodeStore store, CenterCaller caller, string root, string selected, WorkspaceRemovalSnapshot snapshot, CancellationToken token)
    {
        var workspace = new RegisteredWorkspaces(store).RegisterFromVerifiedHuman(root, cancellationToken: token);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = selected },
        };
        return store.Write(tx =>
        {
            var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId };
            var prepared = FileRemovalPlans.PrepareWorkspace(tx, request.Meta.CommandId.Value.Span, SHA256.HashData(request.ToByteArray()),
                caller, actor, request.WorkspacePath, root, snapshot, tx.NowMicroseconds, quarantineAvailable: true);
            FileRemovalPlans.RecordWorkspace(tx, prepared);
            return prepared.Plan;
        }, CommitDurability.Full);
    }

    internal static FileServiceExecuteRemovalRequest Execution(FileRemovalPlan plan) =>
        new() { Meta = Tasks.Meta(), PlanId = plan.PlanId.Clone(), PlanDigest = plan.Digest, DeleteWithoutQuarantine = false };

    internal static void ReserveExecution(
        StoreTransaction tx, CenterCaller caller, FileServiceExecuteRemovalRequest request, byte[] raw, string? policyReason = null)
    {
        var command = request.Meta.CommandId.Value.ToByteArray();
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, command, "arcforges.node.v1.FileService/ExecuteRemoval",
            SHA256.HashData(raw), Origin.Remote).Status);
        tx.Execute("INSERT INTO file_removal_command_owner (command_id, caller, policy_reason) VALUES ($id, $caller, $reason);",
            ("$id", command), ("$caller", caller.ToByteArray()), ("$reason", policyReason));
    }

    internal static Task<(FileServiceExecuteRemovalRequest Request, byte[] ApprovalId)> SeedInterruptedAsync(
        CommandProcessor processor, CenterCaller caller, FileRemovalPlan plan, WorkspaceRemovalSnapshot snapshot,
        string destination, CancellationToken token)
    {
        var request = Execution(plan);
        var raw = request.ToByteArray();
        var digest = SHA256.HashData(raw);
        var id = request.Meta.CommandId.Value.ToByteArray();
        var planId = plan.PlanId.Value.ToByteArray();
        return processor.ExecuteAsync(command =>
        {
            var tx = command.Transaction;
            ReserveExecution(tx, caller, request, raw);
            var (approval, created, error) = Approvals.Raise(command, new ApprovalCapture
            {
                Operation = "FileService.ExecuteRemoval",
                MatrixOperation = PermissionMatrix.FileRemove,
                Summary = "Quarantine the exact selected removal plan",
                Risk = RiskClass.High,
                Requester = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId },
                CommandId = id,
                Request = [2, .. id],
                RequestDigest = digest,
                TargetKind = "cleanup_plan",
                TargetId = planId,
                Details =
                [
                    new KeyValue { Name = "plan_id", Value = Convert.ToHexStringLower(planId) },
                    new KeyValue { Name = "plan_digest", Value = Convert.ToHexStringLower(request.PlanDigest.Span) },
                    new KeyValue { Name = "correlation_id", Value = Convert.ToHexStringLower(request.Meta.CorrelationId.Value.Span) },
                    new KeyValue { Name = "delete_without_quarantine", Value = "false" },
                ],
            }, Approvals.DefaultTtl);
            Assert.True(created);
            Assert.Null(error);
            Assert.NotNull(approval);
            Assert.Equal(1, tx.Execute("UPDATE cleanup_plan SET state = 2, approval_id = $approval, rev = rev + 1 WHERE plan_id = $plan AND state = 1;",
                ("$approval", approval.Id), ("$plan", planId)));
            Approvals.Decide(command, approval.Id, approve: true, new ActorRef { Origin = Origin.Human }, null);
            FileMutationJournal.PrepareRemoval(tx, id, request.Meta.CorrelationId.Value.ToByteArray(), digest, caller,
                plan.WorkspacePath.WorkspaceId.Value.ToByteArray(), null, plan.WorkspacePath.Path, snapshot.RootIdentity, snapshot.RootIdentity,
                snapshot.Entries[0].NativeIdentity, planId, destination);
            return (request, approval.Id);
        }, CommitDurability.Full).WaitAsync(token);
    }
}
