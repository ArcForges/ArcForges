// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real routing, native files and durable SQLite; synthetic callers, no successful cleanup claim.</summary>
public sealed class FileRemovalExecutionRoutedTests
{
    [Fact(Timeout = 120_000)]
    public async Task ARealPlanRefusesBeforeEffectAndReplaysItsExactReceiptAcrossRestart()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "removal-execution-root")).FullName;
        var tree = Directory.CreateDirectory(Path.Combine(root, "selected")).FullName;
        var file = Path.Combine(tree, "kept.txt");
        const string body = "owned removal fixture, never a successful quarantine";
        File.WriteAllText(file, body);
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var planned = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "selected" },
        };
        var planAnswer = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, planned.ToByteArray(), planned.Meta.CommandId);
        var planResponse = FileServicePlanRemovalResponse.Parser.ParseFrom(planAnswer.Answer!.Response);
        Assert.Null(planResponse.Error);
        var plan = planResponse.Value.Plan;
        var request = new FileServiceExecuteRemovalRequest
        {
            Meta = Tasks.Meta(),
            PlanId = plan.PlanId.Clone(),
            PlanDigest = plan.Digest,
        };
        var raw = request.ToByteArray();
        var first = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, first.Answer!.Outcome);
        var firstBytes = first.Answer.Response ?? throw new InvalidOperationException("Missing execution response.");
        var response = FileServiceExecuteRemovalResponse.Parser.ParseFrom(firstBytes);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Equal("enforcement_unavailable", response.Error.Code);
        Assert.Equal(ErrorCategory.Resource, response.Error.Category);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(RetryMode.Never, response.Error.Retry.Mode);
        Assert.Null(response.Value);
        Assert.Equal(body, File.ReadAllText(file));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT state FROM cleanup_plan WHERE plan_id = $id;", ("$id", plan.PlanId.Value.ToByteArray()))));
        node.Runtime.Store.Read(reader =>
        {
            using var sql = reader.CreateCommand("""
                SELECT d.payload_digest, d.outcome, o.caller FROM command_dedup d
                JOIN file_removal_command_owner o ON o.command_id = d.command_id WHERE d.command_id = $id;
                """);
            sql.Parameters.AddWithValue("$id", request.Meta.CommandId.Value.ToByteArray());
            using var row = sql.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(0));
            Assert.Equal(firstBytes.ToByteArray(), (byte[])row.GetValue(1));
            Assert.Equal(caller, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2)));
            return 0;
        });

        var changedRaw = raw.Concat(new byte[] { 0x98, 0x06, 0x01 }).ToArray();
        var mismatch = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, changedRaw, request.Meta.CommandId);
        Assert.Equal("command_id_reused", FileServiceExecuteRemovalResponse.Parser.ParseFrom(mismatch.Answer!.Response).Error.Code);
        var other = caller.Clone();
        other.LocalSessionId = CommandIds.New();
        var foreign = await calls.CallAsync(other, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal("command_id_reused", FileServiceExecuteRemovalResponse.Parser.ParseFrom(foreign.Answer!.Response).Error.Code);

        // Rechecking now would observe a changed tree; replay must retain the already committed exact refusal.
        File.WriteAllText(Path.Combine(tree, "later.txt"), "test-owned later child");
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var replay = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(first.Answer.Response, replay.Answer!.Response);
        var fresh = request.Clone();
        fresh.Meta = Tasks.Meta();
        var changed = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, fresh.ToByteArray(), fresh.Meta.CommandId);
        Assert.Equal("file_changed", FileServiceExecuteRemovalResponse.Parser.ParseFrom(changed.Answer!.Response).Error.Code);
        Assert.Equal(body, File.ReadAllText(file));
        Assert.Equal("test-owned later child", File.ReadAllText(Path.Combine(tree, "later.txt")));
    }

    [Fact(Timeout = 120_000)]
    public async Task PlanCallerDigestExpiryAndTerminalStateAreCheckedWithoutChangingThePlan()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var ct = TestContext.Current.CancellationToken;
        var (plan, file) = await PlanFile(node, calls, caller, ct);
        async Task<string> Invoke(FileServiceExecuteRemovalRequest request, CenterCaller? actor = null)
        {
            var result = await calls.CallAsync(actor ?? caller, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
            return FileServiceExecuteRemovalResponse.Parser.ParseFrom(result.Answer!.Response).Error.Code;
        }
        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        Assert.Equal("not_found", await Invoke(Execution(plan), foreign));
        var wrong = Execution(plan);
        wrong.PlanDigest = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(32));
        Assert.Equal("digest_mismatch", await Invoke(wrong));
        var missing = Execution(plan);
        missing.PlanId = CommandIds.New();
        Assert.Equal("not_found", await Invoke(missing));

        // Explicit synthetic metadata input to the expiry predicate, not a 60-minute elapsed-time proof.
        node.Runtime.Store.Write(tx => tx.Execute("UPDATE cleanup_plan SET expires_at = $time WHERE plan_id = $id;",
            ("$time", tx.NowMicroseconds - 1), ("$id", plan.PlanId.Value.ToByteArray())), CommitDurability.Full);
        Assert.Equal("expired", await Invoke(Execution(plan)));
        node.Runtime.Store.Write(tx => tx.Execute("UPDATE cleanup_plan SET expires_at = $time, state = 4 WHERE plan_id = $id;",
            ("$time", tx.NowMicroseconds + 3_600_000_000), ("$id", plan.PlanId.Value.ToByteArray())), CommitDurability.Full);
        Assert.Equal("invalid_state", await Invoke(Execution(plan)));
        Assert.Equal("fixture stays", File.ReadAllText(file));
        Assert.Equal(4L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }

    [Fact(Timeout = 120_000)]
    public async Task AgentDenialIsDurableAndExplicitAllowStillCannotSupplyTheMissingGuard()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var ct = TestContext.Current.CancellationToken;
        var (plan, file) = await PlanFile(node, calls, caller, ct);
        var request = Execution(plan);
        var denied = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, denied.Answer!.Outcome);
        Assert.Equal("permission_denied", denied.Answer.Error!.Code);
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileRemove,
                Origin = Origin.Agent,
                Decision = PermissionDecision.Allow,
            }))).Error);
        }
        var replay = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, replay.Answer!.Outcome);
        Assert.Equal(denied.Answer.Error.Details.State.Reason, replay.Answer.Error!.Details.State.Reason);
        var fresh = Execution(plan);
        fresh.DeleteWithoutQuarantine = true;
        var refused = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, fresh.ToByteArray(), fresh.Meta.CommandId);
        Assert.Equal("enforcement_unavailable", FileServiceExecuteRemovalResponse.Parser.ParseFrom(refused.Answer!.Response).Error.Code);
        Assert.Equal("fixture stays", File.ReadAllText(file));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM approval;")));
    }

    [Fact(Timeout = 120_000)]
    public async Task CleanupExecuteDenialIsRecheckedAndItsReceiptSurvivesPermissionChange()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var (plan, file) = await PlanFile(node, calls, caller, ct);
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy =>
        {
            policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileRemove,
                Origin = Origin.Script,
                Decision = PermissionDecision.Allow,
            });
            policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.CleanupExecute,
                Origin = Origin.Script,
                Decision = PermissionDecision.Deny,
            });
        })).Error);
        var request = Execution(plan);
        var raw = request.ToByteArray();
        var denied = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, denied.Answer!.Outcome);
        Assert.Equal("permission_denied", denied.Answer.Error!.Code);
        var receipt = Assert.IsType<byte[]>(node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        Assert.Equal("permission_denied", FileServiceExecuteRemovalResponse.Parser.ParseFrom(receipt).Error.Code);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy =>
            policy.Permissions.Single(item => item.Operation == PermissionMatrix.CleanupExecute && item.Origin == Origin.Script)
                .Decision = PermissionDecision.Allow)).Error);
        var replay = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, replay.Answer!.Outcome);
        Assert.Equal(receipt, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        var fresh = Execution(plan);
        var refusal = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, fresh.ToByteArray(), fresh.Meta.CommandId);
        Assert.Equal("enforcement_unavailable", FileServiceExecuteRemovalResponse.Parser.ParseFrom(refusal.Answer!.Response).Error.Code);
        Assert.Equal("fixture stays", File.ReadAllText(file));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT state FROM cleanup_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM approval;")));
    }

    [Fact(Timeout = 120_000)]
    public async Task AnUnansweredFullCommitDoesNotInventARollbackAndItsReceiptCanBeRecovered()
    {
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Human);
        var ct = TestContext.Current.CancellationToken;
        var (plan, file) = await PlanFile(node, calls, caller, ct);
        var request = Execution(plan);
        var raw = request.ToByteArray();
        var handler = calls.Dispatcher.FileHandlerForTests!;
        handler.AfterRemovalExecutionCommitForTests = () => throw new SqliteException("test-owned commit return fault", 10);
        var lost = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        handler.AfterRemovalExecutionCommitForTests = null;
        Assert.Null(lost.Answer);
        var recorded = Assert.IsType<byte[]>(node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));
        Assert.Equal("enforcement_unavailable", FileServiceExecuteRemovalResponse.Parser.ParseFrom(recorded).Error.Code);
        var replay = await calls.CallAsync(caller, RoutedMethod.ExecuteNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(recorded, replay.Answer!.Response!.ToByteArray());
        Assert.Equal("fixture stays", File.ReadAllText(file));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
    }

    private static FileServiceExecuteRemovalRequest Execution(FileRemovalPlan plan) => new()
    {
        Meta = Tasks.Meta(),
        PlanId = plan.PlanId.Clone(),
        PlanDigest = plan.Digest,
    };

    private static async Task<(FileRemovalPlan Plan, string File)> PlanFile(InProcessNode node, RoutedCalls calls, CenterCaller caller, CancellationToken token)
    {
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "real-selected-root")).FullName;
        var file = Path.Combine(root, "kept");
        File.WriteAllText(file, "fixture stays");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root,
            cancellationToken: token);
        var request = new FileServicePlanRemovalRequest
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "kept" },
        };
        var answer = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(answer.Answer!.Response);
        Assert.Null(response.Error);
        return (response.Value.Plan, file);
    }
}
