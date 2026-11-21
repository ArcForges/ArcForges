// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Historical Windows file custody with native identities, isolated SQLite and a synthetic routed caller.</summary>
[Trait("env", "windows-real")]
public sealed class AttemptRemovalPlanWindowsTests
{
    private const string Body = "retained-attempt-plan-fixture-4629";
    private const string PlanMethod = "arcforges.node.v1.FileService/PlanRemoval";

    [Fact(Timeout = 120_000)]
    public async Task RetainedAttemptPlanReplaysAcrossRestartWithoutTransferringDescendantOwnership()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows attempt directory identity.");
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var (attempt, path, caller) = RetainedWindowsAttemptFixture.Seed(node, Body);
        var nested = Directory.CreateDirectory(Path.Combine(path, "nested")).FullName;
        File.WriteAllText(Path.Combine(nested, "child.txt"), "unowned child");
        await node.StartAsync();

        var calls = new RoutedCalls(node);
        var request = Request(attempt);
        var raw = request.ToByteArray();
        var command = request.Meta.CommandId.Value.ToByteArray();
        var digest = SHA256.HashData(raw);
        FileServicePlanRemovalResponse persisted;
        using (var root = WorkspacePath.OpenRoot(path))
        {
            persisted = node.Runtime.Store.Write(tx =>
            {
                var identity = (byte[])tx.Scalar("SELECT directory_identity FROM file_attempt_temp_identity WHERE attempt_id = $id;",
                    ("$id", attempt.Value.ToByteArray()))!;
                var snapshot = WorkspaceRemovalPlan.CaptureCheckedRoot(root, 1, identity, ct);
                var tracking = AttemptDirectoryTrackingObservation.Read(tx, snapshot, ct.ThrowIfCancellationRequested);
                Assert.Equal(AttemptDirectoryTracking.Tracked, tracking[""]);
                Assert.Equal(AttemptDirectoryTracking.Untracked, tracking["nested"]);
                var prepared = FileRemovalPlans.PrepareAttempt(tx, command, digest, caller, Actor(caller, request), attempt,
                    path, snapshot, tx.NowMicroseconds, tracking, quarantineAvailable: true);
                BeginReceipt(tx, command, digest, caller);
                FileRemovalPlans.RecordAttempt(tx, prepared);
                var response = new FileServicePlanRemovalResponse
                {
                    Meta = ReplyMeta(request),
                    Value = new FileServicePlanRemovalValue { Plan = prepared.Plan },
                };
                CommandDeduplication.Complete(tx, command, response.ToByteArray());
                AuditLog.AppendFileWorkspace(tx, Actor(caller, request), "cleanup.plan FileService.PlanRemoval", null,
                    attempt.Value.ToByteArray(), null, PermissionDecision.Allow, "planned", null);
                return response;
            }, CommitDurability.Full);
        }

        var expected = persisted.ToByteString();
        var first = await RoutePlan(calls, caller, request, raw);
        Assert.Equal(expected, first);
        var decoded = FileServicePlanRemovalResponse.Parser.ParseFrom(first);
        Assert.True(NodeShapes.IsValid(decoded));
        Assert.Null(decoded.Error);
        var plan = decoded.Value.Plan;
        Assert.Equal(attempt, plan.AttemptId);
        Assert.Equal(RiskClass.High, plan.Risk);
        Assert.True(plan.RequiresApproval);
        Assert.True(plan.QuarantineAvailable);
        Assert.Equal(4, plan.Items.Count);
        Assert.True(plan.Items[0].OwnerVerified);
        Assert.All(plan.Items.Skip(1), item => Assert.False(item.OwnerVerified));
        Assert.Equal(-1, first.Span.IndexOf(Encoding.UTF8.GetBytes(Body)));
        var changed = raw.Concat(new byte[] { 0xa0, 0x06, 0x01 }).ToArray();
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(
            await RoutePlan(calls, caller, request, changed)).Error.Code);
        var other = caller.Clone();
        other.LocalSessionId = CommandIds.New();
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(
            await RoutePlan(calls, other, request, raw)).Error.Code);

        Assert.Equal(0, await node.StopAsync());
        var moved = path + "-held";
        Directory.Move(path, moved);
        Directory.CreateDirectory(path);
        File.WriteAllText(Path.Combine(path, "keep.txt"), "unplanned replacement");
        await node.StartAsync();
        Assert.Equal(expected, await RoutePlan(new RoutedCalls(node), caller, request, raw));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM file_removal_plan_item WHERE owner_verified = 1;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal(Body, File.ReadAllText(Path.Combine(moved, "keep.txt")));
        Assert.Equal("unowned child", File.ReadAllText(Path.Combine(moved, "nested", "child.txt")));
        Assert.Equal("unplanned replacement", File.ReadAllText(Path.Combine(path, "keep.txt")));
        foreach (var database in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var stream = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(Encoding.UTF8.GetBytes(Body)));
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task RetainedAttemptRefusalAndHeldJournalRemainWithoutFreshPlanningOrFileEffect()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows attempt directory identity.");
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var (attempt, path, caller) = RetainedWindowsAttemptFixture.Seed(node, Body);
        await node.StartAsync();
        var calls = new RoutedCalls(node);
        var request = Request(attempt);
        var raw = request.ToByteArray();
        var held = CommandIds.New().Value.ToByteArray();
        var heldDigest = SHA256.HashData("historical-attempt-removal-hold"u8);
        var error = NodeErrors.InUse("attempt_in_use");
        RoutedFileErrors.Complete(error, request.Meta, CommandIds.New(), node.Runtime.Clock);
        var refusal = new FileServicePlanRemovalResponse { Meta = ReplyMeta(request), Error = error };
        using (var parent = WorkspacePath.OpenRoot(Path.GetDirectoryName(path)!))
        using (var root = WorkspacePath.OpenRoot(path))
        {
            var parentIdentity = RegisteredWorkspaces.RootIdentity.Encode(parent.RootIdentity);
            var targetIdentity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            node.Runtime.Store.Write(tx =>
            {
                Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, held,
                    "arcforges.node.v1.FileService/ExecuteRemoval", heldDigest, Origin.Remote).Status);
                tx.Execute("""
                    INSERT INTO file_operation_journal
                      (command_id, kind, phase, request_sha256, caller, correlation_id, attempt_id,
                       identity_platform, root_identity, parent_identity, target_identity, expected_absent,
                       created_at, updated_at, held, acknowledged)
                    VALUES ($id, 3, 3, $digest, $caller, $correlation, $attempt,
                            $platform, $parent, $parent, $target, 0, $now, $now, 1, 0);
                    """, ("$id", held), ("$digest", heldDigest), ("$caller", caller.ToByteArray()),
                    ("$correlation", request.Meta.CorrelationId.Value.ToByteArray()), ("$attempt", attempt.Value.ToByteArray()),
                    ("$platform", parentIdentity.Platform), ("$parent", parentIdentity.Bytes), ("$target", targetIdentity.Bytes),
                    ("$now", tx.NowMicroseconds));
                BeginReceipt(tx, request.Meta.CommandId.Value.ToByteArray(), SHA256.HashData(raw), caller);
                CommandDeduplication.Complete(tx, request.Meta.CommandId.Value.Span, refusal.ToByteArray());
                AuditLog.AppendFileWorkspace(tx, Actor(caller, request), "cleanup.plan FileService.PlanRemoval", null,
                    attempt.Value.ToByteArray(), null, PermissionDecision.Deny, "refused: in_use", null);
            }, CommitDurability.Full);
        }

        var bytes = await RoutePlan(calls, caller, request, raw);
        Assert.Equal(refusal.ToByteString(), bytes);
        var retained = FileServicePlanRemovalResponse.Parser.ParseFrom(bytes);
        Assert.True(NodeShapes.IsValid(retained));
        Assert.Null(retained.Value);
        Assert.Equal(("in_use", "attempt_in_use", EffectCertainty.DidNotHappen, RetryMode.AfterTime),
            (retained.Error.Code, retained.Error.Details.State.Reason, retained.Error.Effect, retained.Error.Retry.Mode));
        var fresh = Request(attempt);
        var refused = FileServicePlanRemovalResponse.Parser.ParseFrom(await RoutePlan(calls, caller, fresh, fresh.ToByteArray()));
        Assert.Null(refused.Value);
        Assert.Equal((ErrorCategory.Internal, "internal", "legacy_removal_plan_outcome_unavailable", EffectCertainty.Unknown, RetryMode.Never),
            (refused.Error.Category, refused.Error.Code, refused.Error.Details.State.Reason, refused.Error.Effect, refused.Error.Retry.Mode));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", fresh.Meta.CommandId.Value.ToByteArray()))));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM file_operation_journal WHERE command_id = $id AND phase = 3 AND held = 1 AND acknowledged = 0;",
            ("$id", held))));
        Assert.Equal(Body, File.ReadAllText(Path.Combine(path, "keep.txt")));
    }

    private static async Task<ByteString> RoutePlan(RoutedCalls calls, CenterCaller caller, FileServicePlanRemovalRequest request, byte[] raw)
    {
        var result = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, result.Answer!.Outcome);
        return Assert.IsType<ByteString>(result.Answer.Response);
    }

    private static void BeginReceipt(StoreTransaction tx, byte[] command, byte[] digest, CenterCaller caller)
    {
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, command, PlanMethod, digest, Origin.Remote).Status);
        tx.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);",
            ("$id", command), ("$caller", caller.ToByteArray()));
    }

    private static FileServicePlanRemovalRequest Request(Id attempt) => new() { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };

    private static ResponseMeta ReplyMeta(FileServicePlanRemovalRequest request) => new() { CorrelationId = request.Meta.CorrelationId.Clone() };

    private static ActorRef Actor(CenterCaller caller, FileServicePlanRemovalRequest request) => new()
    {
        Origin = Origin.Remote,
        CenterCaller = caller,
        RemoteCommandId = request.Meta.CommandId,
    };
}
