// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Exercises the real SQLite receipts and mock-routed replay. Native traversal, producer rollback, and commit-fault tests
/// remain at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
/// </summary>
public sealed class FileRemovalPlanRoutedTests
{
    private const string ServiceMethod = "arcforges.node.v1.FileService/PlanRemoval";
    private const string AuditOperation = "cleanup.plan FileService.PlanRemoval";

    [Fact(Timeout = 30_000)]
    public async Task HistoricalPlanReplaysOriginalBytesAfterRestartAndBindsItsOriginalCaller()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var agent = calls.Relay(Origin.Agent);
        var account = RoutedCalls.Session();
        var root = Path.Combine(node.Root, "unavailable-historical-workspace");
        var request = Request(CommandIds.New());
        var accountRequest = Request(request.WorkspacePath.WorkspaceId);
        var now = node.Runtime.Clock.GetUtcNow();
        var items = new[] { Item("tree", FileEntryKind.Directory, 0), Item("tree/file.txt", FileEntryKind.File, 37) };
        var response = Plan(request, now, items);
        var accountResponse = Plan(accountRequest, now, items);
        var expected = WithUnknownField(response);
        node.Runtime.Store.Write(transaction =>
        {
            Seed(transaction, agent, request, response, root, expected);
            Seed(transaction, account, accountRequest, accountResponse, root);
            return 0;
        }, CommitDurability.Full);

        var replay = await RouteAsync(calls, agent, request, ct);
        Assert.Equal(expected, replay.Response!.ToByteArray());
        var parsed = Parse(replay);
        Assert.Equal(request.Meta.CorrelationId, parsed.Meta.CorrelationId);
        Assert.Equal(37UL, parsed.Value.Plan.TotalBytes);
        Assert.Equal(request.WorkspacePath, parsed.Value.Plan.WorkspacePath);

        var otherRelay = agent.Clone();
        otherRelay.LocalSessionId = CommandIds.New();
        Assert.Equal("command_id_reused", Parse(await RouteAsync(calls, otherRelay, request, ct)).Error.Code);
        var wrongBytes = WithUnknownField(request);
        Assert.Equal("command_id_reused", Parse(await RouteAsync(calls, agent, request, ct, wrongBytes)).Error.Code);
        var differentCorrelation = request.Clone();
        differentCorrelation.Meta.CorrelationId = CommandIds.New();
        Assert.Equal("command_id_reused", Parse(await RouteAsync(calls, agent, differentCorrelation, ct)).Error.Code);
        var otherAccountUser = RoutedCalls.Session();
        otherAccountUser.UserId = CommandIds.New();
        Assert.Equal(accountResponse.ToByteArray(), (await RouteAsync(calls, otherAccountUser, accountRequest, ct)).Response!.ToByteArray());

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        Assert.Equal(expected, (await RouteAsync(calls, agent, request, ct)).Response!.ToByteArray());
        Assert.Equal(accountResponse.ToByteArray(), (await RouteAsync(calls, otherAccountUser, accountRequest, ct)).Response!.ToByteArray());
        Assert.False(Directory.Exists(root));
        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(2L, reader.Scalar("SELECT count(*) FROM command_dedup;"));
            Assert.Equal(2L, reader.Scalar("SELECT count(*) FROM file_removal_plan;"));
            Assert.Equal(4L, reader.Scalar("SELECT count(*) FROM file_removal_plan_item;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM quarantine_entry;"));
            Assert.Equal(SHA256.HashData(request.ToByteArray()), reader.Scalar(
                "SELECT request_sha256 FROM file_removal_plan WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray())) as byte[]);
            return 0;
        });
    }

    [Fact(Timeout = 30_000)]
    public async Task FreshPlanningStaysUnknownAndCurrentPolicyDenialIsAuditedWithoutAdmission()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var request = Request(CommandIds.New());
        var unknown = Parse(await RouteAsync(calls, caller, request, ct));
        Assert.True(RoutedFileResponseValidation.RemovalPlanOutcome(unknown, request));
        Assert.Equal(("internal", EffectCertainty.Unknown, RetryMode.Never), (unknown.Error.Code, unknown.Error.Effect, unknown.Error.Retry.Mode));

        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.CleanupPlan,
            Origin = Origin.Agent,
            Decision = PermissionDecision.Deny,
        }))).Error);
        var denied = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId, cancellationToken: ct);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, denied.Answer!.Outcome);
        Assert.Equal("permission_denied", denied.Answer.Error!.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, denied.Answer.Error.Effect);
        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(1L, reader.Scalar("""
                SELECT count(*) FROM file_workspace_audit f JOIN audit_log a ON a.seq = f.audit_seq
                WHERE a.remote_command_id = $id AND f.workspace_id = $workspace AND a.decision = $deny;
                """, ("$id", request.Meta.CommandId.Value.ToByteArray()), ("$workspace", request.WorkspacePath.WorkspaceId.Value.ToByteArray()),
                ("$deny", (int)PermissionDecision.Deny)));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;",
                ("$id", request.Meta.CommandId.Value.ToByteArray())));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM cleanup_plan;"));
            return 0;
        });
    }

    [Fact(Timeout = 30_000)]
    public async Task RetainedPolicyRefusalPreservesItsRecordedReasonEvenWhenCurrentPolicyAllows()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var request = Request(CommandIds.New());
        var error = NodeErrors.PermissionDenied(PermissionMatrix.CleanupPlan);
        RoutedFileErrors.Complete(error, request.Meta, request.Meta.CorrelationId, node.Runtime.Clock);
        var historical = Refusal(request, error);
        node.Runtime.Store.Write(transaction => Seed(transaction, caller, request, historical, policyReason: "denied"), CommitDurability.Full);

        var replay = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId, cancellationToken: ct);
        Assert.Equal(RoutedOutcome.RefusedByPolicy, replay.Answer!.Outcome);
        Assert.Equal("denied", replay.Answer.Error!.Details.State.Reason);
        Assert.Equal(request.Meta.CorrelationId, replay.Answer.Error.CorrelationId);
        var fresh = Request(request.WorkspacePath.WorkspaceId);
        Assert.Equal(EffectCertainty.Unknown, Parse(await RouteAsync(calls, caller, fresh, ct)).Error.Effect);
        Assert.Equal(historical.ToByteArray(), node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))) as byte[]);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
    }

    [Theory(Timeout = 30_000)]
    [InlineData("removal_descendants", "1000")]
    [InlineData("removal_total_bytes", "67108864")]
    [InlineData("removal_plan_response_bytes", "1040384")]
    public async Task RetainedLimitsReplayExactlyEvenAfterCurrentPolicyChanges(string limitName, string maximum)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var request = Request(CommandIds.New());
        var historical = Refusal(request, Limit(request, limitName, maximum));
        node.Runtime.Store.Write(transaction => Seed(transaction, caller, request, historical), CommitDurability.Full);

        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
        {
            Operation = PermissionMatrix.CleanupPlan,
            Origin = Origin.Agent,
            Decision = PermissionDecision.Deny,
        }))).Error);

        var answer = await RouteAsync(calls, caller, request, ct);
        Assert.Equal(historical.ToByteArray(), answer.Response!.ToByteArray());
        var refusal = Parse(answer);
        Assert.Null(refusal.Value);
        Assert.Equal((limitName, maximum), (refusal.Error.Details.Limit.LimitName, refusal.Error.Details.Limit.Maximum.Value));
        Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
        Assert.True(RoutedFileResponseValidation.RemovalPlanOutcome(refusal, request));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
    }

    [Fact(Timeout = 30_000)]
    public async Task OversizedRequestPathIsRefusedWithoutAStoredPlan()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var request = Request(CommandIds.New());
        request.WorkspacePath.Path = new string('x', 4097);

        var refusal = Parse(await RouteAsync(calls, calls.Relay(Origin.Agent), request, ct));
        Assert.Equal("too_large", refusal.Error.Code);
        Assert.Equal(("path_bytes", "4096"), (refusal.Error.Details.Limit.LimitName, refusal.Error.Details.Limit.Maximum.Value));
        Assert.Equal(EffectCertainty.DidNotHappen, refusal.Error.Effect);
        Assert.True(RoutedFileResponseValidation.RemovalPlanOutcome(refusal, request));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
    }

    [Fact(Timeout = 30_000)]
    public async Task HistoricalPathEnforcementRefusalSurvivesWithoutOpeningTheWorkspace()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var request = Request(CommandIds.New());
        var historical = Refusal(request, new ArcError
        {
            Category = ErrorCategory.State,
            Code = "file_access_denied",
            MessageKey = "error.state.file_access_denied",
            CorrelationId = request.Meta.CorrelationId.Clone(),
            Effect = EffectCertainty.DidNotHappen,
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "path_enforcement_unavailable" } },
        });
        node.Runtime.Store.Write(transaction => Seed(transaction, caller, request, historical), CommitDurability.Full);

        var replay = await RouteAsync(calls, caller, request, ct);
        Assert.Equal(historical.ToByteString(), replay.Response);
        Assert.True(RoutedFileResponseValidation.RemovalPlanOutcome(Parse(replay), request));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
    }

    [Fact(Timeout = 30_000)]
    public async Task ThousandRetainedDescendantsFitThePublishedConsumerWithoutWorkspaceAccess()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var root = Path.Combine(node.Root, "unavailable-large-workspace");
        var request = Request(CommandIds.New());
        var items = new List<FileRemovalItem> { Item("tree", FileEntryKind.Directory, 0) };
        for (var index = 0; index < 1000; index++)
            items.Add(Item(FormattableString.Invariant($"tree/{index:D4}"), FileEntryKind.File, 0));
        var historical = Plan(request, node.Runtime.Clock.GetUtcNow(), items);
        node.Runtime.Store.Write(transaction => Seed(transaction, caller, request, historical, root), CommitDurability.Full);

        var answer = await RouteAsync(calls, caller, request, ct);
        Assert.Equal(historical.ToByteString(), answer.Response);
        Assert.Equal(1001, Parse(answer).Value.Plan.Items.Count);
        var target = CommandIds.New();
        Assert.True(RoutedFileResponseValidation.PlanRemoval(new FleetServicePlanNodeRemovalResponse
        {
            Meta = historical.Meta.Clone(),
            Value = new FleetServicePlanNodeRemovalValue { NodeId = target, Response = answer.Response },
        }, target, request));
        Assert.Equal(1001L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan_item;")));
        Assert.False(Directory.Exists(root));
    }

    internal static FileServicePlanRemovalRequest Request(Id workspace) => new()
    {
        Meta = Tasks.Meta(),
        WorkspacePath = new FilePath { WorkspaceId = workspace.Clone(), Path = "tree" },
    };

    internal static FileRemovalItem Item(string path, FileEntryKind kind, ulong size) => new()
    {
        Path = path,
        Kind = kind,
        SizeBytes = size,
        IdentitySha256 = ByteString.CopyFrom(SHA256.HashData(Encoding.UTF8.GetBytes(path))),
        OwnerVerified = false,
    };

    internal static FileServicePlanRemovalResponse Plan(FileServicePlanRemovalRequest request, DateTimeOffset now,
        IReadOnlyList<FileRemovalItem> items, FileAuditMetadata? audit = null) => new()
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Value = new()
            {
                Plan = new()
                {
                    PlanId = CommandIds.New(),
                    Digest = ByteString.CopyFrom(SHA256.HashData(request.ToByteArray())),
                    ExpiresAt = ProtoTime.ToInstant(now.AddMinutes(5)),
                    WorkspacePath = request.WorkspacePath.Clone(),
                    TotalBytes = checked((ulong)items.Sum(item => (long)item.SizeBytes)),
                    RequiresApproval = true,
                    QuarantineAvailable = true,
                    Risk = RiskClass.High,
                    Items = { items },
                },
            },
            Audit = audit,
        };

    internal static FileServicePlanRemovalResponse Refusal(FileServicePlanRemovalRequest request, ArcError error,
        FileAuditMetadata? audit = null) => new()
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId.Clone() },
            Error = error,
            Audit = audit,
        };

    internal static ArcError Limit(FileServicePlanRemovalRequest request, string name, string maximum) => new()
    {
        Category = ErrorCategory.Resource,
        Code = "too_large",
        MessageKey = "error.resource.too_large",
        CorrelationId = request.Meta.CorrelationId.Clone(),
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Details = new ErrorDetails
        {
            Limit = new LimitFailure { LimitName = name, Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = maximum } },
        },
    };

    internal static async Task<RoutedAnswer> RouteAsync(RoutedCalls calls, CenterCaller caller, FileServicePlanRemovalRequest request,
        CancellationToken cancellationToken, byte[]? raw = null)
    {
        var result = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, raw ?? request.ToByteArray(), request.Meta.CommandId,
            cancellationToken: cancellationToken);
        Assert.NotNull(result.Answer);
        Assert.Equal(RoutedOutcome.Executed, result.Answer.Outcome);
        Assert.NotNull(result.Answer.Response);
        return result.Answer;
    }

    internal static FileServicePlanRemovalResponse Parse(RoutedAnswer answer) => FileServicePlanRemovalResponse.Parser.ParseFrom(answer.Response);

    internal static byte[] WithUnknownField(IMessage message) => [0x98, 0x06, 0x01, .. message.ToByteArray()];

    internal static int Seed(StoreTransaction transaction, CenterCaller caller, FileServicePlanRemovalRequest request,
        FileServicePlanRemovalResponse response, string? workspaceRoot = null, byte[]? retained = null, string? policyReason = null)
    {
        var id = request.Meta.CommandId.Value.ToByteArray();
        var digest = SHA256.HashData(request.ToByteArray());
        var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = request.Meta.CommandId.Clone() };
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, id, ServiceMethod, digest, Origin.Remote).Status);
        transaction.Execute("INSERT INTO file_removal_command_owner (command_id, caller, policy_reason) VALUES ($id, $caller, $reason);",
            ("$id", id), ("$caller", caller.ToByteArray()), ("$reason", policyReason));
        if (response.Value?.Plan is { } plan)
            SeedPlan(transaction, actor, id, digest, plan, workspaceRoot ?? throw new InvalidOperationException("A plan fixture needs its recorded root."));
        AuditLog.AppendFileWorkspace(transaction, actor, AuditOperation, request.WorkspacePath.WorkspaceId.Value.ToByteArray(), null,
            request.WorkspacePath.Path, response.Error is null ? PermissionDecision.Allow : PermissionDecision.Deny,
            response.Error is { } error ? "refused: " + error.Code : "planned", response.Audit);
        CommandDeduplication.Complete(transaction, id, retained ?? response.ToByteArray());
        return 0;
    }

    private static void SeedPlan(StoreTransaction transaction, ActorRef actor, byte[] command, byte[] requestDigest,
        FileRemovalPlan plan, string workspaceRoot)
    {
        var planId = plan.PlanId.Value.ToByteArray();
        var digest = plan.Digest.ToByteArray();
        var workspace = plan.WorkspacePath.WorkspaceId.Value.ToByteArray();
        const int platform = 1;
        byte[] rootIdentity = [1, .. new byte[32]];
        transaction.Execute("""
            INSERT OR IGNORE INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
            VALUES ($workspace, 1, 1, 'historical removal fixture', $root, $now, $now, 0);
            """, ("$workspace", workspace), ("$root", workspaceRoot), ("$now", transaction.NowMicroseconds));
        transaction.Execute("""
            INSERT INTO cleanup_plan (plan_id, state, digest, planned_by, total_bytes, item_count, created_at, expires_at, rev)
            VALUES ($plan, 1, $digest, $actor, $total, $count, $now, $expires, 0);
            """, ("$plan", planId), ("$digest", digest), ("$actor", actor.ToByteArray()), ("$total", (long)plan.TotalBytes),
            ("$count", plan.Items.Count), ("$now", transaction.NowMicroseconds),
            ("$expires", StoreTime.ToMicroseconds(ProtoTime.ToDateTimeOffset(plan.ExpiresAt)!.Value)));
        transaction.Execute("""
            INSERT INTO file_removal_plan (plan_id, command_id, request_sha256, caller, target_kind, workspace_id, workspace_path,
                root_platform, root_identity, requires_approval, quarantine_available)
            VALUES ($plan, $command, $request, $caller, 1, $workspace, $path, $platform, $identity, 1, 1);
            """, ("$plan", planId), ("$command", command), ("$request", requestDigest), ("$caller", actor.CenterCaller.ToByteArray()),
            ("$workspace", workspace), ("$path", plan.WorkspacePath.Path), ("$platform", platform), ("$identity", rootIdentity));
        for (var index = 0; index < plan.Items.Count; index++)
        {
            var item = plan.Items[index];
            var itemId = StoreIds.NewUuid7(transaction.Clock);
            transaction.Execute("""
                INSERT INTO cleanup_item (plan_id, item_id, path, size_bytes, item_class, reason, risk, action,
                    fp_mtime, fp_size, fp_owner_state, external)
                VALUES ($plan, $item, $path, $size, 10, 'ownership_unverified', 3, 1, 0, $size, 'unverified', 1);
                """, ("$plan", planId), ("$item", itemId), ("$path", Path.Combine(workspaceRoot, item.Path)), ("$size", (long)item.SizeBytes));
            transaction.Execute("""
                INSERT INTO file_removal_plan_item (plan_id, item_id, ordinal, relative_path, entry_kind, native_platform, native_identity,
                    identity_sha256, fingerprint_sha256, stamp_size, stamp_mtime, stamp_mtime_nsec, stamp_change, stamp_change_nsec,
                    mode, link_count, owner_verified)
                VALUES ($plan, $item, $index, $path, $kind, $platform, $identity, $digest, $digest, $size, 0, 0, 0, 0, 0, 1, 0);
                """, ("$plan", planId), ("$item", itemId), ("$index", index), ("$path", item.Path), ("$kind", (int)item.Kind),
                ("$platform", platform), ("$identity", rootIdentity), ("$digest", item.IdentitySha256.ToByteArray()), ("$size", (long)item.SizeBytes));
        }
    }
}
