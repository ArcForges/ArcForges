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
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed class LegacyRemovalDrainTests
{
    private const string Service = "arcforges.node.v1.FileService/";

    [Fact(Timeout = 30_000)]
    public async Task RemovalOnlyReplaysExactReceiptsAndLeavesApprovedUncertainWorkAndHoldsIntact()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = InProcessNode.Create();
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = fixture.DataRoot, BootIdentity = "legacy-removal-fixture" });
        using var log = new NodeLog(Path.Combine(fixture.DataRoot, "logs", "node"), LogLevel.Info, fixture.Clock);
        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        await using var processor = new CommandProcessor(store, journal, hub);
        using var runtime = new NodeRuntime(store, journal, hub, processor, log,
            new NodeSettingsManager(fixture.ConfigPath, fixture.DataRoot, log), fixture.DataRoot, "offline-fixture", fixture.Clock,
            new RecoveryReport(false, false, null, store.Opening), new CapabilityReport());
        Assert.Null(runtime.Execution);
        var executors = new ApprovalExecutors();
        var sessions = new ClientSessions();
        var files = new FileServiceHandler(runtime);
        var approvals = new ApprovalServiceHandler(runtime, sessions, executors);
        executors.RegisterReference("FileService.ExecuteRemoval", PermissionMatrix.FileRemove, files.ExecuteApprovedRemovalReferenceAsync);
        using var dispatcher = new RoutedDispatcher(runtime);
        dispatcher.Bind(new TaskServiceHandler(runtime, sessions, executors), new WorkspaceServiceHandler(runtime), files);
        var center = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = RoutedCalls.Account.Clone(),
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(runtime.NodeId.Span) },
            LocalOrigin = Origin.Human,
            LocalSessionId = CommandIds.New(),
        };
        var other = center.Clone();
        other.LocalSessionId = CommandIds.New();
        var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = center };

        async Task<RoutedAnswer> Route(RoutedMethod method, RequestMeta meta, IMessage request, CenterCaller? owner = null, byte[]? raw = null)
        {
            raw ??= request.ToByteArray();
            var now = runtime.Clock.GetUtcNow();
            var header = new CallHeader
            {
                CallId = CommandIds.New(),
                Kid = "fixture",
                AccountId = RoutedCalls.Account.Clone(),
                TargetNodeId = center.RelayingNodeId.Clone(),
                Caller = owner ?? center,
                CommandId = meta.CommandId.Clone(),
                Method = method,
                RequestSha256 = ByteString.CopyFrom(SHA256.HashData(raw)),
                RequestSize = (uint)raw.Length,
                IssuedAt = ProtoTime.ToInstant(now.AddSeconds(-1)),
                ExpiresAt = ProtoTime.ToInstant(now.AddMinutes(1)),
                Deadline = ProtoTime.ToInstant(now.AddSeconds(9)),
            };
            var answer = await dispatcher.DispatchAsync(new VerifiedCall(header, ByteString.CopyFrom(raw), 0), new RoutedCalls.TestLink(), ct);
            Assert.NotNull(answer);
            Assert.Equal(RoutedOutcome.Executed, answer.Outcome);
            Assert.NotNull(answer.Response);
            return answer;
        }

        var path = new FilePath { WorkspaceId = CommandIds.New(), Path = "existing-file" };
        var oldPlan = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), WorkspacePath = path.Clone() };
        var planId = CommandIds.New();
        var digest = ByteString.CopyFrom(SHA256.HashData("historical plan digest"u8));
        var storedPlan = new FileServicePlanRemovalResponse
        {
            Meta = ReplyMeta(oldPlan.Meta),
            Value = new()
            {
                Plan = new()
                {
                    PlanId = planId,
                    Digest = digest,
                    WorkspacePath = path.Clone(),
                    ExpiresAt = ProtoTime.ToInstant(runtime.Clock.GetUtcNow().AddMinutes(5)),
                    TotalBytes = 1,
                    RequiresApproval = false,
                    QuarantineAvailable = true,
                    Risk = RiskClass.Low,
                    Items = { new FileRemovalItem { Path = path.Path, Kind = FileEntryKind.File, SizeBytes = 1, OwnerVerified = true, IdentitySha256 = digest } },
                },
            },
        };
        byte[] planBytes = [0x98, 0x06, 1, .. storedPlan.ToByteArray()];
        var oldRemoval = Execution(planId, digest);
        byte[] removalBytes = [0x98, 0x06, 1, .. PriorRefusal(oldRemoval).ToByteArray()];
        var ownerless = Execution(planId, digest);
        var orphaned = Execution(planId, digest);
        var orphanedReceipt = new FileServiceExecuteRemovalResponse
        {
            Meta = ReplyMeta(orphaned.Meta),
            Value = new FileServiceExecuteRemovalValue
            {
                Result = new FileRemovalResult
                {
                    PlanId = planId,
                    Quarantined = true,
                    QuarantineId = CommandIds.New(),
                    PurgeAfter = ProtoTime.ToInstant(runtime.Clock.GetUtcNow().AddDays(1)),
                    ItemsRemoved = 1,
                    TotalBytes = 1,
                },
            },
        };
        Assert.True(RoutedFileResponseValidation.RemovalExecutionOutcome(orphanedReceipt, orphaned));
        var unresolved = Execution(CommandIds.New(), digest);
        var settled = Execution(CommandIds.New(), digest);
        var settledBytes = PriorRefusal(settled).ToByteArray();
        var (unresolvedId, settledId) = await processor.ExecuteAsync(command =>
        {
            var tx = command.Transaction;
            tx.Execute("""
                INSERT INTO workspace (workspace_id, kind, state, name, root_path, created_at, last_used_at, rev)
                VALUES ($id, 1, 1, 'synthetic', $root, $now, $now, 1);
                """, ("$id", path.WorkspaceId.Value.ToByteArray()), ("$root", Path.Combine(fixture.DataRoot, "synthetic-workspace")),
                ("$now", tx.NowMicroseconds));
            SeedReceipt(tx, "PlanRemoval", oldPlan.Meta, oldPlan, center, planBytes);
            SeedReceipt(tx, "ExecuteRemoval", oldRemoval.Meta, oldRemoval, center, removalBytes);
            SeedReceipt(tx, "ExecuteRemoval", ownerless.Meta, ownerless, null, PriorRefusal(ownerless).ToByteArray());
            SeedReceipt(tx, "ExecuteRemoval", orphaned.Meta, orphaned, center, orphanedReceipt.ToByteArray());
            SeedPlan(tx, planId, oldPlan.Meta.CommandId, digest, path, actor, approval: null);
            byte[] Approval(FileServiceExecuteRemovalRequest request)
            {
                var id = request.Meta.CommandId.Value.ToByteArray();
                var requester = actor.Clone();
                requester.RemoteCommandId = request.Meta.CommandId.Clone();
                var (approval, created, error) = Approvals.Raise(command, new ApprovalCapture
                {
                    Operation = "FileService.ExecuteRemoval",
                    MatrixOperation = PermissionMatrix.FileRemove,
                    Summary = "historical removal fixture",
                    Risk = RiskClass.High,
                    Requester = requester,
                    CommandId = id,
                    Request = [2, .. id],
                    RequestDigest = SHA256.HashData(request.ToByteArray()),
                    TargetKind = "cleanup_plan",
                    TargetId = request.PlanId.Value.ToByteArray(),
                    Details =
                    [
                        new KeyValue { Name = "plan_id", Value = Convert.ToHexStringLower(request.PlanId.Value.Span) },
                        new KeyValue { Name = "plan_digest", Value = Convert.ToHexStringLower(request.PlanDigest.Span) },
                        new KeyValue { Name = "correlation_id", Value = Convert.ToHexStringLower(request.Meta.CorrelationId.Value.Span) },
                        new KeyValue { Name = "delete_without_quarantine", Value = "false" },
                    ],
                }, TimeSpan.FromMinutes(5));
                Assert.True(created);
                Assert.Null(error);
                Assert.NotNull(approval);
                var accepted = Approvals.Decide(command, approval.Id, approve: true, new ActorRef { Origin = Origin.Human }, null);
                SeedPlan(tx, request.PlanId, oldPlan.Meta.CommandId, digest, path, actor, accepted.Id);
                SeedReceipt(tx, "ExecuteRemoval", request.Meta, request, center, null);
                var identity = new RegisteredWorkspaces.RootIdentity(1, [1, .. new byte[32]]);
                FileMutationJournal.PrepareRemoval(tx, id, request.Meta.CorrelationId.Value.ToByteArray(), SHA256.HashData(request.ToByteArray()),
                    center, path.WorkspaceId.Value.ToByteArray(), null, path.Path, identity, identity, identity,
                    request.PlanId.Value.ToByteArray(), "synthetic-quarantine-location");
                return accepted.Id;
            }

            var completed = Approval(settled);
            Assert.Equal(settledBytes, FileMutationJournal.CompleteRemoval(tx, settled.Meta.CommandId.Value.ToByteArray(),
                settled.PlanId.Value.ToByteArray(), PriorRefusal(settled)));
            var pending = Approval(unresolved);
            return (pending, completed);
        }, CommitDurability.Full).WaitAsync(ct);

        var restoredPlan = await Route(RoutedMethod.PlanNodeRemoval, oldPlan.Meta, oldPlan);
        Assert.Equal(planBytes, restoredPlan.Response!.ToByteArray());
        var restoredRemoval = await Route(RoutedMethod.ExecuteNodeRemoval, oldRemoval.Meta, oldRemoval);
        Assert.Equal(removalBytes, restoredRemoval.Response!.ToByteArray());
        var foreign = await Route(RoutedMethod.ExecuteNodeRemoval, oldRemoval.Meta, oldRemoval, other);
        Assert.Equal("command_id_reused", FileServiceExecuteRemovalResponse.Parser.ParseFrom(foreign.Response).Error.Code);
        var missingOwner = await Route(RoutedMethod.ExecuteNodeRemoval, ownerless.Meta, ownerless);
        Assert.Equal("command_id_reused", FileServiceExecuteRemovalResponse.Parser.ParseFrom(missingOwner.Response).Error.Code);
        var noCustody = await Route(RoutedMethod.ExecuteNodeRemoval, orphaned.Meta, orphaned);
        AssertUnknown(FileServiceExecuteRemovalResponse.Parser.ParseFrom(noCustody.Response).Error);
        var changed = await Route(RoutedMethod.PlanNodeRemoval, oldPlan.Meta, oldPlan, raw: [.. oldPlan.ToByteArray(), 0x98, 0x06, 1]);
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(changed.Response).Error.Code);

        var freshPlan = oldPlan.Clone();
        freshPlan.Meta = Tasks.Meta();
        var newPlan = await Route(RoutedMethod.PlanNodeRemoval, freshPlan.Meta, freshPlan);
        var planRefusal = FileServicePlanRemovalResponse.Parser.ParseFrom(newPlan.Response);
        Assert.True(RoutedFileResponseValidation.RemovalPlanOutcome(planRefusal, freshPlan));
        AssertUnknown(planRefusal.Error);
        var freshExecution = Execution(planId, digest);
        var newRemoval = await Route(RoutedMethod.ExecuteNodeRemoval, freshExecution.Meta, freshExecution);
        var removalRefusal = FileServiceExecuteRemovalResponse.Parser.ParseFrom(newRemoval.Response);
        Assert.True(RoutedFileResponseValidation.RemovalExecutionOutcome(removalRefusal, freshExecution));
        AssertUnknown(removalRefusal.Error);
        var foreignPlan = await Route(RoutedMethod.ExecuteNodeRemoval, freshExecution.Meta, freshExecution, other);
        Assert.Equal("not_found", FileServiceExecuteRemovalResponse.Parser.ParseFrom(foreignPlan.Response).Error.Code);
        var wrongDigest = Execution(planId, ByteString.CopyFrom(SHA256.HashData("changed"u8)));
        var conflict = await Route(RoutedMethod.ExecuteNodeRemoval, wrongDigest.Meta, wrongDigest);
        Assert.Equal("digest_mismatch", FileServiceExecuteRemovalResponse.Parser.ParseFrom(conflict.Response).Error.Code);
        var unresolvedReply = await Route(RoutedMethod.ExecuteNodeRemoval, unresolved.Meta, unresolved);
        AssertUnknown(FileServiceExecuteRemovalResponse.Parser.ParseFrom(unresolvedReply.Response).Error);

        await approvals.ResumeAsync().WaitAsync(ct);
        var pendingResult = store.Read(reader => Approvals.Get(reader, unresolvedId));
        Assert.Equal(ApprovalState.Approved, pendingResult!.State);
        Assert.Null(pendingResult.Outcome);
        var settledResult = store.Read(reader => Approvals.Get(reader, settledId));
        Assert.Equal(ApprovalState.Failed, settledResult!.State);
        Assert.Equal(settledBytes, settledResult.Outcome);
        Assert.Equal(6L, store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup;")));
        Assert.Equal(3L, store.Read(reader => reader.Scalar("SELECT count(*) FROM cleanup_plan;")));
        Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM quarantine_entry;")));
        Assert.Equal(2L, store.Read(reader => reader.Scalar("SELECT count(*) FROM approval;")));
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal WHERE phase = 1 AND held = 1;")));

        var recovered = store.Write(tx => FileMutationJournal.MarkUnknown(tx, unresolved.Meta.CommandId.Value.Span), CommitDurability.Full);
        var recoveredReply = await Route(RoutedMethod.ExecuteNodeRemoval, unresolved.Meta, unresolved);
        Assert.Equal(recovered, recoveredReply.Response!.ToByteArray());
        await approvals.ResumeAsync().WaitAsync(ct);
        Assert.Equal(ApprovalState.Approved, store.Read(reader => Approvals.Get(reader, unresolvedId))!.State);
        Assert.Equal(1L, store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal WHERE phase = 3 AND held = 1;")));
    }

    private static void SeedReceipt(StoreTransaction tx, string method, RequestMeta meta, IMessage request, CenterCaller? owner, byte[]? response)
    {
        var id = meta.CommandId.Value.ToByteArray();
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, id, Service + method, SHA256.HashData(request.ToByteArray()), Origin.Remote).Status);
        if (owner is not null)
            tx.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);", ("$id", id), ("$caller", owner.ToByteArray()));
        if (response is not null)
            CommandDeduplication.Complete(tx, id, response);
    }

    private static void SeedPlan(StoreTransaction tx, Id id, Id command, ByteString digest, FilePath path, ActorRef actor, byte[]? approval)
    {
        tx.Execute("""
            INSERT INTO cleanup_plan (plan_id, state, digest, planned_by, approval_id, total_bytes, item_count, created_at, expires_at, rev)
            VALUES ($id, $state, $digest, $actor, $approval, 1, 1, $now, $expires, 1);
            """, ("$id", id.Value.ToByteArray()), ("$state", approval is null ? 1 : 2), ("$digest", digest.ToByteArray()),
            ("$actor", actor.ToByteArray()), ("$approval", approval), ("$now", tx.NowMicroseconds),
            ("$expires", tx.NowMicroseconds + (long)TimeSpan.FromMinutes(5).TotalMicroseconds));
        tx.Execute("""
            INSERT INTO file_removal_plan (plan_id, command_id, request_sha256, caller, target_kind, workspace_id, workspace_path,
                root_platform, root_identity, requires_approval, quarantine_available)
            VALUES ($id, $command, $digest, $caller, 1, $workspace, $path, 1, zeroblob(16), $approval, 1);
            """, ("$id", id.Value.ToByteArray()), ("$command", command.Value.ToByteArray()), ("$digest", digest.ToByteArray()),
            ("$caller", actor.CenterCaller.ToByteArray()), ("$workspace", path.WorkspaceId.Value.ToByteArray()),
            ("$path", path.Path), ("$approval", approval is null ? 0 : 1));
    }

    private static ResponseMeta ReplyMeta(RequestMeta request) => new() { CorrelationId = request.CorrelationId.Clone() };

    private static FileServiceExecuteRemovalRequest Execution(Id plan, ByteString digest) =>
        new() { Meta = Tasks.Meta(), PlanId = plan.Clone(), PlanDigest = digest, DeleteWithoutQuarantine = false };

    private static FileServiceExecuteRemovalResponse PriorRefusal(FileServiceExecuteRemovalRequest request) => new()
    {
        Meta = ReplyMeta(request.Meta),
        Error = new ArcError
        {
            Category = ErrorCategory.Conflict,
            Code = "file_changed",
            MessageKey = "error.conflict.file_changed",
            CorrelationId = request.Meta.CorrelationId.Clone(),
            Effect = EffectCertainty.DidNotHappen,
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "planned_tree_changed" } },
        },
    };

    private static void AssertUnknown(ArcError error)
    {
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
    }
}
