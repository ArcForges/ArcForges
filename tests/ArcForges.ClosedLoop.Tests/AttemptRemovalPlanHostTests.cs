// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.ClosedLoop.Tests;

[Trait("loop", "local")]
public sealed class AttemptRemovalPlanHostTests
{
    // Native Attempt/temp production and Plan collection remain executable at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
    [Fact(Timeout = 180_000)]
    [Trait("env", "windows-real")]
    public async Task ACompletedWindowsAttemptPlanReplaysWithoutReinspectingItsTree()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The retained plan uses Windows identity encoding.");
        var ct = TestContext.Current.CancellationToken;
        await using var history = new LegacyFileHostHistory();
        var owner = history.Caller(Origin.Agent);
        var request = new FileServicePlanRemovalRequest { Meta = LegacyFileHostHistory.Command(), AttemptId = SeedFinishedAttempt(history, owner) };
        var path = Path.Combine(history.Root, "retained-attempt");
        var nested = Directory.CreateDirectory(Path.Combine(path, "later")).FullName;
        var file = Path.Combine(path, "keep.txt");
        File.WriteAllText(file, "retained root file");
        File.WriteAllText(Path.Combine(nested, "child.txt"), "retained child file");
        WorkspaceRemovalSnapshot snapshot;
        using (var root = WorkspacePath.OpenRoot(path))
        {
            var identity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            snapshot = WorkspaceRemovalPlan.CaptureCheckedRoot(root, identity.Platform, identity.Bytes, ct);
        }
        var raw = request.ToByteArray();
        var digest = SHA256.HashData(raw);
        var receipt = history.Store.Write(tx =>
        {
            var caller = new ActorRef { Origin = Origin.Remote, CenterCaller = owner, RemoteCommandId = request.Meta.CommandId };
            var prepared = FileRemovalPlans.PrepareAttempt(tx, request.Meta.CommandId.Value.Span, digest, owner, caller, request.AttemptId,
                path, snapshot, tx.NowMicroseconds,
                new Dictionary<string, AttemptDirectoryTracking>(StringComparer.Ordinal) { [""] = AttemptDirectoryTracking.Tracked, ["later"] = AttemptDirectoryTracking.Untracked },
                quarantineAvailable: true);
            FileRemovalPlans.RecordAttempt(tx, prepared);
            return Retain(tx, request, owner, new FileServicePlanRemovalResponse
            {
                Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
                Value = new FileServicePlanRemovalValue { Plan = prepared.Plan },
            });
        }, CommitDurability.Full);

        var first = await history.RouteAsync(RoutedMethod.PlanNodeRemoval, owner, request, request.Meta.CommandId, ct);
        Assert.Equal(receipt, first?.Response?.ToByteArray());
        var plan = FileServicePlanRemovalResponse.Parser.ParseFrom(receipt).Value.Plan;
        Assert.Equal(request.AttemptId, plan.AttemptId);
        Assert.Null(plan.WorkspacePath);
        Assert.True(plan.RequiresApproval);
        Assert.True(plan.QuarantineAvailable);
        Assert.Equal(RiskClass.High, plan.Risk);
        Assert.Equal(snapshot.TotalBytes, plan.TotalBytes);
        Assert.Equal(4, plan.Items.Count);
        Assert.True(plan.Items[0].OwnerVerified);
        Assert.All(plan.Items.Skip(1), item => Assert.False(item.OwnerVerified));

        File.WriteAllText(file, "later fixture bytes");
        await history.ReopenAsync();
        var replay = await history.RouteAsync(RoutedMethod.PlanNodeRemoval, owner, request, request.Meta.CommandId, ct);
        Assert.Equal(receipt, replay?.Response?.ToByteArray());
        var foreign = owner.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var refused = await history.RouteAsync(RoutedMethod.PlanNodeRemoval, foreign, request, request.Meta.CommandId, ct);
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(refused!.Response).Error.Code);
        Assert.Equal(1L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal("later fixture bytes", File.ReadAllText(file));
        Assert.Equal("retained child file", File.ReadAllText(Path.Combine(nested, "child.txt")));
    }

    [Fact(Timeout = 180_000)]
    [Trait("env", "linux-real")]
    public async Task ARecordedLinuxQualificationRefusalReplaysWithoutCreatingAPlan()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The historical refusal describes unavailable Linux attempt provenance.");
        var ct = TestContext.Current.CancellationToken;
        await using var history = new LegacyFileHostHistory();
        var owner = history.Caller(Origin.Agent);
        var request = new FileServicePlanRemovalRequest { Meta = LegacyFileHostHistory.Command(), AttemptId = SeedFinishedAttempt(history, owner) };
        var path = Directory.CreateDirectory(Path.Combine(history.Root, "retained-attempt")).FullName;
        var file = Path.Combine(path, "keep.txt");
        File.WriteAllText(file, "retained without provenance");
        var receipt = history.Store.Write(tx => Retain(tx, request, owner, new FileServicePlanRemovalResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Error = new ArcError
            {
                Category = ErrorCategory.State,
                Code = "file_access_denied",
                MessageKey = "error.state.file_access_denied",
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                CorrelationId = request.Meta.CorrelationId,
                Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "identity_unavailable" } },
            },
        }), CommitDurability.Full);

        var first = await history.RouteAsync(RoutedMethod.PlanNodeRemoval, owner, request, request.Meta.CommandId, ct);
        Assert.Equal(receipt, first?.Response?.ToByteArray());
        var error = FileServicePlanRemovalResponse.Parser.ParseFrom(receipt).Error;
        Assert.Equal(("identity_unavailable", EffectCertainty.DidNotHappen, RetryMode.Never),
            (error.Details.State.Reason, error.Effect, error.Retry.Mode));
        await history.ReopenAsync();
        var replay = await history.RouteAsync(RoutedMethod.PlanNodeRemoval, owner, request, request.Meta.CommandId, ct);
        Assert.Equal(receipt, replay?.Response?.ToByteArray());

        var changed = request.Clone();
        changed.Meta.CorrelationId = CommandIds.New();
        var refused = await history.RouteAsync(RoutedMethod.PlanNodeRemoval, owner, changed, request.Meta.CommandId, ct);
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(refused!.Response).Error.Code);
        Assert.Equal(0L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0L, history.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
        Assert.Equal("retained without provenance", File.ReadAllText(file));
    }

    private static byte[] Retain(StoreTransaction tx, FileServicePlanRemovalRequest request, CenterCaller owner, FileServicePlanRemovalResponse reply)
    {
        Assert.True(NodeShapes.IsValid(reply));
        var id = request.Meta.CommandId.Value.ToByteArray();
        Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(tx, id, "arcforges.node.v1.FileService/PlanRemoval",
            SHA256.HashData(request.ToByteArray()), Origin.Remote).Status);
        tx.Execute("INSERT INTO file_removal_command_owner (command_id, caller) VALUES ($id, $caller);",
            ("$id", id), ("$caller", owner.ToByteArray()));
        var response = reply.ToByteArray();
        CommandDeduplication.Complete(tx, id, response);
        return response;
    }

    private static Id SeedFinishedAttempt(LegacyFileHostHistory history, CenterCaller owner) => history.Store.Write(tx =>
    {
        var task = StoreIds.NewUuid7(tx.Clock);
        var attempt = StoreIds.NewUuid7(tx.Clock);
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "fixture-never-starts" } } },
        }.ToByteArray();
        var digest = SHA256.HashData(spec);
        var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = owner };
        tx.Execute("""
            INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                              pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                              command_digest, created_at, started_at, finished_at, current_attempt_id, attempt_count, rev)
            VALUES ($task, $state, 1, 'retained history', 'retained history', $spec, $digest, $owner, $origin,
                    'default', 3, 3, 4, 1, 'retained history', $digest, $now, $now, $now, $attempt, 1, 0);
            """, ("$task", task), ("$state", (int)TaskState.Succeeded), ("$spec", spec), ("$digest", digest), ("$owner", actor.ToByteArray()),
            ("$origin", (int)Origin.Remote), ("$now", tx.NowMicroseconds), ("$attempt", attempt));
        tx.Execute("""
            INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, boot_identity,
                                 request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source,
                                 accounted_mem_bytes, created_at, started_at, finished_at, exit_code, termination_reason, effect, rev)
            VALUES ($attempt, $task, 1, 1, 9, $node, $boot, 100, 67108864, 67108864, 1, 67108864,
                    $now, $now, $now, 0, $reason, $effect, 0);
            """, ("$attempt", attempt), ("$task", task), ("$node", history.Store.Metadata.NodeId.ToArray()), ("$boot", BootIdentity.Read()),
            ("$now", tx.NowMicroseconds), ("$reason", (int)TerminationReason.Exited), ("$effect", (int)EffectCertainty.Happened));
        return new Id { Value = ByteString.CopyFrom(attempt) };
    }, CommitDurability.Full);
}
