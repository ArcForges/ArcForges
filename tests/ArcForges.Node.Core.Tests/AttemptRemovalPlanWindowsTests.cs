// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Real Windows task producer, native files, SQLite and routed dispatcher. The caller is a verified-call fixture,
/// not an actual Center or a signed transport; no cleanup effect is attempted.
/// </summary>
[Trait("env", "windows-real")]
public sealed class AttemptRemovalPlanWindowsTests
{
    [Fact(Timeout = 180_000)]
    public async Task ActualFinishedAttemptIsPlannedWithoutInheritingOwnershipAndReplays()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The actual attempt provenance producer is Windows native.");
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var submit = new TaskServiceSubmitTaskRequest
        {
            Meta = Tasks.Meta(),
            Spec = AttemptTempRetentionTests.WriteFixtureToTemp(node.Root),
        };
        var submitted = await calls.SubmitAsync(caller, submit);
        Assert.Equal(RoutedOutcome.Executed, submitted.Answer!.Outcome);
        Assert.Null(submitted.Response!.Error);
        Id attempt;
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            var task = await Tasks.WaitAsync(human, submitted.Response.Value.TaskId);
            Assert.Equal(TaskState.Succeeded, task.State);
            attempt = task.CurrentAttempt!.AttemptId;
        }
        var name = IdText.Format(attempt);
        await Tasks.WaitForAsync(() => Sched.LogEvents(node, "execution.tmp.cleanup_unavailable")
            .Any(entry => Sched.Text(entry, "attempt") == name), Tasks.Bound, "the retained real attempt");
        await Tasks.WaitForAsync(() => !node.Runtime.Execution!.RunningAttempts.Any(),
            Tasks.Bound, "the attempt supervisor to finish");

        var root = Path.Combine(node.DataRoot, "tmp", name);
        const string body = "attempt-plan-test-content-never-persisted-4629";
        var file = Path.Combine(root, "keep.txt");
        Assert.Equal("retained", File.ReadAllText(file).Trim());
        File.WriteAllText(file, body);
        var nested = Directory.CreateDirectory(Path.Combine(root, "later")).FullName;
        File.WriteAllText(Path.Combine(nested, "child.txt"), "child-fixture");
        var unrelated = Directory.CreateDirectory(Path.Combine(node.Root, "unrelated-reference")).FullName;
        var unrelatedWorkspace = new RegisteredWorkspaces(node.Runtime.Store)
            .RegisterFromVerifiedHuman(unrelated, cancellationToken: ct);
        using (var attemptRoot = WorkspacePath.OpenRoot(root))
        using (var unrelatedRoot = WorkspacePath.OpenRoot(unrelated))
            Assert.Equal(attemptRoot.RootIdentity.Volume, unrelatedRoot.RootIdentity.Volume);

        // Session/cache rows are isolated metadata fixtures; the task and attempt provenance above are produced
        // by the actual native task path. A live unrelated session, and one without a path, are not target proof.
        var sessionId = CommandIds.New().Value.ToByteArray();
        var pathlessSessionId = CommandIds.New().Value.ToByteArray();
        var cacheId = CommandIds.New().Value.ToByteArray();
        var expiredCacheId = CommandIds.New().Value.ToByteArray();
        var otherDirectoryId = CommandIds.New().Value.ToByteArray();
        node.Runtime.Store.Write(transaction =>
        {
            transaction.Execute("""
                INSERT INTO session (session_id, client, source, state, cwd, workspace_id, started_at, last_activity_at, rev)
                VALUES ($id, 1, 1, 1, $cwd, $workspace, $now, $now, 0);
                """, ("$id", sessionId), ("$cwd", unrelated), ("$workspace", unrelatedWorkspace.Id),
                ("$now", transaction.NowMicroseconds));
            transaction.Execute("""
                INSERT INTO session (session_id, client, source, state, started_at, last_activity_at, rev)
                VALUES ($id, 1, 1, 1, $now, $now, 0);
                """, ("$id", pathlessSessionId), ("$now", transaction.NowMicroseconds));
            transaction.Execute("""
                INSERT INTO cache_instance (cache_id, kind, path, compat_key, maintenance_lease_holder, rev)
                VALUES ($id, 'attempt-test', $path, 'unrelated-holder', $holder, 0);
                """, ("$id", cacheId), ("$path", unrelated), ("$holder", sessionId));
            transaction.Execute("""
                INSERT INTO cache_instance (cache_id, kind, path, compat_key, maintenance_lease_expires_at, rev)
                VALUES ($id, 'attempt-test', $path, 'expiry-without-holder', $expired, 0);
                """, ("$id", expiredCacheId), ("$path", root), ("$expired", transaction.NowMicroseconds - 1));
            // An unrelated historical row with the same owner cannot replace the producer's exact tmp target.
            transaction.Execute("""
                INSERT INTO managed_directory
                  (directory_id, owner_kind, owner_id, root_class, relative_path, created_at, last_used_at, pinned, state, rev)
                VALUES ($id, 1, $attempt, 'tmp', $path, $now, $now, 0, 4, 0);
                """, ("$id", otherDirectoryId), ("$attempt", attempt.Value.ToByteArray()),
                ("$path", name + "-historical"), ("$now", transaction.NowMicroseconds));
            return 0;
        }, CommitDurability.Full);
        var request = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
        var raw = request.ToByteArray();
        var result = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, result.Answer!.Outcome);
        var responseBytes = result.Answer.Response ?? throw new InvalidOperationException("Missing plan response.");
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(responseBytes);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Null(response.Error);
        var plan = response.Value.Plan;
        Assert.Equal(attempt, plan.AttemptId);
        Assert.Null(plan.WorkspacePath);
        Assert.Equal(RiskClass.High, plan.Risk);
        Assert.True(plan.RequiresApproval);
        Assert.False(plan.QuarantineAvailable);
        Assert.Equal(4, plan.Items.Count);
        Assert.Equal((ulong)(new FileInfo(file).Length + new FileInfo(Path.Combine(nested, "child.txt")).Length), plan.TotalBytes);
        Assert.Equal("", plan.Items[0].Path);
        Assert.Equal(FileEntryKind.Directory, plan.Items[0].Kind);
        Assert.True(plan.Items[0].OwnerVerified);
        Assert.Contains(plan.Items, item => item.Path == "keep.txt");
        Assert.Contains(plan.Items, item => item.Path == "later" && item.Kind == FileEntryKind.Directory);
        Assert.Contains(plan.Items, item => item.Path == "later/child.txt");
        Assert.All(plan.Items.Skip(1), item => Assert.False(item.OwnerVerified));
        Assert.True(response.Audit is null || response.Audit.Observations.Count == 0);
        Assert.Equal(-1, responseBytes.Span.IndexOf(Encoding.UTF8.GetBytes(body)));

        var command = request.Meta.CommandId.Value.ToByteArray();
        node.Runtime.Store.Read(reader =>
        {
            using var sql = reader.CreateCommand("""
                SELECT p.target_kind, p.attempt_id, p.request_sha256, p.caller, d.outcome,
                       (SELECT count(*) FROM file_removal_plan_item i WHERE i.plan_id = p.plan_id),
                       (SELECT count(*) FROM file_removal_plan_item i WHERE i.plan_id = p.plan_id AND i.owner_verified = 1),
                       (SELECT count(*) FROM file_workspace_audit f JOIN audit_log a ON a.seq = f.audit_seq
                        WHERE f.attempt_id = p.attempt_id AND a.operation = 'cleanup.plan FileService.PlanRemoval'
                          AND a.outcome_summary = 'planned'),
                       (SELECT c.item_class FROM cleanup_item c JOIN file_removal_plan_item i
                        ON i.plan_id = c.plan_id AND i.item_id = c.item_id WHERE i.plan_id = p.plan_id AND i.ordinal = 0),
                       (SELECT count(*) FROM cleanup_item c JOIN file_removal_plan_item i
                        ON i.plan_id = c.plan_id AND i.item_id = c.item_id
                        WHERE i.plan_id = p.plan_id AND i.ordinal > 0 AND c.item_class = 10)
                FROM file_removal_plan p JOIN command_dedup d ON d.command_id = p.command_id
                WHERE p.command_id = $command;
                """);
            sql.Parameters.AddWithValue("$command", command);
            using var row = sql.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(2, row.GetInt32(0));
            Assert.Equal(attempt.Value.ToByteArray(), (byte[])row.GetValue(1));
            Assert.Equal(SHA256.HashData(raw), (byte[])row.GetValue(2));
            Assert.Equal(caller, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(3)));
            Assert.Equal(responseBytes.ToByteArray(), (byte[])row.GetValue(4));
            Assert.Equal(4L, row.GetInt64(5));
            Assert.Equal(1L, row.GetInt64(6));
            Assert.Equal(1L, row.GetInt64(7));
            Assert.Equal(1, row.GetInt32(8)); // the verified attempt root is recorded as USAGE
            Assert.Equal(3L, row.GetInt64(9)); // descendants without independent provenance are UNTRACKED
            Assert.False(row.Read());
            return 0;
        });

        async Task AssertReferenceInUse(string reference)
        {
            node.Runtime.Store.Write(transaction => transaction.Execute(
                "UPDATE session SET cwd = $cwd WHERE session_id = $id;", ("$cwd", reference), ("$id", sessionId)),
                CommitDurability.Full);
            var check = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
            var answer = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, check.ToByteArray(), check.Meta.CommandId);
            var inUse = FileServicePlanRemovalResponse.Parser.ParseFrom(answer.Answer!.Response);
            Assert.Equal(ErrorCategory.State, inUse.Error.Category);
            Assert.Equal("in_use", inUse.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, inUse.Error.Effect);
            Assert.Null(inUse.Value);
            Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        }

        await AssertReferenceInUse(root);                       // same native directory
        await AssertReferenceInUse(nested);                     // descendant
        await AssertReferenceInUse(Path.GetDirectoryName(root)!); // ancestor
        node.Runtime.Store.Write(transaction => transaction.Execute(
            "UPDATE session SET cwd = $cwd WHERE session_id = $id;",
            ("$cwd", Path.Combine(node.Root, "missing-reference")), ("$id", sessionId)), CommitDurability.Full);
        var missingReferenceRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
        var missingReference = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, missingReferenceRequest.ToByteArray(),
            missingReferenceRequest.Meta.CommandId);
        var missingIdentity = FileServicePlanRemovalResponse.Parser.ParseFrom(missingReference.Answer!.Response);
        Assert.True(NodeShapes.IsValid(missingIdentity));
        Assert.Equal("file_access_denied", missingIdentity.Error.Code);
        Assert.Equal("identity_unavailable", missingIdentity.Error.Details.State.Reason);
        node.Runtime.Store.Write(transaction => transaction.Execute(
            "UPDATE session SET cwd = $cwd WHERE session_id = $id;", ("$cwd", unrelated), ("$id", sessionId)),
            CommitDurability.Full);

        node.Runtime.Store.Write(transaction => transaction.Execute(
            "UPDATE cache_instance SET path = $path WHERE cache_id = $id;", ("$path", nested), ("$id", cacheId)),
            CommitDurability.Full);
        var cacheRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
        var cacheAnswer = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, cacheRequest.ToByteArray(), cacheRequest.Meta.CommandId);
        Assert.Equal("in_use", FileServicePlanRemovalResponse.Parser.ParseFrom(cacheAnswer.Answer!.Response).Error.Code);
        node.Runtime.Store.Write(transaction => transaction.Execute(
            "UPDATE cache_instance SET path = $path WHERE cache_id = $id;", ("$path", unrelated), ("$id", cacheId)),
            CommitDurability.Full);

        var pinnedDirectory = CommandIds.New().Value.ToByteArray();
        node.Runtime.Store.Write(transaction => transaction.Execute("""
            INSERT INTO managed_directory
              (directory_id, owner_kind, owner_id, root_class, relative_path, created_at, last_used_at, pinned, state, rev)
            VALUES ($id, 5, $owner, 'tmp', $path, $now, $now, 1, 2, 0);
            """, ("$id", pinnedDirectory), ("$owner", node.Runtime.NodeId.ToArray()), ("$path", name + "/later"),
            ("$now", transaction.NowMicroseconds)), CommitDurability.Full);
        var pinnedChildRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
        var pinnedChild = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, pinnedChildRequest.ToByteArray(), pinnedChildRequest.Meta.CommandId);
        Assert.Equal("in_use", FileServicePlanRemovalResponse.Parser.ParseFrom(pinnedChild.Answer!.Response).Error.Code);
        node.Runtime.Store.Write(transaction => transaction.Execute(
            "UPDATE managed_directory SET pinned = 0 WHERE directory_id = $id;", ("$id", pinnedDirectory)), CommitDurability.Full);

        // A registered reference is never adopted by its old name after its native root changes.
        var oldUnrelated = unrelated + "-moved";
        Directory.Move(unrelated, oldUnrelated);
        Directory.CreateDirectory(unrelated);
        var staleReferenceRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
        var staleReference = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, staleReferenceRequest.ToByteArray(),
            staleReferenceRequest.Meta.CommandId);
        var staleReferenceError = FileServicePlanRemovalResponse.Parser.ParseFrom(staleReference.Answer!.Response);
        Assert.Equal("file_access_denied", staleReferenceError.Error.Code);
        Assert.Equal("identity_unavailable", staleReferenceError.Error.Details.State.Reason);
        node.Runtime.Store.Write(transaction => transaction.Execute(
            "UPDATE session SET workspace_id = NULL WHERE session_id = $id;", ("$id", sessionId)), CommitDurability.Full);

        // State 4 is a metadata fixture; this does not assert a real quarantine or a move.
        node.Runtime.Store.Write(transaction => transaction.Execute(
            "UPDATE managed_directory SET state = 4 WHERE owner_kind = 1 AND owner_id = $id AND root_class = 'tmp' AND relative_path = $name;",
            ("$id", attempt.Value.ToByteArray()), ("$name", name)), CommitDurability.Full);
        var unavailableRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
        var unavailableAnswer = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, unavailableRequest.ToByteArray(),
            unavailableRequest.Meta.CommandId);
        var unavailable = FileServicePlanRemovalResponse.Parser.ParseFrom(unavailableAnswer.Answer!.Response);
        Assert.True(NodeShapes.IsValid(unavailable));
        Assert.Equal("not_found", unavailable.Error.Code);
        Assert.Equal("attempt_temp", unavailable.Error.Details.State.Resource.Kind);
        Assert.Equal(attempt, unavailable.Error.Details.State.Resource.Id);
        node.Runtime.Store.Write(transaction => transaction.Execute(
            "UPDATE managed_directory SET state = 2 WHERE owner_kind = 1 AND owner_id = $id AND root_class = 'tmp' AND relative_path = $name;",
            ("$id", attempt.Value.ToByteArray()), ("$name", name)), CommitDurability.Full);

        var foreign = caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var foreignRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
        var foreignAnswer = await calls.CallAsync(foreign, RoutedMethod.PlanNodeRemoval, foreignRequest.ToByteArray(), foreignRequest.Meta.CommandId);
        Assert.Equal("not_found", FileServicePlanRemovalResponse.Parser.ParseFrom(foreignAnswer.Answer!.Response).Error.Code);
        var foreignReplay = await calls.CallAsync(foreign, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(foreignReplay.Answer!.Response).Error.Code);

        File.WriteAllText(file, body + "-changed-after-plan");
        var replay = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(responseBytes, replay.Answer!.Response);

        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            Assert.Null((await human.Tasks.PinTaskAsync(new TaskServicePinTaskRequest
            {
                Meta = Tasks.Meta(),
                TaskId = submitted.Response.Value.TaskId,
                Pinned = true,
            }, cancellationToken: ct)).Error);
            var pinnedRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
            var pinned = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, pinnedRequest.ToByteArray(), pinnedRequest.Meta.CommandId);
            Assert.Equal("in_use", FileServicePlanRemovalResponse.Parser.ParseFrom(pinned.Answer!.Response).Error.Code);
            Assert.Null((await human.Tasks.PinTaskAsync(new TaskServicePinTaskRequest
            {
                Meta = Tasks.Meta(),
                TaskId = submitted.Response.Value.TaskId,
                Pinned = false,
            }, cancellationToken: ct)).Error);
        }

        // Add only test-owned empty entries; the actual planner must refuse rather than truncate or delete.
        for (var index = 0; index < 998; index++)
            File.WriteAllBytes(Path.Combine(root, "overflow-" + index.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)), []);
        var boundedRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
        var boundedRaw = boundedRequest.ToByteArray();
        var bounded = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, boundedRaw, boundedRequest.Meta.CommandId);
        var limit = FileServicePlanRemovalResponse.Parser.ParseFrom(bounded.Answer!.Response);
        Assert.True(NodeShapes.IsValid(limit));
        Assert.Equal("too_large", limit.Error.Code);
        Assert.Equal("removal_descendants", limit.Error.Details.Limit.LimitName);
        Assert.Equal("1000", limit.Error.Details.Limit.Maximum.Value);
        Assert.Equal(EffectCertainty.DidNotHappen, limit.Error.Effect);
        Assert.Null(limit.Value);
        File.WriteAllBytes(Path.Combine(root, "overflow-extra"), []);
        var boundedReplay = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, boundedRaw, boundedRequest.Meta.CommandId);
        Assert.Equal(bounded.Answer.Response, boundedReplay.Answer!.Response);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));

        // A sequential test-owned replacement is not a race or a cleanup effect.
        var moved = root + "-moved";
        Directory.Move(root, moved);
        Directory.CreateDirectory(root);
        var replacement = Path.Combine(root, "replacement.txt");
        File.WriteAllText(replacement, "unplanned-replacement");
        var staleRequest = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
        var stale = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, staleRequest.ToByteArray(), staleRequest.Meta.CommandId);
        var changed = FileServicePlanRemovalResponse.Parser.ParseFrom(stale.Answer!.Response);
        Assert.Equal(ErrorCategory.Conflict, changed.Error.Category);
        Assert.Equal("file_changed", changed.Error.Code);
        Assert.Equal("planned_tree_changed", changed.Error.Details.State.Reason);
        Assert.Equal("unplanned-replacement", File.ReadAllText(replacement));
        Assert.Equal(body + "-changed-after-plan", File.ReadAllText(Path.Combine(moved, "keep.txt")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        var restarted = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId);
        Assert.Equal(responseBytes, restarted.Answer!.Response);
        Assert.Equal(body + "-changed-after-plan", File.ReadAllText(Path.Combine(moved, "keep.txt")));
        Assert.Equal("unplanned-replacement", File.ReadAllText(replacement));
        Assert.True(Directory.Exists(Path.Combine(moved, "later")));
        foreach (var path in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(path)) continue;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var data = new MemoryStream();
            stream.CopyTo(data);
            Assert.Equal(-1, data.ToArray().AsSpan().IndexOf(Encoding.UTF8.GetBytes(body)));
        }
        ct.ThrowIfCancellationRequested();
    }

    [Fact(Timeout = 180_000)]
    public async Task ActualFinishedAttemptWithSyntheticHeldJournalIsRefusedWithoutFileEffect()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The actual attempt provenance producer is Windows native.");
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Agent);
        var submit = new TaskServiceSubmitTaskRequest
        {
            Meta = Tasks.Meta(),
            Spec = AttemptTempRetentionTests.WriteFixtureToTemp(node.Root),
        };
        var submitted = await calls.SubmitAsync(caller, submit);
        Assert.Null(submitted.Response!.Error);
        Id attempt;
        await using (var human = await node.ChannelAsync(helloAsHuman: true))
        {
            var task = await Tasks.WaitAsync(human, submitted.Response.Value.TaskId);
            Assert.Equal(TaskState.Succeeded, task.State);
            attempt = task.CurrentAttempt!.AttemptId;
        }
        var name = IdText.Format(attempt);
        await Tasks.WaitForAsync(() => Sched.LogEvents(node, "execution.tmp.cleanup_unavailable")
            .Any(entry => Sched.Text(entry, "attempt") == name), Tasks.Bound, "the retained real attempt");
        await Tasks.WaitForAsync(() => !node.Runtime.Execution!.RunningAttempts.Any(), Tasks.Bound, "the attempt supervisor to finish");

        RegisteredWorkspaces.RootIdentity rootIdentity, targetIdentity;
        using (var root = WorkspacePath.OpenRoot(Path.Combine(node.DataRoot, "tmp")))
        {
            rootIdentity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
            targetIdentity = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(root.OpenDirectory(name)));
        }
        var holdId = CommandIds.New().Value.ToByteArray();
        var correlation = CommandIds.New().Value.ToByteArray();
        var digest = SHA256.HashData("test-only-held-removal-record"u8);
        // This is an isolated metadata fixture, not an executed or recovered cleanup. No acknowledgment is forged.
        node.Runtime.Store.Write(transaction =>
        {
            Assert.Equal(DedupStatus.Execute, CommandDeduplication.Begin(transaction, holdId,
                "arcforges.node.v1.FileService/ExecuteRemoval", digest, Origin.Remote).Status);
            transaction.Execute("""
                INSERT INTO file_operation_journal
                  (command_id, kind, phase, request_sha256, caller, correlation_id, attempt_id,
                   identity_platform, root_identity, parent_identity, target_identity, expected_absent,
                   created_at, updated_at, held, acknowledged)
                VALUES ($id, 3, 3, $digest, $caller, $correlation, $attempt,
                        $platform, $root, $parent, $target, 0, $now, $now, 1, 0);
                """, ("$id", holdId), ("$digest", digest), ("$caller", caller.ToByteArray()), ("$correlation", correlation),
                ("$attempt", attempt.Value.ToByteArray()), ("$platform", rootIdentity.Platform), ("$root", rootIdentity.Bytes),
                ("$parent", rootIdentity.Bytes), ("$target", targetIdentity.Bytes), ("$now", transaction.NowMicroseconds));
            return 0;
        }, CommitDurability.Full);

        var request = new FileServicePlanRemovalRequest { Meta = Tasks.Meta(), AttemptId = attempt.Clone() };
        var answer = await calls.CallAsync(caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(), request.Meta.CommandId);
        var refused = FileServicePlanRemovalResponse.Parser.ParseFrom(answer.Answer!.Response);
        Assert.True(NodeShapes.IsValid(refused));
        Assert.Equal("in_use", refused.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, refused.Error.Effect);
        Assert.Null(refused.Value);
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM file_operation_journal WHERE command_id = $id AND held = 1;", ("$id", holdId))));
        Assert.Equal("retained", File.ReadAllText(Path.Combine(node.DataRoot, "tmp", name, "keep.txt")).Trim());
    }

}
