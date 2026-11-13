// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;
using Microsoft.Data.Sqlite;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal sealed class RemovalExecutionResponseUnavailableException : Exception { }

internal sealed partial class FileServiceHandler
{
    // Exercises the real FULL commit return boundary against exclusively test-owned metadata.
    internal Action? AfterRemovalExecutionCommitForTests { get; set; }

    /// <summary>
    /// Executes the currently supported, metadata-only preflight. Neither native platform has an admitted strict
    /// namespace backend: an otherwise valid plan therefore refuses before any cleanup or quarantine effect.
    /// </summary>
    internal async Task<FileServiceExecuteRemovalResponse> ExecuteRemovalAsync(Caller caller,
        FileServiceExecuteRemovalRequest request, CancellationToken cancellationToken)
    {
        var routed = caller.Routed ?? throw new InvalidOperationException("A removal requires a verified routed caller.");
        var raw = caller.RawRequest ?? throw new InvalidOperationException("The original transmitted request is required.");
        var limit = routed.RemainingFileOperation();
        if (limit <= TimeSpan.Zero) throw new OperationCanceledException(cancellationToken);
        var started = node.Clock.GetTimestamp();
        using var deadline = new CancellationTokenSource(limit, node.Clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var token = linked.Token;
        var pending = node.Processor.ExecuteAsync(command => RemovalExecutionInTransaction(command.Transaction,
            caller, request, SHA256.HashData(raw), started, limit, token), CommitDurability.Full);
        RemovalExecutionOutcome outcome;
        try { outcome = await pending.WaitAsync(token).ConfigureAwait(false); }
        catch (OperationCanceledException)
        {
            _ = ObserveRemovalExecutionPendingAsync(pending);
            throw;
        }
        catch (SqliteException)
        {
            // An unanswered COMMIT is not a proved rollback. Withhold the signed reply; a subsequent exact
            // receipt lookup may establish the outcome. No fictitious filesystem journal is manufactured.
            throw new RemovalExecutionResponseUnavailableException();
        }

        if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        if (outcome.PolicyReason is { } reason)
        {
            routed.Refused(PermissionMatrix.FileRemove, reason);
            routed.MarkAudited();
        }
        return outcome.Response;
    }

    private RemovalExecutionOutcome RemovalExecutionInTransaction(StoreTransaction transaction, Caller caller,
        FileServiceExecuteRemovalRequest request, byte[] rawDigest, long started, TimeSpan limit, CancellationToken token)
    {
        var routed = caller.Routed!;
        var correlation = routed.Correlation(request.Meta);
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        byte[]? workspace = null, attempt = null;
        string? path = null;
        void CheckBudget()
        {
            if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        }
        void Audit(string outcome) => AuditLog.AppendFileWorkspace(transaction, caller.Actor,
            "file.remove FileService.ExecuteRemoval", workspace, attempt, path, PermissionDecision.Deny, outcome, null);
        FileServiceExecuteRemovalResponse Refuse(ArcError error)
        {
            RoutedFileErrors.Complete(error, request.Meta, routed.CallId, node.Clock);
            Audit("refused: " + error.Code);
            return new FileServiceExecuteRemovalResponse { Meta = meta.Clone(), Error = error };
        }

        CheckBudget();
        if (!NodeShapes.IsValid(request) || request.Meta?.CommandId is not { Value.Length: 16 } command ||
            request.PlanId is not { Value.Length: 16 } planId || !request.HasPlanDigest || request.PlanDigest.Length != 32 ||
            caller.CenterCaller is null || CenterRouting.Shape(caller.CenterCaller) is not null)
            return new RemovalExecutionOutcome(Refuse(Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation)));

        var commandId = command.Value.ToByteArray();
        routed.BeforeReplay();
        var liveReceipt = RemovalHasLiveReceipt(transaction, commandId);
        if (!RemovalCallerMayUse(transaction, commandId, caller.CenterCaller) ||
            !liveReceipt && !RoutedCommandOwnership.MayExecute(transaction, commandId, caller.CenterCaller, "FileService.ExecuteRemoval", rawDigest))
            return new RemovalExecutionOutcome(Refuse(StoreErrors.CommandIdReused()));
        var decision = CommandDeduplication.Begin(transaction, commandId,
            "arcforges.node.v1.FileService/ExecuteRemoval", rawDigest, Origin.Remote);
        if (decision.Status == DedupStatus.Replay)
        {
            var replay = FileServiceExecuteRemovalResponse.Parser.ParseFrom(decision.Outcome!.Value.Span);
            var reason = transaction.Scalar("SELECT policy_reason FROM file_removal_command_owner WHERE command_id = $id;",
                ("$id", commandId)) as string;
            if (replay.Error is { Category: ErrorCategory.Authorization } && reason is null)
                throw new InvalidDataException("The recorded removal policy reason is unavailable.");
            Audit("replayed: " + replay.Error?.Code);
            return new RemovalExecutionOutcome(replay, reason);
        }
        if (decision.Status is DedupStatus.Conflict or DedupStatus.InProgress)
            return new RemovalExecutionOutcome(Refuse(decision.Error ?? NodeErrors.Internal(node.Clock.GetUtcNow())));

        string? policyReason = null;
        FileServiceExecuteRemovalResponse response;
        try
        {
            CheckRemovalPreflightAuthority(transaction, caller);
            var plan = ReadRemovalExecutionPlan(transaction, planId.Value.ToByteArray(), caller.CenterCaller);
            if (plan is null)
                response = Refuse(NodeErrors.NotFound("cleanup_plan", planId.Value.ToByteArray()));
            else
            {
                workspace = plan.Workspace;
                attempt = plan.Attempt;
                path = plan.Path;
                var time = RoutedFileValidationTime.Sample(transaction);
                if (!time.Healthy) throw new RoutedAbortException(RoutedAbort.ClockUncertain);
                if (!CryptographicOperations.FixedTimeEquals(plan.Digest, request.PlanDigest.Span))
                    response = Refuse(Error(ErrorCategory.Conflict, "digest_mismatch", "plan_digest_mismatch", correlation));
                else if (time.BoundaryMicroseconds >= plan.Expires)
                    response = Refuse(Error(ErrorCategory.State, "expired", "removal_plan_expired", correlation));
                else if (plan.State == 3)
                    response = Refuse(NodeErrors.InUse("removal_plan_executing"));
                else if (plan.State is not (1 or 2))
                    response = Refuse(Error(ErrorCategory.State, "invalid_state", "removal_plan_terminal", correlation));
                else
                {
                    RecheckRemovalExecutionPlan(transaction, caller, planId.Value.ToByteArray(), plan, token);
                    CheckBudget();
                    CheckRemovalPreflightAuthority(transaction, caller);
                    // A policy ALLOW, pending approval or HUMAN delete-without-quarantine request cannot supply
                    // the missing source/ancestor/tree exclusion. Do not raise an unusable approval or mutate plan state.
                    response = Refuse(Error(ErrorCategory.Resource, "enforcement_unavailable", "strict_cleanup_guard_unavailable", correlation));
                }
            }
        }
        catch (FilePolicyException denied)
        {
            policyReason = denied.Reason;
            response = Refuse(Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileRemove, correlation));
        }
        catch (WorkspaceRemovalPlanException failure)
        {
            response = Refuse(failure.Reason switch
            {
                "removal_descendants" => RemovalLimit(correlation, "removal_descendants", "1000"),
                "removal_total_bytes" => RemovalLimit(correlation, "removal_total_bytes", "67108864"),
                "planned_tree_changed" => Error(ErrorCategory.Conflict, "file_changed", "planned_tree_changed", correlation),
                "strict_cleanup_guard_unavailable" => Error(ErrorCategory.Resource, "enforcement_unavailable", failure.Reason, correlation),
                _ => Error(ErrorCategory.State, "file_access_denied", "file_access_denied", correlation),
            });
        }
        catch (RegisteredWorkspaceException failure) when (failure.Reason == "workspace_not_found")
        {
            response = Refuse(Error(ErrorCategory.Conflict, "file_changed", "planned_tree_changed", correlation));
        }
        catch (WorkspacePathException failure) when (failure.Reason is "native_2" or "native_3" or "native_20" or
            "root_changed" or "root_not_directory" or "directory_changed" or "directory_identity_changed" or "file_identity_changed")
        {
            response = Refuse(Error(ErrorCategory.Conflict, "file_changed", "planned_tree_changed", correlation));
        }
        catch (Exception failure) when (failure is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException or IOException or ArgumentException)
        {
            response = Refuse(Failure(failure, correlation));
        }

        CheckBudget();
        routed.BeforeEffect(transaction);
        CheckBudget();
        CommandDeduplication.Complete(transaction, commandId, response.ToByteArray());
        transaction.Execute("INSERT INTO file_removal_command_owner (command_id, caller, policy_reason) VALUES ($id, $caller, $reason);",
            ("$id", commandId), ("$caller", caller.CenterCaller.ToByteArray()), ("$reason", policyReason));
        transaction.AfterCommitForTests = AfterRemovalExecutionCommitForTests;
        return new RemovalExecutionOutcome(response, policyReason);
    }

    private void CheckRemovalPreflightAuthority(StoreReader reader, Caller caller)
    {
        if (caller.CenterCaller is not { } center || caller.Routed is null) throw new FilePolicyException("center_caller_incomplete");
        try
        {
            var policy = PolicyRules.Current(reader);
            if (!CryptographicOperations.FixedTimeEquals(policy.Digest, PolicyDocuments.Digest(policy.Document)) ||
                policy.Document.Permissions.Any(item => PermissionMatrix.Valid(item) is not null) ||
                policy.Document.CenterRouted is { HasRelayedFrom: true } route &&
                    route.RelayedFrom is not (RelayedFrom.Unspecified or RelayedFrom.OwnNode or RelayedFrom.Account))
                throw new FilePolicyException("policy_invalid");
            if (CenterRouting.Refusal(center, node.NodeId.Span, policy.Document.CenterRouted) is { } reason)
                throw new FilePolicyException(reason);
            if (PermissionMatrix.DecideRouted(PermissionMatrix.FileRemove, caller.CellsOrigin, policy.Document.Permissions).Decision == PermissionDecision.Deny ||
                PermissionMatrix.DecideRouted(PermissionMatrix.CleanupExecute, caller.CellsOrigin, policy.Document.Permissions).Decision == PermissionDecision.Deny)
                throw new FilePolicyException("denied");
            caller.Routed.BeforeEffect(reader);
        }
        catch (FilePolicyException) { throw; }
        catch (Exception exception) when (exception is not RoutedAbortException and not OperationCanceledException and not OutOfMemoryException)
        {
            throw new FilePolicyException("policy_invalid");
        }
    }

    private static RemovalExecutionPlan? ReadRemovalExecutionPlan(StoreReader reader, byte[] id, CenterCaller caller)
    {
        using var command = reader.CreateCommand("""
            SELECT p.caller, c.digest, c.state, c.expires_at, p.target_kind, p.workspace_id, p.workspace_path,
                   p.attempt_id, p.root_platform, p.root_identity, c.total_bytes, c.item_count
            FROM file_removal_plan p JOIN cleanup_plan c ON c.plan_id = p.plan_id WHERE p.plan_id = $id;
            """);
        command.Parameters.AddWithValue("$id", id);
        using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        try
        {
            if (!CenterRouting.SameFileCaller(CenterCaller.Parser.ParseFrom((byte[])row.GetValue(0)), caller)) return null;
        }
        catch (InvalidProtocolBufferException) { return null; }
        return new RemovalExecutionPlan((byte[])row.GetValue(1), row.GetInt32(2), row.GetInt64(3), row.GetInt32(4),
            row.IsDBNull(5) ? null : (byte[])row.GetValue(5), row.IsDBNull(6) ? null : row.GetString(6),
            row.IsDBNull(7) ? null : (byte[])row.GetValue(7), row.GetInt32(8), (byte[])row.GetValue(9),
            checked((ulong)row.GetInt64(10)), row.GetInt32(11));
    }

    private void RecheckRemovalExecutionPlan(StoreTransaction reader, Caller caller, byte[] id, RemovalExecutionPlan plan, CancellationToken token)
    {
        WorkspaceRemovalSnapshot snapshot;
        if (plan.TargetKind == 1 && plan.Workspace is { } workspace && plan.Path is { } path)
        {
            using var use = _workspaces.OpenForUse(reader, workspace,
                beforeUse: selected => CheckRemovalPreflightAuthority(selected, caller), token);
            if (reader.Scalar("SELECT 1 FROM file_private_stage_object LIMIT 1;") is not null)
                throw new WorkspaceRemovalPlanException("file_access_denied");
            snapshot = WorkspaceRemovalPlan.Capture(use.Root, path, token);
            MatchRemovalExecutionSnapshot(reader, id, plan, snapshot);
        }
        else if (plan.TargetKind == 2 && plan.Attempt is not null)
        {
            // This preflight has no strict task-temp backend either. It does not reinterpret a stored absolute
            // display path as authority, enumerate an unbound root, or claim an external-open absence proof.
            throw new WorkspaceRemovalPlanException("strict_cleanup_guard_unavailable");
        }
        else throw new WorkspaceRemovalPlanException("planned_tree_changed");
    }

    private static void MatchRemovalExecutionSnapshot(StoreReader reader, byte[] id, RemovalExecutionPlan plan,
        WorkspaceRemovalSnapshot snapshot)
    {
        if (snapshot.RootIdentity.Platform != plan.RootPlatform ||
            !CryptographicOperations.FixedTimeEquals(snapshot.RootIdentity.Bytes, plan.RootIdentity) ||
            snapshot.TotalBytes != plan.TotalBytes || snapshot.Entries.Count != plan.Count)
            throw new WorkspaceRemovalPlanException("planned_tree_changed");
        using var command = reader.CreateCommand("""
            SELECT ordinal, relative_path, entry_kind, fingerprint_sha256 FROM file_removal_plan_item
            WHERE plan_id = $id ORDER BY ordinal;
            """);
        command.Parameters.AddWithValue("$id", id);
        using var row = command.ExecuteReader();
        var index = 0;
        while (row.Read())
        {
            if (index >= snapshot.Entries.Count || row.GetInt32(0) != index ||
                row.GetString(1) != snapshot.Entries[index].Path || row.GetInt32(2) != (int)snapshot.Entries[index].Kind ||
                !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(3), snapshot.Entries[index].FingerprintSha256))
                throw new WorkspaceRemovalPlanException("planned_tree_changed");
            index++;
        }
        if (index != snapshot.Entries.Count) throw new WorkspaceRemovalPlanException("planned_tree_changed");
    }

    private async Task ObserveRemovalExecutionPendingAsync(Task<RemovalExecutionOutcome> pending)
    {
        try { _ = await pending.ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OutOfMemoryException) { node.Log.Error("api.file.removal_execution.audit_failed"); }
    }

    private sealed record RemovalExecutionPlan(byte[] Digest, int State, long Expires, int TargetKind,
        byte[]? Workspace, string? Path, byte[]? Attempt, int RootPlatform, byte[] RootIdentity, ulong TotalBytes, int Count);
    private sealed record RemovalExecutionOutcome(FileServiceExecuteRemovalResponse Response, string? PolicyReason = null);
}
