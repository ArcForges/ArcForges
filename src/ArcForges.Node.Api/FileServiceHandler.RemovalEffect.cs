// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    internal Action? AfterRemovalIntentCommitForTests { get; set; }
    internal Action? AfterRemovalMoveForTests { get; set; }

    private sealed class RemovalEffectLease : IDisposable
    {
        internal RegisteredWorkspaceUse? Use;
        internal WorkspacePath? TemporaryRoot;
        internal WorkspacePath? AttemptRoot;
        internal WorkspacePath? Destination;
        internal WorkspacePath Root => Use?.Root ?? TemporaryRoot ?? throw new InvalidOperationException("Missing selected root.");
        internal RemovalExecutionPlan? Plan;
        internal WorkspaceRemovalSnapshot? Snapshot;
        internal string Source = "";
        internal string DestinationName = "";
        internal string DestinationPath = "";
        internal byte[] Item = [];
        internal WorkspaceObjectIdentity Parent;
        internal WorkspaceObjectIdentity Target;
        internal bool Prepared;
        internal bool EffectStarted;
        internal long PurgeAfter;
        internal long MovedAt;
        internal string? PolicyReason;
        public void Dispose() { Destination?.Dispose(); AttemptRoot?.Dispose(); TemporaryRoot?.Dispose(); Use?.Dispose(); }
    }

    private async Task<FileServiceExecuteRemovalResponse> ExecuteCoordinatedRemovalAsync(Caller caller,
        FileServiceExecuteRemovalRequest request, CancellationToken cancellationToken, byte[]? approvedDigest = null)
    {
        if (caller.CenterCaller is null || caller.Routed is null && !caller.Approved)
            throw new InvalidOperationException("A verified file caller is required.");
        var raw = caller.Routed is not null ? caller.RawRequest ?? throw new InvalidOperationException("Missing original request.") : null;
        var digest = approvedDigest ?? SHA256.HashData(raw!);
        var limit = caller.Routed?.RemainingFileOperation() ?? TimeSpan.FromSeconds(10);
        if (limit <= TimeSpan.Zero) throw new OperationCanceledException(cancellationToken);
        var started = node.Clock.GetTimestamp();
        using var deadline = new CancellationTokenSource(limit, node.Clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token, node.Stopping);
        var token = linked.Token;
        // Acquire outside the command writer: an admitted launch may itself be waiting for that writer.
        using var admission = node.Execution is null ? null : await node.Execution.CoordinateFileCleanupAsync(token).ConfigureAwait(false);
        using var lease = new RemovalEffectLease();
        FileServiceExecuteRemovalResponse response;
        try
        {
            var pending = node.Processor.ExecuteAsync(command =>
                PrepareRemovalEffect(command, caller, request, digest, lease, started, limit, token), CommitDurability.Full);
            response = await pending.ConfigureAwait(false);
            if (!lease.Prepared)
            {
                ReportRemovalPolicy(caller, lease.PolicyReason);
                if (Expired(started, limit, token)) throw new OperationCanceledException(token);
                return response;
            }
            AfterRemovalIntentCommitForTests?.Invoke();
            var effected = node.Processor.ExecuteAsync(command =>
                ApplyRemovalEffect(command.Transaction, caller, request, lease, started, limit, token), CommitDurability.Full);
            response = await effected.ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
        {
            // The actual callback is awaited before its handles/coordination are released. No child performs this move.
            if (lease.Prepared)
            {
                try
                {
                    await node.Processor.ExecuteAsync(command =>
                    {
                        var op = FileMutationJournal.GetForCaller(command.Transaction, request.Meta.CommandId.Value.Span, caller.CenterCaller);
                        if (op?.State == FileOperationState.Prepared)
                            _ = FileMutationJournal.MarkUnknown(command.Transaction, request.Meta.CommandId.Value.Span);
                        return 0;
                    }, CommitDurability.Full).ConfigureAwait(false);
                }
                catch (Exception error) when (error is not OutOfMemoryException) { node.Log.Error("api.file.removal.recovery_deferred"); }
            }
            if (failure is OperationCanceledException) throw;
            throw new RemovalExecutionResponseUnavailableException();
        }
        ReportRemovalPolicy(caller, lease.PolicyReason);
        if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        return response;
    }

    private static void ReportRemovalPolicy(Caller caller, string? reason)
    {
        if (caller.Routed is { } routed && reason is not null)
        {
            routed.Refused(PermissionMatrix.FileRemove, reason);
            routed.MarkAudited();
        }
    }

    private FileServiceExecuteRemovalResponse PrepareRemovalEffect(CommandContext command, Caller caller,
        FileServiceExecuteRemovalRequest request, byte[] digest, RemovalEffectLease lease, long started, TimeSpan limit, CancellationToken token)
    {
        var tx = command.Transaction;
        var correlation = caller.Routed?.Correlation(request.Meta) ?? request.Meta.CorrelationId.Clone();
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        var id = request.Meta?.CommandId?.Value.ToByteArray();
        var begun = false;
        FileServiceExecuteRemovalResponse Refuse(ArcError error, bool complete = true)
        {
            RoutedFileErrors.Complete(error, request.Meta, correlation, node.Clock);
            var reply = new FileServiceExecuteRemovalResponse { Meta = meta.Clone(), Error = error };
            AuditLog.AppendFileWorkspace(tx, caller.Actor, "file.remove FileService.ExecuteRemoval", lease.Plan?.Workspace,
                lease.Plan?.Attempt, lease.Plan?.Path, PermissionDecision.Deny, "refused: " + error.Code, null);
            if (begun && complete)
            {
                CommandDeduplication.Complete(tx, id!, reply.ToByteArray());
                tx.AfterCommitForTests = AfterRemovalExecutionCommitForTests;
                RecordRemovalCaller(tx, id!, caller.CenterCaller!, lease.PolicyReason);
            }
            return reply;
        }
        try
        {
            CheckRemovalBudget(started, limit, token);
            if (!NodeShapes.IsValid(request) || id is not { Length: 16 } || caller.CenterCaller is null ||
                CenterRouting.Shape(caller.CenterCaller) is not null)
                return Refuse(Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation), false);
            caller.Routed?.BeforeReplay();
            if (!RemovalCallerMayUse(tx, id, caller.CenterCaller) ||
                !RemovalHasLiveReceipt(tx, id) && !RoutedCommandOwnership.MayExecute(tx, id, caller.CenterCaller, "FileService.ExecuteRemoval", digest))
                return Refuse(StoreErrors.CommandIdReused(), false);
            var existing = Approvals.ByCommand(tx, id);
            if (existing is not null)
            {
                if (existing.View.Operation != "FileService.ExecuteRemoval" || existing.Request.Length != 17 || existing.Request[0] != 2 ||
                    !existing.Request.AsSpan(1).SequenceEqual(id) || !CryptographicOperations.FixedTimeEquals(existing.RequestDigest, digest) ||
                    !CenterRouting.SameFileCaller(existing.View.Requester.CenterCaller, caller.CenterCaller))
                    return Refuse(StoreErrors.CommandIdReused(), false);
                if (!caller.Approved)
                {
                    var old = tx.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", id)) as byte[];
                    if (old is not null)
                    {
                        lease.PolicyReason = tx.Scalar("SELECT policy_reason FROM file_removal_command_owner WHERE command_id = $id;", ("$id", id)) as string;
                        return FileServiceExecuteRemovalResponse.Parser.ParseFrom(old);
                    }
                    if (existing.State is ApprovalState.Pending or ApprovalState.Approved)
                    {
                        lease.PolicyReason = "approval_required";
                        return Refuse(RoutedRefusals.ApprovalRequired(PermissionMatrix.FileRemove, existing.View.ApprovalId, correlation), false);
                    }
                    lease.PolicyReason = "denied";
                    begun = true;
                    return Refuse(Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileRemove, correlation));
                }
                if (caller.ApprovalId is null || !caller.ApprovalId.AsSpan().SequenceEqual(existing.Id) ||
                    existing.State != ApprovalState.Approved)
                    return Refuse(StoreErrors.CommandIdReused(), false);
                var sample = RoutedFileValidationTime.Sample(tx);
                if (!sample.Healthy) throw new RoutedAbortException(RoutedAbort.ClockUncertain);
                if (ProtoTime.ToDateTimeOffset(existing.View.ExpiresAt) <= StoreTime.FromMicroseconds(sample.BoundaryMicroseconds))
                {
                    begun = true;
                    return Refuse(Error(ErrorCategory.State, "expired", "approval_expired", correlation));
                }
            }
            var decision = CommandDeduplication.Begin(tx, id, "arcforges.node.v1.FileService/ExecuteRemoval", digest, Origin.Remote);
            if (decision.Status == DedupStatus.Replay)
            {
                var replay = FileServiceExecuteRemovalResponse.Parser.ParseFrom(decision.Outcome!.Value.Span);
                lease.PolicyReason = tx.Scalar("SELECT policy_reason FROM file_removal_command_owner WHERE command_id = $id;", ("$id", id)) as string;
                AuditLog.AppendFileWorkspace(tx, caller.Actor, "file.remove FileService.ExecuteRemoval", null, null, null,
                    replay.Error is null ? PermissionDecision.Allow : PermissionDecision.Deny, "replayed: removal", null);
                return replay;
            }
            if (decision.Status == DedupStatus.Conflict || decision.Status == DedupStatus.InProgress && !caller.Approved)
                return Refuse(decision.Error ?? NodeErrors.Internal(node.Clock.GetUtcNow()), false);
            begun = true;
            CheckRemovalPreflightAuthority(tx, caller);
            var plan = lease.Plan = ReadRemovalExecutionPlan(tx, request.PlanId.Value.ToByteArray(), caller.CenterCaller);
            if (plan is null) return Refuse(NodeErrors.NotFound("cleanup_plan", request.PlanId.Value.Span));
            var time = RoutedFileValidationTime.Sample(tx);
            if (!time.Healthy) throw new RoutedAbortException(RoutedAbort.ClockUncertain);
            if (!CryptographicOperations.FixedTimeEquals(plan.Digest, request.PlanDigest.Span))
                return Refuse(Error(ErrorCategory.Conflict, "digest_mismatch", "plan_digest_mismatch", correlation));
            if (time.BoundaryMicroseconds >= plan.Expires) return Refuse(Error(ErrorCategory.State, "expired", "removal_plan_expired", correlation));
            if (plan.State == 3) return Refuse(NodeErrors.InUse("removal_plan_executing"));
            if (plan.State is not (1 or 2)) return Refuse(Error(ErrorCategory.State, "invalid_state", "removal_plan_terminal", correlation));
            if (caller.Approved && tx.Scalar("SELECT 1 FROM cleanup_plan WHERE plan_id = $plan AND approval_id = $approval;",
                    ("$plan", request.PlanId.Value.ToByteArray()), ("$approval", caller.ApprovalId)) is null)
                return Refuse(StoreErrors.CommandIdReused());
            if (request.DeleteWithoutQuarantine)
                throw new WorkspaceRemovalPlanException("strict_cleanup_guard_unavailable");
            CaptureRemovalForEffect(tx, caller, request, lease, token);
            var policy = PolicyRules.Current(tx).Document;
            var owned = tx.Scalar("SELECT 1 FROM file_removal_plan_item WHERE plan_id = $plan AND owner_verified = 0 LIMIT 1;",
                ("$plan", request.PlanId.Value.ToByteArray())) is null;
            var needsApproval = !owned ||
                PermissionMatrix.DecideRouted(PermissionMatrix.FileRemove, caller.CellsOrigin, policy.Permissions).Decision == PermissionDecision.Approval ||
                PermissionMatrix.DecideRouted(PermissionMatrix.CleanupExecute, caller.CellsOrigin, policy.Permissions).Decision == PermissionDecision.Approval ||
                caller.CellsOrigin == Origin.Agent && policy.Cleanup.AgentExecute != AgentCleanupMode.LowRiskOnly;
            if (needsApproval && !caller.Approved)
            {
                var details = DescribeRemovalApproval(tx, request, correlation, lease);
                var capture = new ApprovalCapture
                {
                    Operation = "FileService.ExecuteRemoval",
                    MatrixOperation = PermissionMatrix.FileRemove,
                    Summary = "Quarantine the exact selected removal plan",
                    Details = details,
                    Risk = RiskClass.High,
                    Requester = caller.Actor,
                    CommandId = id,
                    RequestDigest = digest,
                    Request = [2, .. id],
                    TargetKind = "cleanup_plan",
                    TargetId = request.PlanId.Value.ToByteArray(),
                };
                var approval = Approvals.Raise(command, capture, TimeSpan.FromMicroseconds(Math.Max(1, plan.Expires - time.BoundaryMicroseconds)));
                if (approval.Error is not null || approval.Approval is null) return Refuse(approval.Error ?? StoreErrors.CommandIdReused());
                tx.Execute("UPDATE cleanup_plan SET state = 2, approval_id = $approval, rev = rev + 1 WHERE plan_id = $plan AND state IN (1,2);",
                    ("$approval", approval.Approval.Id), ("$plan", request.PlanId.Value.ToByteArray()));
                RecordRemovalCaller(tx, id, caller.CenterCaller, "approval_required");
                lease.PolicyReason = "approval_required";
                return Refuse(RoutedRefusals.ApprovalRequired(PermissionMatrix.FileRemove, approval.Approval.View.ApprovalId, correlation), false);
            }
            CheckRemovalBudget(started, limit, token);
            if (!RemovalManagedUsesClear(tx, lease, token))
                return Refuse(NodeErrors.InUse("managed_file_in_use"));
            PrepareRemovalDestination(tx, request, lease);
            var parentPath = lease.Source.Contains('/') ? lease.Source[..lease.Source.LastIndexOf('/')] : "";
            lease.Parent = WorkspacePath.Identity(lease.Root.OpenDirectory(parentPath));
            FileMutationJournal.PrepareRemoval(tx, id, correlation.Value.ToByteArray(), digest, caller.CenterCaller,
                plan.Workspace, plan.Attempt, plan.Path, RegisteredWorkspaces.RootIdentity.Encode(lease.Root.RootIdentity),
                RegisteredWorkspaces.RootIdentity.Encode(lease.Parent),
                lease.Snapshot!.Entries[0].NativeIdentity, request.PlanId.Value.ToByteArray(), lease.DestinationPath);
            RecordRemovalCaller(tx, id, caller.CenterCaller, null);
            lease.Prepared = true;
            return new FileServiceExecuteRemovalResponse { Meta = meta };
        }
        catch (FilePolicyException denied)
        {
            lease.PolicyReason = denied.Reason;
            return Refuse(Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileRemove, correlation));
        }
        catch (WorkspaceRemovalPlanException failure)
        {
            return Refuse(failure.Reason == "managed_file_in_use" ? NodeErrors.InUse("managed_file_in_use") : failure.Reason == "planned_tree_changed"
                ? Error(ErrorCategory.Conflict, "file_changed", failure.Reason, correlation)
                : failure.Reason == "strict_cleanup_guard_unavailable"
                    ? Error(ErrorCategory.Resource, "enforcement_unavailable", failure.Reason, correlation)
                    : Error(ErrorCategory.State, "file_access_denied", "file_access_denied", correlation));
        }
        catch (WorkspacePathException failure) when (failure.Reason is "native_2" or "native_3" or "native_20" or "root_changed" or "root_not_directory" or
            "directory_changed" or "directory_identity_changed" or "file_identity_changed")
        {
            return Refuse(Error(ErrorCategory.Conflict, "file_changed", "planned_tree_changed", correlation));
        }
        catch (Exception failure) when (failure is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException or IOException or ArgumentException)
        {
            return Refuse(Failure(failure, correlation));
        }
    }

    private FileServiceExecuteRemovalResponse ApplyRemovalEffect(StoreTransaction tx, Caller caller,
        FileServiceExecuteRemovalRequest request, RemovalEffectLease lease, long started, TimeSpan limit, CancellationToken token)
    {
        var correlation = caller.Routed?.Correlation(request.Meta) ?? request.Meta.CorrelationId.Clone();
        void Recheck()
        {
            CheckRemovalBudget(started, limit, token);
            CheckRemovalPreflightAuthority(tx, caller);
            var sample = RoutedFileValidationTime.Sample(tx);
            if (!sample.Healthy) throw new RoutedAbortException(RoutedAbort.ClockUncertain);
            if (sample.BoundaryMicroseconds >= lease.Plan!.Expires) throw new WorkspaceRemovalPlanException("planned_tree_changed");
        }
        try
        {
            Recheck();
            var snapshot = CaptureSelectedRemoval(lease, token);
            MatchRemovalExecutionSnapshot(tx, request.PlanId.Value.ToByteArray(), lease.Plan!, snapshot);
            RecheckRemovalOwnership(tx, caller, request, lease.Root, snapshot, token);
            if (!RemovalManagedUsesClear(tx, lease, token)) throw new WorkspaceRemovalPlanException("managed_file_in_use");
            if (lease.Destination!.InspectRemovalAbsent(lease.DestinationName) is false) throw new WorkspaceRemovalPlanException("planned_tree_changed");
            lease.AttemptRoot?.Dispose(); lease.AttemptRoot = null;
            lease.Root.MoveRemovalTo(lease.Source, lease.Destination, lease.DestinationName,
                lease.Target, lease.Parent, Recheck, () => lease.EffectStarted = true);
            AfterRemovalMoveForTests?.Invoke();
            var now = RoutedFileValidationTime.Advance(tx);
            lease.MovedAt = Math.Max(now.BoundaryMicroseconds, tx.NowMicroseconds);
            lease.PurgeAfter = checked(lease.MovedAt + Math.Max(24L, PolicyRules.Current(tx).Document.Cleanup.QuarantineHours) * 60 * 60 * 1_000_000);
            var result = new FileRemovalResult
            {
                PlanId = request.PlanId.Clone(),
                Quarantined = true,
                QuarantineId = new Id { Value = ByteString.CopyFrom(lease.Item) },
                PurgeAfter = ProtoTime.ToInstant(StoreTime.FromMicroseconds(lease.PurgeAfter)),
                ItemsRemoved = checked((uint)snapshot.Entries.Count),
                TotalBytes = snapshot.TotalBytes,
            };
            var response = new FileServiceExecuteRemovalResponse
            {
                Meta = new ResponseMeta { CorrelationId = correlation.Clone() },
                Value = new FileServiceExecuteRemovalValue { Result = result },
            };
            FileMutationJournal.CompleteRemoval(tx, request.Meta.CommandId.Value.ToByteArray(), request.PlanId.Value.ToByteArray(), response,
                Path.Combine(lease.Root.RootPath, lease.Source.Replace('/', Path.DirectorySeparatorChar)), lease.DestinationPath, lease.Item, lease.PurgeAfter, lease.MovedAt);
            tx.AfterCommitForTests = AfterRemovalExecutionCommitForTests;
            return response;
        }
        catch (Exception failure) when (!lease.EffectStarted && failure is not OutOfMemoryException and not StackOverflowException)
        {
            var error = failure is WorkspaceRemovalPlanException { Reason: "managed_file_in_use" }
                ? NodeErrors.InUse("managed_file_in_use")
                : failure is FilePolicyException
                    ? Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileRemove, correlation)
                    : Error(ErrorCategory.Conflict, "file_changed", "planned_tree_changed", correlation);
            RoutedFileErrors.Complete(error, request.Meta, correlation, node.Clock);
            var response = new FileServiceExecuteRemovalResponse { Meta = new ResponseMeta { CorrelationId = correlation.Clone() }, Error = error };
            if (failure is FilePolicyException denied)
            {
                lease.PolicyReason = denied.Reason;
                RecordRemovalCaller(tx, request.Meta.CommandId.Value.ToByteArray(), caller.CenterCaller!, denied.Reason);
            }
            FileMutationJournal.CompleteRemoval(tx, request.Meta.CommandId.Value.ToByteArray(), request.PlanId.Value.ToByteArray(), response);
            return response;
        }
    }

    private void CheckRemovalBudget(long started, TimeSpan limit, CancellationToken token)
    {
        if (Expired(started, limit, token)) throw new OperationCanceledException(token);
    }

    private static void RecordRemovalCaller(StoreTransaction tx, byte[] command, CenterCaller caller, string? reason) =>
        tx.Execute("""
            INSERT INTO file_removal_command_owner (command_id, caller, policy_reason) VALUES ($id, $caller, $reason)
            ON CONFLICT(command_id) DO UPDATE SET policy_reason = excluded.policy_reason;
            """, ("$id", command), ("$caller", caller.ToByteArray()), ("$reason", reason));
}
