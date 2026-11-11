// SPDX-License-Identifier: AGPL-3.0-only
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
    // Test-only gate after the actual FULL reservation, before creating a named stage.
    internal Func<Task>? AfterApprovalReservationForTests { get; set; }
    internal Task? LastApprovalProducerForTests { get; private set; }

    private static MutationPreparation? PreviousFileApproval(StoreTransaction transaction, Caller caller, MutationRequest request,
        byte[] raw, Id correlation)
    {
        var id = request.Meta!.CommandId.Value.Span;
        var previous = Approvals.ByCommand(transaction, id);
        if (previous is null) return null;
        caller.Routed!.BeforeEffect(transaction);
        var method = request.Kind == FileOperationKind.Write ? "FileService.WriteFile" : "FileService.EditFile";
        if (previous.View.Operation != method || previous.Request.Length != 17 || previous.Request[0] != 1 ||
            !previous.Request.AsSpan(1).SequenceEqual(id) || previous.RequestDigest.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(previous.RequestDigest, SHA256.HashData(raw)) ||
            !CenterRouting.SameFileCaller(previous.View.Requester?.CenterCaller, caller.CenterCaller))
            return FileApprovalRefusal(request, Error(ErrorCategory.Conflict, "command_id_reused", "command_id_reused", correlation));
        if (previous.State == ApprovalState.Pending)
        {
            var sample = RoutedFileValidationTime.Advance(transaction);
            if (!sample.Healthy) return new MutationPreparation(false);
            var expiry = transaction.Scalar("SELECT expires_at FROM approval WHERE approval_id = $id;", ("$id", previous.Id));
            if (expiry is not long until || until <= sample.BoundaryMicroseconds)
                return FileApprovalRefusal(request, Error(ErrorCategory.State, "invalid_state", "approval_expired", correlation));
            return PendingFileApproval(request, previous, correlation);
        }
        if (previous.State == ApprovalState.Approved) return new MutationPreparation(false);
        if (previous.State is ApprovalState.Denied or ApprovalState.Cancelled)
            return FileApprovalRefusal(request, Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileWrite, correlation), "denied");
        if (previous.State == ApprovalState.Expired)
            return FileApprovalRefusal(request, Error(ErrorCategory.State, "invalid_state", "approval_expired", correlation));
        // A terminal approval without a journal receipt is not sufficient evidence of the file result.
        return new MutationPreparation(false);
    }

    private static MutationPreparation PendingFileApproval(MutationRequest request, StoredApproval approval, Id correlation)
    {
        var error = RoutedRefusals.ApprovalRequired(PermissionMatrix.FileWrite, approval.View.ApprovalId, correlation);
        return FileApprovalRefusal(request, error, "approval_required");
    }

    private static MutationPreparation FileApprovalRefusal(MutationRequest request, ArcError error, string? policyReason = null)
    {
        var meta = new ResponseMeta { CorrelationId = error.CorrelationId.Clone() };
        if (request.Kind == FileOperationKind.Write)
        {
            var response = new FileServiceWriteFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("The file approval refusal is invalid.");
            return new MutationPreparation(false, response.ToByteArray(), policyReason);
        }
        var edit = new FileServiceEditFileResponse { Meta = meta, Error = error };
        if (!NodeShapes.IsValid(edit)) throw new InvalidDataException("The file approval refusal is invalid.");
        return new MutationPreparation(false, edit.ToByteArray(), policyReason);
    }

    private async Task<MutationPreparation> ProduceApprovalAsync(Caller caller, MutationRequest request, byte[] raw,
        long started, TimeSpan limit, CancellationToken token)
    {
        using var lease = new ApprovalProducerLease();
        try
        {
            var begin = await node.Processor.ExecuteAsync(command =>
                BeginApprovalStage(command.Transaction, caller, request, raw, lease, started, limit, token), CommitDurability.Full)
                .ConfigureAwait(false);
            if (!begin.Ready) return begin;
            if (AfterApprovalReservationForTests is { } afterReservation) await afterReservation().ConfigureAwait(false);
            token.ThrowIfCancellationRequested();

            if (lease.OriginalBytes is { } original)
            {
                using var stage = await PrivateStageProducer.CreateBoundAsync(node.Processor, request.Meta!.CommandId.Value.Memory,
                    1, lease.Use!.Root, lease.StageDirectory!, lease.OriginalName!, token,
                    beforeCreate: tx => CheckStageApprovalAuthority(tx, caller, started, limit, token)).ConfigureAwait(false);
                lease.OriginalIdentity = stage.Identity;
                PrivateStageRegistry.WriteBoundStage(node.Store, request.Meta.CommandId.Value.Span, 1, caller.CenterCaller!,
                    raw, stage, original, token, beforeWrite: tx => CheckStageApprovalAuthority(tx, caller, started, limit, token));
            }
            using (var stage = await PrivateStageProducer.CreateBoundAsync(node.Processor, request.Meta!.CommandId.Value.Memory,
                2, lease.Use!.Root, lease.StageDirectory!, lease.IntendedName!, token,
                beforeCreate: tx => CheckStageApprovalAuthority(tx, caller, started, limit, token)).ConfigureAwait(false))
            {
                lease.IntendedIdentity = stage.Identity;
                PrivateStageRegistry.WriteBoundStage(node.Store, request.Meta.CommandId.Value.Span, 2, caller.CenterCaller!,
                    raw, stage, lease.IntendedBytes!, token, beforeWrite: tx => CheckStageApprovalAuthority(tx, caller, started, limit, token));
            }

            return await node.Processor.ExecuteAsync(command =>
                RaiseFileApproval(command, caller, request, raw, lease, started, limit, token), CommitDurability.Full).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            // Never invent an approval or an effect outcome after a reserved/partly written stage. Its actual
            // identity, phase and location remain in the durable registry for local recovery.
            node.Log.Error("api.file.approval.producer_deferred");
            try
            {
                // Awaited native work above has ended; the FULL writer rechecks that no approval or target journal won.
                await node.Processor.ExecuteAsync(command => PrivateStageTerminal.RecoverFailedProducer(
                    command.Transaction, request.Meta!.CommandId.Value.Span), CommitDurability.Full).ConfigureAwait(false);
            }
            catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
            {
                node.Log.Error("api.file.approval.recovery_deferred");
            }
            return new MutationPreparation(false);
        }
    }

    private MutationPreparation BeginApprovalStage(StoreTransaction transaction, Caller caller, MutationRequest request, byte[] raw,
        ApprovalProducerLease lease, long started, TimeSpan limit, CancellationToken token)
    {
        var routed = caller.Routed!;
        var correlation = routed.Correlation(request.Meta);
        var workspace = request.Path!.WorkspaceId.Value.ToByteArray();
        var path = request.Path.Path;
        MutationPreparation Refuse(ArcError error, string? policyReason = null)
        {
            AuditLog.AppendFileWorkspace(transaction, caller.Actor, PermissionMatrix.FileWrite + " FileService." +
                (request.Kind == FileOperationKind.Write ? "WriteFile" : "EditFile"), workspace, null, path,
                PermissionDecision.Deny, "refused: " + error.Code, lease.Observation);
            return FileApprovalRefusal(request, error, policyReason);
        }

        try
        {
            CheckStageApprovalAuthority(transaction, caller, started, limit, token);
            if (PreviousFileApproval(transaction, caller, request, raw, correlation) is { } previous)
            {
                if (previous.PolicyReason == "approval_required")
                    AuditLog.AppendFileWorkspace(transaction, caller.Actor, PermissionMatrix.FileWrite + " FileService." +
                        (request.Kind == FileOperationKind.Write ? "WriteFile" : "EditFile"), workspace, null, path,
                        PermissionDecision.Approval, "refused: approval_required", null);
                else if (previous.Response is not null)
                    AuditLog.AppendFileWorkspace(transaction, caller.Actor, PermissionMatrix.FileWrite + " FileService." +
                        (request.Kind == FileOperationKind.Write ? "WriteFile" : "EditFile"), workspace, null, path,
                        PermissionDecision.Deny, "refused: existing_approval", null);
                return previous;
            }

            var id = request.Meta!.CommandId.Value.ToByteArray();
            if (transaction.Scalar("SELECT 1 FROM command_dedup WHERE command_id = $id;", ("$id", id)) is not null)
            {
                using var prior = transaction.CreateCommand("SELECT kind, request_sha256, caller FROM file_private_stage_reservation WHERE command_id = $id;");
                prior.Parameters.AddWithValue("$id", id);
                using var row = prior.ExecuteReader();
                if (row.Read() && row.GetInt32(0) == (int)request.Kind &&
                    CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(1), SHA256.HashData(raw)) &&
                    CenterRouting.SameFileCaller(CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2)), caller.CenterCaller))
                    return new MutationPreparation(false); // A producer or recovery still owns this exact reservation.
                return Refuse(Error(ErrorCategory.Conflict, "command_id_reused", "command_id_reused", correlation));
            }
            if (FileMutationJournal.HasWorkspaceHold(transaction, workspace))
                return Refuse(Error(ErrorCategory.State, "invalid_state", "file_recovery_pending", correlation));
            // Linux staging awaits the dedicated exact-FD lease-break coordinator; do not use a check/write gap.
            if (!OperatingSystem.IsWindows())
                return Refuse(Error(ErrorCategory.Resource, "enforcement_unavailable", "file_guard_unavailable", correlation));

            _ = WorkspacePath.Components(path);
            lease.Use = _workspaces.OpenForUse(transaction, workspace,
                beforeUse: tx => CheckStageApprovalAuthority(tx, caller, started, limit, token), token);
            var slash = path.LastIndexOf('/');
            var parentName = slash < 0 ? "" : path[..slash];
            var parent = lease.Use.Root.OpenDirectory(parentName);
            lease.ParentIdentity = WorkspacePath.Identity(parent);
            var parentPath = parentName.Length == 0 ? lease.Use.Root.RootPath :
                System.IO.Path.Combine(lease.Use.Root.RootPath, parentName.Replace('/', System.IO.Path.DirectorySeparatorChar));
            lease.StageDirectory = WorkspacePath.OpenRoot(parentPath, lease.ParentIdentity);
            if (request.HasExpectedSha256)
            {
                lease.Target = lease.Use.Root.OpenExistingWriteGuard(path);
                using var content = lease.Target.ReadForMutation(token);
                lease.Observation = new FileAuditMetadata
                {
                    Observations =
                    {
                        new FileAuditObservation
                        {
                            Kind = FileAuditKind.InputBytes,
                            SizeBytes = checked((ulong)content.Bytes.Length),
                            DigestInputBytes = checked((ulong)content.Bytes.Length),
                            Sha256 = ByteString.CopyFrom(content.Sha256.Span),
                        },
                    },
                };
                if (!CryptographicOperations.FixedTimeEquals(request.ExpectedSha256.Span, content.Sha256.Span))
                    return Refuse(Error(ErrorCategory.Conflict, "file_changed", "hash_mismatch", correlation));
                lease.OriginalBytes = content.Bytes.ToArray();
                using var edit = request.Kind == FileOperationKind.Edit
                    ? WorkspaceFileEdit.Plan(content.Bytes.Span, request.ExpectedSha256.Span, request.OldText!, request.NewText!,
                        request.ExpectedOccurrences, token) : null;
                lease.IntendedBytes = edit is null ? request.Data.ToByteArray() : edit.Bytes.ToArray();
            }
            else
            {
                // Exact absence is checked again by PrivateStageApproval immediately before raising.
                try
                {
                    _ = lease.Use.Root.InspectEntry(path);
                    return Refuse(Error(ErrorCategory.Conflict, "file_changed", "expected_absent_conflict", correlation));
                }
                catch (WorkspacePathException missing) when (missing.Reason == "native_2") { }
                lease.IntendedBytes = request.Data.ToByteArray();
            }
            CheckStageApprovalAuthority(transaction, caller, started, limit, token);
            var tag = Convert.ToHexStringLower(id);
            lease.OriginalName = ".arcforges-stage-" + tag + "-1";
            lease.IntendedName = ".arcforges-stage-" + tag + "-2";
            var stages = new List<PrivateStageSpec>();
            if (lease.OriginalBytes is { } original)
                stages.Add(new PrivateStageSpec(1, System.IO.Path.Combine(lease.StageDirectory.RootPath, lease.OriginalName),
                    original.Length, SHA256.HashData(original)));
            stages.Add(new PrivateStageSpec(2, System.IO.Path.Combine(lease.StageDirectory.RootPath, lease.IntendedName),
                lease.IntendedBytes.Length, SHA256.HashData(lease.IntendedBytes)));
            var reserved = PrivateStageRegistry.Reserve(transaction, _writeStageBudget, request.Kind, id, workspace,
                correlation.Value.Span, caller.CenterCaller!, raw, stages);
            return reserved switch
            {
                PrivateStageReservationResult.Reserved => new MutationPreparation(true),
                PrivateStageReservationResult.Existing => new MutationPreparation(false),
                PrivateStageReservationResult.Capacity => Refuse(Error(ErrorCategory.Resource, "enforcement_unavailable", "file_stage_capacity", correlation)),
                _ => Refuse(Error(ErrorCategory.Conflict, "command_id_reused", "command_id_reused", correlation)),
            };
        }
        catch (ApprovalDecisionChangedException) { return new MutationPreparation(false); }
        catch (FilePolicyException denied)
        {
            return Refuse(Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileWrite, correlation), denied.Reason);
        }
        catch (WorkspaceFileEditException failure)
        {
            return failure.Reason switch
            {
                "occurrence_mismatch" => Refuse(Error(ErrorCategory.Conflict, "occurrence_mismatch", "occurrence_mismatch", correlation)),
                "file_existing_bytes" or "file_edit_result_bytes" => Refuse(TooLargeFile(failure.Reason, "4194304", correlation)),
                "file_edit_text_bytes" => Refuse(TooLargeFile(failure.Reason, "65536", correlation)),
                "hash_mismatch" => Refuse(Error(ErrorCategory.Conflict, "file_changed", "hash_mismatch", correlation)),
                _ => Refuse(Error(ErrorCategory.Validation, "invalid_argument", "content: invalid_utf8", correlation)),
            };
        }
        catch (WorkspacePathException failure) when (failure.Reason == "file_too_large")
        {
            return Refuse(TooLargeFile("file_existing_bytes", "4194304", correlation));
        }
        catch (Exception failure) when (failure is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException or IOException)
        {
            return Refuse(Failure(failure, correlation));
        }
    }

    private MutationPreparation RaiseFileApproval(CommandContext context, Caller caller, MutationRequest request, byte[] raw,
        ApprovalProducerLease lease, long started, TimeSpan limit, CancellationToken token)
    {
        var tx = context.Transaction;
        CheckStageApprovalAuthority(tx, caller, started, limit, token);
        var root = RegisteredWorkspaces.RootIdentity.Encode(lease.Use!.Root.RootIdentity);
        var parent = RegisteredWorkspaces.RootIdentity.Encode(lease.ParentIdentity!.Value);
        var target = lease.Target is null ? null : RegisteredWorkspaces.RootIdentity.Encode(lease.Target.ObjectIdentity, directory: false);
        var intent = new FileJournalIntent(request.Kind, request.Meta!.CommandId.Value.ToByteArray(),
            caller.Routed!.Correlation(request.Meta).Value.ToByteArray(), caller.CenterCaller!,
            request.Path!.WorkspaceId.Value.ToByteArray(), request.Path.Path, root.Platform, root.Bytes, parent.Bytes,
            target?.Bytes, lease.OriginalBytes?.Length, lease.OriginalBytes is null ? null : SHA256.HashData(lease.OriginalBytes),
            lease.OriginalIdentity?.Bytes, lease.IntendedBytes!.Length, SHA256.HashData(lease.IntendedBytes),
            lease.IntendedIdentity!.Bytes);
        var policy = PolicyRules.Current(tx).Document.Approvals;
        var ttl = policy is { HasDefaultTtlMs: true, DefaultTtlMs: > 0 } ? TimeSpan.FromMilliseconds(policy.DefaultTtlMs) : Approvals.DefaultTtl;
        var result = PrivateStageApproval.Raise(context, intent, raw, caller.Actor, lease.Use.Root, lease.Target, ttl, token);
        if (result.Error is not null || result.Approval is null) return new MutationPreparation(false);
        // The final transaction rechecks the live call after the expensive stage/target verification.
        CheckStageApprovalAuthority(tx, caller, started, limit, token);
        AuditLog.AppendFileWorkspace(tx, caller.Actor, PermissionMatrix.FileWrite + " FileService." +
            (request.Kind == FileOperationKind.Write ? "WriteFile" : "EditFile"), intent.WorkspaceId, null, intent.RelativePath,
            PermissionDecision.Approval, "refused: approval_required", lease.Observation);
        if (result.Created && policy?.NotifyDesktop != false)
            Notifications.Add(context, "approval_needed", Severity.Warning, "Approval needed",
                $"{PermissionMatrix.Name(caller.Origin)} asks: {result.Approval.View.Summary}",
                "arcforges://approvals/" + IdText.Format(result.Approval.View.ApprovalId));
        return PendingFileApproval(request, result.Approval, caller.Routed.Correlation(request.Meta));
    }

    private void CheckStageApprovalAuthority(StoreReader reader, Caller caller, long started, TimeSpan limit, CancellationToken token)
    {
        if (Expired(started, limit, token)) throw new OperationCanceledException(token);
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
            var decision = PermissionMatrix.DecideRouted(PermissionMatrix.FileWrite, caller.CellsOrigin, policy.Document.Permissions).Decision;
            if (decision == PermissionDecision.Allow) throw new ApprovalDecisionChangedException();
            if (decision != PermissionDecision.Approval || caller.CellsOrigin == Origin.Agent)
                throw new FilePolicyException("denied");
            caller.Routed.BeforeEffect(reader);
        }
        catch (FilePolicyException) { throw; }
        catch (ApprovalDecisionChangedException) { throw; }
        catch (Exception failure) when (failure is not RoutedAbortException and not OperationCanceledException and not OutOfMemoryException)
        {
            throw new FilePolicyException("policy_invalid");
        }
    }

    private async Task ObserveApprovalProducerAsync(Task<MutationPreparation> pending)
    {
        try { _ = await pending.ConfigureAwait(false); }
        catch (Exception failure) when (failure is not OutOfMemoryException) { node.Log.Error("api.file.approval.pending_failed"); }
    }

    private sealed class ApprovalDecisionChangedException : Exception;

    private sealed class ApprovalProducerLease : IDisposable
    {
        internal RegisteredWorkspaceUse? Use { get; set; }
        internal WorkspacePath? StageDirectory { get; set; }
        internal WorkspaceWriteGuard? Target { get; set; }
        internal WorkspaceObjectIdentity? ParentIdentity { get; set; }
        internal string? OriginalName { get; set; }
        internal string? IntendedName { get; set; }
        internal byte[]? OriginalBytes { get; set; }
        internal byte[]? IntendedBytes { get; set; }
        internal RegisteredWorkspaces.RootIdentity? OriginalIdentity { get; set; }
        internal RegisteredWorkspaces.RootIdentity? IntendedIdentity { get; set; }
        internal FileAuditMetadata? Observation { get; set; }

        public void Dispose()
        {
            if (OriginalBytes is not null) CryptographicOperations.ZeroMemory(OriginalBytes);
            if (IntendedBytes is not null) CryptographicOperations.ZeroMemory(IntendedBytes);
            try { Target?.Dispose(); }
            finally
            {
                try { StageDirectory?.Dispose(); }
                finally { Use?.Dispose(); }
            }
        }
    }
}
