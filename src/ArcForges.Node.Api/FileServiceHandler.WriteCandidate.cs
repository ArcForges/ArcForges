// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;
using WireDecimal = ArcForges.Contracts.Foundation.V1.Decimal;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    // Legacy WriteFile and EditFile admit only the reconciliation of prior commands.
    internal Task<byte[]?> WriteExistingCandidateAsync(Caller caller, CancellationToken cancellationToken)
    {
        var raw = caller.RawRequest ?? throw new InvalidOperationException("The exact transmitted request is required.");
        var request = FileServiceWriteFileRequest.Parser.ParseFrom(raw);
        var admission = WriteAdmission(request);
        return MutateExistingCandidateAsync(caller, raw, new MutationRequest(FileOperationKind.Write, request.Meta, request.Path,
            admission.Valid, admission.Limit), cancellationToken);
    }

    internal Task<byte[]?> EditExistingCandidateAsync(Caller caller, CancellationToken cancellationToken)
    {
        var raw = caller.RawRequest ?? throw new InvalidOperationException("The exact transmitted request is required.");
        var request = FileServiceEditFileRequest.Parser.ParseFrom(raw);
        var admission = EditAdmission(request);
        return MutateExistingCandidateAsync(caller, raw, new MutationRequest(FileOperationKind.Edit, request.Meta, request.Path,
            admission.Valid, admission.Limit), cancellationToken);
    }

    // The published shape validator includes resource maxima. Validate all other rules against a bounded clone while
    // measuring the original values; otherwise a valid oversized value would be mislabeled invalid_argument.
    private static (bool Valid, string? Limit) WriteAdmission(FileServiceWriteFileRequest original)
    {
        try
        {
            var bounded = original.Clone();
            var pathLimit = NormalizeOversizedPath(bounded.Path);
            var writeLimit = bounded.HasData && bounded.Data.Length > 196_608;
            if (writeLimit) bounded.Data = ByteString.Empty;
            return (NodeShapes.IsValid(bounded), pathLimit ? "path_bytes" : writeLimit ? "file_write_bytes" : null);
        }
        catch (Exception exception) when (exception is System.Text.EncoderFallbackException or WorkspacePathException)
        {
            return (false, null);
        }
    }

    private static (bool Valid, string? Limit) EditAdmission(FileServiceEditFileRequest original)
    {
        try
        {
            var bounded = original.Clone();
            var pathLimit = NormalizeOversizedPath(bounded.Path);
            var oldLimit = bounded.HasOldText && StrictUtf8.GetByteCount(bounded.OldText) > 65_536;
            var newLimit = bounded.HasNewText && StrictUtf8.GetByteCount(bounded.NewText) > 65_536;
            if (oldLimit) bounded.OldText = "x";
            if (newLimit) bounded.NewText = string.Empty;
            return (NodeShapes.IsValid(bounded), pathLimit ? "path_bytes" : oldLimit || newLimit ? "file_edit_text_bytes" : null);
        }
        catch (Exception exception) when (exception is System.Text.EncoderFallbackException or WorkspacePathException)
        {
            return (false, null);
        }
    }

    private static bool NormalizeOversizedPath(FilePath? path)
    {
        if (path is not { HasPath: true } || StrictUtf8.GetByteCount(path.Path) <= 4096) return false;
        // Do not erase traversal, platform-reserved names or other path errors when classifying an oversized path.
        _ = WorkspacePath.ComponentsIgnoringSize(path.Path);
        path.Path = "x";
        return true;
    }

    private async Task<byte[]?> MutateExistingCandidateAsync(Caller caller, byte[] raw, MutationRequest request, CancellationToken cancellationToken)
    {
        var routed = caller.Routed ?? throw new InvalidOperationException("A file mutation requires a verified routed caller.");
        var limit = routed.RemainingFileOperation();
        if (limit <= TimeSpan.Zero) throw new OperationCanceledException(cancellationToken);
        var started = node.Clock.GetTimestamp();
        using var deadline = new CancellationTokenSource(limit, node.Clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token, node.Stopping, routed.Link.EffectEnding);
        var token = linked.Token;
        var preparation = node.Processor.ExecuteAsync(command => PrepareMutation(command.Transaction, caller, request, raw, started, limit, token),
            CommitDurability.Full);
        MutationPreparation prepared;
        try
        {
            prepared = await preparation.WaitAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = ObserveMutationAsync(preparation);
            throw;
        }

        if (prepared.PolicyReason is { } reason)
        {
            routed.Refused(PermissionMatrix.FileWrite, reason);
            routed.MarkAudited();
        }

        return prepared.Response;
    }

    private MutationPreparation PrepareMutation(StoreTransaction transaction, Caller caller, MutationRequest request, byte[] raw,
        long started, TimeSpan limit, CancellationToken token)
    {
        var routed = caller.Routed!;
        var correlation = routed.Correlation(request.Meta);
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        var method = request.Kind == FileOperationKind.Write ? "WriteFile" : "EditFile";
        var auditOperation = request.Kind == FileOperationKind.Write ? "file.write" : "file.edit";
        byte[]? workspace = null;
        string? path = null;
        void Audit(PermissionDecision decision, string outcome) => AuditLog.AppendFileWorkspace(transaction, caller.Actor,
            auditOperation + " FileService." + method, workspace, null, path, decision, outcome, null);
        MutationPreparation Refuse(ArcError error, string? policyReason = null)
        {
            RoutedFileErrors.Complete(error, request.Meta, correlation, node.Clock);
            Audit(PermissionDecision.Deny, "refused: " + error.Code);
            var bytes = request.Kind == FileOperationKind.Write
                ? new FileServiceWriteFileResponse { Meta = meta, Error = error }.ToByteArray()
                : new FileServiceEditFileResponse { Meta = meta, Error = error }.ToByteArray();
            return new MutationPreparation(bytes, policyReason);
        }
        void CheckBudget()
        {
            if (Expired(started, limit, token)) throw new OperationCanceledException(token);
        }
        MutationPreparation Unavailable()
        {
            var error = Error(ErrorCategory.Execution, "operation_failed", "file_outcome_unknown", correlation);
            error.Effect = EffectCertainty.Unknown;
            return Refuse(error);
        }

        try
        {
            CheckBudget();
            if (!request.ShapeValid || Validation.CommandId(request.Meta) is not null ||
                request.Meta!.CommandId is null || caller.RemoteCommandId is null || !request.Meta.CommandId.Equals(caller.RemoteCommandId) ||
                request.Path?.WorkspaceId is not { Value.Length: 16 } selected || !request.Path.HasPath ||
                caller.CenterCaller is null || raw.Length is < 1 or > 245_760)
                return Refuse(Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));
            workspace = selected.Value.ToByteArray();
            path = request.Limit == "path_bytes" ? null : request.Path.Path;
            if (request.Limit is { } resource)
                return Refuse(TooLargeFile(resource, resource switch
                {
                    "path_bytes" => "4096",
                    "file_write_bytes" => "196608",
                    "file_edit_text_bytes" => "65536",
                    _ => throw new InvalidOperationException("Unknown mutation request limit."),
                }, correlation));
            path = request.Path.Path;
            // A recorded command is replayed only to the original caller with the exact transmitted bytes. Like the
            // existing workspace mutation flow, replay still requires a live, non-stopping link, but does not execute
            // another effect or depend on the current write matrix or the target remaining available.
            routed.BeforeReplay();
            CheckBudget();
            var id = request.Meta.CommandId.Value.ToByteArray();
            var binding = FindRetainedMutation(transaction, request.Kind, id, caller.CenterCaller, SHA256.HashData(raw));
            if (binding == RetainedMutation.Conflict)
                return Refuse(Error(ErrorCategory.Conflict, "command_id_reused", "command_id_reused", correlation));
            if (binding == RetainedMutation.Unavailable)
                return Unavailable();
            if (binding == RetainedMutation.Receipt)
            {
                byte[]? cached;
                ArcError? replayError;
                try
                {
                    cached = FileMutationJournal.Replay(transaction, request.Kind, id, caller.CenterCaller, raw);
                    if (cached is null) return new MutationPreparation();
                    replayError = request.Kind == FileOperationKind.Write
                        ? FileServiceWriteFileResponse.Parser.ParseFrom(cached).Error
                        : FileServiceEditFileResponse.Parser.ParseFrom(cached).Error;
                }
                catch (Exception failure) when (failure is InvalidDataException or InvalidProtocolBufferException)
                {
                    return Unavailable();
                }
                Audit(replayError is null ? PermissionDecision.Allow : PermissionDecision.Deny,
                    replayError is null ? "replayed" : "replayed: " + replayError.Code);
                return new MutationPreparation(cached);
            }

            if (binding == RetainedMutation.PendingStage)
            {
                MutationPreparation? previous;
                try { previous = PreviousFileApproval(transaction, caller, request, raw, correlation); }
                catch (Exception failure) when (failure is InvalidDataException or InvalidProtocolBufferException)
                {
                    return Unavailable();
                }
                if (previous is null) return new MutationPreparation(); // Preserve an unsettled producer.
                if (previous.PolicyReason == "approval_required")
                    Audit(PermissionDecision.Approval, "refused: approval_required");
                else if (previous.Response is not null)
                    Audit(PermissionDecision.Deny, "refused: existing_approval");
                return previous;
            }

            CheckWriteCandidateAuthority(transaction, caller);
            CheckBudget();
            // An absent receipt cannot establish the effect of an earlier submission. This path cannot open
            // a target, reserve a journal, stage new data, or ask for a new approval.
            return Unavailable();
        }
        catch (FilePolicyException refusal)
        {
            return Refuse(Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileWrite, correlation), refusal.Reason);
        }
        catch (FileApprovalNotImplementedException)
        {
            return Unavailable();
        }
    }

    private enum RetainedMutation { None, Conflict, Unavailable, Receipt, PendingStage }

    private static RetainedMutation FindRetainedMutation(StoreReader reader, FileOperationKind kind, byte[] id, CenterCaller caller,
        byte[] digest)
    {
        // Match the journal or stage binding before reading retained outcomes or approval data.
        using var query = reader.CreateCommand("""
            SELECT coalesce(j.kind, r.kind), coalesce(j.request_sha256, r.request_sha256), coalesce(j.caller, r.caller),
                   j.command_id IS NOT NULL, r.active, t.command_id IS NOT NULL,
                   d.method, d.payload_digest, d.origin, d.outcome IS NULL
            FROM command_dedup d
            LEFT JOIN file_operation_journal j ON j.command_id = d.command_id
            LEFT JOIN file_private_stage_reservation r ON r.command_id = d.command_id
            LEFT JOIN file_private_stage_terminal t ON t.command_id = r.command_id
            WHERE d.command_id = $id;
            """);
        query.Parameters.AddWithValue("$id", id);
        using var row = query.ExecuteReader();
        if (!row.Read()) return RetainedMutation.None;
        if (row.IsDBNull(0) || row.GetInt32(0) != (int)kind ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(1), digest))
            return RetainedMutation.Conflict;

        CenterCaller saved;
        try { saved = CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2)); }
        catch (InvalidProtocolBufferException) { return RetainedMutation.None; }
        if (CenterRouting.Shape(saved) is not null) return RetainedMutation.None;
        if (!CenterRouting.SameFileCaller(saved, caller)) return RetainedMutation.Conflict;

        var method = kind == FileOperationKind.Write ? "WriteFile" : "EditFile";
        if (row.GetString(6) != "arcforges.node.v1.FileService/" + method || row.GetInt32(8) != (int)Origin.Remote ||
            !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(7), digest))
            return RetainedMutation.Unavailable;
        if (row.GetBoolean(3)) return RetainedMutation.Receipt;
        var outcomeMissing = row.GetBoolean(9);
        if (row.GetBoolean(5)) return outcomeMissing ? RetainedMutation.Unavailable : RetainedMutation.Receipt;
        return row.GetInt32(4) == 1 && outcomeMissing ? RetainedMutation.PendingStage : RetainedMutation.Unavailable;
    }

    private void CheckWriteCandidateAuthority(StoreReader reader, Caller caller)
    {
        if (caller.CenterCaller is not { } center || caller.Routed is null)
            throw new FilePolicyException("center_caller_incomplete");
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
            var verdict = PermissionMatrix.DecideRouted(PermissionMatrix.FileWrite, caller.CellsOrigin, policy.Document.Permissions);
            if (verdict.Decision == PermissionDecision.Approval)
                throw new FileApprovalNotImplementedException();
            if (verdict.Decision != PermissionDecision.Allow)
                throw new FilePolicyException("denied");
            caller.Routed.BeforeEffect(reader);
        }
        catch (FilePolicyException) { throw; }
        catch (FileApprovalNotImplementedException) { throw; }
        catch (Exception exception) when (exception is not RoutedAbortException and not OperationCanceledException and not OutOfMemoryException)
        {
            throw new FilePolicyException("policy_invalid");
        }
    }

    // An actual approval cannot be inferred from this exception.
    private sealed class FileApprovalNotImplementedException() : NotSupportedException("Durable file approval is not implemented.");

    private static ArcError TooLargeFile(string name, string maximum, Id correlation) => new()
    {
        Category = ErrorCategory.Resource,
        Code = "too_large",
        MessageKey = "error.resource.too_large",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = correlation.Clone(),
        Details = new ErrorDetails { Limit = new LimitFailure { LimitName = name, Maximum = new WireDecimal { Value = maximum } } },
    };

    private async Task ObserveMutationAsync(Task<MutationPreparation> pending)
    {
        try { _ = await pending.ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OutOfMemoryException) { node.Log.Error("api.file.mutation.pending_failed"); }
    }

    private sealed record MutationRequest(FileOperationKind Kind, RequestMeta? Meta, FilePath? Path, bool ShapeValid, string? Limit);

    private sealed record MutationPreparation(byte[]? Response = null, string? PolicyReason = null);
}
